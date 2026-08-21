import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SOURCE = readFileSync(
  new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt", import.meta.url),
  "utf8",
);
const PACKAGE_SOURCE = readFileSync(
  new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadReactPackage.kt", import.meta.url),
  "utf8",
);
const PACKAGE_CONFIG = readFileSync(
  new URL("../packages/react-native/react-native.config.cjs", import.meta.url),
  "utf8",
);
const PACKAGE_MANIFEST = JSON.parse(
  readFileSync(new URL("../packages/react-native/package.json", import.meta.url), "utf8"),
);
const ANDROID_BUILD_GRADLE = readFileSync(
  new URL("../packages/react-native/android/build.gradle", import.meta.url),
  "utf8",
);
const ANDROID_VIEW_SOURCE = readFileSync(
  new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", import.meta.url),
  "utf8",
);
const IOS_VIEW_SOURCE = readFileSync(
  new URL("../native/ios/SecureKeypadView.swift", import.meta.url),
  "utf8",
);
const ANDROID_PRESENTATION_SOURCE = readFileSync(
  new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt", import.meta.url),
  "utf8",
);
const IOS_PRESENTATION_SOURCE = readFileSync(
  new URL("../native/ios/SecureKeypadPresentation.swift", import.meta.url),
  "utf8",
);

test("React Native Android bridge rejects unknown keys before reading values", () => {
  assert.match(SOURCE, /value\?\.toPublicMap\(LAYOUT_KEYS\)/);
  assert.match(SOURCE, /value\?\.toPublicMap\(THEME_KEYS\)/);

  const keyGuard = SOURCE.indexOf("require(key in allowedKeys)");
  const valueRead = SOURCE.indexOf("result[key] = getPublicValue(key");
  assert.ok(keyGuard >= 0, "bridge must check the key allowlist");
  assert.ok(valueRead >= 0, "bridge must read values through one boundary helper");
  assert.ok(keyGuard < valueRead, "unknown keys must be rejected before their values are read");
});

test("React Native Android bridge exposes its view manager through an autolinkable package", () => {
  assert.match(PACKAGE_SOURCE, /class SecureKeypadReactPackage\s*:\s*ReactPackage/);
  assert.match(PACKAGE_SOURCE, /createNativeModules\(/);
  assert.match(PACKAGE_SOURCE, /createViewManagers\(/);
  assert.match(PACKAGE_SOURCE, /SecureKeypadViewManager\(\)/);
  assert.match(PACKAGE_CONFIG, /packageImportPath/);
  assert.match(PACKAGE_CONFIG, /com\.uulab\.securekeypad\.reactnative\.SecureKeypadReactPackage/);
  assert.ok(PACKAGE_MANIFEST.files.includes("react-native.config.cjs"));
  assert.match(ANDROID_BUILD_GRADLE, /reactNativeArchitectures/);
  assert.match(ANDROID_BUILD_GRADLE, /abiFilters/);
});

test("React Native Android bridge dispatches events through the New Architecture event dispatcher", () => {
  assert.match(SOURCE, /UIManagerHelper/);
  assert.match(SOURCE, /Event<SecureKeypadEvent>/);
  assert.match(SOURCE, /dispatchEvent\(SecureKeypadEvent/);
  assert.doesNotMatch(SOURCE, /getJSModule\(RCTEventEmitter/);
});

test("React Native Android bridge bounds defensive public-value conversion", () => {
  assert.match(SOURCE, /MAX_PUBLIC_BRIDGE_DEPTH/);
  assert.match(SOURCE, /MAX_PUBLIC_BRIDGE_NODES/);
  assert.match(SOURCE, /MAX_PUBLIC_BRIDGE_KEYS/);
  assert.match(SOURCE, /MAX_PUBLIC_BRIDGE_ITEMS/);
  assert.match(SOURCE, /MAX_PUBLIC_BRIDGE_STRING_LENGTH/);
  assert.match(SOURCE, /require\(size\(\) <= MAX_PUBLIC_BRIDGE_ITEMS\)/);
  assert.match(SOURCE, /require\(value\.length <= MAX_PUBLIC_BRIDGE_STRING_LENGTH\)/);
});

test("React Native Android bridge converts hostile public maps inside the fail-closed boundary", () => {
  assert.match(SOURCE, /setConfigurationValue\(view, "layout"\) \{ value\?\.toPublicMap\(LAYOUT_KEYS\) \}/);
  assert.match(SOURCE, /setConfigurationValue\(view, "theme"\) \{ value\?\.toPublicMap\(THEME_KEYS\) \}/);
  assert.match(SOURCE, /setConfigurationValue\(view, "headlessKeyPress"\) \{ value\?\.toPublicMap\(HEADLESS_KEY_PRESS_KEYS\) \}/);
  assert.match(SOURCE, /catch \(_:\s*IllegalArgumentException\) \{[\s\S]{0,240}view\.releaseSession\(\)[\s\S]{0,240}emitResult\(view, "invalid"\)/);
});

test("native RN cancel commands reject stale tokens and coalesce replays", () => {
  assert.match(ANDROID_VIEW_SOURCE, /secureKeypadMonotonicCommandDecision/);
  assert.match(IOS_VIEW_SOURCE, /secureKeypadMonotonicCommandDecision/);
  assert.match(ANDROID_PRESENTATION_SOURCE, /requestId < previous/);
  assert.match(ANDROID_PRESENTATION_SOURCE, /requestId == previous/);
  assert.match(IOS_PRESENTATION_SOURCE, /requestId < previous/);
  assert.match(IOS_PRESENTATION_SOURCE, /requestId == previous/);
});
