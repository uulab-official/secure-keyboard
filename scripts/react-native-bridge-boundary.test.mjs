import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SOURCE = readFileSync(
  new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt", import.meta.url),
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

test("React Native Android bridge rejects unknown keys before reading values", () => {
  assert.match(SOURCE, /value\?\.toPublicMap\(LAYOUT_KEYS\)/);
  assert.match(SOURCE, /value\?\.toPublicMap\(THEME_KEYS\)/);

  const keyGuard = SOURCE.indexOf("require(key in allowedKeys)");
  const valueRead = SOURCE.indexOf("result[key] = getPublicValue(key");
  assert.ok(keyGuard >= 0, "bridge must check the key allowlist");
  assert.ok(valueRead >= 0, "bridge must read values through one boundary helper");
  assert.ok(keyGuard < valueRead, "unknown keys must be rejected before their values are read");
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
  assert.match(ANDROID_VIEW_SOURCE, /requestId < previous/);
  assert.match(ANDROID_VIEW_SOURCE, /requestId == previous/);
  assert.match(IOS_VIEW_SOURCE, /requestId < previous/);
  assert.match(IOS_VIEW_SOURCE, /requestId == previous/);
});
