import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKFLOW = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");
const FLUTTER_PLUGIN = readFileSync(
  `${ROOT}/packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift`,
  "utf8",
);
const IOS_BRIDGE_CONFIG = readFileSync(
  `${ROOT}/packages/flutter/ios/Classes/SecureKeypadBridgeConfig.swift`,
  "utf8",
);
const RN_VIEW_MANAGER = readFileSync(
  `${ROOT}/packages/react-native/ios/SecureKeypadViewManager.swift`,
  "utf8",
);
const RN_NATIVE_VIEW_MANAGER = readFileSync(
  `${ROOT}/native/ios/react-native/SecureKeypadViewManager.swift`,
  "utf8",
);
const RN_HOST_BUILD_START = WORKFLOW.indexOf("Create the React Native iOS host");
const RN_HOST_BUILD_END = WORKFLOW.indexOf("Create and compile the Flutter iOS host", RN_HOST_BUILD_START);
const RN_IOS_HOST = WORKFLOW.slice(RN_HOST_BUILD_START, RN_HOST_BUILD_END);
const HOST_BUILD_START = WORKFLOW.indexOf("Create and compile the Flutter iOS host");
const HOST_BUILD_END = WORKFLOW.indexOf("Launch the Flutter host in an iOS Simulator", HOST_BUILD_START);
const FLUTTER_IOS_HOST = WORKFLOW.slice(HOST_BUILD_START, HOST_BUILD_END);

test("Flutter iOS CI materializes CocoaPods before editing the generated host", () => {
  const pubGetIndex = FLUTTER_IOS_HOST.indexOf("flutter pub get");
  const podfileIndex = FLUTTER_IOS_HOST.indexOf('podfile = host / "ios/Podfile"');

  assert.notEqual(pubGetIndex, -1);
  assert.notEqual(podfileIndex, -1);
  assert.ok(pubGetIndex < podfileIndex, "flutter pub get must precede Podfile edits");
});

test("React Native iOS CI runs a bundled release UI smoke test", () => {
  assert.notEqual(RN_HOST_BUILD_START, -1);
  assert.notEqual(RN_HOST_BUILD_END, -1);
  assert.match(RN_IOS_HOST, /getSecureKeypadView\(\)/);
  assert.match(RN_IOS_HOST, /DEFAULT_NUMERIC_LAYOUT/);
  assert.match(RN_IOS_HOST, /SecureKeypadHostUITests\/SecureKeypadHostUITests\.swift/);
  assert.match(RN_IOS_HOST, /com\.apple\.product-type\.bundle\.ui-testing/);
  assert.match(RN_IOS_HOST, /PRODUCT_NAME.*SecureKeypadHostUITests/);
  assert.match(RN_IOS_HOST, /scheme\.add_test_target\(ui_target\)/);
  assert.match(RN_IOS_HOST, /xcodebuild -workspace SecureKeypadHost\.xcworkspace[\s\S]*-configuration Release[\s\S]*test/);
  assert.match(RN_IOS_HOST, /xcrun simctl list devices available -j/);
  assert.match(RN_IOS_HOST, /-destination "platform=iOS Simulator,id=\$SIMULATOR_ID"/);
  assert.match(RN_IOS_HOST, /digitOne\.tap\(\)/);
  assert.match(RN_IOS_HOST, /1 characters entered/);
  assert.doesNotMatch(RN_IOS_HOST, /-configuration Debug/);
});

test("Flutter iOS CI uses the Flutter 3.47 build output contract", () => {
  assert.match(FLUTTER_IOS_HOST, /FLUTTER_SWIFT_PACKAGE_MANAGER=false flutter create/);
  assert.match(FLUTTER_IOS_HOST, /FLUTTER_SWIFT_PACKAGE_MANAGER=false flutter pub get/);
  assert.match(FLUTTER_IOS_HOST, /FLUTTER_SWIFT_PACKAGE_MANAGER=false flutter build ios/);
  assert.match(FLUTTER_IOS_HOST, /SECURE_KEYPAD_FFI_XCFRAMEWORK=.*pod install/);
  assert.match(FLUTTER_IOS_HOST, /xcodebuild -project Pods\/Pods\.xcodeproj -scheme secure_keypad_flutter/);
  assert.match(FLUTTER_IOS_HOST, /SecureKeypadHostSmoke/);
  assert.match(FLUTTER_IOS_HOST, /SecureKeypadConfiguration\.defaultNumeric/);
  assert.doesNotMatch(FLUTTER_IOS_HOST, /Flutter Demo Home Page/);
  assert.match(FLUTTER_IOS_HOST, /flutter build ios --simulator --no-codesign/);
  assert.doesNotMatch(FLUTTER_IOS_HOST, /--build-dir/);
  assert.match(FLUTTER_IOS_HOST, /config\.build_settings\['ARCHS'\]\s*=\s*'arm64'/);
  assert.match(FLUTTER_IOS_HOST, /config\.build_settings\['ONLY_ACTIVE_ARCH'\]\s*=\s*'YES'/);
  assert.match(FLUTTER_IOS_HOST, /ARCHS = arm64;/);
  assert.match(FLUTTER_IOS_HOST, /ONLY_ACTIVE_ARCH = YES;/);
  assert.match(FLUTTER_IOS_HOST, /RunnerTests\/RunnerTests\.swift/);
  assert.match(FLUTTER_IOS_HOST, /com\.apple\.product-type\.bundle\.ui-testing/);
  assert.match(FLUTTER_IOS_HOST, /xcodebuild -workspace "\$HOST_DIR\/ios\/Runner\.xcworkspace"/);
  assert.match(FLUTTER_IOS_HOST, /xcrun simctl list devices available -j/);
  assert.match(FLUTTER_IOS_HOST, /-destination "platform=iOS Simulator,id=\$SIMULATOR_ID"/);
  assert.match(FLUTTER_IOS_HOST, /digitOne\.tap\(\)/);
  assert.match(FLUTTER_IOS_HOST, /1 characters entered/);
  assert.match(
    WORKFLOW,
    /APP_PATH: \$\{\{ runner\.temp \}\}\/secure-keypad-flutter-ios-host\/build\/ios\/iphonesimulator\/Runner\.app/,
  );
});

test("Flutter iOS PlatformView preserves standard creation arguments", () => {
  assert.match(FLUTTER_PLUGIN, /func createArgsCodec\(\) -> FlutterMessageCodec & NSObjectProtocol/);
  assert.match(FLUTTER_PLUGIN, /FlutterStandardMessageCodec\.sharedInstance\(\)/);
  assert.match(FLUTTER_PLUGIN, /guard let dictionary = Self\.dictionary\(arguments\)/);
});

test("Flutter iOS UI test stays isolated from CocoaPods test-target linkage", () => {
  const flutterBuildIndex = FLUTTER_IOS_HOST.indexOf(
    "flutter build ios --simulator --no-codesign",
  );
  const postBuildIsolationIndex = FLUTTER_IOS_HOST.indexOf(
    'project = Path(os.environ["HOST_DIR"]) / "ios/Runner.xcodeproj/project.pbxproj"',
    flutterBuildIndex,
  );

  assert.notEqual(flutterBuildIndex, -1);
  assert.notEqual(postBuildIsolationIndex, -1);
  assert.match(FLUTTER_IOS_HOST.slice(postBuildIsolationIndex), /PBXFrameworksBuildPhase/);
  assert.match(FLUTTER_IOS_HOST.slice(postBuildIsolationIndex), /Pods_RunnerTests\.framework/);
  assert.match(FLUTTER_IOS_HOST.slice(postBuildIsolationIndex), /baseConfigurationReference/);
});

test("iOS bridge numeric parsing keeps integer zero distinct from Boolean", () => {
  assert.match(IOS_BRIDGE_CONFIG, /CFGetTypeID\(value\) == CFBooleanGetTypeID\(\)/);
  assert.doesNotMatch(IOS_BRIDGE_CONFIG, /guard !\(value is Bool\)/);
});

test("React Native iOS manager uses a distinct immutable bridge dictionary", () => {
  for (const source of [RN_VIEW_MANAGER, RN_NATIVE_VIEW_MANAGER]) {
    assert.match(source, /var config: \[String: Any\]/);
    assert.match(source, /let configDictionary = config as NSDictionary/);
    assert.doesNotMatch(source, /let config = config as NSDictionary/);
  }
});
