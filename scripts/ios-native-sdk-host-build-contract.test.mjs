import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKFLOW = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");

test("iOS CI builds the standalone Native SDK host without framework bridges", () => {
  const start = WORKFLOW.indexOf("Create and compile the standalone Native iOS host");
  const end = WORKFLOW.indexOf("Create and compile the Flutter iOS host", start);

  assert.notEqual(start, -1, "standalone Native iOS host step is required");
  assert.notEqual(end, -1, "standalone Native iOS host step must precede Flutter host build");

  const section = WORKFLOW.slice(start, end);
  assert.match(section, /GITHUB_WORKSPACE\/native\/ios/);
  assert.match(section, /rsync -a[\s\S]*--exclude ['"]flutter['"][\s\S]*--exclude ['"]react-native['"][\s\S]*--exclude ['"]\*ContractTest\.swift['"]/);
  assert.doesNotMatch(section, /crates\/secure-ffi\/include/);
  assert.match(section, /SecureKeypadKit\.podspec/);
  assert.match(section, /pod ['"]SecureKeypadKit['"], :path =>/);
  assert.match(section, /secure_ffi\.xcframework/);
  assert.match(section, /require ['"]xcodeproj['"]/);
  assert.match(section, /source_group\.new_file\(filename\)/);
  assert.doesNotMatch(section, /source_group\.new_file\(File\.join\(['"]SecureKeypadNativeHost['"], filename\)\)/);
  assert.match(section, /pod install/);
  assert.match(section, /xcodebuild -workspace SecureKeypadNativeHost\.xcworkspace/);
  assert.match(section, /-scheme SecureKeypadNativeHost/);
  assert.match(section, /-configuration Release/);
  assert.match(section, /ARCHS=arm64 build/);
  assert.doesNotMatch(section, /React Native|React-Core|Flutter/);
});

test("iOS CI runs a standalone Native SDK UI and simulator runtime smoke", () => {
  const start = WORKFLOW.indexOf("Create and compile the standalone Native iOS host");
  const end = WORKFLOW.indexOf("Create and compile the Flutter iOS host", start);
  const section = WORKFLOW.slice(start, end);

  assert.match(section, /SecureKeypadNativeHostUITests\/SecureKeypadNativeHostUITests\.swift/);
  assert.match(section, /com\.apple\.product-type\.bundle\.ui-testing/);
  assert.match(section, /scheme\.add_test_target\(ui_target\)/);
  assert.match(section, /xcodebuild -workspace SecureKeypadNativeHost\.xcworkspace[\s\S]*-configuration Release[\s\S]*test/);
  assert.match(section, /xcrun simctl list devices available -j/);
  assert.match(section, /-destination "platform=iOS Simulator,id=\$SIMULATOR_ID"/);
  assert.match(section, /digitOne\.tap\(\)/);
  assert.match(section, /1 characters entered/);
  assert.match(section, /XCUIDevice\.shared\.press\(\.home\)/);
  assert.match(section, /app\.activate\(\)/);
  assert.match(section, /No input/);
  assert.match(WORKFLOW, /Launch the standalone Native iOS host in an iOS Simulator/);
  assert.match(WORKFLOW, /secure-keypad-native-ios-runtime\/native\.png/);
  assert.match(WORKFLOW, /ios-simulator-runtime-smoke\.sh/);
});
