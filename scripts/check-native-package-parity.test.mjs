import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  NATIVE_PACKAGE_MIRRORS,
  findNativePackageParityMismatches,
} from "./check-native-package-parity.mjs";

test("publishable native packages contain every central bridge source", () => {
  assert.ok(NATIVE_PACKAGE_MIRRORS.length >= 14);
  assert.deepEqual(findNativePackageParityMismatches(), []);
});

test("framework manifests publish native source and fail-closed build inputs", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const reactNativePackage = JSON.parse(
    readFileSync(path.join(root, "packages/react-native/package.json"), "utf8"),
  );
  assert.deepEqual(reactNativePackage.files, [
    "dist",
    "android",
    "ios",
    "SecureKeypadReactNative.podspec",
    "app.plugin.js",
    "react-native.config.cjs",
    "secure_ffi.xcframework",
    "libsecure_ffi.a",
    "LICENSE",
  ]);
  assert.equal(reactNativePackage["react-native"], "./dist/index.js");
  assert.equal(reactNativePackage.exports["."]["react-native"], "./dist/index.js");

  const contractsPackage = JSON.parse(
    readFileSync(path.join(root, "packages/contracts/package.json"), "utf8"),
  );
  assert.equal(contractsPackage.exports["."]["react-native"], "./dist/index.js");

  const flutterPubspec = readFileSync(path.join(root, "packages/flutter/pubspec.yaml"), "utf8");
  assert.match(flutterPubspec, /plugin:\n\s+platforms:\n\s+android:/);
  assert.match(flutterPubspec, /pluginClass: SecureKeypadFlutterPlugin/);

  for (const buildFile of [
    "packages/react-native/android/build.gradle",
    "packages/flutter/android/build.gradle",
  ]) {
    const contents = readFileSync(path.join(root, buildFile), "utf8");
    if (buildFile.includes("react-native")) {
      assert.match(contents, /android\.builtInKotlin/);
    }
    const cmakeFile = buildFile.replace(/build\.gradle$/, "CMakeLists.txt");
    const cmake = readFileSync(path.join(root, cmakeFile), "utf8");
    assert.match(cmake, /SECURE_KEYPAD_FFI_LIB_DIR/);
    assert.match(cmake, /CMAKE_CURRENT_LIST_DIR}\/secure_ffi/);
    assert.match(cmake, /EXISTS\s+"\$\{SECURE_KEYPAD_FFI_LIB_DIR\}\/\$\{ANDROID_ABI\}\/libsecure_ffi\.a"/);
  }

  const flutterBuild = readFileSync(path.join(root, "packages/flutter/android/build.gradle"), "utf8");
  assert.doesNotMatch(flutterBuild, /org\.jetbrains\.kotlin\.android/);
  assert.doesNotMatch(flutterBuild, /kotlinOptions\s*\{/);
  assert.match(flutterBuild, /kotlin\s*\{[\s\S]*compilerOptions\s*\{/);
});

test("iOS podspecs consume only staged relative FFI artifacts", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  for (const podspec of [
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
  ]) {
    const contents = readFileSync(path.join(root, podspec), "utf8");
    assert.match(contents, /spec\.platforms\s*=\s*\{\s*:ios\s*=>\s*['"]15\.1['"]\s*\}/);
    assert.match(contents, /File\.join\(__dir__, ['"]secure_ffi\.xcframework['"]\)/);
    assert.match(contents, /spec\.vendored_frameworks\s*=\s*['"]secure_ffi\.xcframework['"]/);
    assert.match(contents, /elsif Dir\.exist\?\(staged_xcframework\)/);
    assert.match(contents, /elsif File\.file\?\(staged_library\)/);
    assert.doesNotMatch(contents, /spec\.vendored_frameworks\s*=\s*ffi_xcframework/);
  }

  const workflow = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert.equal((workflow.match(/platform :ios, '15\.1'/g) ?? []).length, 2);
  assert.equal((workflow.match(/IPHONEOS_DEPLOYMENT_TARGET = 15\.1;/g) ?? []).length, 3);
  assert.match(
    workflow,
    /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" packages\/react-native\/secure_ffi\.xcframework/,
  );
  assert.match(
    workflow,
    /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" packages\/flutter\/ios\/secure_ffi\.xcframework/,
  );
  assert.match(workflow, /ONLY_ACTIVE_ARCH=YES\s+\\\s+ARCHS=arm64 build/);
  assert.match(workflow, /<SecureKeypadView\s+style=\{styles\.keypad\}/);
  assert.match(workflow, /xcodebuild -workspace SecureKeypadHost\.xcworkspace[\s\S]*?-configuration Release[\s\S]*?ARCHS=arm64 build/);
  assert.match(workflow, /secure-keypad-rn-ios-derived\/Build\/Products\/Release-iphonesimulator\/SecureKeypadHost\.app/);
  assert.match(workflow, /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" "\$RN_PACKAGE_DIR\/secure_ffi\.xcframework"/);
  assert.match(workflow, /FLUTTER_PACKAGE_DIR/);
  assert.match(workflow, /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" "\$FLUTTER_PACKAGE_DIR\/ios\/secure_ffi\.xcframework"/);
});

test("native CI executes the Android input-key randomization contract", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const workflow = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert.match(workflow, /Android input-key randomization contract/);
  assert.match(workflow, /native\/android\/SecureKeypadRandomizationContractTest\.kt/);
  assert.match(workflow, /secure-keypad-randomization-contract\.jar/);
});
