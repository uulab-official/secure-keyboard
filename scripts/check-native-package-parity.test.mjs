import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
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
  assert.equal((workflow.match(/platform :ios, '15\.1'/g) ?? []).length, 3);
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

test("native CI executes the deterministic presentation snapshot contracts", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const workflow = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert.match(workflow, /Swift presentation snapshot contract/);
  assert.match(workflow, /native\/ios\/SecureKeypadPresentationContractTest\.swift/);
  assert.match(workflow, /Android presentation snapshot contract/);
  assert.match(workflow, /native\/android\/SecureKeypadPresentationContractTest\.kt/);
  assert.match(workflow, /secure-keypad-presentation-contract\.jar/);
});

test("iOS podspecs reject explicit FFI artifacts that differ from the staged bundle", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const rubyHarness = `
    module Pod
      class Spec
        @@last = nil
        def self.last
          @@last
        end
        def initialize
          @@last = self
          yield self
        end
        def method_missing(_name, *_args)
          nil
        end
      end
    end
    load ARGV.fetch(0)
    puts Pod::Spec.last
  `;

  for (const podspec of [
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
  ]) {
    const stage = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-podspec-"));
    try {
      const stagedPodspec = path.join(stage, path.basename(podspec));
      cpSync(path.join(root, podspec), stagedPodspec);
      const stagedLibrary = path.join(stage, "libsecure_ffi.a");
      const explicitLibrary = path.join(stage, "external-libsecure_ffi.a");
      writeFileSync(stagedLibrary, "staged native bytes\n");
      writeFileSync(explicitLibrary, "different native bytes\n");

      const result = spawnSync("ruby", ["-e", rubyHarness, stagedPodspec], {
        env: { ...process.env, SECURE_KEYPAD_FFI_LIB: explicitLibrary },
        encoding: "utf8",
      });
      assert.notEqual(result.status, 0, `${podspec} accepted mismatched explicit FFI bytes`);
      assert.match(`${result.stdout}\n${result.stderr}`, /does not match the staged package FFI artifact/);
    } finally {
      rmSync(stage, { recursive: true, force: true });
    }
  }
});
