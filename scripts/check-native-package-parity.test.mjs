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
    "LICENSE",
  ]);

  const flutterPubspec = readFileSync(path.join(root, "packages/flutter/pubspec.yaml"), "utf8");
  assert.match(flutterPubspec, /plugin:\n\s+platforms:\n\s+android:/);
  assert.match(flutterPubspec, /pluginClass: SecureKeypadFlutterPlugin/);

  for (const buildFile of [
    "packages/react-native/android/build.gradle",
    "packages/flutter/android/build.gradle",
  ]) {
    const contents = readFileSync(path.join(root, buildFile), "utf8");
    assert.match(contents, /android\.builtInKotlin/);
    const cmakeFile = buildFile.replace(/build\.gradle$/, "CMakeLists.txt");
    const cmake = readFileSync(path.join(root, cmakeFile), "utf8");
    assert.match(cmake, /SECURE_KEYPAD_FFI_LIB_DIR/);
  }
});
