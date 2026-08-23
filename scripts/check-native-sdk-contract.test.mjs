import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { checkNativeSdkContract } from "./check-native-sdk-contract.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function copyFixture() {
  const fixture = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-native-contract-"));
  const paths = [
    "native/sdk-contract.json",
    "crates/secure-ffi/include/secure_keypad.h",
    "docs/PLATFORM-SUPPORT.json",
    "packages/react-native/package.json",
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/react-native/android/build.gradle",
    "packages/flutter/pubspec.yaml",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
    "packages/flutter/android/build.gradle",
  ];
  for (const relative of paths) {
    const source = path.join(ROOT, relative);
    const destination = path.join(fixture, relative);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(source, destination);
  }
  return fixture;
}

function withFixture(callback) {
  const fixture = copyFixture();
  try {
    return callback(fixture);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

test("native contract accepts the checked-in ABI and package matrix", () => {
  assert.equal(checkNativeSdkContract(ROOT), 0);
});

test("native contract rejects an ABI mismatch before packaging", () => {
  withFixture((root) => {
    const header = path.join(root, "crates/secure-ffi/include/secure_keypad.h");
    writeFileSync(header, readFileSync(header, "utf8").replace("UINT32_C(2)", "UINT32_C(3)"));
    assert.equal(checkNativeSdkContract(root), 1);
  });
});

test("native contract rejects a package version drift", () => {
  withFixture((root) => {
    const packageJson = path.join(root, "packages/react-native/package.json");
    writeFileSync(packageJson, readFileSync(packageJson, "utf8").replace('"version": "0.1.0"', '"version": "0.2.0"'));
    assert.equal(checkNativeSdkContract(root), 1);
  });
});

test("native contract rejects an unsupported Android ABI", () => {
  withFixture((root) => {
    const buildGradle = path.join(root, "packages/flutter/android/build.gradle");
    writeFileSync(buildGradle, readFileSync(buildGradle, "utf8").replace("arm64-v8a,x86_64", "armeabi-v7a"));
    assert.equal(checkNativeSdkContract(root), 1);
  });
});
