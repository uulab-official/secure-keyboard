import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Central native files are mirrored into each publishable framework package.
 * Keep this list explicit so a new bridge file cannot silently remain outside
 * the package tarball.
 */
export const NATIVE_PACKAGE_MIRRORS = Object.freeze([
  ["native/ios/SecureKeypadPresentation.swift", "packages/react-native/ios/SecureKeypadPresentation.swift"],
  ["native/ios/SecureKeypadPresentation.swift", "packages/flutter/ios/Classes/SecureKeypadPresentation.swift"],
  ["native/ios/SecureKeypadBridgeConfig.swift", "packages/react-native/ios/SecureKeypadBridgeConfig.swift"],
  ["native/ios/SecureKeypadBridgeConfig.swift", "packages/flutter/ios/Classes/SecureKeypadBridgeConfig.swift"],
  ["native/ios/SecureKeypadView.swift", "packages/react-native/ios/SecureKeypadView.swift"],
  ["native/ios/SecureKeypadView.swift", "packages/flutter/ios/Classes/SecureKeypadView.swift"],
  ["native/ios/react-native/SecureKeypadViewManager.swift", "packages/react-native/ios/SecureKeypadViewManager.swift"],
  ["native/ios/react-native/SecureKeypadViewManager.m", "packages/react-native/ios/SecureKeypadViewManager.m"],
  ["native/ios/flutter/SecureKeypadFlutterPlugin.swift", "packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift"],
  ["crates/secure-ffi/include/secure_keypad.h", "packages/react-native/ios/SecureKeypadFFI/secure_keypad.h"],
  ["crates/secure-ffi/include/secure_keypad.h", "packages/flutter/ios/Classes/SecureKeypadFFI/secure_keypad.h"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt", "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt", "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt", "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadReactPackage.kt", "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadReactPackage.kt"],
  ["native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt", "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt"],
  ["native/android/src/main/cpp/secure_keypad_jni.c", "packages/react-native/android/src/main/cpp/secure_keypad_jni.c"],
  ["native/android/src/main/cpp/secure_keypad_jni.c", "packages/flutter/android/src/main/cpp/secure_keypad_jni.c"],
  ["crates/secure-ffi/include/secure_keypad.h", "packages/react-native/android/src/main/cpp/include/secure_keypad.h"],
  ["crates/secure-ffi/include/secure_keypad.h", "packages/flutter/android/src/main/cpp/include/secure_keypad.h"],
].map(([source, destination]) => Object.freeze({ source, destination })));

function digest(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

/**
 * Returns missing or drifted central-to-package native source mappings.
 *
 * @param {string} root repository root used by tests and release tooling
 * @returns {Array<{source: string, destination: string, reason: string}>}
 */
export function findNativePackageParityMismatches(root = ROOT) {
  return NATIVE_PACKAGE_MIRRORS.flatMap(({ source, destination }) => {
    const sourcePath = path.join(root, source);
    const destinationPath = path.join(root, destination);
    if (!existsSync(sourcePath)) {
      return [{ source, destination, reason: "central source is missing" }];
    }
    if (!existsSync(destinationPath)) {
      return [{ source, destination, reason: "package copy is missing" }];
    }
    if (digest(sourcePath) !== digest(destinationPath)) {
      return [{ source, destination, reason: "package copy differs from central source" }];
    }
    return [];
  });
}

export function checkNativePackageParity(root = ROOT) {
  const mismatches = findNativePackageParityMismatches(root);
  if (mismatches.length === 0) return 0;

  for (const mismatch of mismatches) {
    process.stderr.write(`${mismatch.reason}: ${mismatch.source} -> ${mismatch.destination}\n`);
  }
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkNativePackageParity();
}
