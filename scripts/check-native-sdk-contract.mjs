import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function read(root, relativePath) {
  return readFileSync(path.join(root, relativePath), "utf8");
}

function json(root, relativePath) {
  return JSON.parse(read(root, relativePath));
}

function matchOne(contents, expression, label, failures) {
  const match = contents.match(expression);
  if (!match) failures.push(`${label}: pattern not found`);
  return match?.[1];
}

function expectEqual(actual, expected, label, failures) {
  if (actual !== expected) failures.push(`${label}: expected ${expected}, got ${actual ?? "missing"}`);
}

function expectSet(actual, expected, label, failures) {
  const actualSet = [...new Set(actual)].sort();
  const expectedSet = [...new Set(expected)].sort();
  if (JSON.stringify(actualSet) !== JSON.stringify(expectedSet)) {
    failures.push(`${label}: expected ${expectedSet.join(",")}, got ${actualSet.join(",")}`);
  }
}

function checkOptionalVersion(root, relativePath, expression, expected, failures) {
  if (!existsSync(path.join(root, relativePath))) return;
  const contents = read(root, relativePath);
  expectEqual(matchOne(contents, expression, `${relativePath} version`, failures), expected, `${relativePath} version`, failures);
}

export function findNativeSdkContractFailures(root = ROOT) {
  const failures = [];
  let contract;

  try {
    contract = json(root, "native/sdk-contract.json");
  } catch (error) {
    return [`native/sdk-contract.json: ${error.message}`];
  }

  if (contract.schemaVersion !== 1) failures.push("native/sdk-contract.json: unsupported schemaVersion");
  if (typeof contract.nativeSdkVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(contract.nativeSdkVersion)) {
    failures.push("native/sdk-contract.json: nativeSdkVersion must be semantic version text");
  }
  if (!Number.isInteger(contract.abiVersion) || contract.abiVersion < 1) {
    failures.push("native/sdk-contract.json: abiVersion must be a positive integer");
  }
  if (!contract.ios || typeof contract.ios.minimum !== "string") failures.push("native/sdk-contract.json: iOS minimum is missing");
  if (!contract.android || !Number.isInteger(contract.android.minimumApi)) failures.push("native/sdk-contract.json: Android minimumApi is missing");

  const header = read(root, "crates/secure-ffi/include/secure_keypad.h");
  const headerAbi = matchOne(header, /#define\s+SECURE_KEYPAD_ABI_VERSION\s+UINT32_C\((\d+)\)/, "C ABI version", failures);
  expectEqual(headerAbi, String(contract.abiVersion), "C ABI version", failures);

  const rnPackage = json(root, "packages/react-native/package.json");
  expectEqual(rnPackage.version, contract.nativeSdkVersion, "React Native package version", failures);

  const flutterVersion = matchOne(read(root, "packages/flutter/pubspec.yaml"), /^version:\s*(\S+)/m, "Flutter package version", failures);
  expectEqual(flutterVersion, contract.nativeSdkVersion, "Flutter package version", failures);

  for (const relativePath of [
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
  ]) {
    const version = matchOne(read(root, relativePath), /spec\.version\s*=\s*['"]([^'"]+)['"]/, `${relativePath} version`, failures);
    expectEqual(version, contract.nativeSdkVersion, `${relativePath} version`, failures);
    const minimum = matchOne(read(root, relativePath), /spec\.platforms\s*=\s*\{\s*:ios\s*=>\s*['"]([^'"]+)['"]\s*\}/, `${relativePath} iOS minimum`, failures);
    expectEqual(minimum, contract.ios.minimum, `${relativePath} iOS minimum`, failures);
  }

  for (const relativePath of [
    "packages/react-native/android/build.gradle",
    "packages/flutter/android/build.gradle",
  ]) {
    const contents = read(root, relativePath);
    const version = matchOne(contents, /version\s*=\s*['"]([^'"]+)['"]/, `${relativePath} version`, failures);
    expectEqual(version, contract.nativeSdkVersion, `${relativePath} version`, failures);
    const minimumApi = matchOne(contents, /minSdk\s+project\.hasProperty\('minSdkVersion'\)\s*\?\s*project\.minSdkVersion\s*:\s*(\d+)/, `${relativePath} minimum API`, failures);
    expectEqual(minimumApi, String(contract.android.minimumApi), `${relativePath} minimum API`, failures);
    const abiExpression = relativePath.includes("react-native")
      ? /reactNativeArchitectures'\)\s*\?:\s*['"]([^'"]+)['"]/ 
      : /secureKeypadAndroidArchitectures'\)\s*\?:\s*['"]([^'"]+)['"]/;
    const abiList = matchOne(contents, abiExpression, `${relativePath} release ABIs`, failures);
    expectSet(abiList?.split(",") ?? [], contract.android.releaseAbis, `${relativePath} release ABIs`, failures);
  }

  const platformSupport = json(root, "docs/PLATFORM-SUPPORT.json");
  expectEqual(platformSupport.platforms?.ios?.minimumOsVersion, contract.ios.minimum, "platform policy iOS minimum", failures);
  expectEqual(platformSupport.platforms?.android?.minimumApiLevel, contract.android.minimumApi, "platform policy Android minimum", failures);

  checkOptionalVersion(root, "native/ios/SecureKeypadKit.podspec", /spec\.version\s*=\s*['"]([^'"]+)['"]/, contract.nativeSdkVersion, failures);
  checkOptionalVersion(root, "native/android/build.gradle", /version\s*=\s*['"]([^'"]+)['"]/, contract.nativeSdkVersion, failures);

  return failures;
}

export function checkNativeSdkContract(root = ROOT) {
  const failures = findNativeSdkContractFailures(root);
  if (failures.length === 0) return 0;
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkNativeSdkContract();
}
