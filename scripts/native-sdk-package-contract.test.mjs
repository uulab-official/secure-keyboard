import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function read(relativePath) {
  return readFileSync(path.join(ROOT, relativePath), "utf8");
}

test("standalone iOS native SDK Podspec excludes framework bridges", () => {
  const podspec = read("native/ios/SecureKeypadKit.podspec");
  assert.match(podspec, /spec\.name\s*=\s*['"]SecureKeypadKit['"]/);
  assert.match(podspec, /spec\.version\s*=\s*['"]0\.1\.0['"]/);
  assert.match(podspec, /spec\.platforms\s*=\s*\{\s*:ios\s*=>\s*['"]15\.1['"]\s*\}/);
  assert.match(podspec, /spec\.swift_version\s*=\s*['"]5\.9['"]/);
  assert.match(
    podspec,
    /spec\.source_files\s*=\s*\[\s*['"]SecureKeypadBridgeConfig\.swift['"],\s*['"]SecureKeypadPresentation\.swift['"],\s*['"]SecureKeypadView\.swift['"]\s*\]/,
  );
  assert.doesNotMatch(podspec, /source_files[\s\S]*SecureKeypadPresentationContractTest/);
  assert.match(podspec, /spec\.vendored_frameworks\s*=\s*['"]secure_ffi\.xcframework['"]/);
  assert.doesNotMatch(podspec, /React-Core|Flutter|react-native|SecureKeypadViewManager|SecureKeypadFlutterPlugin/);
});

test("standalone iOS native SDK verifies staged FFI artifact ownership", () => {
  const podspec = read("native/ios/SecureKeypadKit.podspec");
  assert.match(podspec, /SECURE_KEYPAD_FFI_XCFRAMEWORK/);
  assert.match(podspec, /does not match the staged package FFI artifact/);
  assert.match(podspec, /File\.join\(__dir__, ['"]secure_ffi\.xcframework['"]\)/);
});

test("standalone iOS native SDK module map is package portable", () => {
  const moduleMap = read("native/ios/SecureKeypadFFI/module.modulemap");
  assert.match(moduleMap, /header ['"]secure_keypad\.h['"]/);
  assert.doesNotMatch(moduleMap, /\.\.\/\.\.\//);

  const header = read("native/ios/SecureKeypadFFI/secure_keypad.h");
  assert.match(header, /#define SECURE_KEYPAD_ABI_VERSION UINT32_C\(2\)/);
  assert.doesNotMatch(header, /secure_keypad_[a-z0-9_]*(?:password|secret|get_value|value_bytes)[a-z0-9_]*\s*\(/i);
});

test("standalone iOS Swift SDK consumes the public C ABI without a consumer-visible submodule", () => {
  const view = read("native/ios/SecureKeypadView.swift");
  assert.doesNotMatch(view, /^import SecureKeypadFFI$/m);
  assert.match(view, /secure_keypad_session_new_numeric/);
});

test("standalone Android native SDK has no framework dependency", () => {
  const gradle = read("native/android/build.gradle");
  assert.match(gradle, /com\.android\.library/);
  assert.match(gradle, /namespace\s+['"]com\.uulab\.securekeypad['"]/);
  assert.match(gradle, /version\s*=\s*['"]0\.1\.0['"]/);
  assert.match(gradle, /minSdk\s+project\.hasProperty\('minSdkVersion'\)\s*\?\s*project\.minSdkVersion\s*:\s*24/);
  assert.match(gradle, /secureKeypadAndroidArchitectures/);
  assert.match(gradle, /arm64-v8a,x86_64/);
  assert.match(gradle, /exclude ['"]com\/uulab\/securekeypad\/flutter\/\*\*['"]/);
  assert.match(gradle, /exclude ['"]com\/uulab\/securekeypad\/reactnative\/\*\*['"]/);
  assert.match(gradle, /tasks\.withType\(org\.jetbrains\.kotlin\.gradle\.tasks\.KotlinCompile\)[\s\S]*exclude ['"]\*\*\/flutter\/\*\*['"][\s\S]*exclude ['"]\*\*\/reactnative\/\*\*['"]/);
  assert.doesNotMatch(gradle, /repositories\s*\{/);
  assert.doesNotMatch(gradle, /react-native|com\.facebook\.react|Flutter/);
});

test("standalone Android native SDK manifest has no component registration", () => {
  const manifest = read("native/android/src/main/AndroidManifest.xml");
  assert.match(manifest, /<manifest\b/);
  assert.doesNotMatch(manifest, /<\s*(activity|service|receiver)\b/);
});

test("standalone Android native SDK fails closed for missing FFI slices", () => {
  const cmake = read("native/android/CMakeLists.txt");
  assert.match(cmake, /SECURE_KEYPAD_FFI_LIB_DIR/);
  assert.match(cmake, /EXISTS\s+"\$\{SECURE_KEYPAD_FFI_LIB_DIR\}\/\$\{ANDROID_ABI\}\/libsecure_ffi\.a"/);
  assert.match(cmake, /message\(FATAL_ERROR/);
  const rules = read("native/android/consumer-rules.pro");
  assert.match(rules, /secure_keypad/);
});

test("public docs bind native SDK versions to the release evidence boundary", () => {
  for (const relativePath of [
    "README.md",
    "docs/COMPATIBILITY.md",
    "docs/PRODUCTION-READINESS.md",
  ]) {
    assert.match(read(relativePath), /native\/sdk-contract\.json/);
  }
  assert.match(read("docs/COMPATIBILITY.md"), /SecureKeypadKit|Native SDK/);
  assert.match(read("docs/PRODUCTION-READINESS.md"), /physical-device|physical device/);
  assert.match(read("docs/PRODUCTION-READINESS.md"), /independent security review/);
});
