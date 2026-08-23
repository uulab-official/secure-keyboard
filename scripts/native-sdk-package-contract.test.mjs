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
  assert.match(podspec, /spec\.source_files\s*=\s*['"]SecureKeypad\*\.swift['"]/);
  assert.match(podspec, /spec\.vendored_frameworks\s*=\s*['"]secure_ffi\.xcframework['"]/);
  assert.doesNotMatch(podspec, /React-Core|Flutter|react-native|SecureKeypadViewManager|SecureKeypadFlutterPlugin/);
});

test("standalone iOS native SDK verifies staged FFI artifact ownership", () => {
  const podspec = read("native/ios/SecureKeypadKit.podspec");
  assert.match(podspec, /SECURE_KEYPAD_FFI_XCFRAMEWORK/);
  assert.match(podspec, /does not match the staged package FFI artifact/);
  assert.match(podspec, /File\.join\(__dir__, ['"]secure_ffi\.xcframework['"]\)/);
});
