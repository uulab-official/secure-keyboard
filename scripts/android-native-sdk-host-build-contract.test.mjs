import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKFLOW = readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");

function standaloneJob() {
  return WORKFLOW.match(/  android-native-sdk-host-runtime-smoke:[\s\S]*?(?=\n  [a-z0-9-]+:|\s*$)/)?.[0] ?? "";
}

test("CI builds a framework-free standalone Android SDK host with the staged FFI slices", () => {
  const job = standaloneJob();
  assert.notEqual(job, "", "standalone Android SDK host job is required");
  assert.match(job, /needs:\s*\[react-native-host-build\]/);
  assert.match(job, /flutter create --platforms=android/);
  assert.match(job, /include\(":secure-keypad-native"\)/);
  assert.match(job, /project\(":secure-keypad-native"\)\.projectDir/);
  assert.match(job, /SecureKeypadView/);
  assert.match(job, /configureNumeric/);
  assert.match(job, /SECURE_KEYPAD_FFI_LIB_DIR/);
  assert.match(job, /android\.builtInKotlin/);
  assert.match(job, /:app:assembleRelease/);
  assert.doesNotMatch(job, /allprojects\s*\{[\s\S]{0,160}repositories\s*\{/);
  assert.doesNotMatch(job, /@react-native|dev\.flutter|flutter-gradle-plugin/);
});

test("CI launches the standalone Android SDK host in an emulator and retains runtime evidence", () => {
  const job = standaloneJob();
  assert.match(job, /reactivecircus\/android-emulator-runner@/);
  assert.match(job, /api-level: 35/);
  assert.match(job, /arch: x86_64/);
  assert.match(job, /android-emulator-runtime-smoke\.sh/);
  assert.match(job, /app-release\.apk/);
  assert.match(job, /native-android\.png/);
  assert.match(job, /native-android-ui\.xml/);
  assert.match(job, /name: secure-keypad-native-android-runtime/);
  assert.match(WORKFLOW, /job-android-native-sdk-host-runtime-smoke/);
});
