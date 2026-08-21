import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKFLOW = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");
const SMOKE_SCRIPT = readFileSync(`${ROOT}/scripts/android-emulator-runtime-smoke.sh`, "utf8");

test("Android RN runtime smoke uses a bundled release APK", () => {
  const rnBuildSection = WORKFLOW.match(
    /Build the React Native host APK with the native FFI boundary[\s\S]*?Emit React Native Android FFI checksum manifest/,
  )?.[0];
  assert.ok(rnBuildSection, "React Native Android build section must exist");
  assert.match(rnBuildSection, /npm install --install-links --no-audit --no-fund/);
  assert.match(rnBuildSection, /assembleRelease/);
  assert.doesNotMatch(rnBuildSection, /assembleDebug/);

  const rnIosBuildSection = WORKFLOW.match(
    /Link and compile the React Native iOS host[\s\S]*?Launch the React Native host in an iOS Simulator/,
  )?.[0];
  assert.ok(rnIosBuildSection, "React Native iOS build section must exist");
  assert.match(rnIosBuildSection, /npm install --install-links --no-audit --no-fund/);

  const rnArtifactSection = WORKFLOW.match(
    /name: secure-keypad-react-native-host-apk[\s\S]*?path: [^\n]+/,
  )?.[0];
  assert.match(rnArtifactSection ?? "", /outputs\/apk\/release\/app-release\.apk/);
  assert.doesNotMatch(rnArtifactSection ?? "", /app-debug\.apk/);
});

test("Android runtime smoke starts the resolved launcher activity without monkey", () => {
  assert.match(SMOKE_SCRIPT, /cmd package resolve-activity/);
  assert.match(SMOKE_SCRIPT, /adb shell am start -W/);
  assert.doesNotMatch(SMOKE_SCRIPT, /adb shell monkey/);
});

test("Android runtime smoke verifies the secure native hierarchy without reading input", () => {
  assert.match(SMOKE_SCRIPT, /FLAG_SECURE/);
  assert.match(SMOKE_SCRIPT, /uiautomator dump/);
  assert.match(SMOKE_SCRIPT, /content-desc="No input"/);
  assert.match(SMOKE_SCRIPT, /content-desc="1"/);
  assert.doesNotMatch(SMOKE_SCRIPT, /adb shell input|adb shell[^\n]*(?:getText|password|secret)/i);
});

test("Android runtime smoke executes the RN release artifact", () => {
  const runtimeSection = WORKFLOW.match(
    /android-host-runtime-smoke:[\s\S]*?(?=\n  [a-z0-9-]+:|\s*$)/,
  )?.[0];
  assert.ok(runtimeSection, "Android runtime smoke job must exist");
  assert.match(runtimeSection, /react-native\/app-release\.apk/);
  assert.doesNotMatch(runtimeSection, /react-native\/app-debug\.apk/);
});
