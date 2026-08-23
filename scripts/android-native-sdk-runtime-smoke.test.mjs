import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKFLOW = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");
const SMOKE_SCRIPT = readFileSync(`${ROOT}/scripts/android-native-sdk-runtime-smoke.sh`, "utf8");

function standaloneSection() {
  const start = WORKFLOW.indexOf("android-native-sdk-host-runtime-smoke:");
  const end = WORKFLOW.indexOf("\n  android-host-runtime-smoke:", start);
  return WORKFLOW.slice(start, end);
}

test("standalone Android SDK runtime smoke exercises lifecycle zeroization and recovery", () => {
  const section = standaloneSection();
  assert.match(section, /android-native-sdk-runtime-smoke\.sh/);
  assert.match(section, /native-android-after-lifecycle\.png/);
  assert.match(section, /native-android-after-lifecycle-ui\.xml/);
  assert.match(SMOKE_SCRIPT, /KEYCODE_HOME/);
  assert.match(SMOKE_SCRIPT, /am start -W -n/);
  assert.match(SMOKE_SCRIPT, /content-desc="1 characters entered"/);
  assert.match(SMOKE_SCRIPT, /content-desc="No input"/);
  assert.match(SMOKE_SCRIPT, /password="true"/);
  assert.match(SMOKE_SCRIPT, /uiautomator dump/);
  assert.match(SMOKE_SCRIPT, /input tap/);
  assert.doesNotMatch(SMOKE_SCRIPT, /getText|secret|plaintext/i);
});

test("standalone Android lifecycle smoke taps only a clickable public digit key", () => {
  assert.match(SMOKE_SCRIPT, /node\.attrib\.get\("content-desc"\) != "1"/);
  assert.match(SMOKE_SCRIPT, /node\.attrib\.get\("clickable"\) != "true"/);
});

test("Android RN and Flutter host smokes exercise lifecycle recovery", () => {
  const start = WORKFLOW.indexOf("android-host-runtime-smoke:");
  const end = WORKFLOW.indexOf("\n  fuzz:", start);
  const section = WORKFLOW.slice(start, end);

  assert.equal(
    (section.match(/android-native-sdk-runtime-smoke\.sh/g) ?? []).length,
    2,
    "Android RN and Flutter hosts must use the lifecycle-aware runtime smoke",
  );
  assert.match(section, /flutter\/app-debug\.apk/);
  assert.match(section, /react-native\/app-release\.apk/);
  assert.match(section, /flutter-ui\.xml/);
  assert.match(section, /react-native-ui\.xml/);
  assert.match(SMOKE_SCRIPT, /KEYCODE_HOME/);
  assert.match(SMOKE_SCRIPT, /content-desc="No input"/);
  assert.doesNotMatch(section, /android-emulator-runtime-smoke\.sh/);
});
