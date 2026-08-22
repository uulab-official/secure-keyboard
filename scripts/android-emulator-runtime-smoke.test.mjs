import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const WORKFLOW = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");
const SMOKE_SCRIPT = readFileSync(`${ROOT}/scripts/android-emulator-runtime-smoke.sh`, "utf8");

function fakeAndroidTools(
  uiXml,
  secureFlags = "0x2000",
  focusedPackage = "dev.fake.securekeypad",
) {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-android-smoke-tools-"));
  const apkPath = join(root, "host.apk");
  const uiXmlPath = join(root, "source-ui.xml");
  const aaptPath = join(root, "aapt");
  const adbPath = join(root, "adb");
  writeFileSync(apkPath, "fixture-apk\n");
  writeFileSync(uiXmlPath, uiXml);
  writeFileSync(
    aaptPath,
    "#!/bin/sh\nprintf \"package: name='dev.fake.securekeypad' versionCode='1'\\n\"\n",
    { mode: 0o700 },
  );
  writeFileSync(
    adbPath,
    `#!/bin/sh
set -eu
case "\${1:-}" in
  install) exit 0 ;;
  exec-out) printf 'PNG-fixture\\n' ;;
  shell)
    shift
    case "\${1:-}" in
      am|cmd) [ "\${1:-}" = am ] && exit 0 || printf '%s/.Main\\n' "\${FAKE_PACKAGE}" ;;
      pidof) printf '123\\n' ;;
      dumpsys) printf 'mCurrentFocus=Window{fixture u0 %s/.Main}\\nWindow{fixture u0 %s/.Main}: mAttrs={fl=%s}\\n' "\${FAKE_FOCUS_PACKAGE}" "\${FAKE_PACKAGE}" "\${FAKE_SECURE_FLAGS}" ;;
      uiautomator) exit 0 ;;
      cat) cat "\${FAKE_UI_XML}" ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
`,
    { mode: 0o700 },
  );
  chmodSync(aaptPath, 0o700);
  chmodSync(adbPath, 0o700);
  return { root, apkPath, uiXmlPath, aaptPath, adbPath };
}

function runSmokeWithFakeTools(
  uiXml,
  secureFlags = "0x2000",
  focusedPackage = "dev.fake.securekeypad",
) {
  const tools = fakeAndroidTools(uiXml, secureFlags, focusedPackage);
  const screenshotPath = join(tools.root, "out/smoke.png");
  const dumpPath = join(tools.root, "out/ui.xml");
  const result = spawnSync("bash", ["-s", tools.apkPath, screenshotPath, dumpPath], {
    input: SMOKE_SCRIPT,
    encoding: "utf8",
    env: {
      ...process.env,
      AAPT: tools.aaptPath,
      FAKE_PACKAGE: "dev.fake.securekeypad",
      FAKE_FOCUS_PACKAGE: focusedPackage,
      FAKE_SECURE_FLAGS: secureFlags,
      FAKE_UI_XML: tools.uiXmlPath,
      PATH: `${tools.root}:${process.env.PATH ?? ""}`,
    },
  });
  return { ...tools, screenshotPath, dumpPath, result };
}

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
  assert.match(SMOKE_SCRIPT, /dumpsys window windows/);
  assert.match(SMOKE_SCRIPT, /0x2000/);
  assert.match(SMOKE_SCRIPT, /uiautomator dump/);
  assert.match(SMOKE_SCRIPT, /usage: \$0 APK_PATH SCREENSHOT_PATH UI_DUMP_PATH/);
  assert.match(SMOKE_SCRIPT, /UI_DUMP_PATH="\$3"/);
  assert.match(SMOKE_SCRIPT, /adb shell cat "\$ui_dump_path"[^\n]*> "\$UI_DUMP_PATH"/);
  assert.match(SMOKE_SCRIPT, /test -s "\$UI_DUMP_PATH"/);
  assert.match(SMOKE_SCRIPT, /content-desc="No input"/);
  assert.match(SMOKE_SCRIPT, /content-desc="1"/);
  assert.match(SMOKE_SCRIPT, /android\.widget\.EditText/);
  assert.match(SMOKE_SCRIPT, /password="true"/);
  assert.doesNotMatch(SMOKE_SCRIPT, /adb shell input|adb shell[^\n]*(?:getText|password|secret)/i);
});

test("Android runtime smoke executes the RN release artifact", () => {
  const runtimeSection = WORKFLOW.match(
    /android-host-runtime-smoke:[\s\S]*?(?=\n  [a-z0-9-]+:|\s*$)/,
  )?.[0];
  assert.ok(runtimeSection, "Android runtime smoke job must exist");
  assert.match(runtimeSection, /react-native\/app-release\.apk/);
  assert.match(runtimeSection, /react-native-ui\.xml/);
  assert.match(runtimeSection, /flutter-ui\.xml/);
  assert.doesNotMatch(runtimeSection, /react-native\/app-debug\.apk/);
});

test("Android runtime smoke writes screenshot and UI dump artifacts with fake host tools", () => {
  const run = runSmokeWithFakeTools(
    '<hierarchy><node content-desc="No input"/><node content-desc="1"/></hierarchy>\n',
  );
  assert.equal(run.result.status, 0, run.result.stderr);
  assert.equal(readFileSync(run.screenshotPath, "utf8"), "PNG-fixture\n");
  assert.match(readFileSync(run.dumpPath, "utf8"), /content-desc="No input"/);
});

test("Android runtime smoke fails on editable or password accessibility nodes", () => {
  const run = runSmokeWithFakeTools(
    '<hierarchy><node content-desc="No input"/><node content-desc="1" class="android.widget.EditText" password="true"/></hierarchy>\n',
  );
  assert.equal(run.result.status, 1);
  assert.match(run.result.stderr, /editable text controls|password accessibility nodes/);
});

test("Android runtime smoke fails when the foreground window lacks FLAG_SECURE", () => {
  const run = runSmokeWithFakeTools(
    '<hierarchy><node content-desc="No input"/><node content-desc="1"/></hierarchy>\n',
    "0x0",
  );
  assert.equal(run.result.status, 1);
  assert.match(run.result.stderr, /FLAG_SECURE/);
});

test("Android runtime smoke rejects a secure window that is not the focused app", () => {
  const run = runSmokeWithFakeTools(
    '<hierarchy><node content-desc="No input"/><node content-desc="1"/></hierarchy>\n',
    "0x2000",
    "dev.other.app",
  );
  assert.equal(run.result.status, 1);
  assert.match(run.result.stderr, /foreground app window/);
});

test("Flutter host artifact contains every supported Android target platform", () => {
  const flutterBuildSection = WORKFLOW.match(
    /Build the Flutter host APK with the native FFI boundary[\s\S]*?Emit Flutter Android FFI checksum manifest/,
  )?.[0];
  assert.ok(flutterBuildSection, "Flutter Android build section must exist");
  assert.match(flutterBuildSection, /flutter build apk --debug --target-platform android-arm64,android-x64/);
  assert.doesNotMatch(flutterBuildSection, /target-platform android-arm64\s*\n\s*flutter build apk --debug --target-platform android-x64/);
});

test("Android host builds exercise the bundled FFI fallback", () => {
  assert.match(WORKFLOW, /Stage bundled Flutter Android FFI artifacts/);
  assert.match(WORKFLOW, /packages\/flutter\/android\/secure_ffi\/arm64-v8a/);
  assert.match(WORKFLOW, /packages\/flutter\/android\/secure_ffi\/x86_64/);
  assert.match(WORKFLOW, /Stage bundled React Native Android FFI artifacts/);
  assert.match(WORKFLOW, /RN_PACKAGE_DIR\/android\/secure_ffi\/arm64-v8a/);
  assert.match(WORKFLOW, /RN_PACKAGE_DIR\/android\/secure_ffi\/x86_64/);

  const flutterBuildSection = WORKFLOW.match(
    /Build the Flutter host APK with the native FFI boundary[\s\S]*?Emit Flutter Android FFI checksum manifest/,
  )?.[0];
  const rnBuildSection = WORKFLOW.match(
    /Build the React Native host APK with the native FFI boundary[\s\S]*?Emit React Native Android FFI checksum manifest/,
  )?.[0];
  assert.ok(flutterBuildSection);
  assert.ok(rnBuildSection);
  assert.doesNotMatch(flutterBuildSection, /SECURE_KEYPAD_FFI_LIB_DIR/);
  assert.doesNotMatch(rnBuildSection, /SECURE_KEYPAD_FFI_LIB_DIR/);
});
