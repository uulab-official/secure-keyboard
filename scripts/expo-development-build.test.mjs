import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const PACKAGE_ROOT = fileURLToPath(new URL("../packages/react-native/", import.meta.url));
const PACKAGE_JSON = JSON.parse(readFileSync(`${PACKAGE_ROOT}/package.json`, "utf8"));
const README = readFileSync(`${PACKAGE_ROOT}/README.md`, "utf8");
const PLUGIN = readFileSync(`${PACKAGE_ROOT}/app.plugin.js`, "utf8");

test("React Native package exposes an Expo development-build plugin", () => {
  assert.equal(PACKAGE_JSON["app.plugin"], "./app.plugin.js");
  assert.ok(PACKAGE_JSON.files.includes("app.plugin.js"));
  assert.match(PLUGIN, /withDangerousMod/);
  assert.match(PLUGIN, /SECURE_KEYPAD_FFI_XCFRAMEWORK/);
  assert.match(PLUGIN, /secure_ffi\.xcframework/);
  assert.match(PLUGIN, /SECURE_KEYPAD_FFI_LIB_DIR/);
  assert.match(PLUGIN, /android[\\/]secure_ffi/);
});

test("Expo documentation keeps the secure native and Expo Go boundary explicit", () => {
  assert.match(README, /Expo Development Build/);
  assert.match(README, /npx expo prebuild/);
  assert.match(README, /Expo Go/);
  assert.match(README, /SECURE_KEYPAD_FFI_XCFRAMEWORK/);
  assert.match(README, /SECURE_KEYPAD_FFI_LIB_DIR/);
  assert.match(README, /candidate-only|secure native/i);
});

test("Expo plugin source has no secret-bearing input or callback channel", () => {
  assert.doesNotMatch(PLUGIN, /password|plaintext|inputValue|inputText|onChangeText/i);
});
