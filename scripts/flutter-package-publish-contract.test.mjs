import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PACKAGE_ROOT = `${ROOT}/packages/flutter`;

test("Flutter package exposes a package-named canonical library entrypoint", () => {
  const canonical = `${PACKAGE_ROOT}/lib/secure_keypad_flutter.dart`;
  assert.equal(existsSync(canonical), true);
  assert.match(readFileSync(canonical, "utf8"), /library secure_keypad_flutter;/);
  assert.equal(existsSync(`${PACKAGE_ROOT}/lib/secure_keypad.dart`), false);
});

test("Flutter package excludes generated build state from publication", () => {
  const pubignore = `${PACKAGE_ROOT}/.pubignore`;
  assert.equal(existsSync(pubignore), true);
  const contents = readFileSync(pubignore, "utf8");
  assert.match(contents, /^build\/$/m);
  assert.match(contents, /^\.dart_tool\/$/m);
  assert.match(contents, /^pubspec\.lock$/m);
});

test("Flutter layout randomization survives the Dart-to-native creation boundary", () => {
  const source = readFileSync(`${PACKAGE_ROOT}/lib/secure_keypad_flutter.dart`, "utf8");
  assert.match(source, /final bool randomizeInputKeys;/);
  assert.match(source, /'randomizeInputKeys': layout\.randomizeInputKeys/);
  assert.match(source, /layout\.randomizeInputKeys != true && layout\.randomizeInputKeys != false/);
});
