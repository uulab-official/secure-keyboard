import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const readExample = (relativePath) => readFileSync(new URL(`../examples/${relativePath}`, import.meta.url), "utf8");

test("checked-in examples cover the supported public integration surfaces", () => {
  const readme = readExample("README.md");
  const reactNative = readExample("react-native/App.tsx");
  const flutter = readExample("flutter/lib/main.dart");
  const web = readExample("web/src/passkey.ts");

  assert.match(readme, /React Native/);
  assert.match(readme, /Flutter/);
  assert.match(readme, /WebAuthn/);
  assert.match(reactNative, /getSecureKeypadView/);
  assert.match(reactNative, /inputPolicy: "numeric"/);
  assert.match(flutter, /SecureKeypadConfiguration/);
  assert.match(flutter, /InputPolicy\.hangul/);
  assert.match(flutter, /late final SecureKeypadConfiguration _configuration/);
  assert.match(flutter, /void initState\(\)/);
  assert.match(web, /createPasskeyController/);
  assert.match(web, /controller\.cancel\(\)/);
  assert.doesNotMatch(web, /SerializedRegistrationCredential|return credential/);
});

test("checked-in examples never introduce framework secret channels", () => {
  for (const relativePath of [
    "react-native/App.tsx",
    "flutter/lib/main.dart",
    "web/src/passkey.ts",
  ]) {
    const source = readExample(relativePath);
    assert.doesNotMatch(source, /TextInput|TextEditingController|onChangeText|password\s*[:(]|secret\s*[:(]/i);
  }
});
