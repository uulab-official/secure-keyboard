import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  findMutableCiActionLines,
  findNativeAbiVersionMismatches,
  runSecurityAudit,
} from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});

test("CI action audit rejects mutable refs and accepts immutable revisions", () => {
  assert.deepEqual(
    findMutableCiActionLines([
      "      - uses: actions/checkout@v4",
      "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
    ].join("\n")),
    ["      - uses: actions/checkout@v4"],
  );
});

test("Android secure native view fails closed without a secure Activity window", () => {
  const source = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", import.meta.url),
    "utf8",
  );

  assert.match(source, /findActivity\(\)\s*\?:\s*error/);
  assert.match(source, /onAttachedToWindow\(\)[\s\S]*addFlags\(WindowManager\.LayoutParams\.FLAG_SECURE\)/);
});

test("native host ABI expectations stay synchronized with the FFI header", () => {
  assert.deepEqual(findNativeAbiVersionMismatches(), []);
});

test("native views enforce bounded public layout and theme configuration", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /MAX_LAYOUT_ROWS\s*=\s*16/);
    assert.match(source, /MAX_LAYOUT_KEYS_PER_ROW\s*=\s*32/);
    assert.match(source, /MAX_LAYOUT_KEYS\s*=\s*512/);
    assert.match(source, /MAX_ACCESSIBILITY_LABEL_LENGTH\s*=\s*80/);
    assert.match(source, /layout\.rows\.size\s+in\s+1\.\.MAX_LAYOUT_ROWS/);
    assert.match(source, /row\.size\s+in\s+1\.\.MAX_LAYOUT_KEYS_PER_ROW/);
    assert.match(source, /totalKeys\s*<=\s*MAX_LAYOUT_KEYS/);
    assert.match(source, /MAX_KEY_LABEL_BYTES\s*=\s*16/);
    assert.match(source, /key\.label\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*MAX_KEY_LABEL_BYTES/);
    assert.match(source, /key\.accessibilityLabel\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*MAX_ACCESSIBILITY_LABEL_LENGTH/);
    assert.match(source, /validateTheme\(theme\)/);
    assert.match(source, /theme\.keyHeightPx\s+in\s+32\.\.160/);
    assert.match(source, /theme\.keyFontSizePx\.isFinite\(\).*theme\.keyFontSizePx\s+in\s+10f\.\.72f/);
  }

  const iosSources = [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ];
  for (const relativePath of iosSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /1\.\.\.16\)\.contains\(layout\.rows\.count\)/);
    assert.match(source, /1\.\.\.32\)\.contains\(row\.count\)/);
    assert.match(source, /totalKeys\s*<=\s*512/);
    assert.match(source, /key\.label\.utf8\.count\s*<=\s*16/);
    assert.match(source, /key\.accessibilityLabel\.utf8\.count\s+<=\s+80/);
    assert.match(source, /try validate\(theme: theme\)/);
    assert.match(source, /theme\.keyHeight\s+>=\s+32/);
    assert.match(source, /theme\.keyFontSize\.isFinite/);
  }
});

test("all public adapters apply the same UTF-8 byte bounds to labels", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /toByteArray\(Charsets\.UTF_8\)\.size/);
  }

  const flutterSource = readFileSync(
    new URL("../packages/flutter/lib/secure_keypad.dart", import.meta.url),
    "utf8",
  );
  assert.match(flutterSource, /utf8\.encode\(key\.label!\)\.length/);
  assert.match(flutterSource, /utf8\.encode\(key\.accessibilityLabel!\)\.length/);

  const contractsSource = readFileSync(
    new URL("../packages/contracts/src/index.ts", import.meta.url),
    "utf8",
  );
  assert.match(contractsSource, /MAX_KEY_LABEL_BYTES\s*=\s*16/);
  assert.match(contractsSource, /MAX_ACCESSIBILITY_LABEL_BYTES\s*=\s*80/);
  assert.match(contractsSource, /function utf8ByteLength/);
});

test("Flutter native event bridges retain a bounded backlog without overwriting terminal results", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /MAX_PENDING_EVENTS\s*=\s*32/);
    assert.match(source, /ArrayDeque/);
    assert.match(source, /pendingEvents/);
    assert.match(source, /removeFirst/);
    assert.doesNotMatch(source, /pendingEvent\s*:/);
  }

  const iosSources = [
    "../native/ios/flutter/SecureKeypadFlutterPlugin.swift",
    "../packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift",
  ];
  for (const relativePath of iosSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /maxPendingEvents\s*=\s*32/);
    assert.match(source, /pendingEvents/);
    assert.match(source, /removeFirst/);
    assert.doesNotMatch(source, /pendingEvent\s*:/);
  }
});
