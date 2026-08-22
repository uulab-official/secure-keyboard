import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  findOpaqueSecretOutputMismatches,
  findMutableCiActionLines,
  findNativeClipboardMismatches,
  findNativeAbiVersionMismatches,
  runSecurityAudit,
} from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});

test("release evidence and signing outputs use exclusive creation", () => {
  const sourcePaths = [
    "../scripts/emit-release-gate-evidence.mjs",
    "../scripts/emit-signed-release-evidence.mjs",
    "../scripts/merge-release-evidence.mjs",
    "../scripts/sign-release.mjs",
  ];

  for (const relativePath of sourcePaths) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /writeFileSync\([\s\S]{0,240}flag:\s*["']wx["']/,
      `${relativePath} must create security-sensitive outputs exclusively`,
    );
  }
});

test("OPAQUE secret outputs require a zeroizing source copy", () => {
  const source = readFileSync(new URL("../crates/secure-auth/src/lib.rs", import.meta.url), "utf8");
  assert.deepEqual(findOpaqueSecretOutputMismatches(source), []);

  const findings = findOpaqueSecretOutputMismatches(
    "let session_key = result.session_key.to_vec();",
  );
  assert.equal(findings.length, 2);
  assert.match(findings[0].detail, /zeroizing helper/);
  assert.match(findings[1].detail, /direct GenericArray copy/);
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

test("security policy provides a private vulnerability reporting channel", () => {
  const policy = readFileSync(new URL("../SECURITY.md", import.meta.url), "utf8");
  assert.match(policy, /github\.com\/uulab-official\/secure-keyboard\/security\/advisories\/new/);
  assert.match(policy, /Do not open a public issue/);
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

test("FFI audit locks opaque object and identifier range alias checks", () => {
  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /auth_finish_arguments_alias/);
  assert.match(securityAudit, /pointer_slot_overlaps_object/);
  assert.match(securityAudit, /buffer_overlaps_object\\\(client_identifier/);
});

test("native presentation snapshots expose only bounded masked state", () => {
  const presentationSources = [
    "../native/ios/SecureKeypadPresentation.swift",
    "../packages/react-native/ios/SecureKeypadPresentation.swift",
    "../packages/flutter/ios/Classes/SecureKeypadPresentation.swift",
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
  ];
  for (const relativePath of presentationSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /secureKeypadSecuritySnapshot/);
    assert.match(source, /maskedDisplay/);
    assert.match(source, /accessibility/);
    assert.doesNotMatch(source, /\b(?:password|rawInput|onChangeText)\s*[:(=]/i);
  }
});

test("release bundle audit covers Android FFI commit binding", () => {
  const releaseBundleAudit = readFileSync(
    new URL("./check-release-bundle.mjs", import.meta.url),
    "utf8",
  );
  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(releaseBundleAudit, /source\/secure-keypad-android-ffi\.commit/);
  assert.match(releaseBundleAudit, /MAX_NATIVE_COMMIT_BINDING_BYTES/);
  assert.match(securityAudit, /MAX_NATIVE_COMMIT_BINDING_BYTES/);
  assert.match(
    securityAudit,
    /must use a distinct public key from the maintainer release signature/,
  );
  assert.match(securityAudit, /verifyNativeChecksumBinding/);
  assert.match(securityAudit, /expectedHostModeVersions/);
});

test("security specification describes the shipped ABI v2 registration boundary", () => {
  const specification = readFileSync(
    new URL("../docs/SECURITY-SPEC.md", import.meta.url),
    "utf8",
  );
  assert.match(specification, /ABI version 2 is required for the registration handoff/);
  assert.match(specification, /ABI v1 is not a supported production registration path/);
  assert.doesNotMatch(specification, /Version 1 does not provide a production-safe native registration path/);
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

test("native keypad views do not include editable text controls", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(source, /\b(?:EditText|TextInputEditText|AutoCompleteTextView)\b/);
  }

  const iosSources = [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ];
  for (const relativePath of iosSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(source, /\b(?:UITextField|UITextView|UISearchBar|UITextInput)\b/);
  }
});

test("native keypad sources reject clipboard APIs as a secret channel", () => {
  assert.deepEqual(findNativeClipboardMismatches("import UIKit\nlet board = UIPasteboard.general", "ios"), [
    { detail: "iOS native keypad must not use clipboard APIs" },
  ]);
  assert.deepEqual(findNativeClipboardMismatches("val manager = getSystemService(ClipboardManager::class.java)", "android"), [
    { detail: "Android native keypad must not use clipboard APIs" },
  ]);
  assert.deepEqual(findNativeClipboardMismatches("final class SecureKeypadView {}", "ios"), []);
  assert.deepEqual(findNativeClipboardMismatches("class SecureKeypadView", "android"), []);
});

test("opaque submission routing binds the consumer contract to the originating native view", () => {
  const iosView = readFileSync(new URL("../native/ios/SecureKeypadView.swift", import.meta.url), "utf8");
  const iosManager = readFileSync(
    new URL("../native/ios/react-native/SecureKeypadViewManager.swift", import.meta.url),
    "utf8",
  );
  assert.match(iosView, /typealias Consumer = \(SecureKeypadView, SecureKeypadSubmission\) -> Bool/);
  assert.match(iosView, /deliver\(_ submission: SecureKeypadSubmission, from view: SecureKeypadView\)/);
  assert.match(iosManager, /guard let view = self else \{\s*submission\.close\(\)\s*return\s*\}/);
  assert.match(iosManager, /deliver\(submission, from: view\)/);

  const androidView = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", import.meta.url),
    "utf8",
  );
  const androidManager = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt", import.meta.url),
    "utf8",
  );
  assert.match(androidView, /typealias SecureKeypadSubmissionConsumer = \(SecureKeypadView, SecureKeypadSubmission\) -> Boolean/);
  assert.match(androidView, /deliver\(submission: SecureKeypadSubmission, from: SecureKeypadView\)/);
  assert.match(androidManager, /deliver\(submission, view\)/);
});

test("native adapter teardown breaks callback ownership cycles", () => {
  const iosFlutter = readFileSync(
    new URL("../native/ios/flutter/SecureKeypadFlutterPlugin.swift", import.meta.url),
    "utf8",
  );
  assert.match(iosFlutter, /\[weak self, weak nativeKeypad\]/);
  assert.match(iosFlutter, /guard let nativeKeypad else \{\s*submission\.close\(\)\s*return\s*\}/);

  const androidView = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", import.meta.url),
    "utf8",
  );
  assert.match(androidView, /internal fun clearBridgeCallbacks\(\)/);

  const androidReactNative = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt", import.meta.url),
    "utf8",
  );
  assert.match(androidReactNative, /view\.clearBridgeCallbacks\(\)/);

  const androidFlutter = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt", import.meta.url),
    "utf8",
  );
  assert.match(androidFlutter, /keypad\.clearBridgeCallbacks\(\)/);
});

test("release candidate validates the unpublished workspace crate chain through Cargo dry-run publish", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  const releaseGates = readFileSync(new URL("../docs/RELEASE-GATES.md", import.meta.url), "utf8");
  assert.match(workflow, /cargo publish --locked --workspace --all-features --dry-run --target-dir/);
  assert.doesNotMatch(workflow, /cargo package --locked --workspace --all-features/);
  assert.match(releaseGates, /cargo publish --locked --workspace --all-features --dry-run/);
});

test("native views reject noncanonical input IDs for the selected policy", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /validateLayout\(layout, policy\)/);
    assert.match(source, /SecureKeyRole\.INPUT[\s\S]{0,240}isCanonicalInputKeyId/);
  }

  const iosSources = [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ];
  for (const relativePath of iosSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /try validate\(layout: layout, policy: policy\)/);
    assert.match(source, /case \.input:[\s\S]{0,240}isCanonicalInputKeyId/);
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
    new URL("../packages/flutter/lib/secure_keypad_flutter.dart", import.meta.url),
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

test("Android bridge validates theme numbers before narrowing to Float", () => {
  const androidSources = [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
  ];
  for (const relativePath of androidSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /val result = \(value as\? Number\)\?\.toDouble\(\)/);
    assert.match(source, /result >= minimum\.toDouble\(\)[\s\S]*result <= maximum\.toDouble\(\)/);
    assert.match(source, /return result\.toFloat\(\)/);
  }
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
