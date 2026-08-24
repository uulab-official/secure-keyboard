import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  findOpaqueSecretOutputMismatches,
  findMutableCiActionLines,
  findNativeClipboardMismatches,
  findNativeAbiVersionMismatches,
  findReleaseWorkflowToolchainMismatches,
  runSecurityAudit,
} from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});

test("release workflows pin every production host toolchain consistently", () => {
  const ciWorkflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const releaseWorkflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );

  assert.deepEqual(findReleaseWorkflowToolchainMismatches(ciWorkflow, releaseWorkflow), []);

  const brokenReleaseWorkflow = releaseWorkflow.replaceAll("22.13.0", "22.13.1");
  assert.deepEqual(findReleaseWorkflowToolchainMismatches(ciWorkflow, brokenReleaseWorkflow), [
    {
      file: ".github/workflows/release-candidate.yml",
      toolchain: "node",
      expected: "22.13.0",
      detail: "release candidate workflow must pin node to 22.13.0",
    },
  ]);
});

test("release workflows pin the package manager consistently", () => {
  const ciWorkflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const releaseWorkflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );

  const brokenReleaseWorkflow = releaseWorkflow.replaceAll("version: 11.19.0", "version: 11.19.1");
  assert.deepEqual(findReleaseWorkflowToolchainMismatches(ciWorkflow, brokenReleaseWorkflow), [
    {
      file: ".github/workflows/release-candidate.yml",
      toolchain: "pnpm",
      expected: "11.19.0",
      detail: "release candidate workflow must pin pnpm to 11.19.0",
    },
  ]);

  const brokenCiWorkflow = ciWorkflow.replace("            --toolchain pnpm=11.19.0 \\\n", "");
  assert.deepEqual(findReleaseWorkflowToolchainMismatches(brokenCiWorkflow, releaseWorkflow), [
    {
      file: ".github/workflows/ci.yml",
      toolchain: "pnpm",
      expected: "11.19.0",
      detail: "CI workflow must pin pnpm to 11.19.0",
    },
  ]);
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

test("CI exercises every release evidence emitter contract", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.match(workflow, /pnpm test:emit-release-artifact-fragment/);
  assert.match(workflow, /pnpm test:emit-native-device-evidence/);
});

test("independent security audit covers the production-candidate gate aggregator", () => {
  const audit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(audit, /scripts\/verify-production-candidate\.mjs/);
  assert.match(audit, /scripts\/check-clean-checkout\.mjs/);
  assert.match(audit, /generated_path in packages\\\/flutter/);
  assert.match(audit, /--require-trusted-keys/);
  assert.match(audit, /external device, service, CI-provenance, and independent-review evidence is not synthesized/);
});

test("CI checkout steps do not persist GitHub credentials into candidate worktrees", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.ok((workflow.match(/actions\/checkout@/g) ?? []).length > 0);
  assert.equal(
    (workflow.match(/actions\/checkout@/g) ?? []).length,
    (workflow.match(/persist-credentials:\s*false/g) ?? []).length,
  );
});

test("release candidate moves all generated Flutter state outside the checkout", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  assert.match(
    workflow,
    /for generated_path in packages\/flutter\/\.dart_tool packages\/flutter\/build packages\/flutter\/pubspec\.lock/,
  );
});

test("React Native does not publish an unwrapped native view escape hatch", () => {
  const source = readFileSync(new URL("../packages/react-native/src/index.ts", import.meta.url), "utf8");
  const guide = readFileSync(new URL("../packages/react-native/README.md", import.meta.url), "utf8");
  assert.doesNotMatch(source, /export function getSecureKeypadNativeView/);
  assert.match(source, /function resolveSecureKeypadNativeView/);
  assert.doesNotMatch(guide, /getSecureKeypadNativeView|unwrapped escape hatch/);
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

  assert.match(source, /context\.findActivity\(\)\s*\?:\s*return false/);
  assert.match(source, /check\(ensureSecureWindowProtection\(\)\)/);
  assert.match(source, /onAttachedToWindow\(\)[\s\S]*addFlags\(WindowManager\.LayoutParams\.FLAG_SECURE\)/);
});

test("native framework managers release stale sessions when required configuration disappears", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /if \(layout == null \|\| theme == null\) \{[\s\S]{0,240}pendingConfigurations\.remove\(view\)[\s\S]{0,240}view\.releaseSession\(\)/,
    );
  }

  for (const relativePath of [
    "../native/ios/react-native/SecureKeypadViewManager.swift",
    "../packages/react-native/ios/SecureKeypadViewManager.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /guard let layout, let theme else \{[\s\S]{0,240}configuredFingerprint = nil[\s\S]{0,240}releaseSession\(\)/,
    );
  }
});

test("React Native Android preserves initial partial configuration until required props complete", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /private val configuredViews = WeakHashMap<SecureKeypadView, Boolean>\(\)/);
    assert.match(
      source,
      /if \(layout == null \|\| theme == null\) \{\s*if \(configuredViews\.remove\(view\) != null\) \{[\s\S]{0,360}pendingConfigurations\.remove\(view\)[\s\S]{0,240}view\.releaseSession\(\)[\s\S]{0,120}\}\s*return/,
    );
    assert.match(source, /configuredViews\[view\] = true/);
  }
});

test("React Native iOS recreates a session after native lifecycle loss", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /internal var hasActiveSession: Bool \{ session != nil \}/);
  }

  for (const relativePath of [
    "../native/ios/react-native/SecureKeypadViewManager.swift",
    "../packages/react-native/ios/SecureKeypadViewManager.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /if fingerprint == configuredFingerprint && hasActiveSession \{/);
  }
});

test("React Native Android recreates a session after window lifecycle loss", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /internal var onSessionNeedsReconfiguration: \(\(\) -> Unit\)\? = null/);
    assert.match(
      source,
      /if \(hasWindowFocus\) \{[\s\S]{0,300}if \(!ensureSecureWindowProtection\(\)\)[\s\S]{0,220}requestSessionReconfigurationIfNeeded\(\)/,
    );
    assert.match(
      source,
      /onWindowVisibilityChanged\(visibility: Int\)[\s\S]{0,360}if \(visibility == View\.VISIBLE\) \{[\s\S]{0,220}requestSessionReconfigurationIfNeeded\(\)/,
    );
    assert.match(source, /private data class RetainedConfiguration/);
    assert.match(source, /private fun requestSessionReconfigurationIfNeeded\(\)[\s\S]{0,260}reconfigureRetainedConfiguration\(\)/);
  }

  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /view\.onSessionNeedsReconfiguration = \{[\s\S]{0,240}configureStoredConfiguration\(currentView, replayHeadlessKeyPress = false\)/);
    assert.match(source, /view\.onSessionNeedsReconfiguration = null/);
  }
});

test("Android native views recover a detached session on reattachment", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /override fun onAttachedToWindow\(\)[\s\S]{0,260}if \(!ensureSecureWindowProtection\(\)\)[\s\S]{0,180}requestSessionReconfigurationIfNeeded\(\)/,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /onAttachedToWindow/);
  assert.match(securityAudit, /requestSessionReconfigurationIfNeeded/);
});

test("Android reattachment secure-window failures zeroize without throwing", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /override fun onAttachedToWindow\(\)[\s\S]{0,260}if \(!ensureSecureWindowProtection\(\)\) \{\s*failClosedSecureWindowBoundary\(\)\s*return\s*\}[\s\S]{0,160}requestSessionReconfigurationIfNeeded\(\)/,
      `${relativePath} must fail closed instead of throwing when reattachment protection cannot be restored`,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /Android reattachment secure-window failures must fail closed without throwing/);
});

test("Android native input reasserts secure-window protection at the input boundary", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /private fun ensureSecureWindowProtection\(\)[\s\S]{0,520}FLAG_SECURE/);
    assert.match(
      source,
      /private fun ensureSecureInputBoundary\(\)[\s\S]{0,220}ensureSecureWindowProtection\(\)/,
    );
    assert.match(
      source,
      /public fun requestHeadlessKeyPress[\s\S]{0,800}ensureSecureInputBoundary\(\)/,
    );
    assert.match(
      source,
      /private fun activate\(key: SecureKeySpec\)[\s\S]{0,300}ensureSecureInputBoundary\(\)/,
    );
    assert.match(source, /if \(!activate\(key\)\) return[\s\S]{0,80}lastHeadlessKeyPress = requestId/);
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /ensureSecureInputBoundary/);
  assert.match(securityAudit, /lastHeadlessKeyPress/);
});

test("iOS headless replay state advances only after native activation succeeds", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const headlessStart = source.indexOf("public func requestHeadlessKeyPress");
    const headlessEnd = source.indexOf("/// Starts a printable-ASCII", headlessStart);
    assert.ok(headlessStart >= 0 && headlessEnd > headlessStart);
    assert.match(
      source.slice(headlessStart, headlessEnd),
      /if activate\(key: key\) \{\s*lastHeadlessKeyPress = requestId\s*\}/,
      `${relativePath} must advance the replay floor only after activation succeeds`,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /iOS headless replay state must advance only after secure input succeeds/);
});

test("native session activation failures do not advance the headless replay floor", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const activateStart = source.indexOf("private func activate(key:");
    const activateEnd = source.indexOf("private func refreshMaskedState", activateStart);
    assert.ok(activateStart >= 0 && activateEnd > activateStart);
    assert.match(
      source.slice(activateStart, activateEnd),
      /if status != 0 \{\s*onError\?\(status\)\s*return false\s*\}/,
      `${relativePath} must keep rejected native commands out of the replay floor`,
    );
  }

  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const activateStart = source.indexOf("private fun activate(key:");
    const activateEnd = source.indexOf("private fun keyBackground", activateStart);
    assert.ok(activateStart >= 0 && activateEnd > activateStart);
    assert.match(
      source.slice(activateStart, activateEnd),
      /if \(status != 0\) \{\s*onError\?\.invoke\(status\)\s*return false\s*\}/,
      `${relativePath} must keep rejected native commands out of the replay floor`,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /native activation failures must not advance headless replay floors/);
});

test("cancel request failures do not advance the native cancel replay floor", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const cancelStart = source.indexOf("public func requestCancel");
    const cancelEnd = source.indexOf("private func installViews", cancelStart);
    assert.ok(cancelStart >= 0 && cancelEnd > cancelStart);
    assert.match(
      source.slice(cancelStart, cancelEnd),
      /if cancelSessionAndReport\(\) \{\s*lastCancelRequest = requestId\s*\}/,
      `${relativePath} must advance the cancel replay floor only after native cancel succeeds`,
    );
  }

  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const cancelStart = source.indexOf("public fun requestCancel");
    const cancelEnd = source.indexOf("override fun onDetachedFromWindow", cancelStart);
    assert.ok(cancelStart >= 0 && cancelEnd > cancelStart);
    assert.match(
      source.slice(cancelStart, cancelEnd),
      /if \(cancelSessionAndReport\(\)\) \{\s*lastCancelRequest = requestId\s*\}/,
      `${relativePath} must advance the cancel replay floor only after native cancel succeeds`,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /cancel failures must not advance the native cancel replay floor/);
});

test("Android lifecycle secure-window failures zeroize without throwing", () => {
  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /onWindowFocusChanged\(hasWindowFocus: Boolean\)[\s\S]{0,260}if \(!ensureSecureWindowProtection\(\)\) \{\s*failClosedSecureWindowBoundary\(\)\s*return\s*\}/,
      `${relativePath} must fail closed instead of throwing when focus protection cannot be restored`,
    );
    assert.match(
      source,
      /onWindowVisibilityChanged\(visibility: Int\)[\s\S]{0,300}if \(!ensureSecureWindowProtection\(\)\) \{\s*failClosedSecureWindowBoundary\(\)\s*return\s*\}/,
      `${relativePath} must fail closed instead of throwing when visibility protection cannot be restored`,
    );
    assert.match(
      source,
      /private fun failClosedSecureWindowBoundary\(\)[\s\S]{0,180}zeroizeSessionForLifecycleLoss\(\)[\s\S]{0,120}onError\?\.invoke\(SECURE_KEYPAD_ERROR_INTERNAL\)/,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /Android lifecycle secure-window failures must fail closed without throwing/);
});

test("all framework adapters restore lifecycle-lost sessions without replaying headless commands", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /internal var onSessionNeedsReconfiguration: \(\(\) -> Void\)\? = nil/);
    assert.match(source, /UIScene\.didActivateNotification[\s\S]{0,360}requestSessionReconfigurationIfNeeded\(\)/);
    assert.match(source, /private func handleScreenCaptureChange[\s\S]{0,900}requestSessionReconfigurationIfNeeded\(\)/);
    assert.match(source, /onSessionNeedsReconfiguration = nil/);
  }

  for (const relativePath of [
    "../native/ios/react-native/SecureKeypadViewManager.swift",
    "../packages/react-native/ios/SecureKeypadViewManager.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /onSessionNeedsReconfiguration = \{ \[weak self\] in self\?\.configureIfReady\(\) \}/);
    assert.match(source, /let isInitialConfiguration = configuredFingerprint == nil/);
    assert.match(source, /if \(forceHeadlessCommand \|\| isInitialConfiguration\), let headlessKeyPress/);
  }

  for (const relativePath of [
    "../native/ios/flutter/SecureKeypadFlutterPlugin.swift",
    "../packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /activeConfiguration/);
    assert.match(source, /onSessionNeedsReconfiguration = \{ \[weak self\] in[\s\S]{0,220}applyConfiguration\([\s\S]{0,180}replayHeadlessKeyPress: false/);
  }

  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /activeConfiguration/);
    assert.match(source, /keypad\.onSessionNeedsReconfiguration = \{[\s\S]{0,220}replayHeadlessKeyPress = false/);
    assert.match(source, /keypad\.onSessionNeedsReconfiguration = null/);
  }

  for (const relativePath of [
    "../native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /configureStoredConfiguration\(currentView, replayHeadlessKeyPress = false\)/);
    assert.match(source, /if \(replayHeadlessKeyPress \|\| replayInitialHeadlessKeyPress\) \{[\s\S]{0,180}parsed\.headlessKeyPress\?\.let/);
  }
});

test("native headless replay floors survive session release", () => {
  const nativeViewSources = [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
    "../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "../packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ];

  for (const relativePath of nativeViewSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /releaseSession\(\)\s*\{/);
    assert.doesNotMatch(
      source,
      /releaseSession\(\)\s*\{[\s\S]{0,700}lastHeadlessKeyPress\s*=/,
      `${relativePath} must retain the headless replay floor across lifecycle release`,
    );
  }
});

test("Flutter headless controller keeps its token sequence across reattachment", () => {
  const source = readFileSync(
    new URL("../packages/flutter/lib/secure_keypad_flutter.dart", import.meta.url),
    "utf8",
  );
  const attachStart = source.indexOf("  void _attach(");
  const detachStart = source.indexOf("  void _detach(", attachStart);
  assert.ok(attachStart >= 0 && detachStart > attachStart);
  assert.doesNotMatch(
    source.slice(attachStart, detachStart),
    /_nextHeadlessKeyPressToken\s*=\s*0/,
  );
  assert.doesNotMatch(
    source.slice(detachStart, detachStart + 260),
    /_nextHeadlessKeyPressToken\s*=\s*0/,
  );

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /Flutter headless controller must preserve its token sequence/);
});

test("native host ABI expectations stay synchronized with the FFI header", () => {
  assert.deepEqual(findNativeAbiVersionMismatches(), []);
});

test("FFI audit locks opaque object and identifier range alias checks", () => {
  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /auth_finish_arguments_alias/);
  assert.match(securityAudit, /pointer_slot_overlaps_object/);
  assert.match(securityAudit, /buffer_overlaps_object\\\(client_identifier/);
  assert.match(securityAudit, /secure_keypad_client_login_finish/);
  assert.match(securityAudit, /secure_keypad_client_registration_finish/);
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
  assert.match(specification, /pointer-sized output slot[\s\S]*?must not overlap[\s\S]*?live[\s\S]*?opaque handle objects/i);
  assert.match(specification, /finish identifier buffers[\s\S]*?must not[\s\S]*?overlap[\s\S]*?any live handle or pointer slot/i);
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

test("iOS native views fail closed when masked-state refresh fails", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const start = source.indexOf("private func refreshMaskedState");
    const end = source.indexOf("private func performFeedback", start);
    assert.ok(start >= 0 && end > start, "iOS native refresh block must exist");
    const refreshBlock = source.slice(start, end);
    assert.match(
      refreshBlock,
      /let status = secure_keypad_session_refresh\(session, &state\)[\s\S]*guard status == 0 else \{[\s\S]*releaseSession\(\)[\s\S]*onError\?\(status\)/,
      "iOS native views must release the session before reporting a native refresh failure",
    );
  }
});

test("iOS protected presentation rejects headless host input", () => {
  const presentationSources = [
    "../native/ios/SecureKeypadPresentation.swift",
    "../packages/react-native/ios/SecureKeypadPresentation.swift",
    "../packages/flutter/ios/Classes/SecureKeypadPresentation.swift",
  ];
  for (const relativePath of presentationSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /func secureKeypadShouldAcceptProgrammaticKeyPress\(protected: Bool\)/);
    assert.match(source, /secureKeypadShouldAcceptProgrammaticKeyPress\(protected: Bool\)[\s\S]*!protected/);
  }

  const viewSources = [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ];
  for (const relativePath of viewSources) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const headlessStart = source.indexOf("public func requestHeadlessKeyPress");
    const headlessEnd = source.indexOf("/// Starts a printable-ASCII", headlessStart);
    assert.ok(headlessStart >= 0 && headlessEnd > headlessStart);
    assert.match(
      source.slice(headlessStart, headlessEnd),
      /secureKeypadShouldAcceptProgrammaticKeyPress\(protected: protectedPresentation\)/,
    );
    const activateStart = source.indexOf("private func activate(key:");
    const activateEnd = source.indexOf("private func refreshMaskedState", activateStart);
    assert.ok(activateStart >= 0 && activateEnd > activateStart);
    assert.match(
      source.slice(activateStart, activateEnd),
      /guard secureKeypadShouldAcceptProgrammaticKeyPress\(protected: protectedPresentation\) else \{ return(?: false)? \}/,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /secureKeypadShouldAcceptProgrammaticKeyPress/);
});

test("iOS screen-capture transitions release a live native session", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadPresentation.swift",
    "../packages/react-native/ios/SecureKeypadPresentation.swift",
    "../packages/flutter/ios/Classes/SecureKeypadPresentation.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /func secureKeypadShouldClearSessionForScreenCapture\(screenIsCaptured: Bool, sessionIsLive: Bool\)[\s\S]*screenIsCaptured && sessionIsLive/,
    );
  }

  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    const observerStart = source.indexOf("UIScreen.capturedDidChangeNotification");
    const observerEnd = source.indexOf("refreshProtectionState()", observerStart);
    assert.ok(observerStart >= 0 && observerEnd > observerStart);
    assert.match(source.slice(observerStart, observerEnd), /handleScreenCaptureChange\(\)/);
    const handlerStart = source.indexOf("private func handleScreenCaptureChange");
    const handlerEnd = source.indexOf("private func refreshProtectionState", handlerStart);
    assert.ok(handlerStart >= 0 && handlerEnd > handlerStart);
    assert.match(
      source.slice(handlerStart, handlerEnd),
      /secureKeypadShouldClearSessionForScreenCapture[\s\S]*releaseNativeSessionPreservingConfiguration\(\)[\s\S]*onMaskedStateChanged\?\(0, 3\)[\s\S]*refreshProtectionState\(\)[\s\S]*requestSessionReconfigurationIfNeeded\(\)/,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /secureKeypadShouldClearSessionForScreenCapture/);
});

test("iOS protected presentation zeroizes any live session", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(
      source,
      /private func setProtectedPresentation\(_ protected: Bool\)[\s\S]{0,280}if protected, session != nil \{[\s\S]{0,180}releaseNativeSessionPreservingConfiguration\(\)[\s\S]{0,120}onMaskedStateChanged\?\(0, 3\)/,
      `${relativePath} must zeroize a live session whenever protected presentation is enabled`,
    );
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /iOS protected presentation must zeroize a live native session/);
});

test("iOS lifecycle protection is scoped to the keypad window scene", () => {
  for (const relativePath of [
    "../native/ios/SecureKeypadView.swift",
    "../packages/react-native/ios/SecureKeypadView.swift",
    "../packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /UIScene\.willDeactivateNotification/);
    assert.match(source, /UIScene\.didActivateNotification/);
    assert.match(source, /window\?\.windowScene\?\.activationState == \.foregroundActive/);
    assert.doesNotMatch(source, /UIApplication\.shared\.applicationState/);
    assert.match(source, /private func isCurrentSceneNotification\(_ object: Any\?\)/);
  }

  const securityAudit = readFileSync(new URL("./security-audit.mjs", import.meta.url), "utf8");
  assert.match(securityAudit, /UIScene\\\.willDeactivateNotification/);
  assert.match(securityAudit, /activationState == \\.foregroundActive/);
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
  assert.match(releaseGates, /cargo publish --locked --workspace --all-features --dry-run[\s\S]*?--target-dir/);
});

test("Flutter release gates use the Flutter CLI for package dry-runs", () => {
  const candidateVerifier = readFileSync(
    new URL("./verify-production-candidate.mjs", import.meta.url),
    "utf8",
  );
  const ciWorkflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const releaseWorkflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  const releaseGates = readFileSync(new URL("../docs/RELEASE-GATES.md", import.meta.url), "utf8");
  assert.match(candidateVerifier, /command\("Flutter publish dry-run", "flutter", \["pub", "publish", "--dry-run"\]/);
  assert.doesNotMatch(candidateVerifier, /command\("Flutter publish dry-run", "dart"/);
  for (const source of [ciWorkflow, releaseWorkflow, releaseGates]) {
    assert.match(source, /flutter pub publish --dry-run/);
    assert.doesNotMatch(source, /dart pub publish --dry-run/);
  }
});

test("release candidate executes every standalone release contract and copies crates once", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /pnpm test:emit-native-device-evidence/);
  assert.match(workflow, /pnpm test:ios-host-build-contract/);
  assert.equal(
    [...workflow.matchAll(/cp \"\$RUNNER_TEMP\/secure-keypad-cargo-target\/package\/\"\*\.crate/g)].length,
    1,
  );
});

test("release candidate runs artifact validation and evidence emission from the trusted verifier checkout", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  for (const script of [
    "check-release-bundle.mjs",
    "check-release-archive.mjs",
    "emit-signed-release-evidence.mjs",
    "emit-release-artifact-fragment.mjs",
  ]) {
    assert.match(workflow, new RegExp(`node \\\"\\$GITHUB_WORKSPACE/verifier/scripts/${script}\\\"`));
    assert.doesNotMatch(workflow, new RegExp(`node scripts/${script}`));
  }
  assert.match(workflow, /--commit \"\$RELEASE_REF\"/);
  assert.match(workflow, /--package-version \"\$CANDIDATE_PACKAGE_VERSION\"/);
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
    assert.match(
      source,
      /key\.testId\?\.matches\(Regex\("\[a-z0-9\]\[a-z0-9\._-\]\{0,63\}"\)\) != false/,
      `${relativePath} must bound optional native test IDs before UI allocation`,
    );
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
    assert.match(
      source,
      /key\.id\.range\(of: "\^\[a-z0-9\]\[a-z0-9\._-\]\{0,63\}\$", options: \.regularExpression\)/,
      `${relativePath} must enforce the canonical public key-ID grammar before native UI allocation`,
    );
    assert.match(
      source,
      /key\.testId\?\.range\(of: "\^\[a-z0-9\]\[a-z0-9\._-\]\{0,63\}\$", options: \.regularExpression\) != nil/,
      `${relativePath} must bound optional native test IDs before UI allocation`,
    );
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
