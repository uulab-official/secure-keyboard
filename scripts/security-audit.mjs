import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { findNativePackageParityMismatches } from "./check-native-package-parity.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const SECRET_FIELD_PATTERN = /\b(?:password|secret|onChangeText)\b\s*(?:\??\s*[:(]|=)/i;

function source(relativePath, findings) {
  const absolutePath = path.join(ROOT, relativePath);
  if (!existsSync(absolutePath)) {
    findings.push({ rule: "file-present", file: relativePath, detail: "required audit input is missing" });
    return "";
  }
  return readFileSync(absolutePath, "utf8");
}

function requireText(findings, relativePath, contents, pattern, detail) {
  if (!pattern.test(contents)) {
    findings.push({ rule: "required-contract", file: relativePath, detail });
  }
}

function forbidText(findings, relativePath, contents, pattern, detail) {
  if (pattern.test(contents)) {
    findings.push({ rule: "forbidden-secret-channel", file: relativePath, detail });
  }
}

const NATIVE_ABI_HOST_FILES = Object.freeze([
  [
    "native/ios/SecureKeypadView.swift",
    /secure_keypad_abi_version\(\)\s*==\s*(\d+)/,
    "iOS host ABI expectation",
  ],
  [
    "packages/react-native/ios/SecureKeypadView.swift",
    /secure_keypad_abi_version\(\)\s*==\s*(\d+)/,
    "React Native iOS host ABI expectation",
  ],
  [
    "packages/flutter/ios/Classes/SecureKeypadView.swift",
    /secure_keypad_abi_version\(\)\s*==\s*(\d+)/,
    "Flutter iOS host ABI expectation",
  ],
  [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    /EXPECTED_ABI_VERSION\s*=\s*(\d+)/,
    "Android host ABI expectation",
  ],
  [
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    /EXPECTED_ABI_VERSION\s*=\s*(\d+)/,
    "React Native Android host ABI expectation",
  ],
  [
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    /EXPECTED_ABI_VERSION\s*=\s*(\d+)/,
    "Flutter Android host ABI expectation",
  ],
]);

/**
 * Compares every native host's fail-closed ABI expectation with the central C
 * header and Rust implementation. This is deliberately independent of native
 * framework runtimes so a version bump cannot leave one package stale.
 *
 * @param {string} root repository root used by tests and release tooling
 * @returns {Array<{file: string, detail: string}>}
 */
export function findNativeAbiVersionMismatches(root = ROOT) {
  const headerFile = "crates/secure-ffi/include/secure_keypad.h";
  const implementationFile = "crates/secure-ffi/src/lib.rs";
  const header = existsSync(path.join(root, headerFile))
    ? readFileSync(path.join(root, headerFile), "utf8")
    : "";
  const implementation = existsSync(path.join(root, implementationFile))
    ? readFileSync(path.join(root, implementationFile), "utf8")
    : "";
  const headerVersion = header.match(/#define\s+SECURE_KEYPAD_ABI_VERSION\s+UINT32_C\((\d+)\)/)?.[1];
  const implementationVersion = implementation.match(
    /SECURE_KEYPAD_ABI_VERSION:\s*u32\s*=\s*(\d+)/,
  )?.[1];
  const mismatches = [];

  if (headerVersion === undefined) {
    mismatches.push({ file: headerFile, detail: "ABI version macro is missing" });
  }
  if (implementationVersion === undefined) {
    mismatches.push({ file: implementationFile, detail: "ABI version constant is missing" });
  }
  if (headerVersion !== undefined && implementationVersion !== undefined && headerVersion !== implementationVersion) {
    mismatches.push({
      file: implementationFile,
      detail: `ABI version ${implementationVersion} differs from header ${headerVersion}`,
    });
  }
  if (headerVersion === undefined) return mismatches;

  for (const [relativePath, pattern, label] of NATIVE_ABI_HOST_FILES) {
    const absolutePath = path.join(root, relativePath);
    if (!existsSync(absolutePath)) {
      mismatches.push({ file: relativePath, detail: `${label} file is missing` });
      continue;
    }
    const actualVersion = readFileSync(absolutePath, "utf8").match(pattern)?.[1];
    if (actualVersion === undefined) {
      mismatches.push({ file: relativePath, detail: `${label} is missing` });
    } else if (actualVersion !== headerVersion) {
      mismatches.push({
        file: relativePath,
        detail: `${label} ${actualVersion} differs from header ${headerVersion}`,
      });
    }
  }
  return mismatches;
}

export function findMutableCiActionLines(ciWorkflow) {
  return ciWorkflow
    .split("\n")
    .filter((line) => /\buses:\s*/.test(line))
    .filter((line) => !/^\s*(?:-\s+)?uses:\s*[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?\s*$/.test(line));
}

/**
 * Checks that OPAQUE export/session keys are copied through the zeroizing
 * helper instead of relying on a temporary GenericArray drop.
 *
 * @param {string} contents secure-auth source text
 * @returns {Array<{detail: string}>}
 */
export function findOpaqueSecretOutputMismatches(contents) {
  const findings = [];
  if (
    !/fn secret_output_from_zeroizing<T[\s\S]*?T:\s*AsRef<\[u8\]>\s*\+\s*Zeroize[\s\S]*?SecretOutput\(copy_and_zeroize_serialized\(&mut serialized\)\)/.test(
      contents,
    )
  ) {
    findings.push({ detail: "OPAQUE secret outputs must use the zeroizing helper" });
  }
  if (/\b(?:export_key|session_key)\.to_vec\(\)/.test(contents)) {
    findings.push({ detail: "OPAQUE secret outputs must not use a direct GenericArray copy" });
  }
  return findings;
}

/**
 * Runs a dependency-free, read-only release audit independent from framework
 * runtimes. It checks source-level invariants that unit tests cannot prove
 * when a package manifest or bridge copy is changed.
 *
 * @returns {Array<{rule: string, file: string, detail: string}>}
 */
export function runSecurityAudit() {
  const findings = [];

  const rn = source("packages/react-native/src/index.ts", findings);
  const rnProps = rn.match(/export interface SecureKeypadProps \{[\s\S]*?\n\}/)?.[0] ?? "";
  requireText(findings, "packages/react-native/src/index.ts", rn, /ALLOWED_PROP_NAMES/, "RN allowlist is missing");
  requireText(
    findings,
    "packages/react-native/src/index.ts",
    rnProps,
    /layout|theme|inputPolicy|mode|acknowledgeLowerAssurance|headlessKeyPress|maxTokens|timeoutMs|cancelRequest|onMaskedStateChange|onResult/g,
    "RN public props must be explicitly enumerated",
  );
  requireText(findings, "packages/react-native/src/index.ts", rnProps, /cancelRequest/, "RN must expose only a non-secret cancel command token");
  requireText(findings, "packages/react-native/src/index.ts", rn, /SecureKeypadMode/, "RN must expose an explicit renderer mode");
  requireText(findings, "packages/react-native/src/index.ts", rn, /acknowledgeLowerAssurance/, "RN headless mode must require explicit acknowledgement");
  requireText(findings, "packages/react-native/src/index.ts", rn, /validateHeadlessKeyPress/, "RN headless commands must be bounded and allowlisted");
  forbidText(
    findings,
    "packages/react-native/src/index.ts",
    rnProps,
    SECRET_FIELD_PATTERN,
    "RN props must not define a password/secret/change-text channel",
  );
  requireText(findings, "packages/react-native/src/index.ts", rn, /requireNativeComponent/, "RN must resolve a native component");

  const flutter = source("packages/flutter/lib/secure_keypad.dart", findings);
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /class SecureKeypad extends StatefulWidget/, "Flutter must expose a native PlatformView widget");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /class SecureKeypadController/, "Flutter must expose a non-secret native controller");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /invokeMethod<void>\('cancel'\)/, "Flutter controller must use a native cancel method");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /enum SecureKeypadMode/, "Flutter must expose an explicit renderer mode");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /invokeMethod<void>\('pressKey'/, "Flutter headless commands must use a native method channel");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /acknowledgeLowerAssurance/, "Flutter headless mode must require explicit acknowledgement");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /toPlatformCreationParams/, "Flutter must have an explicit public creation map");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /TextEditingController/, "Flutter must not use a text editing controller");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /final\s+(?:String\??)\s+(?:value|password|secret)\b/i, "Flutter configuration must not hold a secret string field");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter.match(/toPlatformCreationParams\(\)[\s\S]*?\n  \}/)?.[0] ?? "", /onResult|onMaskedStateChanged/, "Flutter native creation params must not serialize callbacks");

  const authDebug = source("crates/secure-auth/src/lib.rs", findings);
  for (const mismatch of findOpaqueSecretOutputMismatches(authDebug)) {
    findings.push({
      rule: "secret-output-zeroization",
      file: "crates/secure-auth/src/lib.rs",
      detail: mismatch.detail,
    });
  }
  requireText(findings, "crates/secure-auth/src/lib.rs", authDebug, /impl core::fmt::Debug for AuthEnvelope/, "OPAQUE transport Debug must be manually redacted");
  requireText(findings, "crates/secure-auth/src/lib.rs", authDebug, /field\("payload_len", &self\.payload\.len\(\)\)/, "OPAQUE transport Debug may expose payload length only");
  forbidText(findings, "crates/secure-auth/src/lib.rs", authDebug, /#\[derive\(Debug,\s*Serialize\)\][\s\S]{0,120}pub struct AuthEnvelope/, "OPAQUE transport must not derive Debug over its payload");
  const httpContract = source("crates/secure-auth-http/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-http/src/lib.rs", httpContract, /csrf_validated:\s*bool/, "framework-neutral OPAQUE requests must carry an explicit CSRF verdict");
  const axumAdapter = source("crates/secure-auth-axum/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axumAdapter, /csrf:\s*Arc</, "Axum adapters must retain a host CSRF callback");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axumAdapter, /invalid_request_response\(403\)/, "Axum adapters must reject failed CSRF validation before body buffering");
  const webauthnDebug = source("crates/secure-webauthn-example/src/lib.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /impl core::fmt::Debug for CeremonyStart/, "WebAuthn ceremony Debug must be manually redacted");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /field\("handle_len", &self\.handle\.len\(\)\)/, "WebAuthn ceremony Debug may expose handle length only");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /field\("options", &"<redacted>"\)/, "WebAuthn ceremony Debug must redact browser options");
  forbidText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /#\[derive\(Debug,\s*Serialize\)\][\s\S]{0,160}pub struct CeremonyStart/, "WebAuthn ceremony must not derive Debug over its handle or options");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /csrf_validated:\s*bool/, "WebAuthn requests must carry an explicit CSRF verdict");

  const nativeManagers = [
    "native/ios/react-native/SecureKeypadViewManager.swift",
    "native/ios/flutter/SecureKeypadFlutterPlugin.swift",
    "native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
    "packages/react-native/ios/SecureKeypadViewManager.swift",
    "packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
  ];
  for (const file of nativeManagers) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SecureKeypadNativeSubmissionRouter\.deliver\(submission\)/, "framework bridge must require an installed native submission consumer");
    requireText(findings, file, contents, /submission\.close\(\)/, "framework bridge must release an unconsumed submission");
    requireText(findings, file, contents, /(?:setRendererMode|mode)/, "framework bridge must enforce an explicit renderer mode");
    requireText(findings, file, contents, /(?:headlessKeyPress|pressKey)/, "framework bridge must expose only the bounded headless key-ID command");
    forbidText(findings, file, contents, /submission\.close\(\)[\s\S]{0,100}(?:code.*success|success.*code)/, "framework bridge must not report success after unconditional release");
  }

  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /MAX_PENDING_EVENTS\s*=\s*32/, "Flutter Android event backlog must have a small fixed bound");
    requireText(findings, file, contents, /ArrayDeque/, "Flutter Android event backlog must use a bounded FIFO queue");
    requireText(findings, file, contents, /pendingEvents/, "Flutter Android event backlog must be explicit and auditable");
    requireText(findings, file, contents, /removeFirst/, "Flutter Android event backlog must evict oldest entries when bounded");
    forbidText(findings, file, contents, /pendingEvent\s*:/, "Flutter Android must not overwrite the backlog with a single pending event");
  }
  for (const file of [
    "native/ios/flutter/SecureKeypadFlutterPlugin.swift",
    "packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /maxPendingEvents\s*=\s*32/, "Flutter iOS event backlog must have a small fixed bound");
    requireText(findings, file, contents, /pendingEvents/, "Flutter iOS event backlog must be explicit and auditable");
    requireText(findings, file, contents, /removeFirst/, "Flutter iOS event backlog must evict oldest entries when bounded");
    forbidText(findings, file, contents, /pendingEvent\s*:/, "Flutter iOS must not overwrite the backlog with a single pending event");
  }

  for (const file of [
    "native/ios/react-native/SecureKeypadViewManager.swift",
    "packages/react-native/ios/SecureKeypadViewManager.swift",
    "native/ios/react-native/SecureKeypadViewManager.m",
    "packages/react-native/ios/SecureKeypadViewManager.m",
    "native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /cancelRequest/, "RN native manager must expose the non-secret cancel command");
    requireText(findings, file, contents, /mode/, "RN native manager must expose an explicit renderer mode");
    requireText(findings, file, contents, /acknowledgeLowerAssurance/, "RN native manager must enforce lower-assurance acknowledgement");
    requireText(findings, file, contents, /headlessKeyPress/, "RN native manager must expose the bounded headless key-ID command");
  }
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadViewManager.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /toPublicMap\(LAYOUT_KEYS\)/, "RN Android layout conversion must use an explicit allowlist");
    requireText(findings, file, contents, /toPublicMap\(THEME_KEYS\)/, "RN Android theme conversion must use an explicit allowlist");
    requireText(findings, file, contents, /require\(key in allowedKeys\)/, "RN Android must reject unknown keys before reading bridge values");
    requireText(findings, file, contents, /MAX_PUBLIC_BRIDGE_NODES/, "RN Android public bridge conversion must bound aggregate nodes");
    requireText(findings, file, contents, /MAX_PUBLIC_BRIDGE_STRING_LENGTH/, "RN Android public bridge conversion must bound string values");
  }
  for (const file of [
    "native/ios/flutter/SecureKeypadFlutterPlugin.swift",
    "packages/flutter/ios/Classes/SecureKeypadFlutterPlugin.swift",
    "native/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/flutter/SecureKeypadFlutterPlugin.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /controlChannel/, "Flutter native plugin must expose a per-view control channel");
    requireText(findings, file, contents, /cancel/, "Flutter native plugin must implement the cancel command");
    requireText(findings, file, contents, /pressKey/, "Flutter native plugin must implement the bounded headless key-ID command");
    requireText(findings, file, contents, /setRendererMode|config\.mode/, "Flutter native plugin must enforce the explicit renderer mode");
  }

  for (const file of [
    "native/ios/SecureKeypadView.swift",
    "packages/react-native/ios/SecureKeypadView.swift",
    "packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /case \.cancel:/, "iOS native keypad must implement the explicit cancel action");
    requireText(findings, file, contents, /takeOpaqueHandle\(\)/, "iOS native submission must have an opaque transfer API");
    requireText(findings, file, contents, /public enum SecureKeypadNativeSubmissionRouter/, "iOS native handoff must be explicitly routed");
  }
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /MAX_LAYOUT_ROWS\s*=\s*16/, "Android native layout must bound row count");
    requireText(findings, file, contents, /MAX_LAYOUT_KEYS_PER_ROW\s*=\s*32/, "Android native layout must bound keys per row");
    requireText(findings, file, contents, /MAX_LAYOUT_KEYS\s*=\s*512/, "Android native layout must bound aggregate key count");
    requireText(findings, file, contents, /MAX_KEY_LABEL_BYTES\s*=\s*16/, "Android native layout must bound key labels");
    requireText(findings, file, contents, /MAX_ACCESSIBILITY_LABEL_LENGTH\s*=\s*80/, "Android native layout must bound accessibility labels");
    requireText(findings, file, contents, /layout\.rows\.size\s+in\s+1\.\.MAX_LAYOUT_ROWS/, "Android native layout must reject oversized row lists");
    requireText(findings, file, contents, /row\.size\s+in\s+1\.\.MAX_LAYOUT_KEYS_PER_ROW/, "Android native layout must reject oversized rows");
    requireText(findings, file, contents, /totalKeys\s*<=\s*MAX_LAYOUT_KEYS/, "Android native layout must reject oversized aggregate layouts");
    requireText(findings, file, contents, /key\.label\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*MAX_KEY_LABEL_BYTES/, "Android native layout must bound key label bytes");
    requireText(findings, file, contents, /key\.accessibilityLabel\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*MAX_ACCESSIBILITY_LABEL_LENGTH/, "Android native layout must bound accessibility bytes");
    requireText(findings, file, contents, /validateTheme\(theme\)/, "Android native renderer must validate public theme values");
    requireText(findings, file, contents, /theme\.keyHeightPx\s+in\s+32\.\.160/, "Android native theme must bound key height");
    requireText(findings, file, contents, /theme\.keyRadiusPx\.isFinite\(\)/, "Android native theme must reject non-finite radius values");
    requireText(findings, file, contents, /theme\.keyFontSizePx\.isFinite\(\)/, "Android native theme must reject non-finite font sizes");
    requireText(findings, file, contents, /CANCEL/, "Android native keypad must implement the explicit cancel action");
    requireText(findings, file, contents, /sessionCancel/, "Android native keypad must call the C ABI cancellation path");
    requireText(findings, file, contents, /takeNativeHandle\(\)/, "Android native submission must have an opaque transfer API");
    requireText(findings, file, contents, /object SecureKeypadNativeSubmissionRouter/, "Android native handoff must be explicitly routed");
    requireText(findings, file, contents, /findActivity\(\)/, "Android secure-window protection must resolve wrapped host contexts");
    requireText(findings, file, contents, /FLAG_SECURE/, "Android native keypad must enable secure-window protection");
    requireText(findings, file, contents, /onWindowFocusChanged\(hasWindowFocus: Boolean\)/, "Android native keypad must zeroize when its window loses focus");
    requireText(findings, file, contents, /onWindowFocusChanged\(hasWindowFocus: Boolean\)[\s\S]{0,300}if \(hasWindowFocus\)\s*\{\s*requireSecureWindow\(\)/, "Android native keypad must reassert secure-window protection when focus returns");
    requireText(findings, file, contents, /onWindowVisibilityChanged\(visibility: Int\)/, "Android native keypad must zeroize when its window becomes invisible");
    requireText(findings, file, contents, /isAbiCompatible/, "Android native keypad must fail closed on an FFI ABI mismatch before session creation");
    requireText(findings, file, contents, /IMPORTANT_FOR_AUTOFILL_NO/, "Android native keypad must opt out of autofill");
    requireText(findings, file, contents, /configureAscii/, "Android native keypad must expose the bounded printable-ASCII policy");
    forbidText(findings, file, contents, /\bEditText\b/, "Android native keypad must not use an editable text widget");
  }
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SECURE_KEYPAD_MAX_RENDERED_LENGTH/, "Android presentation must bound rendered masked length");
    requireText(findings, file, contents, /secureKeypadMaskedDisplayText/, "Android presentation must render masked text through one bounded helper");
    requireText(findings, file, contents, /secureKeypadAccessibilityLabel/, "Android accessibility must expose only masked state and length");
    requireText(findings, file, contents, /secureKeypadIsValidDisplayState/, "Android presentation must validate native display-state codes");
    forbidText(findings, file, contents, /password|secret|plaintext|inputValue|inputText/i, "Android presentation contract must not mention secret-bearing fields");
  }
  for (const file of [
    "native/ios/SecureKeypadView.swift",
    "packages/react-native/ios/SecureKeypadView.swift",
    "packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /1\.\.\.16\)\.contains\(layout\.rows\.count\)/, "iOS native layout must bound row count");
    requireText(findings, file, contents, /1\.\.\.32\)\.contains\(row\.count\)/, "iOS native layout must bound keys per row");
    requireText(findings, file, contents, /totalKeys\s*<=\s*512/, "iOS native layout must bound aggregate key count");
    requireText(findings, file, contents, /key\.label\.utf8\.count\s*<=\s*16/, "iOS native layout must bound key label bytes");
    requireText(findings, file, contents, /key\.accessibilityLabel\.utf8\.count\s*<=\s*80/, "iOS native layout must bound accessibility labels");
    requireText(findings, file, contents, /try validate\(theme: theme\)/, "iOS native renderer must validate public theme values");
    requireText(findings, file, contents, /theme\.keyHeight\.isFinite/, "iOS native theme must reject non-finite key heights");
    requireText(findings, file, contents, /theme\.keyFontSize\.isFinite/, "iOS native theme must reject non-finite font sizes");
    requireText(findings, file, contents, /UIApplication\.willResignActiveNotification/, "iOS native keypad must mask while inactive");
    requireText(findings, file, contents, /willResignActiveNotification[\s\S]{0,240}handleWillResignActive\(\)/, "iOS native keypad must handle application resign-active transitions");
    requireText(findings, file, contents, /private func handleWillResignActive\(\)[\s\S]{0,180}releaseSession\(\)/, "iOS native keypad must zeroize when the application resigns active state");
    requireText(findings, file, contents, /UIScreen\.capturedDidChangeNotification/, "iOS native keypad must react to screen capture");
    requireText(findings, file, contents, /refreshProtectionState\(\)/, "iOS native keypad must recompute protection across lifecycle transitions");
    requireText(findings, file, contents, /didMoveToWindow\(\)/, "iOS native keypad must recompute protection when attached to a captured window");
    requireText(findings, file, contents, /if window == nil \{\s*releaseSession\(\)\s*\}/, "iOS native keypad must release pending input when detached from a window");
    requireText(findings, file, contents, /secureKeypadShouldProtectPresentation\(/, "iOS native keypad must preserve protection while capture remains active");
    requireText(findings, file, contents, /protectedPresentation/, "iOS native keypad must have a protected presentation state");
    requireText(findings, file, contents, /secureKeypadIsValidRenderedLength/, "iOS native keypad must bound masked rendering before allocation");
    requireText(findings, file, contents, /secureKeypadIsValidDisplayState/, "iOS native keypad must reject invalid display-state codes");
    requireText(findings, file, contents, /secureKeypadMaskedDisplayText/, "iOS native keypad must render masked text through one bounded helper");
    requireText(findings, file, contents, /secureKeypadAccessibilityLabel/, "iOS accessibility must expose only masked state and length");
    requireText(findings, file, contents, /secure_keypad_abi_version\(\)/, "iOS native keypad must fail closed on an FFI ABI mismatch before session creation");
    requireText(findings, file, contents, /configureAscii/, "iOS native keypad must expose the bounded printable-ASCII policy");
    forbidText(findings, file, contents, /\bUITextField\b/, "iOS native keypad must not use an editable text widget");
  }
  for (const file of [
    "native/ios/SecureKeypadBridgeConfig.swift",
    "packages/react-native/ios/SecureKeypadBridgeConfig.swift",
    "packages/flutter/ios/Classes/SecureKeypadBridgeConfig.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /label\.utf8\.count\s*<=\s*16/, "iOS bridge configuration must bound key label bytes");
    requireText(findings, file, contents, /accessibilityLabel\.utf8\.count\s*<=\s*80/, "iOS bridge configuration must bound accessibility label bytes");
    requireText(findings, file, contents, /exactKeys\(colors, \[\"background\", \"keyBackground\", \"keyForeground\", \"keyPressedBackground\", \"keyDisabledBackground\", \"error\"\]\)/, "iOS bridge configuration must require every theme color key");
    requireText(findings, file, contents, /exactKeys\(metrics, \[\"keyHeight\", \"keyGap\", \"keyRadius\", \"contentPadding\"\]\)/, "iOS bridge configuration must require every theme metric key");
    requireText(findings, file, contents, /private static func exactKeys/, "iOS bridge configuration must distinguish exact required maps from optional maps");
    requireText(findings, file, contents, /color\(colors\[\"keyDisabledBackground\"\]\) != nil/, "iOS bridge configuration must validate every theme color value");
  }
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /label\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*16/, "Android bridge configuration must bound key label bytes");
    requireText(findings, file, contents, /accessibilityLabel\.toByteArray\(Charsets\.UTF_8\)\.size\s*<=\s*80/, "Android bridge configuration must bound accessibility label bytes");
    requireText(findings, file, contents, /requireExactKeys\(colors, \"background\", \"keyBackground\", \"keyForeground\", \"keyPressedBackground\", \"keyDisabledBackground\", \"error\"\)/, "Android bridge configuration must require every theme color key");
    requireText(findings, file, contents, /requireExactKeys\(metrics, \"keyHeight\", \"keyGap\", \"keyRadius\", \"contentPadding\"\)/, "Android bridge configuration must require every theme metric key");
    requireText(findings, file, contents, /private fun requireExactKeys/, "Android bridge configuration must distinguish exact required maps from optional maps");
    requireText(findings, file, contents, /color\(colors, \"keyDisabledBackground\"\)/, "Android bridge configuration must validate every theme color value");
    requireText(findings, file, contents, /hex\.all\s*\{\s*it in '0'\.\.'9'\s*\|\|\s*it in 'a'\.\.'f'\s*\|\|\s*it in 'A'\.\.'F'/, "Android bridge configuration must reject signed or non-hex color text");
  }

  const ffiHeader = source("crates/secure-ffi/include/secure_keypad.h", findings);
  const ffiImplementation = source("crates/secure-ffi/src/lib.rs", findings);
  for (const mismatch of findNativeAbiVersionMismatches()) {
    findings.push({
      rule: "native-abi-version-parity",
      file: mismatch.file,
      detail: mismatch.detail,
    });
  }
  requireText(findings, "crates/secure-ffi/src/lib.rs", ffiImplementation, /secure_keypad_abi_version/, "FFI must report the linked library ABI version");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_abi_version/, "C ABI header must expose the linked library ABI query");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_session_new_ascii/, "C ABI must expose the bounded printable-ASCII policy");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_submission_free/, "C ABI must expose submission ownership release");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_session_cancel/, "C ABI must expose explicit cancellation and zeroization");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_client_login_start/, "C ABI must expose native-only auth handoff");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /SECURE_KEYPAD_ABI_VERSION UINT32_C\(2\)/, "C ABI must version the native registration handoff");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_client_registration_start/, "C ABI must expose native-only registration handoff");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_client_registration_finish/, "C ABI must expose native-only registration completion");
  forbidText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /\bsecure_keypad_[a-z0-9_]*(?:password|secret|get_value|value_bytes)[a-z0-9_]*\s*\(/i, "C ABI must not define a secret getter");

  const iosNativeView = source("native/ios/SecureKeypadView.swift", findings);
  requireText(findings, "native/ios/SecureKeypadView.swift", iosNativeView, /isConsumed/, "iOS submission routing must verify that the opaque handle was actually transferred");
  const androidNativeView = source("native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", findings);
  requireText(findings, "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", androidNativeView, /isConsumed/, "Android submission routing must verify that the opaque handle was actually transferred");
  requireText(findings, "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", androidNativeView, /isAbiCompatible/, "Android native keypad must fail closed on an FFI ABI mismatch before session creation");
  const androidOwnership = source("native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt", findings);
  requireText(findings, "native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt", androidOwnership, /if \(!isConsumed\(value\)\) release\(value\)/, "Android callback failure handling must not release an already-transferred opaque handle");

  for (const file of [
    "native/android/src/main/cpp/secure_keypad_jni.c",
    "packages/react-native/android/src/main/cpp/secure_keypad_jni.c",
    "packages/flutter/android/src/main/cpp/secure_keypad_jni.c",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /nativeAbiVersion/, "Android JNI must expose the linked FFI ABI version before session creation");
    requireText(findings, file, contents, /secure_keypad_abi_version\(\)/, "Android JNI ABI query must call the native FFI implementation");
  }

  for (const file of [
    "native/ios/react-native/SecureKeypadViewManager.m",
    "packages/react-native/ios/SecureKeypadViewManager.m",
  ]) {
    const manager = source(file, findings);
    requireText(findings, file, manager, /@interface RCT_EXTERN_MODULE\(SecureKeypadViewManager, RCTViewManager\)/, "React Native Objective-C export must use the current RCT_EXTERN_MODULE interface form");
    requireText(findings, file, manager, /@end\s*$/, "React Native Objective-C export must close its extern interface");
    requireText(findings, file, manager, /mode/, "React Native Objective-C export must expose renderer mode");
    requireText(findings, file, manager, /acknowledgeLowerAssurance/, "React Native Objective-C export must expose lower-assurance acknowledgement");
    requireText(findings, file, manager, /headlessKeyPress/, "React Native Objective-C export must expose the public headless command");
  }

  for (const file of [
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
  ]) {
    const podspec = source(file, findings);
    requireText(findings, file, podspec, /File\.join\(__dir__, ['"]secure_ffi\.xcframework['"]\)/, "iOS podspec must validate the staged FFI XCFramework path");
    requireText(findings, file, podspec, /spec\.vendored_frameworks\s*=\s*['"]secure_ffi\.xcframework['"]/, "iOS podspec must pass a relative staged FFI XCFramework path to CocoaPods");
    forbidText(findings, file, podspec, /spec\.vendored_frameworks\s*=\s*ffi_xcframework/, "iOS podspec must not pass an absolute FFI XCFramework path to CocoaPods");
  }

  const core = source("crates/secure-core/src/lib.rs", findings);
  const coreBuffer = source("crates/secure-core/src/secret_buffer.rs", findings);
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /SecretTokenBuffer/, "core must keep secret token storage behind a dedicated buffer type");
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /tokens\[self\.len\]\.zeroize\(\)/, "core must zeroize tokens removed by backspace");
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /Box<\[u32\]>/, "core token storage must avoid secret-bearing Vec reallocation");
  const coreInput = source("crates/secure-core/src/input.rs", findings);
  requireText(findings, "crates/secure-core/src/input.rs", coreInput, /MAX_INPUT_TOKENS/, "core input policy must retain a bounded token limit");
  requireText(findings, "crates/secure-core/src/input.rs", coreInput, /Self::Ascii/, "core input policy must retain the explicit printable-ASCII policy");
  requireText(findings, "crates/secure-core/src/input.rs", coreInput, /SecretBuffer::with_capacity/, "core rendered secret output must be preallocated");
  const coreHangul = source("crates/secure-core/src/hangul.rs", findings);
  requireText(findings, "crates/secure-core/src/hangul.rs", coreHangul, /bytes\.zeroize\(\)/, "core UTF-8 conversion must clear its temporary secret bytes");
  const coreFuzz = source("fuzz/fuzz_targets/core_sequence.rs", findings);
  requireText(findings, "fuzz/fuzz_targets/core_sequence.rs", coreFuzz, /ASCII_KEYS/, "core fuzzing must exercise printable-ASCII keys");
  const ffiFuzz = source("fuzz/fuzz_targets/ffi_sequence.rs", findings);
  requireText(findings, "fuzz/fuzz_targets/ffi_sequence.rs", ffiFuzz, /secure_keypad_session_new_ascii/, "FFI fuzzing must exercise the printable-ASCII constructor");

  const auth = source("crates/secure-auth/src/lib.rs", findings);
  requireText(findings, "crates/secure-core/src/lib.rs", core, /pub fn with_native_bytes\(&self, operation: impl FnOnce\(&\[u8\]\)\)/, "native submission handoff must not return secret bytes");
  forbidText(findings, "crates/secure-core/src/lib.rs", core, /with_native_bytes<R>/, "native submission handoff must not expose a generic secret-returning callback");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /pub fn with_bytes\(&self, operation: impl FnOnce\(&\[u8\]\)\)/, "OPAQUE secret-output handoff must not return secret bytes");
  forbidText(findings, "crates/secure-auth/src/lib.rs", auth, /pub fn with_bytes<R>/, "OPAQUE secret-output handoff must not expose a generic secret-returning callback");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /opaque-ke-4\.0\.1-ristretto255-tripledh-sha512-argon2/, "OPAQUE suite must be pinned in the protocol contract");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /MAX_JSON_BODY_BYTES: usize = 128 \* 1024/, "auth JSON body must be bounded");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /MAX_SERVER_SETUP_BYTES/, "server setup persistence must be bounded");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /MAX_CREDENTIAL_FILE_BYTES/, "credential file persistence must be bounded");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /MAX_SERVER_LOGIN_STATE_BYTES/, "serialized login state must be bounded before allocation");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /Copies a bounded, non-empty protocol message/, "transport message construction must be bounded before allocation");
  const authManifest = source("crates/secure-auth/Cargo.toml", findings);
  requireText(findings, "crates/secure-auth/Cargo.toml", authManifest, /opaque-ke\s*=\s*\{\s*version\s*=\s*"=4\.0\.1"/, "OPAQUE dependency must be exact-pinned");
  forbidText(findings, "crates/secure-auth/Cargo.toml", authManifest, /opaque-ke\s*=\s*\{\s*version\s*=\s*"4\.0\.1"/, "OPAQUE dependency must not allow semver patch drift");

  const web = source("packages/web/src/index.ts", findings);
  requireText(findings, "packages/web/src/index.ts", web, /WEB_FALLBACK_WARNING_CODE/, "Web fallback warning must be stable");
  requireText(findings, "packages/web/src/index.ts", web, /fallback-not-acknowledged/, "Web fallback must fail closed without acknowledgement");
  requireText(findings, "packages/web/src/index.ts", web, /createPasskey/, "Web adapter must expose passkey-first registration");
  requireText(findings, "packages/web/src/index.ts", web, /MAX_WEBAUTHN_EXTENSION_NODES/, "WebAuthn extension JSON must be bounded");
  requireText(findings, "packages/web/src/index.ts", web, /copyBoundedExtensionValue/, "WebAuthn extension JSON must be defensively copied");
  requireText(findings, "packages/web/src/index.ts", web, /toNativeAuthenticatorSelection/, "WebAuthn authenticator selection must be allowlisted before browser handoff");
  requireText(findings, "packages/web/src/index.ts", web, /__proto__|constructor|prototype/, "WebAuthn extension copying must reject prototype-pollution keys");
  requireText(findings, "packages/web/src/index.ts", web, /encodedCredentialBinary/, "WebAuthn browser credential output must be bounded before serialization");
  requireText(findings, "packages/web/src/index.ts", web, /typeof container\.create === "function"[\s\S]{0,100}typeof container\.get === "function"/, "WebAuthn default environment must verify both browser credential methods");
  forbidText(findings, "packages/web/src/index.ts", web, /\b(?:password|pin)\s*[:(]/i, "Web adapter must not expose a password/PIN API");
  const contracts = source("packages/contracts/src/index.ts", findings);
  requireText(findings, "packages/contracts/src/index.ts", contracts, /"ascii"/, "public contracts must enumerate the native printable-ASCII policy");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /"cancel"/, "public layout contract must expose an explicit cancel role");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /is duplicated/, "public layout contract must reject duplicate key IDs before native serialization");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /MAX_RENDERED_LENGTH/, "public contracts must bound masked state metadata");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /MAX_KEY_LABEL_BYTES\s*=\s*16/, "public contracts must bound key labels by UTF-8 bytes");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /MAX_ACCESSIBILITY_LABEL_BYTES\s*=\s*80/, "public contracts must bound accessibility labels by UTF-8 bytes");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /function utf8ByteLength/, "public contracts must use an environment-independent UTF-8 byte counter");
  requireText(findings, "packages/contracts/src/index.ts", contracts, /validateMaskedState/, "public contracts must validate masked state metadata");
  const layoutSchema = source("schema/layout.schema.json", findings);
  requireText(findings, "schema/layout.schema.json", layoutSchema, /"role"\s*:\s*\{\s*"enum"\s*:\s*\[[^\]]*"cancel"/, "JSON layout schema must expose the explicit cancel role");
  requireText(findings, "schema/layout.schema.json", layoutSchema, /"additionalProperties"\s*:\s*false/, "JSON layout schema must reject unsupported configuration fields");
  const reactNativeContract = source("packages/react-native/src/index.ts", findings);
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /validateMaskedStateEvent/, "React Native must expose masked event validation at the bridge boundary");
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /createSecureKeypadEventHandlers/, "React Native must install fail-closed event handlers");
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /hasExactKeys/, "React Native bridge event wrappers must reject unexpected outer fields");
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /getSecureKeypadNativeProps/, "React Native must allowlist props before native serialization");
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /nativeProps = getSecureKeypadNativeProps\(props\);[\s\S]{0,500}return null/, "React Native must fail closed before creating a native view for invalid props");
  requireText(findings, "packages/react-native/src/index.ts", reactNativeContract, /getSecureKeypadNativeView/, "React Native low-level native view access must be explicitly named");
  const reactNativePackage = source("packages/react-native/package.json", findings);
  requireText(findings, "packages/react-native/package.json", reactNativePackage, /"app\.plugin"\s*:\s*"\.\/app\.plugin\.js"/, "React Native must expose its Expo config plugin");
  const expoPlugin = source("packages/react-native/app.plugin.js", findings);
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /withDangerousMod/, "Expo integration must stage native artifacts during prebuild");
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /SECURE_KEYPAD_FFI_XCFRAMEWORK/, "Expo iOS builds must require an explicit FFI XCFramework");
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /SECURE_KEYPAD_FFI_LIB_DIR/, "Expo Android builds must require an explicit FFI library directory");
  const reactNativeGuide = source("packages/react-native/README.md", findings);
  requireText(findings, "packages/react-native/README.md", reactNativeGuide, /Expo Development Build/, "React Native must document Expo Development Build support");
  requireText(findings, "packages/react-native/README.md", reactNativeGuide, /Expo Go/, "React Native must document the Expo Go limitation");
  const flutterContract = source("packages/flutter/lib/secure_keypad.dart", findings);
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /enum KeyRole \{[^}]*cancel/, "Flutter contract must expose an explicit cancel role");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /secureKeypadMaxRenderedLength/, "Flutter must bound masked event metadata");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /isSecureKeypadNativeEventShapeValid/, "Flutter must reject unexpected native event fields");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /_onNativeEvent\([\s\S]{0,500}isSecureKeypadRenderedLengthValid/, "Flutter must validate masked event length before invoking callbacks");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /bool _hasExactKeys\(/, "Flutter configuration maps must use an exact-key allowlist");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /_colorPattern/, "Flutter theme colors must be format-validated before bridge serialization");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /_isBoundedNumber\(/, "Flutter theme metrics must be range-validated before bridge serialization");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /_isBoundedInteger\(/, "Flutter integer policy and animation bounds must reject invalid values");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /toPlatformCreationParams\(\)\s*\{[\s\S]{0,180}validate\(\)/, "Flutter bridge serialization must fail closed for invalid configuration");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /secureKeypadMaxHeadlessKeyPressToken/, "Flutter headless command tokens must be bounded");
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutterContract, /mode == SecureKeypadMode\.headlessHost/, "Flutter must bind headless command access to the acknowledged mode");
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SecureKeyRole\.CANCEL/, "Android bridge parser must accept the explicit cancel role");
    requireText(findings, file, contents, /private fun integer\(/, "Android bridge parser must reject fractional numeric configuration values");
    requireText(findings, file, contents, /private fun optionalMap\(/, "Android bridge parser must reject unknown nested configuration fields");
  }
  for (const file of [
    "native/ios/SecureKeypadBridgeConfig.swift",
    "packages/react-native/ios/SecureKeypadBridgeConfig.swift",
    "packages/flutter/ios/Classes/SecureKeypadBridgeConfig.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /isBooleanNumber/, "iOS bridge parser must not coerce Boolean bridge values into integer configuration");
  }
  for (const file of [
    "native/ios/SecureKeypadBridgeConfig.swift",
    "packages/react-native/ios/SecureKeypadBridgeConfig.swift",
    "packages/flutter/ios/Classes/SecureKeypadBridgeConfig.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /private static func boundedInteger\(/, "iOS bridge parser must reject fractional numeric configuration values");
    requireText(findings, file, contents, /private static func optionalMap\(/, "iOS bridge parser must reject unknown nested configuration fields");
  }

  const opaqueHttp = source("crates/secure-auth-http/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /pub struct HttpDeploymentContext/, "OPAQUE HTTP routes must require an explicit deployment context");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /TrustedProxyTls/, "OPAQUE HTTP routes must define trusted-proxy TLS handling");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /connection_limits_enforced/, "OPAQUE HTTP routes must require connection/read limits");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /RESPONSE_SECURITY_HEADERS/, "OPAQUE HTTP responses must carry cache and MIME security headers");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /fn registration_finish[\s\S]{0,500}valid_identifier\(request\.identifier\.as_bytes\(\)\)/, "OPAQUE registration finish must bound the persistence identifier before protocol processing");

  const axum = source("crates/secure-auth-axum/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /let \(parts, body\) = request\.into_parts\(\);[\s\S]{0,1400}to_bytes\(body, body_limit\)/, "Axum adapter must bound streaming request bodies before route parsing");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /state\.router\.handle\(/, "Axum adapter must delegate to the framework-neutral route contract");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /RESPONSE_SECURITY_HEADERS/, "Axum adapter must preserve static response security headers");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /Fn\(&Parts\) -> Option<Uuid>/, "WebAuthn Axum principal resolver must receive request parts without the body");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /to_bytes\(body, body_limit\)/, "WebAuthn Axum adapter must bound streaming request bodies before principal resolution");
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /WebAuthnHttpRouter(?:::<[^>]+>)?::new/, "WebAuthn Axum adapter must delegate to the framework-neutral route contract");
  forbidText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /X-Forwarded-Proto|x-forwarded-proto/i, "Axum adapter must not parse forwarded transport headers");

  const webauthnHttp = source("crates/secure-webauthn-example/src/lib.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /pub struct WebAuthnDeploymentContext/, "WebAuthn HTTP routes must require an explicit deployment context");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WebAuthnTransportSecurity::TrustedProxyTls/, "WebAuthn HTTP routes must define trusted-proxy TLS handling");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /connection_limits_enforced/, "WebAuthn HTTP routes must require connection/read limits");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WEBAUTHN_RESPONSE_SECURITY_HEADERS/, "WebAuthn responses must carry cache and MIME security headers");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /new_with_stores/, "WebAuthn service must wire storage contracts into the service boundary");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /MAX_CEREMONY_TTL:\s*Duration\s*=\s*Duration::from_secs\(15 \* 60\)/, "WebAuthn ceremony retention must have a fixed 15-minute maximum");
  const webauthnStorage = source("crates/secure-webauthn-example/src/storage.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub trait CeremonyStateStore/, "WebAuthn service must expose an injectable ceremony state backend contract");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub trait CredentialStore/, "WebAuthn service must expose an injectable credential backend contract");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /atomically delete and return|atomically consume/, "WebAuthn ceremony backend must document atomic consume semantics");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub struct WebAuthnStateKey/, "WebAuthn durable ceremony state must have an explicit host-managed key type");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /Aes256Gcm/, "WebAuthn durable ceremony state must use authenticated AES-256-GCM protection");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /MAX_PROTECTED_CEREMONY_RECORD_BYTES/, "WebAuthn encrypted ceremony records must have an explicit storage bound");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub\(crate\) fn validate_ceremony_ttl[\s\S]{0,240}ttl > MAX_CEREMONY_TTL/, "WebAuthn ceremony stores must enforce the replay-retention maximum");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub\(crate\) fn validate_backend_ttl[\s\S]{0,180}validate_ceremony_ttl\(ttl\)/, "database TTL adapters must share the WebAuthn ceremony retention validator");
  const webauthnRedis = source("crates/secure-webauthn-example/src/storage_redis.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /pub fn from_url\([\s\S]{0,240}encryption_key: WebAuthnStateKey/, "Redis WebAuthn production construction must require a host-managed encryption key");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /validate_backend_ttl\(ttl\)/, "Redis WebAuthn storage must validate ceremony TTLs before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /protector\.seal\(encoded\.as_slice\(\)\)/, "Redis WebAuthn storage must encrypt ceremony records before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /protector\.open\(encoded\)/, "Redis WebAuthn storage must authenticate ceremony records after retrieval");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /const BOUNDED_CREDENTIAL_GET_SCRIPT: &str/, "Redis credential reads must use a dedicated bounded retrieval script");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /BOUNDED_CREDENTIAL_GET_SCRIPT[\s\S]{0,240}STRLEN[\s\S]{0,240}'GET'/, "Redis credential reads must check STRLEN before GET");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /fn get_bounded_credentials[\s\S]{0,600}MAX_CREDENTIAL_RECORD_BYTES/, "Redis credential reads must enforce the application byte bound before decoding");
  const webauthnPostgres = source("crates/secure-webauthn-example/src/storage_postgres.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /pub fn from_config\([\s\S]{0,260}encryption_key: WebAuthnStateKey/, "PostgreSQL WebAuthn production construction must require a host-managed encryption key");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /validate_backend_ttl\(ttl\)/, "PostgreSQL WebAuthn storage must validate ceremony TTLs before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /protector\.seal\(encoded\.as_slice\(\)\)/, "PostgreSQL WebAuthn storage must encrypt ceremony records before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /protector\.open\(protected\)/, "PostgreSQL WebAuthn storage must authenticate ceremony records after retrieval");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /POSTGRES_CREDENTIAL_LOAD_SQL[\s\S]{0,400}LIMIT \$3/, "PostgreSQL credential loads must bound database rows before materialization");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /POSTGRES_CREDENTIAL_LOAD_SQL[\s\S]{0,400}octet_length\(passkey::text\) <= \$4/, "PostgreSQL credential loads must bound JSONB bytes before materialization");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL[\s\S]{0,500}FOR UPDATE/, "PostgreSQL credential updates must retain row locking while bounding materialization");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL[\s\S]{0,500}octet_length\(passkey::text\) <= \$4/, "PostgreSQL credential updates must bound JSONB bytes before materialization");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WEBAUTHN_CEREMONY_STATE_VERSION: u16 = 1/, "WebAuthn ceremony state format must be version-pinned");
  const webauthnManifest = source("crates/secure-webauthn-example/Cargo.toml", findings);
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /aes-gcm = "=0\.10\.3"/, "WebAuthn durable ceremony protection must pin AES-GCM");
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /danger-allow-state-serialisation/, "WebAuthn state serialization must be an explicit pinned server dependency feature");
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /redis-backend/, "Redis storage must be explicitly feature-gated");
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /postgres-backend/, "PostgreSQL storage must be explicitly feature-gated");
  const authServerManifest = source("crates/secure-auth-server/Cargo.toml", findings);
  requireText(findings, "crates/secure-auth-server/Cargo.toml", authServerManifest, /redis-backend/, "Redis rate limiting must be explicitly feature-gated");
  requireText(findings, "crates/secure-auth-server/Cargo.toml", authServerManifest, /postgres-backend/, "PostgreSQL rate limiting must be explicitly feature-gated");
  requireText(findings, "crates/secure-auth-server/Cargo.toml", authServerManifest, /aes-gcm = "=0\.10\.3"/, "durable OPAQUE state protection must pin AES-GCM");
  const opaqueStateCodec = source("crates/secure-auth-server/src/opaque_state_codec.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /RECORD_VERSION/, "OPAQUE durable state must use a versioned record format");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES/, "OPAQUE durable state records must be bounded before persistence");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /MAX_DISTRIBUTED_LOGIN_STATE_STORAGE_BYTES/, "OPAQUE durable state storage bounds must include encryption overhead");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /OpaqueStateKey/, "OPAQUE durable state must require an explicit at-rest key");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /Aes256Gcm/, "OPAQUE durable state must use AES-256-GCM");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /PROTECTED_AAD/, "OPAQUE durable state must authenticate a versioned associated-data contract");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /encrypt_in_place/, "OPAQUE durable state must encrypt before persistence");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_codec.rs", opaqueStateCodec, /decrypt_in_place/, "OPAQUE durable state must authenticate before decoding");
  const opaqueStateRedis = source("crates/secure-auth-server/src/opaque_state_redis.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /INSERT_SCRIPT/, "Redis OPAQUE state insertion must use one atomic script");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /CONSUME_SCRIPT/, "Redis OPAQUE state consumption must use one atomic script");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /Sha256/, "Redis OPAQUE state handles must be hashed before storage");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /protector\.seal/, "Redis OPAQUE state must encrypt before storage");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /protector\.open/, "Redis OPAQUE state must authenticate before decoding");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /rediss:\/\//, "Redis OPAQUE state must require TLS by default");
  const opaqueStatePostgres = source("crates/secure-auth-server/src/opaque_state_postgres.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /POSTGRES_ONE_TIME_LOGIN_STATE_SCHEMA_SQL/, "PostgreSQL OPAQUE state must ship an explicit migration");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /pg_advisory_xact_lock/, "PostgreSQL OPAQUE state capacity must be serialized");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /DELETE FROM secure_keypad_opaque_login_states[\s\S]{0,240}RETURNING state/, "PostgreSQL OPAQUE state consumption must be atomic");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /MakeTlsConnect/, "PostgreSQL OPAQUE state must accept an explicit TLS connector");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /SslMode::Require/, "PostgreSQL OPAQUE state must reject configurations that can downgrade TLS");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /TypeId::of::<T>\(\) == TypeId::of::<NoTls>\(\)/, "PostgreSQL OPAQUE state must reject the NoTls connector even when sslmode requires TLS");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /CHECK \(octet_length\(state\) BETWEEN 1 AND 32802\)/, "PostgreSQL OPAQUE state schema must enforce bounded encrypted records");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /protector\.seal/, "PostgreSQL OPAQUE state must encrypt before storage");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /protector\.open/, "PostgreSQL OPAQUE state must authenticate before decoding");
  const durableOneTimeStateTest = source("crates/secure-auth-server/tests/durable_one_time_state.rs", findings);
  requireText(findings, "crates/secure-auth-server/tests/durable_one_time_state.rs", durableOneTimeStateTest, /SKPE/, "durable OPAQUE service tests must verify encrypted storage records");
  requireText(findings, "crates/secure-auth-server/tests/durable_one_time_state.rs", durableOneTimeStateTest, /second_store|cross_instance_handle/, "durable OPAQUE service tests must verify same-key cross-instance consumption");
  const redisRateLimit = source("crates/secure-auth-server/src/rate_limit_redis.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /RATE_LIMIT_SCRIPT/, "Redis rate limiting must use one atomic script");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /Sha256/, "Redis rate-limit keys must be hashed before storage");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /rediss:\/\//, "Redis rate limiting must require TLS by default");
  const postgresRateLimit = source("crates/secure-auth-server/src/rate_limit_postgres.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /POSTGRES_RATE_LIMIT_SCHEMA_SQL/, "PostgreSQL rate limiting must ship an explicit migration");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /pg_advisory_xact_lock/, "PostgreSQL rate limiting must serialize capacity/check updates");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /MakeTlsConnect/, "PostgreSQL rate limiting must accept an explicit TLS connector");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /secure_keypad_rate_limit_key_hash_length/, "PostgreSQL rate limiting must persist the key-hash bound during upgrades");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /secure_keypad_rate_limit_attempts_range/, "PostgreSQL rate limiting must persist the attempt-count bound during upgrades");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /SslMode::Require/, "PostgreSQL rate limiting must reject configurations that can downgrade TLS");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /TypeId::of::<T>\(\) == TypeId::of::<NoTls>\(\)/, "PostgreSQL rate limiting must reject the NoTls connector even when sslmode requires TLS");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /CHECK \(octet_length\(namespace\) BETWEEN 1 AND 64\)/, "PostgreSQL rate-limit schema must enforce bounded namespaces");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /CHECK \(namespace ~ '\^\[A-Za-z0-9._-\]\+\$'\)/, "PostgreSQL rate-limit schema must enforce safe namespaces");
  const postgresStorage = source("crates/secure-webauthn-example/src/storage_postgres.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", postgresStorage, /MakeTlsConnect/, "PostgreSQL WebAuthn storage must accept an explicit TLS connector");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", postgresStorage, /SslMode::Require/, "PostgreSQL WebAuthn storage must reject configurations that can downgrade TLS");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", postgresStorage, /TypeId::of::<T>\(\) == TypeId::of::<NoTls>\(\)/, "PostgreSQL WebAuthn storage must reject the NoTls connector even when sslmode requires TLS");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", postgresStorage, /CHECK \(octet_length\(namespace\) BETWEEN 1 AND 64\)/, "PostgreSQL WebAuthn schema must enforce bounded namespaces");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", postgresStorage, /CHECK \(namespace ~ '\^\[A-Za-z0-9._-\]\+\$'\)/, "PostgreSQL WebAuthn schema must enforce safe namespaces");
  for (const constraint of [
    "secure_keypad_webauthn_ceremony_handle_length",
    "secure_keypad_webauthn_ceremony_kind",
    "secure_keypad_webauthn_ceremony_state_length",
    "secure_keypad_webauthn_credential_id_length",
    "secure_keypad_webauthn_credential_passkey_length",
    "secure_keypad_webauthn_credential_revision_nonnegative",
  ]) {
    requireText(
      findings,
      "crates/secure-webauthn-example/src/storage_postgres.rs",
      postgresStorage,
      new RegExp(constraint),
      `PostgreSQL WebAuthn schema must persist ${constraint} during upgrades`,
    );
  }
  const webauthnStorageGuide = source("docs/WEBAUTHN-STORAGE.md", findings);
  requireText(findings, "docs/WEBAUTHN-STORAGE.md", webauthnStorageGuide, /danger-allow-state-serialisation/, "WebAuthn storage guide must prohibit client-side ceremony state serialization");
  requireText(findings, "docs/WEBAUTHN-STORAGE.md", webauthnStorageGuide, /blocking adapters/, "WebAuthn storage guide must declare blocking adapter execution requirements");
  requireText(findings, "docs/WEBAUTHN-STORAGE.md", webauthnStorageGuide, /idempotently[\s\S]{0,100}existing ceremony and credential tables/, "WebAuthn storage guide must document durable schema upgrades");
  const distributedBackendGuide = source("docs/DISTRIBUTED-BACKENDS.md", findings);
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedBackendGuide, /RedisOneTimeLoginStateStore/, "distributed backend guide must document the durable OPAQUE one-time adapter");
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedBackendGuide, /AES-256-GCM/, "distributed backend guide must document authenticated at-rest encryption");
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedBackendGuide, /OpaqueStateKey/, "distributed backend guide must document host-managed state keys");
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedBackendGuide, /idempotently[\s\S]{0,100}existing table/, "distributed backend guide must document durable rate-limit schema upgrades");
  const nativePlatformsGuide = source("docs/NATIVE-PLATFORMS.md", findings);
  requireText(findings, "docs/NATIVE-PLATFORMS.md", nativePlatformsGuide, /SecureKeypadPresentation\.kt/, "native platform guide must compile the Android presentation contract source");
  requireText(findings, "docs/NATIVE-PLATFORMS.md", nativePlatformsGuide, /16 rows, 32 keys per row, 512 total keys/, "native platform guide must document native layout bounds");
  requireText(findings, "docs/NATIVE-PLATFORMS.md", nativePlatformsGuide, /finite and bounded theme dimensions/, "native platform guide must document native theme bounds");

  for (const file of [
    "packages/react-native/SecureKeypadReactNative.podspec",
    "packages/flutter/ios/secure_keypad_flutter.podspec",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_XCFRAMEWORK/, "iOS package must prefer an explicit FFI XCFramework");
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_LIB/, "iOS package must support a single-platform FFI fallback");
    requireText(findings, file, contents, /raise ['"]SECURE_KEYPAD_FFI_XCFRAMEWORK/, "iOS package must fail closed without FFI artifacts");
  }
  for (const file of [
    "packages/react-native/android/CMakeLists.txt",
    "packages/flutter/android/CMakeLists.txt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_LIB_DIR/, "Android package must require an ABI library directory");
    requireText(findings, file, contents, /message\(FATAL_ERROR/, "Android package must fail closed without the FFI library");
  }

  const androidSubmissionOwnership = source(
    "native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt",
    findings,
  );
  requireText(
    findings,
    "native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt",
    androidSubmissionOwnership,
    /catch \(error: Throwable\)[\s\S]*release\(value\)[\s\S]*throw error/,
    "Android submission delivery must release opaque input when a host consumer throws",
  );

  for (const mismatch of findNativePackageParityMismatches(ROOT)) {
    findings.push({ rule: "native-package-parity", file: mismatch.destination, detail: mismatch.reason });
  }

  const securitySpec = source("docs/SECURITY-SPEC.md", findings);
  requireText(findings, "docs/SECURITY-SPEC.md", securitySpec, /cannot guarantee that a password is absent from memory/, "security specification must document memory limitations");
  requireText(findings, "docs/SECURITY-SPEC.md", securitySpec, /Native renderers must revalidate all public layout and theme data/, "security specification must require native configuration revalidation");
  requireText(findings, "schema/layout.schema.json", layoutSchema, /"x-maxUtf8Bytes"\s*:\s*16/, "layout schema must declare the UTF-8 key-label byte bound");
  requireText(findings, "schema/layout.schema.json", layoutSchema, /"x-maxUtf8Bytes"\s*:\s*80/, "layout schema must declare the UTF-8 accessibility-label byte bound");
  const authTransportGuide = source("docs/AUTH-TRANSPORT.md", findings);
  requireText(findings, "docs/AUTH-TRANSPORT.md", authTransportGuide, /reject[\s\S]{0,24}empty or oversized input[\s\S]{0,24}before copying/, "auth transport documentation must describe pre-allocation bounds");
  const platformPolicy = source("docs/PLATFORM-SECURITY-POLICY.md", findings);
  requireText(findings, "docs/PLATFORM-SECURITY-POLICY.md", platformPolicy, /does not claim to provide certificate[\s\S]{0,40}public-key pinning/, "platform policy must assign pinning ownership without an unsupported SDK claim");
  requireText(findings, "docs/PLATFORM-SECURITY-POLICY.md", platformPolicy, /does not claim to detect or defeat rooted\/jailbroken devices/, "platform policy must document compromised-runtime limitations");
  requireText(findings, "docs/PLATFORM-SECURITY-POLICY.md", platformPolicy, /fail closed on a pin[\s\S]{0,20}mismatch/, "platform policy must require fail-closed host pinning when selected");
  const releaseGates = source("docs/RELEASE-GATES.md", findings);
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /independent[\s\S]{0,40}security review/i, "release gates must require independent review");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /release-signature/, "release gates must require a hashed release-signature artifact");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /independent-review-(?:report|public-key|signature)/, "release gates must bind the reviewer report to a detached signature");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /--require-trusted-keys/, "release gates must provide a trusted-key validation mode");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /cargo package --locked --workspace --all-features/, "release gates must package-check all feature-gated crates");
  const thirdPartyNotices = source("docs/THIRD-PARTY-NOTICES.md", findings);
  requireText(findings, "docs/THIRD-PARTY-NOTICES.md", thirdPartyNotices, /playwright.*verification-only/i, "browser verification dependencies must be identified as non-shipped tooling");
  const deviceVerification = source("docs/DEVICE-VERIFICATION.md", findings);
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /check-device-evidence\.mjs/, "device verification must define machine-readable evidence validation");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /--require-physical/, "device verification must define a physical-device release invocation");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /sanitizedLogs: true/, "device evidence must require sanitized logs");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /Physical devices are required/, "device verification must require physical-device coverage");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /FLAG_SECURE/, "device verification must cover Android screenshot protection");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /reassert it when focus/, "device verification must cover Android secure-window reassertion");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /VoiceOver and TalkBack/, "device verification must cover accessibility surfaces");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /screenshotsAndBackgroundSnapshots/, "device verification must require screenshot and background-snapshot evidence");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /crashReportReview/, "device verification must require crash-report review evidence");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /protocolDowngrade/, "device verification must require protocol downgrade evidence");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /replay, expired-state,[\s\S]*rate-limit/i, "device verification must cover server replay and rate-limit behavior");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /secure-keypad-test-sentinel-7f2c4e/, "device verification must define the canonical disposable sentinel");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /byte-level preflight[\s\S]{0,160}secure-keypad-test-sentinel-7f2c4e/, "release gates must document byte-level sanitized-artifact preflight");
  const deviceEvidenceCheck = source("scripts/check-device-evidence.mjs", findings);
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /verifyDeviceEvidenceFiles/, "device evidence tooling must recompute referenced file digests");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /SANITIZED_TEST_SENTINEL/, "device evidence tooling must reject the canonical test sentinel");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /scanEvidenceFileContent/, "device evidence tooling must scan referenced content for secret-bearing text");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /realpathSync/, "device evidence paths must be contained after symlink resolution");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /requirePhysicalDevice/, "device evidence tooling must distinguish physical-device release evidence");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /expectedCommit/, "device evidence tooling must bind records to the expected checkout commit");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /DEVICE_RELEASE_GATES/, "device evidence tooling must bind records to a supported device release gate");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /expectedGate/, "device evidence tooling must bind records to the expected release gate");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /REQUIRED_PHYSICAL_NATIVE_ARTIFACT_KINDS/, "physical device evidence must require categorized review artifacts");
  const ciGateEvidence = source("scripts/emit-ci-gate-evidence.mjs", findings);
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /buildReleaseGateFragment/, "CI gate evidence must bind fragments to the release evidence contract");
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /sanitized CI gate record/, "CI gate evidence must reject raw log payloads");
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /realpathSync/, "CI gate evidence paths must be contained after symlink resolution");
  const webEvidenceEmitter = source("scripts/emit-web-browser-evidence.mjs", findings);
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /chromium.*firefox.*webkit/, "web evidence must require the complete browser matrix");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /verifyDeviceEvidenceFiles|buildReleaseGateFragment/, "web evidence must bind hashed files to the release gate contract");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /secureContext: true/, "web evidence must record secure-context verification");
  const deploymentGuide = source("docs/HTTP-DEPLOYMENT.md", findings);
  requireText(findings, "docs/HTTP-DEPLOYMENT.md", deploymentGuide, /client_max_body_size 128k/, "deployment guide must declare an upstream body limit");
  requireText(findings, "docs/HTTP-DEPLOYMENT.md", deploymentGuide, /request_body/, "deployment guide must include a reverse-proxy body-limit example");
  requireText(findings, "docs/HTTP-DEPLOYMENT.md", deploymentGuide, /X-Forwarded-/, "deployment guide must document forwarded-header trust boundaries");
  const webDeploymentGuide = source("docs/WEB-DEPLOYMENT.md", findings);
  requireText(findings, "docs/WEB-DEPLOYMENT.md", webDeploymentGuide, /unsafe-inline/, "web deployment guide must forbid unsafe inline scripts");
  requireText(findings, "docs/WEB-DEPLOYMENT.md", webDeploymentGuide, /integrity="sha384-/, "web deployment guide must require SRI for unavoidable third-party assets");
  const distributedGuide = source("docs/DISTRIBUTED-BACKENDS.md", findings);
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedGuide, /GETDEL/, "distributed backend guide must require atomic delete-and-return");
  requireText(findings, "docs/DISTRIBUTED-BACKENDS.md", distributedGuide, /RateLimiter::check/, "distributed backend guide must require atomic rate-limit checks");
  const ciWorkflow = source(".github/workflows/ci.yml", findings);
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /dtolnay\/rust-toolchain@032958afbdc797a9164d3bc0b56325c1308924a5/, "CI Rust jobs must use the repository-pinned toolchain revision");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /dtolnay\/rust-toolchain@stable/, "CI must not float on the stable Rust channel");
  for (const line of findMutableCiActionLines(ciWorkflow)) {
    findings.push({
      rule: "ci-action-immutability",
      file: ".github/workflows/ci.yml",
      detail: `every GitHub Action must use a 40-character immutable commit SHA: ${line.trim()}`,
    });
  }
  const releaseWorkflow = source(".github/workflows/release-candidate.yml", findings);
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /ref:\s*\n\s*description:[^\n]*40-character commit SHA[\s\S]{0,180}required:\s*true/, "release workflow must require an immutable commit input");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /RELEASE_REF:\s*\$\{\{\s*inputs\.ref\s*\}\}/, "release workflow must validate the requested immutable commit ref");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /\[\[\s*\"\$RELEASE_REF\"\s*=~\s*\^\[0-9a-f\]\{40\}\$\s*\]\]/, "release workflow must reject mutable or malformed release refs");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /git rev-parse HEAD\)\"\s*=\s*\"\$RELEASE_REF/, "release workflow must prove checkout HEAD equals the requested release commit");
  for (const line of findMutableCiActionLines(releaseWorkflow)) {
    findings.push({
      rule: "ci-action-immutability",
      file: ".github/workflows/release-candidate.yml",
      detail: `every GitHub Action must use a 40-character immutable commit SHA: ${line.trim()}`,
    });
  }
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /runs-on:\s*ubuntu-24\.04/, "release workflow must use the repository-pinned runner image");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /bundle:[\s\S]{0,260}environment:\s*secure-keypad-release/, "release signing must run behind the protected release environment");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /RELEASE_SIGNING_KEY_PEM/, "release workflow must require a protected signing key");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/sign-release\.mjs/, "release workflow must produce the detached signature through the audited signer");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /playwright install --with-deps chromium firefox webkit/, "release candidate must run the browser adapter smoke matrix");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:web-browser all/, "release candidate must execute all browser smoke targets");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:merge-release-evidence/, "release candidate must test evidence fragment merging");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:emit-release-gate-evidence/, "release candidate must test evidence fragment emission");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/release-candidate-metadata\.mjs/, "release candidate must embed immutable candidate metadata in the signed bundle");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /release-candidate-metadata\.json/, "release candidate must retain the candidate metadata record");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /services:/, "release candidate must provide isolated durable backend services");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_storage/, "release candidate must execute WebAuthn durable interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_rate_limit/, "release candidate must execute distributed rate-limit interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_one_time_state/, "release candidate must execute distributed OPAQUE one-time-state interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cargo package --locked --workspace --all-features/, "release candidate must verify all feature-gated crates from the packaged workspace");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /if-no-files-found: error/, "release workflow must fail when a release artifact is missing");
  forbidText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /contents:\s*write/, "release candidate workflow must not publish directly with write permissions");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /node-version:.*22\.13\.0/, "CI Node jobs must use the repository-pinned Node toolchain");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo test --locked --workspace/, "CI Rust tests must use the locked dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo clippy --locked --workspace/, "CI Rust lint must use the locked dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo install cargo-audit --locked --version 0\.22\.2/, "CI must install the pinned RustSec audit tool");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo audit/, "CI must run the RustSec dependency audit");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cargo install cargo-audit --locked --version 0\.22\.2/, "release candidate must install the pinned RustSec audit tool");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cargo audit/, "release candidate must run the RustSec dependency audit");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /node-version:\s*22(?:\s|$)/, "CI must not float on an unpinned Node major version");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /runs-on:\s*ubuntu-24\.04/, "Linux CI jobs must use the repository-pinned runner image");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /runs-on:\s*macos-15/, "Apple CI jobs must use the repository-pinned runner image");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /runs-on:\s*(?:ubuntu|macos)-latest/, "CI must not float on a latest runner image");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /27\.1\.12297006/, "Android host builds must use the repository-pinned NDK");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /ANDROID_NDK_LATEST_HOME|find[^\n]*SDK_ROOT\/ndk/, "Android host builds must not select an unpinned latest NDK");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /nightly-2026-08-19/, "Fuzz CI must use the repository-pinned nightly toolchain");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /toolchain install nightly --|cargo \+nightly fuzz/, "Fuzz CI must not float on the nightly channel");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /durable_rate_limit/, "CI must run distributed rate-limit interoperability tests");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /durable_one_time_state/, "CI must run distributed OPAQUE one-time-state interoperability tests");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-version-parity/, "CI must test public release version parity");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /check:release-version-parity/, "CI must enforce public release version parity");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-evidence/, "CI must validate the complete release evidence manifest contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:merge-release-evidence/, "CI must validate release evidence fragment merging");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-release-gate-evidence/, "CI must validate release evidence fragment emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-ci-gate-evidence/, "CI must validate CI gate evidence emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-web-browser-evidence/, "CI must validate web browser evidence emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-keypad-ci-release-evidence/, "CI must retain an aggregated release evidence artifact");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /emit-web-browser-evidence\.mjs/, "CI must emit a validator-compatible web browser evidence record");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:device-evidence/, "CI must validate the machine-readable device evidence contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Android presentation accessibility contract/, "CI must execute the Android presentation accessibility contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /web-browser-matrix/, "CI must include a real browser adapter smoke matrix");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /playwright install --with-deps/, "CI browser smoke must install its pinned browser runtime explicitly");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:web-browser/, "CI browser smoke must execute the checked-in runtime harness");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-keypad-browser-smoke-\$\{\{ matrix\.browser \}\}/, "CI browser smoke must retain per-browser evidence artifacts");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /if: always\(\)[\s\S]{0,240}secure-keypad-browser-smoke/, "CI browser smoke evidence must upload after failures");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-host-build/, "CI must include a Flutter host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /react-native-host-build/, "CI must include a React Native host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ios-host-builds/, "CI must include iOS host-link build gates");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ios-simulator-runtime/, "CI must retain iOS Simulator runtime smoke evidence");
  requireText(findings, "scripts/ios-simulator-runtime-smoke.sh", source("scripts/ios-simulator-runtime-smoke.sh", findings), /simctl install/, "iOS runtime smoke must install the generated host app through simctl");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /android-host-runtime-smoke/, "CI must retain Android emulator runtime smoke evidence");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /reactivecircus\/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d/, "Android emulator runtime smoke must use an immutable action revision");
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", source("scripts/android-emulator-runtime-smoke.sh", findings), /adb install/, "Android runtime smoke must install the generated host APK");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /SecureKeypadController\(\)/, "Flutter host smoke app must compile the native controller contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /controller: controller/, "Flutter host smoke app must link the controller to the PlatformView");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cancelRequest=\{0\}/, "React Native host smoke app must compile the native cancel prop");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-version:\s*['"]3\.47\.0['"]/, "CI must pin the Flutter host-build toolchain");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /--version 0\.87\.0/, "CI must pin the React Native host-build version");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo build --locked --release -p secure-ffi/, "native host gates must use the locked Rust dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-runs=1000000/, "CI must retain the extended fuzz stability campaign");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-rss_limit_mb=1024/, "CI fuzz campaigns must have a bounded RSS guard");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ffi_sequence/, "CI must fuzz the exported native FFI boundary");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-keypad-fuzz-logs/, "CI must retain fuzz campaign logs as a release artifact");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /if: always\(\)/, "CI must upload fuzz evidence even when a sanitizer campaign fails");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /shasum -a 256/, "CI must emit native artifact checksums");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cd \"\$RUNNER_TEMP\/secure_ffi\.xcframework\"/, "iOS checksum manifests must use artifact-relative paths");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cd \"\$RUNNER_TEMP\/secure-keypad-ffi\"/, "Android checksum manifests must use artifact-relative paths");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-xcframework-and-checksum/, "CI must retain the native artifact checksum manifest");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-android-flutter-host-and-checksum/, "CI must retain the Flutter Android FFI checksum manifest");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-android-react-native-host-and-checksum/, "CI must retain the React Native Android FFI checksum manifest");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /pnpm --dir packages\/contracts pack --dry-run/, "CI must inspect the publishable contracts npm tarball");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /pnpm --dir packages\/web pack --dry-run/, "CI must inspect the publishable Web npm tarball");
  const reactNativeAndroidBuild = source("packages/react-native/android/build.gradle", findings);
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAndroidBuild, /externalNativeBuild/, "React Native package must retain its native Android build boundary");
  const customizationGuide = source("docs/CUSTOMIZATION-EXAMPLES.md", findings);
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy: InputPolicy\.hangul/, "customization guide must cover Hangul native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy=\"ascii\"/, "customization guide must cover printable-ASCII native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /DEFAULT_THEME/, "customization guide must cover branded themes");
  forbidText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /(?:password|secret)\s*[:=][^\n]*(?:String|value|input)/i, "customization examples must not define a secret value channel");
  const rootPackage = source("package.json", findings);
  requireText(findings, "package.json", rootPackage, /"playwright"\s*:\s*"1\.62\.1"/, "browser runtime verification must use an exact Playwright version");
  requireText(findings, "package.json", rootPackage, /"test:web-browser"/, "the workspace must expose the browser runtime smoke gate");
  requireText(findings, "package.json", rootPackage, /"test:expo-development-build"/, "the workspace must expose the Expo development-build contract test");
  requireText(findings, "package.json", rootPackage, /"test:release-bundle"/, "the workspace must expose the release staging inspector test");
  for (const file of ["packages/contracts/package.json", "packages/web/package.json"]) {
    const packageManifest = source(file, findings);
    requireText(findings, file, packageManifest, /"files"\s*:\s*\[[^\]]*"LICENSE"/, "publishable npm packages must include their license file");
  }
  for (const file of ["packages/contracts/LICENSE", "packages/web/LICENSE"]) {
    const license = source(file, findings);
    requireText(findings, file, license, /^MIT License\s/m, "publishable npm packages must ship the MIT license text");
  }
  const browserSmoke = source("scripts/web-browser-smoke.mjs", findings);
  requireText(findings, "scripts/web-browser-smoke.mjs", browserSmoke, /chromium, firefox, webkit/, "browser smoke must enumerate Chromium, Firefox, and WebKit");
  requireText(findings, "scripts/web-browser-smoke.mjs", browserSmoke, /secureContext/, "browser smoke must verify secure-context behavior");
  requireText(findings, "scripts/web-browser-smoke.mjs", browserSmoke, /fallback-not-acknowledged/, "browser smoke must verify explicit fallback acknowledgement");
  const migrationGuide = source("docs/MIGRATION-FROM-PASSWORD.md", findings);
  requireText(findings, "docs/MIGRATION-FROM-PASSWORD.md", migrationGuide, /does not turn an existing\s+password hash into an OPAQUE credential file/i, "migration guidance must reject password-hash-to-OPAQUE conversion claims");
  requireText(findings, "docs/MIGRATION-FROM-PASSWORD.md", migrationGuide, /fresh OPAQUE registration or passkey ceremony/i, "migration guidance must require a fresh protected ceremony");
  requireText(findings, "docs/MIGRATION-FROM-PASSWORD.md", migrationGuide, /client-side hash/i, "migration guidance must prohibit replayable client-side hashes");
  const releaseVersionCheck = source("scripts/check-release-version-parity.mjs", findings);
  requireText(findings, "scripts/check-release-version-parity.mjs", releaseVersionCheck, /RELEASE_ARTIFACTS/, "release tooling must enumerate public artifacts for version parity");
  requireText(findings, "scripts/check-release-version-parity.mjs", releaseVersionCheck, /findReleaseVersionMismatches/, "release tooling must compare artifact versions");
  const releaseEvidenceCheck = source("scripts/check-release-evidence.mjs", findings);
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /REQUIRED_RELEASE_GATES/, "release tooling must enumerate mandatory production evidence gates");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /gate\.commit/, "release evidence must bind every gate to the manifest commit");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /independent-security-review/, "release evidence must require an independent security review");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /signed-release/, "release evidence must require signed release evidence");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /independent-review-report/, "release evidence must require a hashed independent review report");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /independentReview/, "release evidence must verify the independent reviewer attestation descriptor");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /reviewedCommit/, "release evidence must bind the independent review to the reviewed commit");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /reviewedPackageVersion/, "release evidence must bind the independent review to the reviewed package version");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256/, "release evidence must support a protected maintainer-key fingerprint");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256/, "release evidence must support a protected reviewer-key fingerprint");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /requireTrustedKeys/, "release evidence must fail closed when trusted-key mode is requested");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyReleaseEvidenceFiles/, "release tooling must verify referenced evidence file digests");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /sentinel|input\(\?:Value\|Text\|Bytes\)/, "release evidence must reject sentinel and raw-input field names");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyGateEvidenceRecord/, "release tooling must bind embedded gate evidence records");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /DEVICE_RELEASE_GATE_POLICIES/, "release tooling must map device gates to their expected platforms");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /validateDeviceEvidence/, "release tooling must revalidate embedded device evidence records");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyDeviceEvidenceFiles/, "release tooling must verify nested device evidence digests");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /gate evidence commit/, "release tooling must reject stale embedded gate evidence commits");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /gate evidence gate/, "release tooling must reject cross-gate evidence reuse");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /gate: <same gate name>/, "release gates must require machine-readable gate-bound records");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /nested log and artifact digests/, "release gates must revalidate nested device evidence digests");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /createPublicKey/, "release tooling must verify the detached public-key signature");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /currentCommit/, "release evidence must bind to the current checkout commit");
  const releaseCandidateMetadata = source("scripts/release-candidate-metadata.mjs", findings);
  requireText(findings, "scripts/release-candidate-metadata.mjs", releaseCandidateMetadata, /candidate-only/, "candidate metadata must not claim production readiness");
  requireText(findings, "scripts/release-candidate-metadata.mjs", releaseCandidateMetadata, /requiredFinalGates/, "candidate metadata must enumerate final release gates");
  requireText(findings, "scripts/release-candidate-metadata.mjs", releaseCandidateMetadata, /currentCommit/, "candidate metadata must bind to the checked-out commit");
  requireText(findings, "scripts/release-candidate-metadata.mjs", releaseCandidateMetadata, /validateReleaseCandidateCheckoutStatus/, "candidate metadata must reject a dirty checkout");
  requireText(findings, "package.json", rootPackage, /"test:release-candidate-metadata"/, "the workspace must expose the release candidate metadata test");
  const releaseBundleCheck = source("scripts/check-release-bundle.mjs", findings);
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /checkReleaseStaging/, "release tooling must inspect the exact staging input before archiving");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /secure-keypad\.sbom\.spdx\.json/, "release staging must require the SPDX SBOM");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /THIRD-PARTY-NOTICES\.md/, "release staging must require third-party notices");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /private signing material/, "release staging must reject private signing material");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/check-release-bundle\.mjs\s+\"\$RELEASE_DIR\"/, "release workflow must inspect staging before creating the signed archive");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-bundle/, "CI must execute the release staging inspector contract test");
  const releaseEvidenceMerge = source("scripts/merge-release-evidence.mjs", findings);
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /mergeReleaseEvidence/, "release tooling must merge evidence fragments through one policy function");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /duplicate release gate|duplicate release artifact/, "release evidence merging must reject duplicate claims");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /independentReview/, "release evidence merging must preserve the independent reviewer attestation");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /realpathSync/, "release evidence merging must contain fragment and output paths");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /verifyReleaseEvidenceFiles/, "release evidence merging must verify referenced files after assembly");
  requireText(findings, "package.json", rootPackage, /"test:merge-release-evidence"/, "the workspace must expose the release evidence merge test");
  requireText(findings, "package.json", rootPackage, /"test:emit-release-gate-evidence"/, "the workspace must expose the release gate fragment emitter test");
  const releaseEvidenceEmitter = source("scripts/emit-release-gate-evidence.mjs", findings);
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /currentCommit/, "release evidence emitter must derive the commit from the checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /"status",\s*"--porcelain/, "release evidence emitter must require a clean checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /currentPackageVersion/, "release evidence emitter must derive the package version from the checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /createHash\("sha256"\)/, "release evidence emitter must hash exact evidence bytes");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /secret-bearing evidence fields/, "release evidence emitter must reject secret-bearing evidence fields");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /match the fragment gate/, "release evidence emitter must reject cross-gate evidence reuse");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /sentinel|input\(\?:Value\|Text\|Bytes\)/, "release evidence emitter must reject sentinel and raw-input field names");
  const releaseSigner = source("scripts/sign-release.mjs", findings);
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /asymmetricKeyType !== \"ed25519\"/, "release signing must reject non-Ed25519 keys");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /private key is read only/i, "release signing must not copy or log the private key");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /sign\(null, artifact, privateKey\)/, "release signing must create a detached signature over the artifact");

  return findings;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const findings = runSecurityAudit();
  for (const finding of findings) {
    process.stderr.write(`${finding.rule}: ${finding.file}: ${finding.detail}\n`);
  }
  process.exitCode = findings.length === 0 ? 0 : 1;
}
