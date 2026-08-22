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

  const flutter = source("packages/flutter/lib/secure_keypad_flutter.dart", findings);
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /class SecureKeypad extends StatefulWidget/, "Flutter must expose a native PlatformView widget");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /class SecureKeypadController/, "Flutter must expose a non-secret native controller");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /invokeMethod<void>\('cancel'\)/, "Flutter controller must use a native cancel method");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /enum SecureKeypadMode/, "Flutter must expose an explicit renderer mode");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /invokeMethod<void>\('pressKey'/, "Flutter headless commands must use a native method channel");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /acknowledgeLowerAssurance/, "Flutter headless mode must require explicit acknowledgement");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /toPlatformCreationParams/, "Flutter must expose an explicit public creation map");
  forbidText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /TextEditingController/, "Flutter must not use a text editing controller");
  forbidText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter, /final\s+(?:String\??)\s+(?:value|password|secret)\b/i, "Flutter configuration must not hold a secret string field");
  forbidText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutter.match(/toPlatformCreationParams\(\)[\s\S]*?\n  \}/)?.[0] ?? "", /onResult|onMaskedStateChanged/, "Flutter native creation params must not serialize callbacks");

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
  const actixAdapter = source("crates/secure-auth-actix/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actixAdapter, /csrf:\s*Arc</, "Actix adapters must retain a host CSRF callback");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actixAdapter, /if !\(state\.csrf\)\(&request\)/, "Actix adapters must reject failed CSRF validation before body buffering");
  const actixManifest = source("crates/secure-auth-actix/Cargo.toml", findings);
  requireText(findings, "crates/secure-auth-actix/Cargo.toml", actixManifest, /webauthn\s*=\s*\["dep:secure-webauthn-example",\s*"dep:uuid"\]/, "Actix WebAuthn support must remain explicitly feature-gated");
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
    "native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadReactPackage.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/reactnative/SecureKeypadReactPackage.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /class SecureKeypadReactPackage\s*:\s*ReactPackage/, "React Native Android package must be discoverable by CLI autolinking");
    requireText(findings, file, contents, /createViewManagers\([\s\S]{0,240}SecureKeypadViewManager\(\)/, "React Native Android package must register the secure keypad view manager");
  }
  const reactNativeAbiBuild = source("packages/react-native/android/build.gradle", findings);
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAbiBuild, /secureKeypadAbiFilters/, "React Native Android native build must derive ABI filters from the host architecture contract");
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAbiBuild, /abiFilters\(\*secureKeypadAbiFilters\)/, "React Native Android native build must pass only selected ABI filters to CMake");
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAbiBuild, /reactNativeArchitectures.*arm64-v8a,x86_64/, "React Native Android default ABI matrix must match the verified release FFI artifacts");
  const flutterAbiBuild = source("packages/flutter/android/build.gradle", findings);
  requireText(findings, "packages/flutter/android/build.gradle", flutterAbiBuild, /secureKeypadAbiFilters/, "Flutter Android native build must restrict compilation to supplied FFI architectures");
  requireText(findings, "packages/flutter/android/build.gradle", flutterAbiBuild, /abiFilters\(\*secureKeypadAbiFilters\)/, "Flutter Android native build must pass only available ABI filters to CMake");
  requireText(findings, "packages/flutter/android/build.gradle", flutterAbiBuild, /kotlin\s*\{[\s\S]*compilerOptions\s*\{[\s\S]*JvmTarget\.JVM_17/, "Flutter Android plugin must use the built-in Kotlin compiler contract");
  forbidText(findings, "packages/flutter/android/build.gradle", flutterAbiBuild, /org\.jetbrains\.kotlin\.android|kotlinOptions\s*\{/, "Flutter Android plugin must not apply the legacy Kotlin Gradle plugin contract");
  const flutterPubspec = source("packages/flutter/pubspec.yaml", findings);
  requireText(findings, "packages/flutter/pubspec.yaml", flutterPubspec, /flutter:\s*['"]>=3\.44\.0['"]/, "Flutter plugin must pin the minimum SDK required by built-in Kotlin support");
  const androidRuntimeHierarchySmoke = source("scripts/android-emulator-runtime-smoke.sh", findings);
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeHierarchySmoke, /FLAG_SECURE/, "Android runtime evidence must acknowledge capture blocking by FLAG_SECURE");
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeHierarchySmoke, /uiautomator dump/, "Android runtime evidence must verify the rendered native hierarchy");
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeHierarchySmoke, /content-desc="No input"/, "Android runtime evidence must verify only the public empty-state label");
  forbidText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeHierarchySmoke, /adb shell input|adb shell[^\n]*(?:getText|password|secret)/i, "Android runtime evidence must not query or serialize input values");

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
    requireText(findings, file, contents, /UIManagerHelper/, "RN Android events must use the New Architecture-compatible UIManagerHelper");
    requireText(findings, file, contents, /dispatchEvent\(SecureKeypadEvent/, "RN Android events must pass through EventDispatcher");
    forbidText(findings, file, contents, /getJSModule\(RCTEventEmitter/, "RN Android must not call the legacy RCTEventEmitter directly");
    requireText(findings, file, contents, /toPublicMap\(LAYOUT_KEYS\)/, "RN Android layout conversion must use an explicit allowlist");
    requireText(findings, file, contents, /LAYOUT_KEYS\s*=\s*setOf\([^\n]*randomizeInputKeys/, "RN Android layout allowlist must preserve native input-key randomization");
    requireText(findings, file, contents, /NESTED_PUBLIC_KEYS\s*=\s*setOf\([\s\S]*randomizeInputKeys/, "RN Android nested public map allowlist must preserve native input-key randomization");
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
    requireText(findings, file, contents, /secureKeypadDecodeMaskedState/, "Android native keypad must fail closed when JNI masked-state refresh fails");
    requireText(findings, file, contents, /display\.text\s*=\s*\"\"/, "Android native keypad must clear the visible masked display when releasing a session");
    forbidText(
      findings,
      file,
      contents,
      /\b(?:EditText|TextInputEditText|AutoCompleteTextView)\b/,
      "Android native keypad must not use an editable text widget",
    );
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
    requireText(findings, file, contents, /secureKeypadDecodeMaskedState/, "Android presentation must distinguish native refresh failure from empty state");
    requireText(findings, file, contents, /Long\.MIN_VALUE/, "Android presentation must reserve a non-empty JNI failure sentinel");
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
    requireText(findings, file, contents, /displayLabel\.text = protectedPresentation \? \"Protected\" : \"\"/, "iOS native keypad must clear the visible masked display when releasing a session");
    requireText(findings, file, contents, /try validate\(theme: theme\)[\s\S]{0,400}releaseSession\(\)/, "iOS native reconfiguration must clear the old session through its nil-setting release path");
    requireText(findings, file, contents, /secure_keypad_abi_version\(\)/, "iOS native keypad must fail closed on an FFI ABI mismatch before session creation");
    requireText(findings, file, contents, /configureAscii/, "iOS native keypad must expose the bounded printable-ASCII policy");
    forbidText(
      findings,
      file,
      contents,
      /\b(?:UITextField|UITextView|UISearchBar|UITextInput)\b/,
      "iOS native keypad must not use an editable text widget",
    );
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
    requireText(findings, file, contents, /SECURE_KEYPAD_MAX_KEY_ID_BYTES 64/, "Android JNI must bound public key-ID arrays before obtaining a JVM byte-array pointer");
    requireText(findings, file, contents, /length <= 0 \|\| \(size_t\)length > SECURE_KEYPAD_MAX_KEY_ID_BYTES/, "Android JNI must reject invalid or oversized public key-ID arrays before copying");
    requireText(findings, file, contents, /INT64_MIN/, "Android JNI refresh must return a distinct failure sentinel instead of empty state");
    forbidText(findings, file, contents, /if \(error != SECURE_KEYPAD_OK\) return 0;/, "Android JNI must not collapse refresh failure into the valid empty-state value");
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
  requireText(findings, "packages/web/src/index.ts", web, /function encodeBase64Url[\s\S]{0,240}bytes\.byteLength\s*>\s*MAX_WEBAUTHN_BINARY_BYTES/, "WebAuthn base64url encoding must reject oversized caller-supplied buffers");
  requireText(findings, "packages/web/src/index.ts", web, /Number\.isSafeInteger\(maxBytes\)[\s\S]{0,180}maxBytes > MAX_WEBAUTHN_BINARY_BYTES/, "WebAuthn base64url decoding must reject unbounded caller-supplied byte limits");
  requireText(findings, "packages/web/src/index.ts", web, /maxEncodedLength\s*=\s*Math\.ceil\(\(maxBytes \* 8\) \/ 6\)[\s\S]{0,220}value\.length\s*>\s*maxEncodedLength/, "WebAuthn base64url decoding must bound encoded length before allocation");
  requireText(findings, "packages/web/src/index.ts", web, /normalizeWebAuthnError/, "WebAuthn browser and credential failures must be normalized before leaving the adapter");
  requireText(findings, "packages/web/src/index.ts", web, /credential-api-failure/, "WebAuthn browser API failures must use a stable generic error code");
  requireText(findings, "packages/web/src/index.ts", web, /function getDefaultWebAuthnEnvironment\(\)[\s\S]{0,1800}catch\s*\{[\s\S]{0,180}isSecureContext: false/, "WebAuthn environment discovery must fail closed when browser getters throw");
  requireText(findings, "packages/web/src/index.ts", web, /typeof container\.create === "function"[\s\S]{0,100}typeof container\.get === "function"/, "WebAuthn default environment must verify both browser credential methods");
  forbidText(findings, "packages/web/src/index.ts", web, /\b(?:password|pin)\s*[:(]/i, "Web adapter must not expose a password/PIN API");
  const nodeServer = source("packages/server-node/src/index.ts", findings);
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /NODE_SERVER_CONTRACT_VERSION\s*=\s*1/, "Node server adapter must expose a pinned contract version");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /MAX_HTTP_BODY_BYTES\s*=\s*128 \* 1024/, "Node server adapter must bound raw request bodies");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /async function readBoundedBody/, "Node server adapter must stream and bound request bodies");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /await reader\.cancel()/, "Node server adapter must cancel an oversized request stream");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /await options\.csrfValidated\(request\)[\s\S]{0,1000}readBoundedBody/, "Node server adapter must validate CSRF before buffering the body");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /transport === \"direct-tls\" \|\| context\.transport === \"trusted-proxy-tls\"/, "Node server adapter must require explicit TLS deployment facts");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /STATUS_CODES = new Set/, "Node server adapter must constrain delegate status codes");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /function byteView[\s\S]{0,700}function zeroizeChunk/, "Node server adapter must preserve byte-view ownership and zeroize malformed chunks");
  requireText(findings, "packages/server-node/src/index.ts", nodeServer, /function responseFromDelegate[\s\S]{0,1200}zeroizeChunk\(body\)/, "Node server adapter must zeroize delegate response bytes after copying them");
  forbidText(findings, "packages/server-node/src/index.ts", nodeServer, /X-Forwarded-Proto|x-forwarded-proto/i, "Node server adapter must not parse forwarded transport headers");
  forbidText(findings, "packages/server-node/src/index.ts", nodeServer, /\b(?:password|pin|rawInput|input(?:Value|Text|Bytes))\s*[:(]/i, "Node server adapter must not expose a secret-bearing application API");
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
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /SECURE_KEYPAD_FFI_XCFRAMEWORK/, "Expo iOS builds must validate an explicit or bundled FFI XCFramework");
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /SECURE_KEYPAD_FFI_LIB_DIR/, "Expo Android builds must validate an explicit or bundled FFI library directory");
  requireText(findings, "packages/react-native/app.plugin.js", expoPlugin, /android[\\/]secure_ffi/, "Expo Android builds must resolve the package-bundled FFI directory");
  const reactNativeGuide = source("packages/react-native/README.md", findings);
  requireText(findings, "packages/react-native/README.md", reactNativeGuide, /Expo Development Build/, "React Native must document Expo Development Build support");
  requireText(findings, "packages/react-native/README.md", reactNativeGuide, /Expo Go/, "React Native must document the Expo Go limitation");
  const flutterContract = source("packages/flutter/lib/secure_keypad_flutter.dart", findings);
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /enum KeyRole \{[^}]*cancel/, "Flutter contract must expose an explicit cancel role");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /secureKeypadMaxRenderedLength/, "Flutter must bound masked event metadata");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /isSecureKeypadNativeEventShapeValid/, "Flutter must reject unexpected native event fields");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /_onNativeEvent\([\s\S]{0,500}isSecureKeypadRenderedLengthValid/, "Flutter must validate masked event length before invoking callbacks");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /bool _hasExactKeys\(/, "Flutter configuration maps must use an exact-key allowlist");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /_colorPattern/, "Flutter theme colors must be format-validated before bridge serialization");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /_isBoundedNumber\(/, "Flutter theme metrics must be range-validated before bridge serialization");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /_isBoundedInteger\(/, "Flutter integer policy and animation bounds must reject invalid values");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /this\.maxTokens\s*=\s*8[\s\S]{0,80}this\.timeoutMs\s*=\s*60000/, "Flutter default session bounds must match the native adapter contract");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /toPlatformCreationParams\(\)\s*\{[\s\S]{0,180}validate\(\)/, "Flutter bridge serialization must fail closed for invalid configuration");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /secureKeypadMaxHeadlessKeyPressToken/, "Flutter headless command tokens must be bounded");
  requireText(findings, "packages/flutter/lib/secure_keypad_flutter.dart", flutterContract, /mode == SecureKeypadMode\.headlessHost/, "Flutter must bind headless command access to the acknowledged mode");
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SecureKeyRole\.CANCEL/, "Android bridge parser must accept the explicit cancel role");
    requireText(findings, file, contents, /private fun integer\(/, "Android bridge parser must reject fractional numeric configuration values");
    requireText(findings, file, contents, /val result = \(value as\? Number\)\?\.toDouble\(\)/, "Android bridge parser must validate numeric precision before narrowing to Float");
    requireText(findings, file, contents, /result >= minimum\.toDouble\(\)[\s\S]*result <= maximum\.toDouble\(\)/, "Android bridge parser must compare theme bounds before narrowing to Float");
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
    requireText(findings, file, contents, /Self\.boundedInteger\(value\["schemaVersion"\], minimum: 1, maximum: 1\)/, "iOS bridge parser must reject non-integral schema versions");
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

  const actix = source("crates/secure-auth-actix/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /payload\.to_bytes_limited\(body_limit\)/, "Actix adapter must bound streaming request bodies before route parsing");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /state\.router\.handle\(/, "Actix adapter must delegate to the framework-neutral route contract");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /RESPONSE_SECURITY_HEADERS/, "Actix adapter must preserve static response security headers");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /Fn\(&HttpRequest\) -> bool/, "Actix adapter CSRF resolver must receive request parts without the body");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /payload\.to_bytes_limited\(body_limit\)[\s\S]{0,800}state\.principal/, "Actix WebAuthn adapter must resolve the host principal only after bounded body collection");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /WebAuthnHttpRouter::new/, "Actix WebAuthn adapter must delegate to the framework-neutral route contract");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /Fn\(&HttpRequest\) -> Option<Uuid>/, "Actix WebAuthn principal resolver must receive request metadata without the body");
  requireText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /WEBAUTHN_RESPONSE_SECURITY_HEADERS/, "Actix WebAuthn adapter must preserve passkey response security headers");
  forbidText(findings, "crates/secure-auth-actix/src/lib.rs", actix, /X-Forwarded-Proto|x-forwarded-proto/i, "Actix adapter must not parse forwarded transport headers");

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
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /CONSUME_SCRIPT[\s\S]{0,700}STRLEN[\s\S]{0,260}'GET'/, "Redis WebAuthn ceremony consumption must bound record bytes before GET");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /MAX_PROTECTED_CEREMONY_RECORD_BYTES/, "Redis WebAuthn ceremony consumption must use the encrypted-record bound");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /const BOUNDED_CREDENTIAL_GET_SCRIPT: &str/, "Redis credential reads must use a dedicated bounded retrieval script");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /BOUNDED_CREDENTIAL_GET_SCRIPT[\s\S]{0,240}STRLEN[\s\S]{0,240}'GET'/, "Redis credential reads must check STRLEN before GET");
  requireText(findings, "crates/secure-webauthn-example/src/storage_redis.rs", webauthnRedis, /fn get_bounded_credentials[\s\S]{0,600}MAX_CREDENTIAL_RECORD_BYTES/, "Redis credential reads must enforce the application byte bound before decoding");
  const webauthnPostgres = source("crates/secure-webauthn-example/src/storage_postgres.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /pub fn from_config\([\s\S]{0,260}encryption_key: WebAuthnStateKey/, "PostgreSQL WebAuthn production construction must require a host-managed encryption key");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /validate_backend_ttl\(ttl\)/, "PostgreSQL WebAuthn storage must validate ceremony TTLs before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /protector\.seal\(encoded\.as_slice\(\)\)/, "PostgreSQL WebAuthn storage must encrypt ceremony records before persistence");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /protector\.open\(protected\)/, "PostgreSQL WebAuthn storage must authenticate ceremony records after retrieval");
  requireText(findings, "crates/secure-webauthn-example/src/storage_postgres.rs", webauthnPostgres, /POSTGRES_CEREMONY_CONSUME_SQL[\s\S]{0,600}octet_length\(state\) <= \$4/, "PostgreSQL WebAuthn ceremony consumption must bound bytes before materialization");
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
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /CONSUME_SCRIPT[\s\S]{0,700}STRLEN[\s\S]{0,260}'GET'/, "Redis OPAQUE state consumption must bound record bytes before GET");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /CONSUME_SCRIPT[\s\S]{0,700}tonumber\(ARGV\[2\]\)/, "Redis OPAQUE state consumption must use the encrypted-record bound");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_redis.rs", opaqueStateRedis, /rediss:\/\//, "Redis OPAQUE state must require TLS by default");
  const opaqueStatePostgres = source("crates/secure-auth-server/src/opaque_state_postgres.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /POSTGRES_ONE_TIME_LOGIN_STATE_SCHEMA_SQL/, "PostgreSQL OPAQUE state must ship an explicit migration");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /pg_advisory_xact_lock/, "PostgreSQL OPAQUE state capacity must be serialized");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /POSTGRES_ONE_TIME_STATE_CONSUME_SQL[\s\S]{0,500}DELETE FROM secure_keypad_opaque_login_states[\s\S]{0,240}RETURNING CASE/, "PostgreSQL OPAQUE state consumption must be atomic");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /MakeTlsConnect/, "PostgreSQL OPAQUE state must accept an explicit TLS connector");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /SslMode::Require/, "PostgreSQL OPAQUE state must reject configurations that can downgrade TLS");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /TypeId::of::<T>\(\) == TypeId::of::<NoTls>\(\)/, "PostgreSQL OPAQUE state must reject the NoTls connector even when sslmode requires TLS");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /CHECK \(octet_length\(state\) BETWEEN 1 AND 32802\)/, "PostgreSQL OPAQUE state schema must enforce bounded encrypted records");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /protector\.seal/, "PostgreSQL OPAQUE state must encrypt before storage");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /protector\.open/, "PostgreSQL OPAQUE state must authenticate before decoding");
  requireText(findings, "crates/secure-auth-server/src/opaque_state_postgres.rs", opaqueStatePostgres, /POSTGRES_ONE_TIME_STATE_CONSUME_SQL[\s\S]{0,600}octet_length\(state\) <= \$3/, "PostgreSQL OPAQUE state consumption must bound bytes before materialization");
  const durableOneTimeStateTest = source("crates/secure-auth-server/tests/durable_one_time_state.rs", findings);
  requireText(findings, "crates/secure-auth-server/tests/durable_one_time_state.rs", durableOneTimeStateTest, /SKPE/, "durable OPAQUE service tests must verify encrypted storage records");
  requireText(findings, "crates/secure-auth-server/tests/durable_one_time_state.rs", durableOneTimeStateTest, /second_store|cross_instance_handle/, "durable OPAQUE service tests must verify same-key cross-instance consumption");
  requireText(findings, "crates/secure-auth-server/tests/durable_one_time_state.rs", durableOneTimeStateTest, /redis_oversized_state_is_removed_before_materialization/, "durable OPAQUE Redis tests must verify oversized values are removed before materialization");
  const durableRateLimitTest = source("crates/secure-auth-server/tests/durable_rate_limit.rs", findings);
  requireText(findings, "crates/secure-auth-server/tests/durable_rate_limit.rs", durableRateLimitTest, /redis_oversized_counter_is_removed_before_lua_get/, "durable Redis rate-limit tests must verify oversized counters are removed before Lua GET");
  const durableWebAuthnTest = source("crates/secure-webauthn-example/tests/durable_storage.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/tests/durable_storage.rs", durableWebAuthnTest, /redis_oversized_ceremony_value_is_removed_before_materialization/, "durable WebAuthn Redis tests must verify oversized ceremony values are removed before materialization");
  requireText(findings, "crates/secure-webauthn-example/tests/durable_storage.rs", durableWebAuthnTest, /redis_oversized_credential_value_fails_closed_before_json_decode/, "durable WebAuthn Redis tests must verify oversized credentials fail closed before JSON decoding");
  const redisRateLimit = source("crates/secure-auth-server/src/rate_limit_redis.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /RATE_LIMIT_SCRIPT/, "Redis rate limiting must use one atomic script");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /RATE_LIMIT_SCRIPT[\s\S]{0,500}STRLEN[\s\S]{0,260}'GET'/, "Redis rate limiting must bound counter bytes before GET");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /MAX_RATE_COUNTER_BYTES/, "Redis rate limiting must define a bounded counter representation");
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
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_XCFRAMEWORK/, "iOS package must support an explicit or bundled FFI XCFramework");
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_LIB/, "iOS package must support a single-platform FFI fallback");
    requireText(findings, file, contents, /require ['"]digest['"]/, "iOS package must use a standard digest implementation for FFI parity");
    requireText(findings, file, contents, /same_ffi_artifact/, "iOS package must compare explicit FFI bytes with the staged artifact");
    requireText(findings, file, contents, /does not match the staged package FFI artifact/, "iOS package must fail closed when explicit FFI bytes differ");
    requireText(findings, file, contents, /raise ['"]SECURE_KEYPAD_FFI_XCFRAMEWORK/, "iOS package must fail closed without FFI artifacts");
  }
  for (const file of [
    "packages/react-native/android/CMakeLists.txt",
    "packages/flutter/android/CMakeLists.txt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /SECURE_KEYPAD_FFI_LIB_DIR/, "Android package must support an explicit or bundled ABI library directory");
    requireText(findings, file, contents, /CMAKE_CURRENT_LIST_DIR.*secure_ffi/, "Android package must resolve its bundled FFI directory");
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
  requireText(findings, "docs/SECURITY-SPEC.md", securitySpec, /@secure-keypad\/server-node[\s\S]{0,500}is a\s+transport bridge/, "security specification must define the Node adapter as a transport bridge");
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
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /hostModes/, "device verification must bind both native framework host modes");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /host-mode react-native=[\s\S]{0,80}host-mode flutter=/, "device verification must document both host-mode emitter inputs");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /replay, expired-state,[\s\S]*rate-limit/i, "device verification must cover server replay and rate-limit behavior");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /secure-keypad-test-sentinel-7f2c4e/, "device verification must define the canonical disposable sentinel");
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /byte-level preflight[\s\S]{0,160}secure-keypad-test-sentinel-7f2c4e/, "release gates must document byte-level sanitized-artifact preflight");
  const deviceEvidenceCheck = source("scripts/check-device-evidence.mjs", findings);
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /MAX_DEVICE_EVIDENCE_RECORD_BYTES/, "device evidence CLI must bound the top-level record before parsing");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /verifyDeviceEvidenceFiles/, "device evidence tooling must recompute referenced file digests");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /ISO_TIMESTAMP/, "device evidence tooling must require canonical timestamps");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /value\.length <= 120/, "device evidence tooling must bound metadata labels");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /evidence\.status !== \"pass\"/, "device evidence tooling must require an explicit passing top-level status");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /SANITIZED_TEST_SENTINEL/, "device evidence tooling must reject the canonical test sentinel");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /scanEvidenceFileContent/, "device evidence tooling must scan referenced content for secret-bearing text");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /realpathSync/, "device evidence paths must be contained after symlink resolution");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /pathHasSymlinkComponent/, "device evidence paths must reject symlink traversal");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /requirePhysicalDevice/, "device evidence tooling must distinguish physical-device release evidence");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /expectedCommit/, "device evidence tooling must bind records to the expected checkout commit");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /DEVICE_RELEASE_GATES/, "device evidence tooling must bind records to a supported device release gate");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /expectedGate/, "device evidence tooling must bind records to the expected release gate");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /REQUIRED_PHYSICAL_NATIVE_ARTIFACT_KINDS/, "physical device evidence must require categorized review artifacts");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /REQUIRED_NATIVE_HOST_MODES/, "physical native device evidence must enumerate required host modes");
  requireText(findings, "scripts/check-device-evidence.mjs", deviceEvidenceCheck, /requireNativeHostModes/, "physical native device evidence must enforce both host modes");
  const nativeEvidenceEmitter = source("scripts/emit-native-device-evidence.mjs", findings);
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /REQUIRED_NATIVE_ARTIFACT_KINDS/, "native evidence emitter must require all physical artifact categories");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /NATIVE_TEST_CASES/, "native evidence emitter must require the complete native test matrix");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /normalizeHostModes/, "native evidence emitter must materialize both native host modes");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /MAX_NATIVE_EVIDENCE_FILE_BYTES/, "native evidence emitter must bound evidence file materialization");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /verifyDeviceEvidenceFiles/, "native evidence emitter must verify referenced files before writing evidence");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /currentCommit/, "native evidence emitter must derive the checkout commit");
  requireText(findings, "scripts/emit-native-device-evidence.mjs", nativeEvidenceEmitter, /pathHasSymlinkComponent/, "native evidence emitter must reject symlink traversal");
  const ciGateEvidence = source("scripts/emit-ci-gate-evidence.mjs", findings);
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /buildReleaseGateFragment/, "CI gate evidence must bind fragments to the release evidence contract");
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /sanitized CI gate record/, "CI gate evidence must reject raw log payloads");
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /realpathSync/, "CI gate evidence paths must be contained after symlink resolution");
  requireText(findings, "scripts/emit-ci-gate-evidence.mjs", ciGateEvidence, /pathHasSymlinkComponent/, "CI gate evidence outputs must reject symlink traversal");
  const webEvidenceEmitter = source("scripts/emit-web-browser-evidence.mjs", findings);
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /chromium.*firefox.*webkit/, "web evidence must require the complete browser matrix");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /verifyDeviceEvidenceFiles|buildReleaseGateFragment/, "web evidence must bind hashed files to the release gate contract");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /secureContext: true/, "web evidence must record secure-context verification");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /parseBrowserSmokeVersion/, "web evidence must bind browser versions to checked-in smoke output");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /currentPlaywrightFrameworkVersion/, "web evidence must bind the framework version to the workspace pin");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", webEvidenceEmitter, /pathHasSymlinkComponent/, "web evidence emitter must reject symlink traversal");
  const independentReviewEmitter = source("scripts/emit-independent-review-fragment.mjs", findings);
  requireText(findings, "scripts/emit-independent-review-fragment.mjs", independentReviewEmitter, /createPublicKey/, "independent review emitter must parse the reviewer public key");
  requireText(findings, "scripts/emit-independent-review-fragment.mjs", independentReviewEmitter, /verify\(/, "independent review emitter must verify the detached signature");
  requireText(findings, "scripts/emit-independent-review-fragment.mjs", independentReviewEmitter, /currentCommit/, "independent review emitter must derive the reviewed checkout commit");
  requireText(findings, "scripts/emit-independent-review-fragment.mjs", independentReviewEmitter, /private signing material/, "independent review emitter must reject private key paths");
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
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" packages\/react-native\/secure_ffi\.xcframework/, "iOS native CI must stage the XCFramework before parsing the React Native Podspec");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cp -R "\$RUNNER_TEMP\/secure_ffi\.xcframework" packages\/flutter\/ios\/secure_ffi\.xcframework/, "iOS native CI must stage the XCFramework before parsing the Flutter Podspec");
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
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /native-ios-artifacts:/, "release workflow must build publishable iOS FFI artifacts in a separate pinned job");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /native-android-artifacts:/, "release workflow must build publishable Android FFI artifacts in a separate pinned job");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /bundle:\s*\n\s*needs:\s*\[native-ios-artifacts,\s*native-android-artifacts\]/, "release bundle must depend on both verified native FFI artifact jobs");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /actions\/download-artifact@[0-9a-f]{40}/, "release bundle must download the immutable iOS FFI artifact");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /find \. -type f ! -name secure-keypad-ios-ffi\.sha256/, "iOS FFI checksum generation must include the commit binding while excluding only the manifest itself");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /shasum -a 256 -c secure-keypad-ios-ffi\.sha256/, "release bundle must verify the downloaded iOS FFI checksum manifest");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /secure-keypad-ios-ffi\.commit/, "release bundle must bind the downloaded iOS FFI artifact to the requested commit");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cat "\$IOS_FFI_DIR\/secure-keypad-ios-ffi\.commit"\)" = "\$RELEASE_REF/, "release bundle must reject an iOS FFI artifact from another commit");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /packages\/react-native\/secure_ffi\.xcframework/, "release bundle must stage the verified React Native iOS XCFramework");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /packages\/flutter\/ios\/libsecure_ffi\.a/, "release bundle must stage the verified Flutter iOS static library");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /name:\s*secure-keypad-release-android-ffi/, "release bundle must download the verified Android FFI artifact");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /sha256sum -c secure-keypad-android-ffi\.sha256/, "release bundle must verify the downloaded Android FFI checksum manifest");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /secure-keypad-android-ffi\.commit/, "release bundle must bind the downloaded Android FFI artifact to the requested commit");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /source\/native-artifacts\/android\/arm64-v8a\/libsecure_ffi\.a/, "release bundle must stage the verified Android arm64 FFI library");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /source\/native-artifacts\/android\/x86_64\/libsecure_ffi\.a/, "release bundle must stage the verified Android x86_64 FFI library");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /packages\/react-native\/android\/secure_ffi\/arm64-v8a/, "release bundle must stage the verified React Native Android arm64 FFI library");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /packages\/flutter\/android\/secure_ffi\/x86_64/, "release bundle must stage the verified Flutter Android x86_64 FFI library");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /bundle:[\s\S]{0,260}environment:\s*secure-keypad-release/, "release signing must run behind the protected release environment");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /RELEASE_SIGNING_KEY_PEM/, "release workflow must require a protected signing key");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /trap\s+'rm -f "\$KEY_FILE"'\s+EXIT/, "release workflow must remove the temporary signing key on every exit path");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/sign-release\.mjs/, "release workflow must produce the detached signature through the audited signer");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /playwright install --with-deps chromium firefox webkit/, "release candidate must run the browser adapter smoke matrix");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:web-browser all/, "release candidate must execute all browser smoke targets");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:merge-release-evidence/, "release candidate must test evidence fragment merging");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:emit-release-gate-evidence/, "release candidate must test evidence fragment emission");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:emit-signed-release-evidence/, "release candidate must test signed-release evidence emission");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /test:emit-independent-review-fragment/, "release candidate must test independent-review fragment emission");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /emit-signed-release-evidence\.mjs/, "release candidate must emit signed-release evidence");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/release-candidate-metadata\.mjs/, "release candidate must embed immutable candidate metadata in the signed bundle");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /release-candidate-metadata\.json/, "release candidate must retain the candidate metadata record");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /services:/, "release candidate must provide isolated durable backend services");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_storage/, "release candidate must execute WebAuthn durable interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_rate_limit/, "release candidate must execute distributed rate-limit interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /durable_one_time_state/, "release candidate must execute distributed OPAQUE one-time-state interoperability tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cargo test --locked -p secure-auth-actix/, "release candidate must run the Actix adapter contract tests");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /pnpm --dir packages\/server-node pack --pack-destination/, "release candidate must package the Node server adapter");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cargo package --locked --workspace --all-features/, "release candidate must verify all feature-gated crates from the packaged workspace");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /-C "\$RELEASE_DIR" source packages/, "release workflow must sign source and publishable package archives in one tarball");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/check-release-archive\.mjs/, "release workflow must inspect the exact signed tarball contents");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /source\/secure-keypad-ios-ffi\.sha256/, "release workflow must carry the verified iOS FFI checksum into the signed source bundle");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /source\/secure-keypad-android-ffi\.sha256/, "release workflow must carry the verified Android FFI checksum into the signed source bundle");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /cp \"\$ANDROID_FFI_DIR\/secure-keypad-android-ffi\.commit\"/, "release workflow must carry the Android FFI commit binding into the signed source bundle");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/emit-release-artifact-fragment\.mjs/, "release workflow must emit the candidate public artifact fragment");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /native-checksum/, "release workflow must evidence the native checksum artifact");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /native-checksum-android/, "release workflow must evidence the Android native checksum artifact");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /license-notices/, "release workflow must evidence the license notices artifact");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /if-no-files-found: error/, "release workflow must fail when a release artifact is missing");
  forbidText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /contents:\s*write/, "release candidate workflow must not publish directly with write permissions");
  const releaseFinalizeWorkflow = source(".github/workflows/release-finalize.yml", findings);
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /workflow_dispatch:/, "release finalization must be manually invoked with explicit evidence run IDs");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /candidate-run-id:/, "release finalization must identify the immutable candidate artifact run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /ci-run-id:/, "release finalization must identify the CI evidence run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /external-evidence-run-id:/, "release finalization must identify the external evidence run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /external-evidence-workflow:/, "release finalization must identify the external evidence workflow path");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /actions:\s*read/, "release finalization must use read-only artifact permissions");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /contents:\s*read/, "release finalization must use read-only repository permissions");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /actions\/download-artifact@[0-9a-f]{40}/, "release finalization must download immutable artifacts through a pinned action");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /run-id:\s*\$\{\{ inputs\.candidate-run-id \}\}/, "release finalization must bind the candidate download to its requested run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /run-id:\s*\$\{\{ inputs\.ci-run-id \}\}/, "release finalization must bind CI evidence to its requested run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /run-id:\s*\$\{\{ inputs\.external-evidence-run-id \}\}/, "release finalization must bind external evidence to its requested run");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/verify-github-run-provenance\.mjs/, "release finalization must verify GitHub run status, commit, repository, and workflow provenance");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /GITHUB_TOKEN:\s*\$\{\{ github\.token \}\}/, "release finalization must provide a read-only GitHub API token to the run provenance verifier");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/check-release-bundle\.mjs/, "release finalization must inspect the downloaded candidate staging contract");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/check-release-archive\.mjs/, "release finalization must inspect the downloaded signed archive contract");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /sha256sum -c secure-keypad-release\.sha256/, "release finalization must verify the candidate artifact checksum manifest");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /source\/secure-keypad-android-ffi\.commit/, "release finalization must compare the Android FFI commit binding inside the signed archive");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /tar --extract --to-stdout/, "release finalization must compare signed source inputs to staged evidence files");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/stage-release-evidence\.mjs/, "release finalization must stage untrusted artifact roots through the audited copier");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/emit-signed-release-fragment\.mjs/, "release finalization must convert signed-release evidence into a complete fragment");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/merge-release-evidence\.mjs/, "release finalization must merge all evidence fragments before verification");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /scripts\/check-release-evidence\.mjs --require-trusted-keys/, "release finalization must require protected maintainer and reviewer fingerprints");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256/, "release finalization must provide the protected maintainer fingerprint");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256/, "release finalization must provide the protected reviewer fingerprint");
  requireText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /name: secure-keypad-production-release-evidence/, "release finalization must retain the verified production evidence artifact");
  const githubRunProvenance = source("scripts/verify-github-run-provenance.mjs", findings);
  requireText(findings, "scripts/verify-github-run-provenance.mjs", githubRunProvenance, /run\.head_sha/, "GitHub run provenance must bind the run to the requested release commit");
  requireText(findings, "scripts/verify-github-run-provenance.mjs", githubRunProvenance, /run\.path/, "GitHub run provenance must bind the run to the expected workflow path");
  requireText(findings, "scripts/verify-github-run-provenance.mjs", githubRunProvenance, /status !== \"completed\"|status !== 'completed'/, "GitHub run provenance must require a completed run");
  requireText(findings, "scripts/verify-github-run-provenance.mjs", githubRunProvenance, /conclusion !== \"success\"|conclusion !== 'success'/, "GitHub run provenance must require a successful run");
  requireText(findings, "scripts/verify-github-run-provenance.mjs", githubRunProvenance, /Authorization: `Bearer/, "GitHub run provenance must authenticate API requests with the workflow token");
  for (const line of findMutableCiActionLines(releaseFinalizeWorkflow)) {
    findings.push({
      rule: "ci-action-immutability",
      file: ".github/workflows/release-finalize.yml",
      detail: `every GitHub Action must use a 40-character immutable commit SHA: ${line.trim()}`,
    });
  }
  forbidText(findings, ".github/workflows/release-finalize.yml", releaseFinalizeWorkflow, /contents:\s*write/, "release finalization must not publish or mutate repository contents");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /node-version:.*22\.13\.0/, "CI Node jobs must use the repository-pinned Node toolchain");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo test --locked --workspace/, "CI Rust tests must use the locked dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo test --locked -p secure-auth-actix/, "CI must run the Actix adapter contract tests");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /pnpm --dir packages\/server-node typecheck/, "CI must typecheck the Node server adapter");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /pnpm --dir packages\/server-node test/, "CI must run the Node server adapter contract tests");
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
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-signed-release-evidence/, "CI must validate signed-release evidence emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-independent-review-fragment/, "CI must validate independent-review fragment emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-ci-gate-evidence/, "CI must validate CI gate evidence emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:emit-web-browser-evidence/, "CI must validate web browser evidence emission");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-keypad-ci-release-evidence/, "CI must retain an aggregated release evidence artifact");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /emit-web-browser-evidence\.mjs/, "CI must emit a validator-compatible web browser evidence record");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:device-evidence/, "CI must validate the machine-readable device evidence contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Android presentation accessibility contract/, "CI must execute the Android presentation accessibility contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Android input-key randomization contract/, "CI must execute the Android input-key randomization contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /SecureKeypadRandomizationContractTest\.kt/, "CI must compile and run the Android input-key randomization contract test");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /web-browser-matrix/, "CI must include a real browser adapter smoke matrix");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /playwright install --with-deps/, "CI browser smoke must install its pinned browser runtime explicitly");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:web-browser/, "CI browser smoke must execute the checked-in runtime harness");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-keypad-browser-smoke-\$\{\{ matrix\.browser \}\}/, "CI browser smoke must retain per-browser evidence artifacts");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /if: always\(\)[\s\S]{0,240}secure-keypad-browser-smoke/, "CI browser smoke evidence must upload after failures");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Retain Android emulator runtime evidence[\s\S]{0,400}secure-keypad-android-emulator-runtime[\s\S]{0,240}retained\/android-emulator-runtime/, "CI aggregate must retain Android emulator runtime evidence");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Retain iOS simulator runtime evidence[\s\S]{0,400}secure-keypad-ios-simulator-runtime[\s\S]{0,240}retained\/ios-simulator-runtime/, "CI aggregate must retain iOS Simulator runtime evidence");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Retain fuzz and LeakSanitizer campaign logs[\s\S]{0,400}secure-keypad-fuzz-logs[\s\S]{0,240}retained\/fuzz-logs/, "CI aggregate must retain fuzz and LeakSanitizer logs");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Retain dependency metadata[\s\S]{0,400}secure-keypad-dependency-metadata[\s\S]{0,240}retained\/dependency-metadata/, "CI aggregate must retain dependency metadata");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-host-build/, "CI must include a Flutter host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /react-native-host-build/, "CI must include a React Native host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Stage bundled Flutter Android FFI artifacts/, "Flutter host CI must exercise the bundled Android FFI fallback");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /Stage bundled React Native Android FFI artifacts/, "React Native host CI must exercise the bundled Android FFI fallback");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ios-host-builds/, "CI must include iOS host-link build gates");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ios-simulator-runtime/, "CI must retain iOS Simulator runtime smoke evidence");
  const iosRuntimeSmoke = source("scripts/ios-simulator-runtime-smoke.sh", findings);
  requireText(findings, "scripts/ios-simulator-runtime-smoke.sh", iosRuntimeSmoke, /simctl install/, "iOS runtime smoke must install the generated host app through simctl");
  requireText(findings, "scripts/ios-simulator-runtime-smoke.sh", iosRuntimeSmoke, /simctl launch/, "iOS runtime smoke must launch the generated host app through simctl");
  requireText(findings, "scripts/ios-simulator-runtime-smoke.sh", iosRuntimeSmoke, /simctl io[^\n]*screenshot/, "iOS runtime smoke must capture a simulator screenshot artifact");
  requireText(findings, "scripts/ios-simulator-runtime-smoke.sh", iosRuntimeSmoke, /test -s "\$SCREENSHOT_PATH"/, "iOS runtime smoke must reject an empty screenshot artifact");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /android-host-runtime-smoke/, "CI must retain Android emulator runtime smoke evidence");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /reactivecircus\/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d/, "Android emulator runtime smoke must use an immutable action revision");
  const androidRuntimeSmoke = source("scripts/android-emulator-runtime-smoke.sh", findings);
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeSmoke, /adb install/, "Android runtime smoke must install the generated host APK");
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeSmoke, /cmd package resolve-activity/, "Android runtime smoke must resolve the APK launcher activity");
  requireText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeSmoke, /adb shell am start -W/, "Android runtime smoke must start the resolved launcher activity explicitly");
  forbidText(findings, "scripts/android-emulator-runtime-smoke.sh", androidRuntimeSmoke, /adb shell monkey/, "Android runtime smoke must not rely on monkey's non-deterministic exit status");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /SecureKeypadController\(\)/, "Flutter host smoke app must compile the native controller contract");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /controller: controller/, "Flutter host smoke app must link the controller to the PlatformView");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cancelRequest=\{0\}/, "React Native host smoke app must compile the native cancel prop");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-version:\s*['"]3\.47\.0['"]/, "CI must pin the Flutter host-build toolchain");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter build apk --debug --target-platform android-arm64,android-x64/, "Flutter host artifact must bundle every supported Android target platform");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /--version 0\.87\.0/, "CI must pin the React Native host-build version");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo build --locked --release -p secure-ffi/, "native host gates must use the locked Rust dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-runs=1000000/, "CI must retain the extended fuzz stability campaign");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-rss_limit_mb=1024/, "CI fuzz campaigns must have a bounded RSS guard");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /fuzz:\n[\s\S]{0,220}timeout-minutes:\s*60/, "CI fuzz and LeakSanitizer campaigns must have a 60-minute job budget");
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
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /pnpm --dir packages\/server-node pack --dry-run/, "CI must inspect the publishable Node server npm tarball");
  const reactNativeAndroidBuild = source("packages/react-native/android/build.gradle", findings);
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAndroidBuild, /externalNativeBuild/, "React Native package must retain its native Android build boundary");
  const customizationGuide = source("docs/CUSTOMIZATION-EXAMPLES.md", findings);
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy: InputPolicy\.hangul/, "customization guide must cover Hangul native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy=\"ascii\"/, "customization guide must cover printable-ASCII native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /DEFAULT_THEME/, "customization guide must cover branded themes");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /randomizeInputKeys: true/, "customization guide must cover native input-key randomization");
  forbidText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /(?:password|secret)\s*[:=][^\n]*(?:String|value|input)/i, "customization examples must not define a secret value channel");
  const contractsSource = source("packages/contracts/src/index.ts", findings);
  requireText(findings, "packages/contracts/src/index.ts", contractsSource, /randomizeInputKeys\?: boolean/, "layout contract must expose explicit input-key randomization");
  const randomizationAndroidView = source("native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", findings);
  requireText(findings, "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", randomizationAndroidView, /java\.security\.SecureRandom/, "Android input-key randomization must use a platform CSPRNG");
  requireText(findings, "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", randomizationAndroidView, /presentationRows\(layout\.rows, layout\.randomizeInputKeys\)/, "Android renderer must apply the randomization option at render time");
  const randomizationIosView = source("native/ios/SecureKeypadView.swift", findings);
  requireText(findings, "native/ios/SecureKeypadView.swift", randomizationIosView, /SystemRandomNumberGenerator/, "iOS input-key randomization must use a platform CSPRNG");
  requireText(findings, "native/ios/SecureKeypadView.swift", randomizationIosView, /presentationRows\(layout\.rows, randomizeInputKeys: layout\.randomizeInputKeys\)/, "iOS renderer must apply the randomization option at render time");
  const rootPackage = source("package.json", findings);
  requireText(findings, "package.json", rootPackage, /"playwright"\s*:\s*"1\.62\.1"/, "browser runtime verification must use an exact Playwright version");
  requireText(findings, "package.json", rootPackage, /"test:web-browser"/, "the workspace must expose the browser runtime smoke gate");
  requireText(findings, "package.json", rootPackage, /"test:expo-development-build"/, "the workspace must expose the Expo development-build contract test");
  requireText(findings, "package.json", rootPackage, /"test:release-bundle"/, "the workspace must expose the release staging inspector test");
  requireText(findings, "package.json", rootPackage, /"test:emit-release-artifact-fragment"/, "the workspace must expose the release artifact fragment test");
  requireText(findings, "package.json", rootPackage, /"test:release-archive"/, "the workspace must expose the signed archive contract test");
  for (const file of ["packages/contracts/package.json", "packages/web/package.json", "packages/server-node/package.json"]) {
    const packageManifest = source(file, findings);
    requireText(findings, file, packageManifest, /"files"\s*:\s*\[[^\]]*"LICENSE"/, "publishable npm packages must include their license file");
  }
  for (const file of ["packages/contracts/LICENSE", "packages/web/LICENSE", "packages/server-node/LICENSE"]) {
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
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /MAX_RELEASE_MANIFEST_BYTES/, "release evidence CLI must bound the top-level manifest before parsing");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /readBoundedManifest/, "release evidence CLI must use the bounded manifest reader");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /REQUIRED_RELEASE_GATES/, "release tooling must enumerate mandatory production evidence gates");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /native-checksum-android/, "release evidence must require the Android native checksum artifact");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /must use a distinct public key from the maintainer release signature/, "release evidence must require an independent reviewer key");
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
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /lstatSync\(cursor\)/, "release evidence must reject symlinked referenced files");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /must not resolve through symbolic links/, "release evidence must fail closed on symlink traversal");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /readBoundedFile/, "release tooling must bound referenced evidence reads before hashing or signature verification");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /MAX_RELEASE_ARTIFACT_BYTES/, "release tooling must bound release artifact materialization");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /ED25519_SIGNATURE_BYTES/, "release tooling must bound detached signature materialization");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /sentinel|input\(\?:Value\|Text\|Bytes\)/, "release evidence must reject sentinel and raw-input field names");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyGateEvidenceRecord/, "release tooling must bind embedded gate evidence records");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /DEVICE_RELEASE_GATE_POLICIES/, "release tooling must map device gates to their expected platforms");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /validateDeviceEvidence/, "release tooling must revalidate embedded device evidence records");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyDeviceEvidenceFiles/, "release tooling must verify nested device evidence digests");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /verifyNativeChecksumBinding/, "release tooling must bind physical native checksums to candidate artifacts");
  requireText(findings, "scripts/check-release-evidence.mjs", releaseEvidenceCheck, /expectedHostModeVersions/, "release tooling must bind physical host modes to manifest toolchain versions");
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
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /secure-keypad-ios-ffi\.sha256/, "release staging must require the verified native FFI checksum manifest");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /validateIosFfiChecksum/, "release staging must verify the iOS FFI checksum manifest against signed package bytes");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /secure-keypad-ios-ffi\.commit/, "release staging must bind iOS FFI checksums to the requested commit");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /MAX_NATIVE_CHECKSUM_MANIFEST_BYTES/, "release staging must bound native checksum manifest materialization");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /secure-keypad-android-ffi\.sha256/, "release staging must require the verified Android FFI checksum manifest");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /validateAndroidFfiChecksum/, "release staging must verify the Android FFI checksum manifest against signed-source paths");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /source\/secure-keypad-android-ffi\.commit/, "release staging must retain the Android FFI commit binding in the signed source bundle");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /must contain the release candidate commit followed by one newline/, "release staging must verify the Android FFI commit binding content");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /MAX_NATIVE_COMMIT_BINDING_BYTES/, "release staging must bound Android FFI commit binding materialization");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /checksum does not match/, "release staging must reject Android FFI checksum mismatches");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /native-artifacts\/android\/arm64-v8a\/libsecure_ffi\.a/, "release staging must require the verified Android arm64 FFI library");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /native-artifacts\/android\/x86_64\/libsecure_ffi\.a/, "release staging must require the verified Android x86_64 FFI library");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /packages\/flutter\/android\/secure_ffi\/arm64-v8a\/libsecure_ffi\.a/, "release staging must require the packaged Flutter Android arm64 FFI library");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /package\/android\/secure_ffi\/x86_64\/libsecure_ffi\.a/, "release staging must require the packaged React Native Android x86_64 FFI library");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /validatePackagedIosFfi/, "release staging must compare packaged iOS FFI bytes with signed source");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /validatePackagedAndroidFfi/, "release staging must compare packaged Android FFI bytes with signed source");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /packaged bytes do not match signed source/, "release staging must reject tampered packaged Android FFI bytes");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /THIRD-PARTY-NOTICES\.md/, "release staging must require third-party notices");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /private signing material/, "release staging must reject private signing material");
  requireText(findings, "scripts/check-release-bundle.mjs", releaseBundleCheck, /only regular files are allowed in release staging/, "release staging must reject non-regular filesystem entries");
  requireText(findings, ".github/workflows/release-candidate.yml", releaseWorkflow, /scripts\/check-release-bundle\.mjs\s+\"\$RELEASE_DIR\"/, "release workflow must inspect staging before creating the signed archive");
  const releaseArchiveCheck = source("scripts/check-release-archive.mjs", findings);
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /validateReleaseArchiveEntries/, "release tooling must inspect the signed archive entry contract");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /secure-keypad-android-ffi\.commit/, "signed archive validation must require the Android FFI commit binding");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /-tvzf/, "signed archive validation must inspect tar entry types");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /must not contain symbolic links/, "signed archive validation must reject symbolic links");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /only regular files and directories/, "signed archive validation must reject non-regular entries");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /secure-keypad-react-native/, "signed archive validation must cover the publishable React Native package");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /secure_ffi\.xcframework/, "signed archive validation must cover publishable native FFI contents");
  requireText(findings, "scripts/check-release-archive.mjs", releaseArchiveCheck, /archive entry must be unique/, "signed archive validation must reject duplicate paths");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-bundle/, "CI must execute the release staging inspector contract test");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-archive/, "CI must execute the signed archive contract test");
  const releaseEvidenceMerge = source("scripts/merge-release-evidence.mjs", findings);
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /mergeReleaseEvidence/, "release tooling must merge evidence fragments through one policy function");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /duplicate release gate|duplicate release artifact/, "release evidence merging must reject duplicate claims");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /independentReview/, "release evidence merging must preserve the independent reviewer attestation");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /realpathSync/, "release evidence merging must contain fragment and output paths");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /pathHasSymlinkComponent/, "release evidence merging must reject symlink traversal");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /MAX_RELEASE_FRAGMENT_BYTES/, "release evidence merging must bound fragment materialization");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /statSync/, "release evidence merging must inspect fragment size before reading");
  requireText(findings, "scripts/merge-release-evidence.mjs", releaseEvidenceMerge, /verifyReleaseEvidenceFiles/, "release evidence merging must verify referenced files after assembly");
  requireText(findings, "package.json", rootPackage, /"test:merge-release-evidence"/, "the workspace must expose the release evidence merge test");
  requireText(findings, "package.json", rootPackage, /"test:emit-release-gate-evidence"/, "the workspace must expose the release gate fragment emitter test");
  requireText(findings, "package.json", rootPackage, /"test:emit-native-device-evidence"/, "the workspace must expose the native device evidence emitter test");
  requireText(findings, "package.json", rootPackage, /"test:emit-independent-review-fragment"/, "the workspace must expose the independent review fragment emitter test");
  requireText(findings, "package.json", rootPackage, /"test:stage-release-evidence"/, "the workspace must expose the release evidence staging test");
  const releaseEvidenceEmitter = source("scripts/emit-release-gate-evidence.mjs", findings);
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /currentCommit/, "release evidence emitter must derive the commit from the checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /"status",\s*"--porcelain/, "release evidence emitter must require a clean checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /currentPackageVersion/, "release evidence emitter must derive the package version from the checkout");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /createHash\("sha256"\)/, "release evidence emitter must hash exact evidence bytes");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /secret-bearing evidence fields/, "release evidence emitter must reject secret-bearing evidence fields");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /match the fragment gate/, "release evidence emitter must reject cross-gate evidence reuse");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /MAX_GATE_EVIDENCE_BYTES/, "release evidence emitter must bound gate evidence materialization");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /readBoundedEvidenceFile/, "release evidence emitter must bound evidence files before reading");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /pathHasSymlinkComponent/, "release evidence emitter must reject symlink traversal");
  requireText(findings, "scripts/emit-release-gate-evidence.mjs", releaseEvidenceEmitter, /sentinel|input\(\?:Value\|Text\|Bytes\)/, "release evidence emitter must reject sentinel and raw-input field names");
  const browserEvidenceEmitter = source("scripts/emit-web-browser-evidence.mjs", findings);
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", browserEvidenceEmitter, /MAX_DEVICE_EVIDENCE_FILE_BYTES/, "browser evidence emitter must bound log materialization");
  requireText(findings, "scripts/emit-web-browser-evidence.mjs", browserEvidenceEmitter, /readBoundedBrowserLog/, "browser evidence emitter must bound log files before reading");
  const releaseSigner = source("scripts/sign-release.mjs", findings);
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /asymmetricKeyType !== \"ed25519\"/, "release signing must reject non-Ed25519 keys");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /private key is read only/i, "release signing must not copy or log the private key");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /MAX_RELEASE_ARTIFACT_BYTES/, "release signing must bound release artifact materialization");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /readBoundedFile/, "release signing must bound files before reading");
  requireText(findings, "scripts/sign-release.mjs", releaseSigner, /sign\(null, artifact, privateKey\)/, "release signing must create a detached signature over the artifact");
  const signedReleaseEvidence = source("scripts/emit-signed-release-evidence.mjs", findings);
  requireText(findings, "scripts/emit-signed-release-evidence.mjs", signedReleaseEvidence, /verify\(null, bundle, publicKey, signature\)/, "signed-release evidence must verify the detached signature");
  requireText(findings, "scripts/emit-signed-release-evidence.mjs", signedReleaseEvidence, /bundleSha256|signatureSha256|publicKeySha256/, "signed-release evidence must hash every signed artifact");
  requireText(findings, "scripts/emit-signed-release-evidence.mjs", signedReleaseEvidence, /currentCommit/, "signed-release evidence must bind to the current checkout commit");
  requireText(findings, "scripts/emit-signed-release-evidence.mjs", signedReleaseEvidence, /pathHasSymlinkComponent/, "signed-release evidence must reject symlink traversal");
  const releaseArtifactFragment = source("scripts/emit-release-artifact-fragment.mjs", findings);
  requireText(findings, "scripts/emit-release-artifact-fragment.mjs", releaseArtifactFragment, /buildReleaseArtifactFragment/, "release artifact evidence must derive a sanitized hashed fragment");
  requireText(findings, "scripts/emit-release-artifact-fragment.mjs", releaseArtifactFragment, /MAX_RELEASE_ARTIFACT_BYTES/, "release artifact evidence must bound file materialization");
  requireText(findings, "scripts/emit-release-artifact-fragment.mjs", releaseArtifactFragment, /pathHasSymlinkComponent/, "release artifact evidence must reject symlink traversal");
  requireText(findings, "scripts/emit-release-artifact-fragment.mjs", releaseArtifactFragment, /flag:\s*["']wx["']/, "release artifact evidence must create fragments exclusively");
  requireText(findings, "scripts/emit-release-artifact-fragment.mjs", releaseArtifactFragment, /PRIVATE_MATERIAL_PATH/, "release artifact evidence must reject private or secret paths");
  const signedReleaseFragment = source("scripts/emit-signed-release-fragment.mjs", findings);
  requireText(findings, "scripts/emit-signed-release-fragment.mjs", signedReleaseFragment, /buildSignedReleaseFragment/, "signed-release finalization must preserve gate, artifact, and detached-signature descriptors");
  requireText(findings, "scripts/emit-signed-release-fragment.mjs", signedReleaseFragment, /MAX_GATE_EVIDENCE_BYTES/, "signed-release fragment conversion must bound record materialization");
  requireText(findings, "scripts/emit-signed-release-fragment.mjs", signedReleaseFragment, /pathHasSymlinkComponent/, "signed-release fragment conversion must reject symlink traversal");
  requireText(findings, "scripts/emit-signed-release-fragment.mjs", signedReleaseFragment, /flag:\s*["']wx["']/, "signed-release fragment conversion must create outputs exclusively");
  const stagedReleaseEvidence = source("scripts/stage-release-evidence.mjs", findings);
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /pathHasSymlinkComponent/, "release evidence staging must reject symlink traversal");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /COPYFILE_EXCL/, "release evidence staging must avoid overwriting downloaded inputs");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /duplicate release evidence path/, "release evidence staging must reject duplicate paths");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /only regular files are allowed/, "release evidence staging must reject special files");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /PRIVATE_MATERIAL_PATH/, "release evidence staging must reject private or secret file inputs");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /MAX_STAGED_FILE_BYTES/, "release evidence staging must bound each untrusted input file");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /MAX_STAGED_TOTAL_BYTES/, "release evidence staging must bound combined untrusted input size");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /MAX_STAGED_FILE_COUNT/, "release evidence staging must bound untrusted input file count");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /MAX_STAGED_DIRECTORY_COUNT/, "release evidence staging must bound untrusted input directory count");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /MAX_STAGED_PATH_DEPTH/, "release evidence staging must bound untrusted input path depth");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /opendirSync/, "release evidence staging must stream directory entries instead of materializing untrusted directories");
  requireText(findings, "scripts/stage-release-evidence.mjs", stagedReleaseEvidence, /candidate signed-release evidence is missing/, "release evidence staging must require the candidate signing record");

  return findings;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const findings = runSecurityAudit();
  for (const finding of findings) {
    process.stderr.write(`${finding.rule}: ${finding.file}: ${finding.detail}\n`);
  }
  process.exitCode = findings.length === 0 ? 0 : 1;
}
