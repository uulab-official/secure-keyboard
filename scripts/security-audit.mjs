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
    /layout|theme|inputPolicy|maxTokens|timeoutMs|onMaskedStateChange|onResult/g,
    "RN public props must be explicitly enumerated",
  );
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
  requireText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /toPlatformCreationParams/, "Flutter must have an explicit public creation map");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /TextEditingController/, "Flutter must not use a text editing controller");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter, /final\s+(?:String\??)\s+(?:value|password|secret)\b/i, "Flutter configuration must not hold a secret string field");
  forbidText(findings, "packages/flutter/lib/secure_keypad.dart", flutter.match(/toPlatformCreationParams\(\)[\s\S]*?\n  \}/)?.[0] ?? "", /onResult|onMaskedStateChanged/, "Flutter native creation params must not serialize callbacks");

  const authDebug = source("crates/secure-auth/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth/src/lib.rs", authDebug, /impl core::fmt::Debug for AuthEnvelope/, "OPAQUE transport Debug must be manually redacted");
  requireText(findings, "crates/secure-auth/src/lib.rs", authDebug, /field\("payload_len", &self\.payload\.len\(\)\)/, "OPAQUE transport Debug may expose payload length only");
  forbidText(findings, "crates/secure-auth/src/lib.rs", authDebug, /#\[derive\(Debug,\s*Serialize\)\][\s\S]{0,120}pub struct AuthEnvelope/, "OPAQUE transport must not derive Debug over its payload");
  const webauthnDebug = source("crates/secure-webauthn-example/src/lib.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /impl core::fmt::Debug for CeremonyStart/, "WebAuthn ceremony Debug must be manually redacted");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /field\("handle_len", &self\.handle\.len\(\)\)/, "WebAuthn ceremony Debug may expose handle length only");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /field\("options", &"<redacted>"\)/, "WebAuthn ceremony Debug must redact browser options");
  forbidText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnDebug, /#\[derive\(Debug,\s*Serialize\)\][\s\S]{0,160}pub struct CeremonyStart/, "WebAuthn ceremony must not derive Debug over its handle or options");

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
    forbidText(findings, file, contents, /submission\.close\(\)[\s\S]{0,100}(?:code.*success|success.*code)/, "framework bridge must not report success after unconditional release");
  }

  for (const file of [
    "native/ios/SecureKeypadView.swift",
    "packages/react-native/ios/SecureKeypadView.swift",
    "packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /takeOpaqueHandle\(\)/, "iOS native submission must have an opaque transfer API");
    requireText(findings, file, contents, /public enum SecureKeypadNativeSubmissionRouter/, "iOS native handoff must be explicitly routed");
  }
  for (const file of [
    "native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "packages/react-native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
    "packages/flutter/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /takeNativeHandle\(\)/, "Android native submission must have an opaque transfer API");
    requireText(findings, file, contents, /object SecureKeypadNativeSubmissionRouter/, "Android native handoff must be explicitly routed");
    requireText(findings, file, contents, /findActivity\(\)/, "Android secure-window protection must resolve wrapped host contexts");
    requireText(findings, file, contents, /FLAG_SECURE/, "Android native keypad must enable secure-window protection");
    requireText(findings, file, contents, /IMPORTANT_FOR_AUTOFILL_NO/, "Android native keypad must opt out of autofill");
    forbidText(findings, file, contents, /\bEditText\b/, "Android native keypad must not use an editable text widget");
  }
  for (const file of [
    "native/ios/SecureKeypadView.swift",
    "packages/react-native/ios/SecureKeypadView.swift",
    "packages/flutter/ios/Classes/SecureKeypadView.swift",
  ]) {
    const contents = source(file, findings);
    requireText(findings, file, contents, /UIApplication\.willResignActiveNotification/, "iOS native keypad must mask while inactive");
    requireText(findings, file, contents, /UIScreen\.capturedDidChangeNotification/, "iOS native keypad must react to screen capture");
    requireText(findings, file, contents, /refreshProtectionState\(\)/, "iOS native keypad must recompute protection across lifecycle transitions");
    requireText(findings, file, contents, /didMoveToWindow\(\)/, "iOS native keypad must recompute protection when attached to a captured window");
    requireText(findings, file, contents, /secureKeypadShouldProtectPresentation\(/, "iOS native keypad must preserve protection while capture remains active");
    requireText(findings, file, contents, /protectedPresentation/, "iOS native keypad must have a protected presentation state");
    forbidText(findings, file, contents, /\bUITextField\b/, "iOS native keypad must not use an editable text widget");
  }

  const ffiHeader = source("crates/secure-ffi/include/secure_keypad.h", findings);
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_submission_free/, "C ABI must expose submission ownership release");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_client_login_start/, "C ABI must expose native-only auth handoff");
  forbidText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /\bsecure_keypad_[a-z0-9_]*(?:password|secret|get_value|value_bytes)[a-z0-9_]*\s*\(/i, "C ABI must not define a secret getter");

  const coreBuffer = source("crates/secure-core/src/secret_buffer.rs", findings);
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /SecretTokenBuffer/, "core must keep secret token storage behind a dedicated buffer type");
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /tokens\[self\.len\]\.zeroize\(\)/, "core must zeroize tokens removed by backspace");
  requireText(findings, "crates/secure-core/src/secret_buffer.rs", coreBuffer, /Box<\[u32\]>/, "core token storage must avoid secret-bearing Vec reallocation");
  const coreInput = source("crates/secure-core/src/input.rs", findings);
  requireText(findings, "crates/secure-core/src/input.rs", coreInput, /MAX_INPUT_TOKENS/, "core input policy must retain a bounded token limit");
  requireText(findings, "crates/secure-core/src/input.rs", coreInput, /SecretBuffer::with_capacity/, "core rendered secret output must be preallocated");
  const coreHangul = source("crates/secure-core/src/hangul.rs", findings);
  requireText(findings, "crates/secure-core/src/hangul.rs", coreHangul, /bytes\.zeroize\(\)/, "core UTF-8 conversion must clear its temporary secret bytes");

  const auth = source("crates/secure-auth/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /opaque-ke-4\.0\.1-ristretto255-tripledh-sha512-argon2/, "OPAQUE suite must be pinned in the protocol contract");
  requireText(findings, "crates/secure-auth/src/lib.rs", auth, /MAX_JSON_BODY_BYTES: usize = 128 \* 1024/, "auth JSON body must be bounded");

  const web = source("packages/web/src/index.ts", findings);
  requireText(findings, "packages/web/src/index.ts", web, /WEB_FALLBACK_WARNING_CODE/, "Web fallback warning must be stable");
  requireText(findings, "packages/web/src/index.ts", web, /fallback-not-acknowledged/, "Web fallback must fail closed without acknowledgement");
  requireText(findings, "packages/web/src/index.ts", web, /createPasskey/, "Web adapter must expose passkey-first registration");
  forbidText(findings, "packages/web/src/index.ts", web, /\b(?:password|pin)\s*[:(]/i, "Web adapter must not expose a password/PIN API");

  const opaqueHttp = source("crates/secure-auth-http/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /pub struct HttpDeploymentContext/, "OPAQUE HTTP routes must require an explicit deployment context");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /TrustedProxyTls/, "OPAQUE HTTP routes must define trusted-proxy TLS handling");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /connection_limits_enforced/, "OPAQUE HTTP routes must require connection/read limits");
  requireText(findings, "crates/secure-auth-http/src/lib.rs", opaqueHttp, /RESPONSE_SECURITY_HEADERS/, "OPAQUE HTTP responses must carry cache and MIME security headers");

  const axum = source("crates/secure-auth-axum/src/lib.rs", findings);
  requireText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /to_bytes\(request\.into_body\(\), body_limit\)/, "Axum adapter must bound streaming request bodies before route parsing");
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
  const webauthnStorage = source("crates/secure-webauthn-example/src/storage.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub trait CeremonyStateStore/, "WebAuthn service must expose an injectable ceremony state backend contract");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /pub trait CredentialStore/, "WebAuthn service must expose an injectable credential backend contract");
  requireText(findings, "crates/secure-webauthn-example/src/storage.rs", webauthnStorage, /atomically delete and return|atomically consume/, "WebAuthn ceremony backend must document atomic consume semantics");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WEBAUTHN_CEREMONY_STATE_VERSION: u16 = 1/, "WebAuthn ceremony state format must be version-pinned");
  const webauthnManifest = source("crates/secure-webauthn-example/Cargo.toml", findings);
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /danger-allow-state-serialisation/, "WebAuthn state serialization must be an explicit pinned server dependency feature");
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /redis-backend/, "Redis storage must be explicitly feature-gated");
  requireText(findings, "crates/secure-webauthn-example/Cargo.toml", webauthnManifest, /postgres-backend/, "PostgreSQL storage must be explicitly feature-gated");
  const authServerManifest = source("crates/secure-auth-server/Cargo.toml", findings);
  requireText(findings, "crates/secure-auth-server/Cargo.toml", authServerManifest, /redis-backend/, "Redis rate limiting must be explicitly feature-gated");
  requireText(findings, "crates/secure-auth-server/Cargo.toml", authServerManifest, /postgres-backend/, "PostgreSQL rate limiting must be explicitly feature-gated");
  const redisRateLimit = source("crates/secure-auth-server/src/rate_limit_redis.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /RATE_LIMIT_SCRIPT/, "Redis rate limiting must use one atomic script");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /Sha256/, "Redis rate-limit keys must be hashed before storage");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_redis.rs", redisRateLimit, /rediss:\/\//, "Redis rate limiting must require TLS by default");
  const postgresRateLimit = source("crates/secure-auth-server/src/rate_limit_postgres.rs", findings);
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /POSTGRES_RATE_LIMIT_SCHEMA_SQL/, "PostgreSQL rate limiting must ship an explicit migration");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /pg_advisory_xact_lock/, "PostgreSQL rate limiting must serialize capacity/check updates");
  requireText(findings, "crates/secure-auth-server/src/rate_limit_postgres.rs", postgresRateLimit, /MakeTlsConnect/, "PostgreSQL rate limiting must accept an explicit TLS connector");
  const webauthnStorageGuide = source("docs/WEBAUTHN-STORAGE.md", findings);
  requireText(findings, "docs/WEBAUTHN-STORAGE.md", webauthnStorageGuide, /danger-allow-state-serialisation/, "WebAuthn storage guide must prohibit client-side ceremony state serialization");
  requireText(findings, "docs/WEBAUTHN-STORAGE.md", webauthnStorageGuide, /blocking adapters/, "WebAuthn storage guide must declare blocking adapter execution requirements");

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

  for (const mismatch of findNativePackageParityMismatches(ROOT)) {
    findings.push({ rule: "native-package-parity", file: mismatch.destination, detail: mismatch.reason });
  }

  const securitySpec = source("docs/SECURITY-SPEC.md", findings);
  requireText(findings, "docs/SECURITY-SPEC.md", securitySpec, /cannot guarantee that a password is absent from memory/, "security specification must document memory limitations");
  const releaseGates = source("docs/RELEASE-GATES.md", findings);
  requireText(findings, "docs/RELEASE-GATES.md", releaseGates, /independent[\s\S]{0,40}security review/i, "release gates must require independent review");
  const deviceVerification = source("docs/DEVICE-VERIFICATION.md", findings);
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /Physical devices are required/, "device verification must require physical-device coverage");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /FLAG_SECURE/, "device verification must cover Android screenshot protection");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /VoiceOver and TalkBack/, "device verification must cover accessibility surfaces");
  requireText(findings, "docs/DEVICE-VERIFICATION.md", deviceVerification, /replay, expired-state,[\s\S]*rate-limit/i, "device verification must cover server replay and rate-limit behavior");
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
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /dtolnay\/rust-toolchain@1\.97\.1/, "CI Rust jobs must use the repository-pinned toolchain");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /dtolnay\/rust-toolchain@stable/, "CI must not float on the stable Rust channel");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /node-version:.*22\.13\.0/, "CI Node jobs must use the repository-pinned Node toolchain");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /node-version:\s*22(?:\s|$)/, "CI must not float on an unpinned Node major version");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /27\.1\.12297006/, "Android host builds must use the repository-pinned NDK");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /ANDROID_NDK_LATEST_HOME|find[^\n]*SDK_ROOT\/ndk/, "Android host builds must not select an unpinned latest NDK");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /nightly-2026-08-19/, "Fuzz CI must use the repository-pinned nightly toolchain");
  forbidText(findings, ".github/workflows/ci.yml", ciWorkflow, /toolchain install nightly --|cargo \+nightly fuzz/, "Fuzz CI must not float on the nightly channel");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /durable_rate_limit/, "CI must run distributed rate-limit interoperability tests");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /test:release-version-parity/, "CI must test public release version parity");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /check:release-version-parity/, "CI must enforce public release version parity");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-host-build/, "CI must include a Flutter host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /react-native-host-build/, "CI must include a React Native host-link build gate");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /ios-host-builds/, "CI must include iOS host-link build gates");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /flutter-version:\s*['"]3\.47\.0['"]/, "CI must pin the Flutter host-build toolchain");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /--version 0\.87\.0/, "CI must pin the React Native host-build version");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cargo build --locked --release -p secure-ffi/, "native host gates must use the locked Rust dependency graph");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-runs=1000000/, "CI must retain the extended fuzz stability campaign");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /-rss_limit_mb=1024/, "CI fuzz campaigns must have a bounded RSS guard");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /shasum -a 256/, "CI must emit native artifact checksums");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cd \"\$RUNNER_TEMP\/secure_ffi\.xcframework\"/, "iOS checksum manifests must use artifact-relative paths");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /cd \"\$RUNNER_TEMP\/secure-keypad-ffi\"/, "Android checksum manifests must use artifact-relative paths");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-xcframework-and-checksum/, "CI must retain the native artifact checksum manifest");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-android-arm64-flutter-host-and-checksum/, "CI must retain the Flutter Android FFI checksum manifest");
  requireText(findings, ".github/workflows/ci.yml", ciWorkflow, /secure-ffi-android-arm64-react-native-host-and-checksum/, "CI must retain the React Native Android FFI checksum manifest");
  const reactNativeAndroidBuild = source("packages/react-native/android/build.gradle", findings);
  requireText(findings, "packages/react-native/android/build.gradle", reactNativeAndroidBuild, /externalNativeBuild/, "React Native package must retain its native Android build boundary");
  const customizationGuide = source("docs/CUSTOMIZATION-EXAMPLES.md", findings);
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy: InputPolicy\.hangul/, "customization guide must cover Hangul native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /DEFAULT_THEME/, "customization guide must cover branded themes");
  forbidText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /(?:password|secret)\s*[:=][^\n]*(?:String|value|input)/i, "customization examples must not define a secret value channel");
  const releaseVersionCheck = source("scripts/check-release-version-parity.mjs", findings);
  requireText(findings, "scripts/check-release-version-parity.mjs", releaseVersionCheck, /RELEASE_ARTIFACTS/, "release tooling must enumerate public artifacts for version parity");
  requireText(findings, "scripts/check-release-version-parity.mjs", releaseVersionCheck, /findReleaseVersionMismatches/, "release tooling must compare artifact versions");

  return findings;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const findings = runSecurityAudit();
  for (const finding of findings) {
    process.stderr.write(`${finding.rule}: ${finding.file}: ${finding.detail}\n`);
  }
  process.exitCode = findings.length === 0 ? 0 : 1;
}
