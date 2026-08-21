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
  }

  const ffiHeader = source("crates/secure-ffi/include/secure_keypad.h", findings);
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_submission_free/, "C ABI must expose submission ownership release");
  requireText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /secure_keypad_client_login_start/, "C ABI must expose native-only auth handoff");
  forbidText(findings, "crates/secure-ffi/include/secure_keypad.h", ffiHeader, /\bsecure_keypad_[a-z0-9_]*(?:password|secret|get_value|value_bytes)[a-z0-9_]*\s*\(/i, "C ABI must not define a secret getter");

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
  forbidText(findings, "crates/secure-auth-axum/src/lib.rs", axum, /X-Forwarded-Proto|x-forwarded-proto/i, "Axum adapter must not parse forwarded transport headers");

  const webauthnHttp = source("crates/secure-webauthn-example/src/lib.rs", findings);
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /pub struct WebAuthnDeploymentContext/, "WebAuthn HTTP routes must require an explicit deployment context");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WebAuthnTransportSecurity::TrustedProxyTls/, "WebAuthn HTTP routes must define trusted-proxy TLS handling");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /connection_limits_enforced/, "WebAuthn HTTP routes must require connection/read limits");
  requireText(findings, "crates/secure-webauthn-example/src/lib.rs", webauthnHttp, /WEBAUTHN_RESPONSE_SECURITY_HEADERS/, "WebAuthn responses must carry cache and MIME security headers");

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
  const customizationGuide = source("docs/CUSTOMIZATION-EXAMPLES.md", findings);
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /inputPolicy: InputPolicy\.hangul/, "customization guide must cover Hangul native input");
  requireText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /DEFAULT_THEME/, "customization guide must cover branded themes");
  forbidText(findings, "docs/CUSTOMIZATION-EXAMPLES.md", customizationGuide, /(?:password|secret)\s*[:=][^\n]*(?:String|value|input)/i, "customization examples must not define a secret value channel");

  return findings;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const findings = runSecurityAudit();
  for (const finding of findings) {
    process.stderr.write(`${finding.rule}: ${finding.file}: ${finding.detail}\n`);
  }
  process.exitCode = findings.length === 0 ? 0 : 1;
}
