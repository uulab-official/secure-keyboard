# Compatibility and version policy

The SDK has separate UI, native ABI, and authentication protocol versions.
Consumers must pin all three in a release pipeline; updating a framework
package must not silently update the authentication suite.

| Surface | Current release contract | Compatibility rule |
|---|---|---|
| Rust toolchain | `rust-toolchain.toml` (`1.97.1`); workspace MSRV `1.88` | Build the Rust core/FFI and native host integration from the same commit. The locked dependency graph and CI MSRV job are required to remain compatible with Rust `1.88`. |
| Native SDK | [`native/sdk-contract.json`](../native/sdk-contract.json); version `0.1.0`; iOS 15.1+; Android API 24+; Android `arm64-v8a`/`x86_64` | Build the iOS Swift/XCFramework or Android Kotlin/JNI/AAR surface and `secure-ffi` artifacts from one commit. React Native and Flutter wrappers must consume the matching native contract and must not introduce a second security implementation. |
| Native session defaults | 8 input tokens; 60-second monotonic inactivity timeout | RN and Flutter use the same bounded defaults when the host omits overrides. A host may choose a smaller or larger value only within the native `1..=4096` token and `1ms..=24h` timeout contract. |
| C ABI | `SECURE_KEYPAD_ABI_VERSION = 2`; `secure_keypad_abi_version()` | A native host must compare the linked library's `secure_keypad_abi_version()` with the header constant and reject an ABI mismatch before creating a session. The shipped iOS view and Android JNI bridge perform this check and fail closed. Version 2 adds native-only OPAQUE registration handoff; version 1 hosts cannot claim registration memory-safety coverage. |
| OPAQUE | `opaque-ke = 4.0.1`; suite `opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2` | Pin the protocol version, suite, and server key ID. Rotation may allow only the explicitly configured active/previous key window. |
| Axum server adapter | package `0.1.0`; `axum = 0.8.9`; optional `webauthn` feature | Use the workspace lockfile, pass a validated deployment context, provide request-parts CSRF validation callbacks for OPAQUE and WebAuthn, resolve WebAuthn principals from host-session request parts only, and keep TLS/proxy, rate-limit, session, and durable-store policy in the host application. |
| Actix Web server adapter | package `0.1.0`; `actix-web = 4.11.0`; optional `webauthn` feature | Use the workspace lockfile, pass a validated deployment context, provide request-parts CSRF validation callbacks, resolve passkey principals from host-session metadata only, and keep TLS/proxy, rate-limit, session, and durable-store policy in the host application. |
| Node/TypeScript server adapter | package `0.1.0`; HTTP transport contract `1`; OPAQUE protocol version `1`; suite `opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2`; Node Web Fetch APIs; TypeScript `5.9.3` in the workspace lockfile | Use `@secure-keypad/server-node` only as a bounded transport bridge to the pinned Rust/native OPAQUE service. Its `NODE_SERVER_CONTRACT_VERSION` must match Rust `HTTP_CONTRACT_VERSION`, and its OPAQUE protocol/suite metadata must match the Rust reference; the parity tests/checks are release gates. Supply host-validated TLS/proxy facts and CSRF/origin validation; financial routes must use `securityProfile: "financial"` with a fresh context and server-verified, provider/subject/operation/nonce/deployment-bound evidence. The host still needs a shared atomic nonce store; never treat JavaScript memory as a secure secret boundary or implement OPAQUE in application JavaScript. |
| WebAuthn example | `webauthn-rs = 0.5.4` plus server-only `danger-allow-state-serialisation` | Keep the verifier and serialized ceremony/credential formats under one lockfile. Use `WebAuthnService<C, S>` with protected durable stores before deployment; never serialize ceremony state client-side. |
| React Native | package `0.1.0`; peer `react-native >=0.76` | Compile the package native sources against the exact host RN/React versions and install a native submission consumer. Expo Go is unsupported. |
| Flutter | package `0.1.0`; Flutter `>=3.44.0`; Dart `>=3.12.0 <4.0.0` | Uses the built-in Kotlin compiler contract for AGP 9 compatibility. Run `flutter analyze`, `flutter test`, and a host app build with the selected stable Flutter/AGP toolchain. `SecureKeypadController.cancel()` carries no input; `pressKey(keyId)` is available only in explicitly acknowledged lower-assurance Headless Host Mode. |
| iOS | iOS 15.1 minimum for the current React Native 0.87 host integration and UIKit configuration APIs; runtime/security floor is machine-readable in `docs/PLATFORM-SUPPORT.json` | Ship matching device/simulator Rust static libraries, record `securityPatchLevel`, attach the hashed `platform-security-patch` artifact, and verify background/capture masking on supported OS versions. |
| Android | API 24 minimum; CMake 3.22.1 contract; release ABIs `arm64-v8a`, `x86_64`; security patch floor is machine-readable in `docs/PLATFORM-SUPPORT.json` | Ship `libsecure_ffi.a` for every selected ABI, record `apiLevel` and `securityPatchLevel`, attach the hashed `platform-security-patch` artifact, and verify `android.builtInKotlin`/host Gradle compatibility. |

The independent `pnpm security-audit` gate also compares the C header macro,
Rust implementation constant, and every shipped iOS/Android host expectation;
a native ABI version bump is therefore rejected until all framework mirrors are
updated together. Native views independently repeat the public layout bounds
and reject public labels over 16 UTF-8 bytes, accessibility labels over 80
UTF-8 bytes, or non-finite/out-of-range theme dimensions before allocating UI
or creating a session, so direct native consumers cannot bypass the
configuration contract by skipping a framework adapter.

The React Native `cancelRequest` prop is a non-negative safe integer command
token; its first value establishes a baseline, a greater value cancels the
native session, an equal value is ignored, and a lower value is rejected as a
stale command. Neither framework controller path transports a secret or
opaque submission handle. Headless key-press tokens use the same lifetime
boundary: their replay floor belongs to the native view instance and survives
session/lifecycle reconfiguration.

## Upgrade procedure

1. Review the lockfile and this matrix together; do not update `opaque-ke`,
   `webauthn-rs`, or the C ABI independently of the release notes.
2. Run `cargo audit`, `pnpm test:native-parity`,
   `pnpm check:native-parity`, `pnpm test:http-contract-version-parity`, and
   `pnpm check:http-contract-version-parity` before building framework
   packages, followed by
   `pnpm test:security-audit` and `pnpm security-audit`.
3. Rebuild `secure_ffi` for every target ABI and verify the host's static
   library checksum against the release manifest.
4. Run the full Rust/JS/Flutter gates, then the RN and Flutter host app builds
   and device matrix.
5. Have an independent reviewer re-run the MASVS evidence map and sign the
   exact commit, SBOM, native artifacts, and residual-risk list.
