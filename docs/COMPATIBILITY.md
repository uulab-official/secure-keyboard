# Compatibility and version policy

The SDK has separate UI, native ABI, and authentication protocol versions.
Consumers must pin all three in a release pipeline; updating a framework
package must not silently update the authentication suite.

| Surface | Current release contract | Compatibility rule |
|---|---|---|
| Rust toolchain | `rust-toolchain.toml` (`1.97.1`) | Build the Rust core/FFI and native host integration from the same commit. The WebAuthn example remains compatible with workspace MSRV `1.85`. |
| C ABI | `SECURE_KEYPAD_ABI_VERSION = 2`; `secure_keypad_abi_version()` | A native host must compare the linked library's `secure_keypad_abi_version()` with the header constant and reject an ABI mismatch before creating a session. The shipped iOS view and Android JNI bridge perform this check and fail closed. Version 2 adds native-only OPAQUE registration handoff; version 1 hosts cannot claim registration memory-safety coverage. |
| OPAQUE | `opaque-ke = 4.0.1`; suite `opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2` | Pin the protocol version, suite, and server key ID. Rotation may allow only the explicitly configured active/previous key window. |
| Axum server adapter | package `0.1.0`; `axum = 0.8.9`; optional `webauthn` feature | Use the workspace lockfile, pass a validated deployment context, provide request-parts CSRF validation callbacks for OPAQUE and WebAuthn, resolve WebAuthn principals from host-session request parts only, and keep TLS/proxy, rate-limit, session, and durable-store policy in the host application. |
| WebAuthn example | `webauthn-rs = 0.5.4` plus server-only `danger-allow-state-serialisation` | Keep the verifier and serialized ceremony/credential formats under one lockfile. Use `WebAuthnService<C, S>` with protected durable stores before deployment; never serialize ceremony state client-side. |
| React Native | package `0.1.0`; peer `react-native >=0.76` | Compile the package native sources against the exact host RN/React versions and install a native submission consumer. Expo Go is unsupported. |
| Flutter | package `0.1.0`; Dart `>=3.4.0 <4.0.0` | Run `flutter analyze`, `flutter test`, and a host app build with the selected stable Flutter/AGP toolchain. `SecureKeypadController.cancel()` carries no input; `pressKey(keyId)` is available only in explicitly acknowledged lower-assurance Headless Host Mode. |
| iOS | iOS 15.1 minimum for the current React Native 0.87 host integration and UIKit configuration APIs | Ship matching device/simulator Rust static libraries and verify background/capture masking on supported OS versions. |
| Android | API 24 minimum; CMake 3.22.1 contract | Ship `libsecure_ffi.a` for every ABI and verify `android.builtInKotlin`/host Gradle compatibility. |

The independent `pnpm security-audit` gate also compares the C header macro,
Rust implementation constant, and every shipped iOS/Android host expectation;
a native ABI version bump is therefore rejected until all framework mirrors are
updated together. Native views independently repeat the public layout bounds
and reject public labels over 16 UTF-8 bytes, accessibility labels over 80
UTF-8 bytes, or non-finite/out-of-range theme dimensions before allocating UI
or creating a session, so direct native consumers cannot bypass the
configuration contract by skipping a framework adapter.

The React Native `cancelRequest` prop is a non-negative safe integer command
token; its first value establishes a baseline and each subsequent value
cancels the native session. Neither framework controller path transports a
secret or opaque submission handle.

## Upgrade procedure

1. Review the lockfile and this matrix together; do not update `opaque-ke`,
   `webauthn-rs`, or the C ABI independently of the release notes.
2. Run `pnpm test:native-parity` and `pnpm check:native-parity` before building
   framework packages, followed by `pnpm test:security-audit` and
   `pnpm security-audit`.
3. Rebuild `secure_ffi` for every target ABI and verify the host's static
   library checksum against the release manifest.
4. Run the full Rust/JS/Flutter gates, then the RN and Flutter host app builds
   and device matrix.
5. Have an independent reviewer re-run the MASVS evidence map and sign the
   exact commit, SBOM, native artifacts, and residual-risk list.
