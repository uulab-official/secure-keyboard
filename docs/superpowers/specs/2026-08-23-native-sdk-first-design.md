# Native SDK First Design

**Status:** Approved for implementation

**Goal:** Make the iOS and Android native keypad implementations the stable,
publishable security product, with Flutter and React Native limited to thin
framework adapters over the same native/core contract.

## Scope

This design covers the mobile native SDK boundary and its framework wrappers.
It does not claim that browser JavaScript is a secure memory boundary, and it
does not replace the required physical-device, sanitizer, signing, or
independent-review release evidence.

The first implementation slice will harden and package the existing native
sources instead of introducing a second security implementation. The canonical
sources remain:

- `native/ios/SecureKeypadView.swift` and its native presentation helpers;
- `native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt`
  and its native presentation helpers;
- `crates/secure-ffi/include/secure_keypad.h` and the `secure-ffi` Rust crate.

The publishable React Native and Flutter packages may contain copies required
by their package managers, but those copies must remain byte-for-byte mirrors
of the canonical native sources under the existing parity check.

## Architecture

```text
secure-core (Rust)
  -> secure-ffi (versioned C ABI, opaque handles)
      -> iOS SecureKeypadKit surface (Swift/UIKit + XCFramework)
      -> Android SecureKeypadKit surface (Kotlin/Java + AAR/JNI)
          -> React Native adapter
          -> Flutter PlatformView adapter
```

`secure-core` owns input policy, Hangul composition, session state, and
zeroization. `secure-ffi` owns the C ABI, pointer validation, ABI version,
opaque session/submission ownership, and native authentication handoff. The
platform SDK owns touch handling, masked presentation, lifecycle protection,
accessibility presentation, and platform screenshot/autofill controls.

React Native and Flutter receive only public layout/theme/policy data, masked
state, bounded error codes, and terminal result codes. They do not receive an
accumulated input string, secret byte array, opaque submission handle, or
native authentication callback payload.

## Native SDK contracts

### iOS

The public native surface is the existing UIKit view and native submission
types in `native/ios/SecureKeypadView.swift`:

- `SecureKeypadView.configureNumeric`, `configureAscii`, and
  `configureHangul` accept only bounded public layout/theme values;
- `SecureKeypadView` renders native controls and only masked length/state;
- `SecureKeypadSubmission.close()` releases and zeroizes an unconsumed
  submission;
- `SecureKeypadSubmission.takeOpaqueHandle()` transfers ownership exactly once
  to a native authentication consumer;
- `SecureKeypadNativeSubmissionRouter` requires a consumer before a framework
  success event can be emitted;
- `releaseSession()` is called on deinit, detached window, inactive/captured
  presentation, and explicit cancel paths.

The iOS release artifact is a version-matched `secure_ffi.xcframework` plus
the Swift native source/module map. Device and simulator slices are built from
the same commit and checked by SHA-256 before a Podspec accepts them.

### Android

The public native surface is the existing Kotlin view and JNI bridge in
`native/android`:

- `SecureKeypadView` accepts only bounded public configuration;
- input is rendered with native buttons and a non-editable masked display;
- `SecureKeypadNative` owns only opaque FFI handles and masked-state values;
- `SecureKeypadSubmission` is consumed or released exactly once by the native
  authentication router;
- `FLAG_SECURE`, autofill exclusion, and native lifecycle hooks are asserted
  on construction, attachment, focus regain, visibility changes, and release;
- API 24 minimum and the declared `arm64-v8a`/`x86_64` release ABI matrix stay
  part of the package contract.

The Android release artifact is an AAR containing the Kotlin/JNI adapter and
verified `libsecure_ffi.a` slices for every declared ABI. CMake must fail when
the matching FFI artifact is missing; it must never silently build a stub or
select an unrelated architecture.

## Framework adapter contracts

The React Native package and Flutter plugin are adapters, not alternate native
SDKs. Their responsibilities are limited to:

1. validate and decode public configuration;
2. create/configure the native view;
3. forward public commands such as `backspace`, `clear`, `submit`, and
   monotonic `cancel` requests;
4. emit masked state and non-secret result/error events;
5. detach callbacks before native session release;
6. request native session reconfiguration after lifecycle loss without
   replaying a prior Headless Host command.

Secure Native Mode remains the default. Headless Host Mode is explicitly
acknowledged lower assurance and is limited to public key IDs; it cannot be
used to claim that the framework runtime is outside the observation boundary.

The adapters must depend on the same ABI version and native source mirror.
They must reject an ABI mismatch before creating a session and must release an
opaque submission when no native consumer is installed or when a consumer
throws before taking ownership.

## Memory and ownership rules

- During active input, the minimum required token state exists in native/core
  memory; no implementation may claim that processing occurs without memory.
- `clear`, `backspace` removal, cancel, timeout, submit transfer, session free,
  and submission free must clear SDK-owned secret buffers through the Rust
  zeroization boundary.
- Public framework state may contain only layout/theme metadata, masked length,
  display state, and result/error codes.
- No wrapper may construct a password `String`, `TextEditingController`, JSON
  payload, log field, analytics property, clipboard value, or crash-report field
  from keypad input.
- The host's native authentication consumer owns the opaque submission only
  after an explicit one-time transfer. If it does not consume the handle, the
  SDK releases it.
- The SDK limitation statement must say that OS/runtime/debugger/core-dump
  copies and a compromised device are outside the zeroization guarantee.

## Versioning and release artifacts

The release pipeline pins three independent versions:

| Surface | Required rule |
| --- | --- |
| Native UI package | iOS/Android native source and framework adapter version; package copies must match the canonical source digest |
| C ABI | `SECURE_KEYPAD_ABI_VERSION` and `secure_keypad_abi_version()` must match before session creation |
| Authentication protocol | OPAQUE/HTTP protocol and cryptographic suite metadata must match the server/native consumer contract |

An ABI bump requires a header update, Rust FFI implementation update, iOS and
Android artifacts, RN/Flutter mirrors, compatibility documentation, and a
full release-candidate gate. A framework package version change alone must not
silently change the ABI or authentication protocol.

Publishable mobile packages must include only verified, relative native
artifacts. Explicit custom artifact paths are accepted only when their content
matches the staged package artifact. Package archives must exclude private
keys, real credentials, generated host state, and unverified native binaries.

## Testing strategy

The implementation must add or preserve tests at each boundary:

- Rust core/FFI ownership, clear, timeout, aliasing, panic, and opaque
  submission tests;
- C11 header layout and ABI version tests;
- iOS Swift native presentation, lifecycle, ABI mismatch, and submission
  ownership contract tests;
- Android Kotlin/JNI presentation, lifecycle, ABI mismatch, architecture
  selection, and submission ownership contract tests;
- native-source parity tests for both publishable framework packages;
- React Native and Flutter contract tests proving no secret props, callbacks,
  or getters exist;
- host app simulator/emulator smoke tests for masked display, capture masking,
  lifecycle release, accessibility, and public key-label non-disclosure;
- release checks for artifact hashes, package contents, version parity, and
  evidence manifest bindings.

Passing local tests or simulator tests is not sufficient for a production
claim. Physical iOS/Android device evidence, Linux LeakSanitizer evidence,
trusted release signing, and an independent security review remain release
gates as documented in `docs/PRODUCTION-READINESS.md`.

## Implementation sequence

1. Make canonical native source and package-mirror ownership explicit in the
   build/release contract.
2. Add standalone native SDK-facing build and smoke contracts while retaining
   RN/Flutter compatibility.
3. Centralize artifact/version metadata and reject mismatched native inputs.
4. Tighten native lifecycle, ownership, and memory regression tests.
5. Run the production-candidate gate and record remaining external evidence
   blockers without changing them into unsupported security claims.

## Non-goals

- No browser keypad is promoted to the same assurance level as Secure Native
  Mode.
- No password or raw accumulated input getter will be added for convenience.
- No framework-specific security implementation will be allowed to diverge
  from the native SDK contract.
- No production approval will be claimed from source tests alone.
