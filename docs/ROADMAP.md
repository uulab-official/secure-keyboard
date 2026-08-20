# Secure Keypad SDK Roadmap

An open-source, cross-platform virtual keypad with a secure native input path and externally customizable UI/UX.

## Design decision

The project has two contracts:

1. A strict security contract implemented by the core and native platform layers.
2. A public customization contract implemented by themes, layouts, slots, renderers, and adapters.

Customization changes presentation and input policy; it must not expose the accumulated secret or weaken the default native security boundary.

## Milestones

### Phase 0 — Security foundation and public contract

Status: foundation complete

- [x] Write the security specification.
- [x] Define Secure Native, Headless Host, and Web modes.
- [x] Define the threat model and security limitations in the README.
- [x] Choose the initial license: MIT for core and adapters.
- [x] Define semantic versioning for packages and independent protocol versioning.
- [x] Publish contribution, disclosure, and dependency policies.

Exit criteria: an external contributor can understand what is protected, what is customizable, and what is explicitly not guaranteed.

### Phase 1 — Core contracts and deterministic behavior

Status: core contract complete

- [x] Create the Rust core workspace.
- [x] Add an opaque submission type; no secret getter exists.
- [x] Implement numeric input, delete, clear, submit, and cancellation.
- [x] Implement primitive Hangul jamo composition behind an input-policy interface.
- [x] Lock the initial canonical composition behavior with test vectors.
- [x] Add explicit buffer clearing and a no-secret-API test harness.
- [x] Add the monotonic inactivity timeout policy.
- [x] Add the native FFI boundary with explicit ownership and null-safety rules.

Exit criteria: core, authentication, FFI, and header-contract tests pass and the public API cannot return the accumulated secret.

### Phase 2 — Customization system

Status: schema contract complete

- [x] Define versioned layout schema with key IDs, semantic roles, display labels, and action keys.
- [x] Define theme tokens and component slots for display, keys, header, footer, and error.
- [x] Define masked state and result event contracts.
- [x] Define locale, RTL, accessibility, haptic, sound, animation, and masking policy fields.
- [x] Add schema validation and secret-field rejection tests.
- [x] Ship a default theme and numeric/Hangul examples.

Exit criteria: an external consumer can create a branded keypad without changing secure-core code.

### Phase 3 — Native mobile renderer

Status: native renderer sources complete; packaging and device verification pending

- [x] Implement iOS native secure view and controller.
- [x] Implement Android native secure view and controller.
- [x] Keep key events and secret composition inside native/core code.
- [x] Provide native submission-to-OPAQUE handoff without exposing a password or client session key.
- [x] Add background masking, screenshot/capture handling, and autofill/clipboard restrictions.
- [x] Add executable iOS/Android native presentation and ownership contract checks to CI.
- [ ] Complete device-level accessibility review and native snapshot tests.

Exit criteria: Secure Native Mode works without a secret crossing the framework bridge.

### Phase 4 — React Native adapter

Status: public contract package complete; native view-manager and release packaging pending

- [ ] Expose the native view through a TurboModule/native component.
- [x] Accept only serializable layout, theme, and policy objects.
- [ ] Expose controller commands and masked state events.
- [ ] Provide Expo development-build support; document that Expo Go cannot host the custom native security layer.
- [ ] Add an opt-in lower-assurance Headless Host Mode with prominent documentation.

Exit criteria: RN users can customize the entire supported visual contract while Secure Native Mode remains the default.

### Phase 5 — Flutter adapter

Status: public contract package complete; PlatformView/FFI and device verification pending

- [x] Publish the Flutter-facing layout/theme/policy contract.
- [x] Keep the secret out of `TextEditingController`, Dart strings, and Dart callbacks.
- [x] Mirror the RN masked-state/result-code contract and add Flutter analyze/test CI gates.
- [ ] Expose the native renderer through PlatformView/FFI.
- [ ] Provide examples for numeric PIN, Hangul password, and branded themes.

Exit criteria: Flutter consumers have parity with the RN secure/native contract.

### Phase 6 — Server SDK and authentication

Status: OPAQUE engine and verified HTTP/JSON route contract complete; deployment controls pending

- [x] Define the versioned OPAQUE registration and login message contract.
- [x] Implement a reference Rust OPAQUE engine with a pinned protocol suite, Argon2 KSF, and key IDs.
- [x] Add typed version/suite/key envelopes and a 16 KiB payload limit.
- [x] Apply envelope bounds to both constructor and Serde deserialization paths.
- [x] Add a bounded JSON decoder and generic external authentication error codes.
- [x] Add a bounded fixed-window rate limiter and shared backend contract.
- [x] Add a missing-account OPAQUE dummy-path response-shape regression test.
- [x] Add explicit active/previous key rotation and finalization downgrade tests.
- [x] Add public opaque-handle generation and an executable atomic backend contract test.
- [x] Add bounded HTTP/JSON routes for registration and one-time login finish.
- [x] Enforce POST, JSON media type, 128 KiB body limit, fixed-size handle encoding, and generic public errors at the route boundary.
- [x] Add end-to-end HTTP OPAQUE registration/login/replay tests without returning credential files or session keys.
- [x] Add positive login, wrong-password, setup persistence, and credential-file tests.
- [x] Bind a sealed keypad submission directly to native OPAQUE login state without a password getter.
- [x] Add zeroizing server-login-state serialization and bounded public identifiers.
- [x] Add a bounded one-time reference store with TTL, capacity, and state-size tests.
- [x] Add transport-neutral registration orchestration that returns protected credential files.
- [x] Add transport-neutral server orchestration with identifier-bound finalization.
- [ ] Add framework-specific HTTP examples with mandatory TLS and reverse-proxy limits.
- [ ] Add distributed replay-store, downgrade, rate-limit, enumeration, and key-rotation tests.
- [ ] Add adapters for the first supported backend language only after the reference implementation is interoperable.
- [ ] Provide migration guidance for systems that currently receive ordinary passwords.

Exit criteria: the server never needs a plaintext password or replayable client-side hash.

### Phase 7 — Web and passkeys

Status: passkey-first adapter contract complete; browser/server example and deployment hardening pending

- [x] Add a WebAuthn/passkey-first adapter with server-JSON conversion and result serialization.
- [x] Make secure-context and WebAuthn API support checks explicit and fail closed.
- [x] Expose a custom web keypad fallback only as an explicitly acknowledged lower-assurance mode.
- [x] Keep browser JavaScript memory outside the trusted security boundary; do not claim Web Crypto changes that limitation.
- [ ] Add WebAuthn registration/login server examples with challenge, origin, RP ID, and replay verification.
- [ ] Add CSP, dependency integrity, and supply-chain guidance.

Exit criteria: web users get a safe default and understand the difference between native and browser security.

### Phase 8 — Verification and release

Status: planned

- [ ] Map tests to OWASP MASVS/MASTG controls.
- [ ] Run static analysis, dependency scanning, fuzzing, and memory/leak tests.
- [ ] Test logs, crash reports, clipboard, autofill, accessibility, screenshots, background snapshots, replay, and downgrade behavior.
- [ ] Publish threat model, limitations, SBOM, license notices, and release signatures.
- [ ] Obtain an independent security review before claiming production readiness.

Exit criteria: a reproducible, documented release with no unsupported security claims.

## Option matrix

| Option | Customization | Security posture | Default |
|---|---|---|---|
| Secure Native Mode | Theme/layout/slots/native animation | Highest available on supported mobile platforms | Yes |
| Headless RN/Flutter Mode | Arbitrary host-rendered UI | Host runtime can observe input events | No |
| WebAuthn | Custom surrounding UX, platform credential UI | Preferred web authentication | Yes on web |
| Web custom keypad | Full web rendering | Browser/page-script limitations | Fallback only |

## Release policy

- UI packages use SemVer.
- Authentication protocol versions are independent from UI package versions.
- Major security-boundary changes require a threat-model update.
- Security fixes receive a changelog entry and coordinated disclosure notice.
- The project never advertises “impossible to steal”; it describes the tested threat model and platform limitations.
