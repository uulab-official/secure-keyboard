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
- [x] Implement bounded printable-ASCII input using public `ascii-XX` key IDs.
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
- [x] Ship a default theme and numeric/printable-ASCII/Hangul examples.

Exit criteria: an external consumer can create a branded keypad without changing secure-core code.

### Phase 3 — Native mobile renderer

Status: native renderer sources complete; packaging and device verification pending

- [x] Implement iOS native secure view and controller.
- [x] Implement Android native secure view and controller.
- [x] Keep key events and secret composition inside native/core code.
- [x] Provide native submission-to-OPAQUE handoff without exposing a password or client session key.
- [x] Add background masking, screenshot/capture handling, and autofill/clipboard restrictions.
- [x] Zeroize the native session on iOS resign-active and Android window focus/visibility loss.
- [x] Add executable iOS/Android native presentation and ownership contract checks to CI.
- [x] Wire a native `cancel` action through the ABI and both framework event contracts.
- [ ] Complete device-level accessibility review and native snapshot tests.

Exit criteria: Secure Native Mode works without a secret crossing the framework bridge.

### Phase 4 — React Native adapter

Status: publishable contract, native source packaging, and parity gate complete; host-app build and device verification pending

- [x] Provide reference iOS/Android native view-manager registration.
- [x] Include iOS/Android native source, FFI module map, and fail-closed package build manifests.
- [x] Require an explicit native submission consumer before reporting framework success.
- [x] Accept only serializable layout, theme, and policy objects.
- [x] Add a reproducible CI host-build gate that links the React Native package and Android arm64 Rust FFI library.
- [x] Add a reproducible CI iOS Simulator host-build gate that links the React Native package and XCFramework.
- [x] Add supplemental Android x86_64 emulator launch evidence for the generated React Native and Flutter hosts.
- [x] Expose an explicit native `cancel` layout action that clears input without a framework secret channel.
- [x] Expose masked state events and non-secret native cancel controller commands.
- [ ] Provide Expo development-build support; document that Expo Go cannot host the custom native security layer.
- [ ] Add an opt-in lower-assurance Headless Host Mode with prominent documentation.

Exit criteria: RN users can customize the entire supported visual contract while Secure Native Mode remains the default.

### Phase 5 — Flutter adapter

Status: publishable contract, native PlatformView package, and parity gate complete; host-app build and device verification pending

- [x] Publish the Flutter-facing layout/theme/policy contract.
- [x] Keep the secret out of `TextEditingController`, Dart strings, and Dart callbacks.
- [x] Mirror the RN masked-state/result-code contract and add Flutter analyze/test CI gates.
- [x] Provide reference PlatformView/FFI registration that carries only public configuration and masked/result events.
- [x] Provide a Flutter `SecureKeypad` PlatformView wrapper with public creation parameters only.
- [x] Require an explicit native submission consumer before reporting framework success.
- [x] Add a reproducible CI host-build gate that links the Flutter plugin and Android arm64 Rust FFI library.
- [x] Add a reproducible CI iOS Simulator host-build gate that links the Flutter plugin and XCFramework.
- [x] Add supplemental Android x86_64 emulator launch evidence for the generated React Native and Flutter hosts.
- [ ] Compile the registration in supported host apps and verify device behavior.
- [x] Provide examples for numeric PIN, printable-ASCII password, Hangul password, and branded themes.

Exit criteria: Flutter consumers have parity with the RN secure/native contract.

### Phase 6 — Server SDK and authentication

Status: OPAQUE engine, verified HTTP/JSON route contract, deployment baseline, injectable WebAuthn storage contracts, and durable/distributed control implementations complete; isolated service execution and deployment evidence pending

- [x] Define the versioned OPAQUE registration and login message contract.
- [x] Implement a reference Rust OPAQUE engine with a pinned protocol suite, Argon2 KSF, and key IDs.
- [x] Add typed version/suite/key envelopes and a 16 KiB payload limit.
- [x] Apply envelope bounds to both constructor and Serde deserialization paths.
- [x] Add a bounded JSON decoder and generic external authentication error codes.
- [x] Add a bounded fixed-window rate limiter and shared backend contract.
- [x] Add feature-gated Redis/PostgreSQL rate-limit adapters with hashed keys, bounded active-key capacity, and atomic fixed-window checks.
- [x] Add a missing-account OPAQUE dummy-path response-shape regression test.
- [x] Add explicit active/previous key rotation and finalization downgrade tests.
- [x] Add public opaque-handle generation and an executable atomic backend contract test.
- [x] Add bounded HTTP/JSON routes for registration and one-time login finish.
- [x] Enforce POST, JSON media type, 128 KiB body limit, fixed-size handle encoding, and generic public errors at the route boundary.
- [x] Add end-to-end HTTP OPAQUE registration/login/replay tests without returning credential files or session keys.
- [x] Add positive login, wrong-password, setup persistence, and credential-file tests.
- [x] Bind a sealed keypad submission directly to native OPAQUE login state without a password getter.
- [x] Bind a sealed keypad submission directly to native OPAQUE registration state and expose it through ABI v2 without a password getter.
- [x] Add zeroizing server-login-state serialization and bounded public identifiers.
- [x] Add a bounded one-time reference store with TTL, capacity, and state-size tests.
- [x] Add transport-neutral registration orchestration that returns protected credential files.
- [x] Add transport-neutral server orchestration with identifier-bound finalization.
- [x] Add a framework-neutral WebAuthn HTTP/JSON route contract with bounded bodies, generic errors, and host-principal binding.
- [x] Add a mandatory TLS/proxy-limit deployment context and Nginx/Caddy HTTP deployment baseline.
- [x] Require an explicit host-validated CSRF result before framework-neutral or Axum JSON dispatch.
- [x] Add a compile-tested Axum adapter after finalizing the host session and storage interfaces.
- [x] Add an optional compile-tested Axum WebAuthn adapter with a body-free host-principal resolver.
- [x] Add generic WebAuthn ceremony/credential storage injection with bounded serialization and atomic backend contracts.
- [ ] Add a second framework adapter only after its body-limit, TLS-context, and response-header contract can be tested equivalently.
- [x] Add bounded replay-store, downgrade, enumeration, and key-rotation tests; wire isolated durable interoperability checks into CI.
- [ ] Add adapters for the first supported backend language only after the reference implementation is interoperable.
- [x] Provide migration guidance for systems that currently receive ordinary passwords.

Exit criteria: the server never needs a plaintext password or replayable client-side hash.

### Phase 7 — Web and passkeys

Status: passkey-first adapter, reference server, bounded HTTP route, compile-tested Axum integration, injectable storage contracts, and feature-gated Redis/PostgreSQL adapters complete; host/device and independent review pending

- [x] Add a WebAuthn/passkey-first adapter with server-JSON conversion and result serialization.
- [x] Make secure-context and WebAuthn API support checks explicit and fail closed.
- [x] Expose a custom web keypad fallback only as an explicitly acknowledged lower-assurance mode.
- [x] Keep browser JavaScript memory outside the trusted security boundary; do not claim Web Crypto changes that limitation.
- [x] Add a pinned Playwright Chromium/Firefox/WebKit runtime smoke gate for the Web adapter.
- [x] Add WebAuthn registration/login server examples with challenge, origin, RP ID, and replay verification.
- [x] Add CSP, dependency integrity, and supply-chain guidance.

Exit criteria: web users get a safe default and understand the difference between native and browser security.

### Phase 8 — Verification and release

Status: release-gate automation complete; actual CI evidence, device review, and independent security review pending

- [x] Create an OWASP MASVS/MASTG evidence map; independent assessor sign-off remains pending.
- [x] Define v1 TLS/pinning ownership and compromised-runtime residual-risk policy without unsupported SDK claims.
- [x] Add strict Rust/TypeScript/Flutter CI checks, dependency audit, bounded auth-decoder fuzz target, and dependency metadata artifact generation.
- [x] Add bounded auth-decoder and native/core state-machine fuzz targets with retained corpora.
- [x] Add a native C ABI sequence fuzz target covering opaque handle ownership and cancellation.
- [x] Add a bounded WebAuthn versioned-ceremony-state fuzz target and CI smoke gate.
- [x] Add feature-gated Redis/PostgreSQL storage adapters with bounded pools, atomic consume, credential uniqueness, and post-authentication CAS updates.
- [x] Bound durable credential record bytes and per-namespace pending ceremonies; clean expired durable ceremony rows/index entries during atomic writes/consumes.
- [x] Add isolated Redis/PostgreSQL service interoperability tests to CI.
- [x] Complete local 10,000-iteration smoke campaigns for the auth-envelope and core-sequence targets; keep CI at a bounded 2,000-iteration smoke gate.
- [x] Complete the local 10,000-iteration smoke campaign for the WebAuthn state target and retain its minimized corpus.
- [x] Complete local 100,000-iteration extended campaigns for the auth-envelope, core-sequence, and WebAuthn-state targets and retain the resulting corpora.
- [x] Complete a local 1,000,000-iteration stability campaign for all four fuzz targets; keep the Linux leak-sanitizer gate separate.
- [x] Add a reproducible CI 1,000,000-iteration campaign with a bounded libFuzzer RSS guard.
- [x] Add a machine-readable release evidence manifest contract for sanitizer, durable-backend, device, independent-review, and signed-release gates.
- [x] Add conflict-checked release evidence fragment merging before final manifest validation.
- [x] Bind every release gate claim to the exact manifest commit and reject missing or mismatched gate bindings.
- [x] Cryptographically bind the independent security review report to a reviewer Ed25519 key and detached signature.
- [x] Add a manual deterministic release-candidate bundle workflow with protected Ed25519 signing and exact-ref/package binding.
- [x] Restrict release signing workflow dispatch to a verified immutable 40-character commit SHA.
- [ ] Run the Linux leak-sanitizer campaign and add platform memory/leak evidence to the release bundle.
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
