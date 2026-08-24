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
- [x] Bound untrusted public key-ID construction and policy resolution before
  native session allocation.
- [x] Add the native FFI boundary with explicit ownership and null-safety rules.
- [x] Reject aliased C ABI ownership/state/output slots and overlapping transport buffers before clearing or consuming opaque handles.

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

Status: native renderer sources and standalone SDK package contracts complete; physical-device verification pending

- [x] Implement iOS native secure view and controller.
- [x] Implement Android native secure view and controller.
- [x] Keep key events and secret composition inside native/core code.
- [x] Provide native submission-to-OPAQUE handoff without exposing a password or client session key.
- [x] Add background masking, screenshot/capture handling, and autofill/clipboard restrictions.
- [x] Zeroize the native session on iOS resign-active and Android window focus/visibility loss.
- [x] Reassert Android `FLAG_SECURE` on every focus regain after host window-flag changes.
- [x] Fail closed without throwing when Android lifecycle `FLAG_SECURE` restoration fails; zeroize the session and emit a stable internal error.
- [x] Fail closed without throwing when Android view reattachment cannot restore `FLAG_SECURE`; zeroize the session before returning from the lifecycle callback.
- [x] Make iOS protected-presentation state itself a zeroization boundary for inactive or screen-captured scenes.
- [x] Reassert and verify Android `FLAG_SECURE` at every native touch and Headless Host input boundary; rejected commands do not advance the replay floor.
- [x] Zeroize the native session when Android input-boundary `FLAG_SECURE` verification fails before reporting the internal error.
- [x] Reject fully and partially obscured Android touches before native activation, zeroizing the session on the tapjacking boundary.
- [x] Add cross-platform `securityMode: strict` local posture gates and expose them through React Native and Flutter public configuration.
- [x] Advance native Headless Host replay floors only after iOS/Android activation returns success across standalone, React Native, and Flutter views.
- [x] Centralize bounded Android/iOS masked-display/accessibility announcements and execute standalone JVM/Swift contract tests.
- [x] Reject out-of-contract native display-state codes before rendering or framework emission.
- [x] Revalidate native layout cardinality, UTF-8 label byte bounds, and finite theme bounds before UI/session allocation.
- [x] Add opt-in native CSPRNG input-key randomization while keeping action-key roles and positions stable.
- [x] Add executable iOS/Android native presentation and ownership contract checks to CI.
- [x] Add deterministic iOS/Android security-facing presentation snapshots for masked and protected states.
- [x] Publish the standalone iOS Native SDK Podspec and Android library/AAR module contract without framework dependencies.
- [x] Build and launch framework-free standalone iOS/Android SDK hosts in CI using Release artifacts and public runtime evidence.
- [x] Bind native SDK version, C ABI, platform floors, and Android ABI artifacts to `native/sdk-contract.json`.
- [x] Cover aborted native OPAQUE registration ownership and one-time release in the FFI contract suite.
- [x] Make the Android framework submission router release an unconsumed opaque handle when a native consumer throws, without double-releasing transferred ownership.
- [x] Fail closed when native submission reports success without returning an opaque handle; zeroize before emitting the stable internal error across iOS, React Native, and Flutter sources.
- [x] Fail closed when no native submission consumer is installed; release the opaque handle and emit the stable internal error instead of silently accepting submit.
- [x] Gate native opaque submission handoff on a successful post-submit masked-state refresh, closing pending handles on refresh failure before framework success emission.
- [x] Restore lifecycle-lost sessions for RN and Flutter adapters from retained public configuration across iOS activation/window transitions and Android focus/visibility transitions without replaying Headless Host commands.
- [x] Restore lifecycle-lost sessions for direct iOS and Android Native SDK consumers without a framework callback; retain only public configuration and make explicit release terminal.
- [x] Wire a native `cancel` action through the ABI and both framework event contracts.
- [x] Release the native session when cancellation fails before reporting the error, without advancing the cancel replay floor.
- [x] Release the native session when key/action activation fails before reporting the error, without advancing the Headless Host replay floor.
- [x] Propagate masked-state refresh failures through activation and cancellation so rejected commands cannot consume replay tokens.
- [x] Centralize masked-state publication in every native session release path: ordinary release/error cleanup publishes empty state, while lifecycle protection explicitly publishes `cancelled`.
- [ ] Complete device-level accessibility review and physical UI snapshot tests.

Exit criteria: Secure Native Mode works without a secret crossing the framework bridge.

### Phase 4 — React Native adapter

Status: publishable contract, native source packaging, parity gate, Expo Development Build support, and opt-in Headless Host command contract complete; physical-device verification pending

- [x] Provide reference iOS/Android native view-manager registration.
- [x] Include iOS/Android native source, FFI module map, and fail-closed package build manifests.
- [x] Require an explicit native submission consumer before reporting framework success.
- [x] Accept only serializable layout, theme, and policy objects.
- [x] Add a reproducible CI host-build gate that links the React Native package and Android arm64 Rust FFI library.
- [x] Add a reproducible CI iOS Simulator host-build gate that links the React Native package and XCFramework.
- [x] Add a generated React Native iOS Release UI test for masked state and public key-label non-disclosure.
- [x] Add supplemental Android x86_64 emulator launch evidence for the generated React Native and Flutter hosts.
- [x] Expose an explicit native `cancel` layout action that clears input without a framework secret channel.
- [x] Expose masked state events and non-secret native cancel controller commands.
- [x] Revalidate RN/Flutter bridge masked-state bounds and stable result-code shapes before host callbacks.
- [x] Bound the Android RN public configuration conversion with allowlisted keys and aggregate/depth limits before native parsing.
- [x] Release stale React Native native sessions when required layout/theme configuration disappears, with canonical-source and package-copy audit parity.
- [x] Recreate React Native iOS sessions after lifecycle/native-state loss even when the public configuration fingerprint is unchanged.
- [x] Recreate React Native Android sessions after window-focus/visibility zeroization without carrying input state or replaying a Headless Host command across the lifecycle callback.
- [x] Add standalone Native Android/iOS host lifecycle UI smoke evidence that proves recovery exposes an empty public state after backgrounding.
- [x] Provide Expo development-build support; document that Expo Go cannot host the custom native security layer.
- [x] Add an opt-in lower-assurance Headless Host Mode with explicit acknowledgement, monotonic public key-ID commands, and prominent documentation.

Exit criteria: RN users can customize the entire supported visual contract while Secure Native Mode remains the default.

### Phase 5 — Flutter adapter

Status: publishable contract, native PlatformView package, parity gate, reproducible host build, iOS Simulator UI smoke, and Android emulator launch smoke complete; physical-device verification pending

- [x] Publish the Flutter-facing layout/theme/policy contract.
- [x] Keep the secret out of `TextEditingController`, Dart strings, and Dart callbacks.
- [x] Mirror the RN masked-state/result-code contract and add Flutter analyze/test CI gates.
- [x] Reject unexpected native event fields and bounded masked metadata before Dart callbacks.
- [x] Bound the native Flutter event backlog, coalesce adjacent state updates, and preserve terminal results preferentially.
- [x] Provide reference PlatformView/FFI registration that carries only public configuration and masked/result events.
- [x] Provide a Flutter `SecureKeypad` PlatformView wrapper with public creation parameters only.
- [x] Add an explicitly acknowledged headless controller command that forwards only a monotonic token and public key ID.
- [x] Require an explicit native submission consumer before reporting framework success.
- [x] Add a reproducible CI host-build gate that links the Flutter plugin and Android arm64/x86_64 Rust FFI libraries in one multi-ABI APK.
- [x] Add a reproducible CI iOS Simulator host-build gate that links the Flutter plugin and XCFramework.
- [x] Preserve Flutter iOS PlatformView creation arguments with the standard codec and accept integer-zero theme durations without Boolean coercion.
- [x] Preserve the Flutter Headless Host controller token sequence across Dart widget attachment and detachment.
- [x] Add a generated Flutter iOS Simulator UI test for masked state and public key-label non-disclosure.
- [x] Publish the canonical Dart library entrypoint and exclude generated build state from pub.dev archives.
- [x] Add supplemental Android x86_64 emulator launch evidence for the generated React Native and Flutter hosts.
- [x] Compile Flutter registration in generated supported host apps and verify simulator/emulator behavior; physical-device verification remains a separate release gate.
- [x] Recreate Flutter iOS/Android sessions after native lifecycle loss using retained public configuration without replaying Headless Host commands.
- [x] Provide examples for numeric PIN, printable-ASCII password, Hangul password, and branded themes.

Exit criteria: Flutter consumers have parity with the RN secure/native contract.

### Phase 6 — Server SDK and authentication

Status: OPAQUE engine, verified HTTP/JSON route contract, deployment baseline, Node/TypeScript transport bridge, injectable WebAuthn storage contracts, and durable/distributed control implementations complete; local isolated service execution is verified, while CI/deployment evidence remains pending

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
- [x] Make Node, Axum, Actix, and optional WebAuthn `Content-Length` parsing fail closed before body buffering.
- [x] Add end-to-end HTTP OPAQUE registration/login/replay tests without returning credential files or session keys.
- [x] Add positive login, wrong-password, setup persistence, and credential-file tests.
- [x] Bind a sealed keypad submission directly to native OPAQUE login state without a password getter.
- [x] Bind a sealed keypad submission directly to native OPAQUE registration state and expose it through ABI v2 without a password getter.
- [x] Add zeroizing server-login-state serialization and bounded public identifiers.
- [x] Add a bounded one-time reference store with TTL, capacity, and state-size tests.
- [x] Add feature-gated Redis/PostgreSQL OPAQUE one-time state adapters with hashed handles, bounded versioned records, AES-256-GCM authenticated encryption using a host-supplied `OpaqueStateKey`, TLS-first constructors, atomic consume, and isolated service tests.
- [x] Add transport-neutral registration orchestration that returns protected credential files.
- [x] Make HTTP credential persistence create-only and reject registration replay or enrollment races without replacing an existing credential.
- [x] Add transport-neutral server orchestration with identifier-bound finalization.
- [x] Add a framework-neutral WebAuthn HTTP/JSON route contract with bounded bodies, generic errors, and host-principal binding.
- [x] Add a mandatory TLS/proxy-limit deployment context and Nginx/Caddy HTTP deployment baseline.
- [x] Require an explicit host-validated CSRF result before framework-neutral or Axum JSON dispatch.
- [x] Add a compile-tested Axum adapter after finalizing the host session and storage interfaces.
- [x] Add an optional compile-tested Axum WebAuthn adapter with a body-free host-principal resolver.
- [x] Add generic WebAuthn ceremony/credential storage injection with bounded serialization and atomic backend contracts.
- [x] Verify Redis/PostgreSQL credential `insert`/`load`/duplicate rejection/post-authentication update lifecycles against isolated live services, including fail-closed invalid-record propagation.
- [x] Add a compile-tested Actix Web adapter after matching the body-limit, TLS-context, CSRF-ordering, generic-error, and response-header contract.
- [x] Add a Node/TypeScript Fetch-compatible adapter with the same bounded body, TLS-context, CSRF-ordering, generic-error, and response-header contract; keep OPAQUE in the pinned Rust/native delegate.
- [x] Require fail-closed pre-buffering rate-limit admission in the Node, Axum, Actix, and framework-neutral OPAQUE HTTP contracts.
- [x] Add a machine-checked HTTP contract-version parity gate between the canonical Rust route and the Node/TypeScript transport bridge.
- [x] Promote HTTP contract-version parity to a first-class commit-bound release evidence gate.
- [x] Bind Node server metadata to the exact Rust OPAQUE protocol version and cipher-suite identifier without implementing cryptography in JavaScript.
- [x] Add bounded replay-store, downgrade, enumeration, and key-rotation tests; wire isolated durable interoperability checks into CI.
- [ ] Add a first non-Rust backend-language cryptographic implementation only after the reference implementation is interoperable; the Node/TypeScript transport bridge is complete, but it deliberately delegates OPAQUE to Rust/native.

The non-Rust cryptographic implementation remains intentionally outside the
current production-candidate scope. Reference OPAQUE interoperability is
complete, but duplicating the cryptographic implementation in JavaScript or a
second backend language would expand the trusted-computing base and create a
second downgrade/parity surface. The supported Node server SDK is therefore a
bounded transport bridge to the pinned Rust/native reference until a separate
review approves a genuinely interoperable second implementation.
- [x] Provide migration guidance for systems that currently receive ordinary passwords.

Exit criteria: the server never needs a plaintext password or replayable client-side hash.

### Phase 7 — Web and passkeys

Status: passkey-first adapter, reference server, bounded HTTP route, compile-tested Axum/Actix integrations, injectable storage contracts, and feature-gated Redis/PostgreSQL adapters complete; host/device and independent review pending

- [x] Add a WebAuthn/passkey-first adapter with server-JSON conversion and result serialization.
- [x] Make secure-context and WebAuthn API support checks explicit and fail closed.
- [x] Expose a secret-free, abortable passkey presentation controller so RN/Web/custom host UIs can render lifecycle state without receiving credential results through UI state.
- [x] Invalidate late WebAuthn results after controller cancellation so abort races cannot publish or return a credential.
- [x] Settle cancelled WebAuthn controller operations independently of browser abort behavior.
- [x] Reject late direct WebAuthn API results before credential response serialization after caller cancellation.
- [x] Retain the controller operation slot until a cancelled browser ceremony actually settles.
- [x] Expose an explicit lower-assurance acknowledgement contract for a product-owned custom web UI fallback; the SDK does not ship a browser DOM keypad.
- [x] Keep browser JavaScript memory outside the trusted security boundary; do not claim Web Crypto changes that limitation.
- [x] Add a pinned Playwright Chromium/Firefox/WebKit runtime smoke gate for the Web adapter.
- [x] Add WebAuthn registration/login server examples with challenge, origin, RP ID, and replay verification.
- [x] Add CSP, dependency integrity, and supply-chain guidance.
- [x] Ship checked-in React Native, Flutter, and WebAuthn host entrypoint examples with a secret-channel contract test.

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
- [x] Serialize concurrent PostgreSQL startup migrations with a transaction advisory lock and regression-test the durable credential lifecycle after migration.
- [x] Encrypt and authenticate built-in WebAuthn ceremony records with a host-managed namespace-bound key and bounded ciphertext schema.
- [x] Bound durable credential record bytes and per-namespace pending ceremonies; clean expired durable ceremony rows/index entries during atomic writes/consumes.
- [x] Make PostgreSQL durable namespace and record-bound constraints idempotently upgrade existing rate-limit, ceremony, and credential tables.
- [x] Add isolated Redis/PostgreSQL service interoperability tests to CI.
- [x] Complete local 10,000-iteration smoke campaigns for the auth-envelope and core-sequence targets; keep CI at a bounded 2,000-iteration smoke gate.
- [x] Complete the local 10,000-iteration smoke campaign for the WebAuthn state target and retain its minimized corpus.
- [x] Complete local 100,000-iteration extended campaigns for the auth-envelope, core-sequence, and WebAuthn-state targets and retain the resulting corpora.
- [x] Complete a local 1,000,000-iteration stability campaign for all four fuzz targets; keep the Linux leak-sanitizer gate separate.
- [x] Add a reproducible CI 1,000,000-iteration campaign with a bounded libFuzzer RSS guard.
- [x] Add a machine-readable release evidence manifest contract for sanitizer, durable-backend, device, independent-review, and signed-release gates.
- [x] Add conflict-checked release evidence fragment merging before final manifest validation.
- [x] Emit commit-bound CI fragments for durable backends, fuzz/LSAN, source gates, host builds, and browser-matrix logs.
- [x] Convert the three-browser Playwright smoke logs into a validator-compatible Web evidence record without embedding raw logs.
- [x] Require Web evidence to bind actual Chromium/Firefox/WebKit runtime versions to the checked-in smoke output.
- [x] Require the Web evidence CLI to match the workspace's exact Playwright dependency pin.
- [x] Bind every release gate claim to the exact manifest commit and reject missing or mismatched gate bindings.
- [x] Bind each referenced JSON gate record's embedded gate name, commit, and pass status to its manifest gate.
- [x] Revalidate iOS/Android/Web gate records, physical-device artifact categories, and nested log/artifact digests during final release verification.
- [x] Bind physical native checksum evidence to the matching candidate iOS or Android checksum artifact.
- [x] Require each physical native release record to include passing React Native and Flutter host-mode evidence.
- [x] Require physical React Native and Flutter host-mode versions to match the release manifest toolchains.
- [x] Bind each physical React Native and Flutter host mode to a distinct sanitized log path and digest; reject shared host evidence.
- [x] Add a checked-in release gate fragment emitter that hashes exact evidence bytes and derives commit/version from the checkout.
- [x] Cryptographically bind the independent security review report to a reviewer Ed25519 key and detached signature.
- [x] Require the maintainer release and independent-review public-key fingerprints to be distinct during final validation.
- [x] Provide a clean-checkout independent-review fragment emitter that verifies the report bytes and public-key binding.
- [x] Add a self-hosted device-lab external-evidence workflow that validates physical iOS/Android records and independent-review signatures before upload without synthesizing pass claims.
- [x] Add a manual deterministic release-candidate bundle workflow with protected Ed25519 signing and exact-ref/package binding.
- [x] Emit a commit-bound `signed-release` evidence record that verifies the detached Ed25519 signature and hashes the bundle, signature, and public key.
- [x] Bound top-level and intermediate release-evidence, device records, browser logs, fragments, and signing inputs before parsing, hashing, or signing.
- [x] Inspect release staging before archiving: candidate metadata, SBOM, notices, publishable package contents, crate archives, and private-key exclusion.
- [x] Restrict release signing workflow dispatch to a verified immutable 40-character commit SHA.
- [x] Bind release signing to a named protected GitHub Environment; administrator reviewer configuration remains external evidence.
- [x] Embed immutable candidate-only release metadata and final evidence-verifier instructions inside the signed bundle.
- [x] Build, commit-bind, and checksum-verify publishable iOS FFI, Android `arm64-v8a`/`x86_64` FFI, and standalone Android AAR artifacts; include the verified native inputs in the signed release bundle and publishable mobile package paths, and keep npm/crate archives inside the detached-signature tarball scope.
- [x] Add a read-only finalization workflow that stages candidate/CI/external artifacts, converts the signed-release record into a complete manifest fragment, and runs trusted-key verification before retaining production evidence.
- [x] Preflight finalization fragments by canonical gate name, rejecting missing, duplicate, unsupported, symlinked, or oversized gate inputs before merge.
- [x] Reject unsupported gate names in the standalone release manifest verifier as well as the finalization preflight.
- [x] Bind finalization artifact run IDs to GitHub API repository, commit, workflow-path, and successful-completion provenance before downloading evidence.
- [x] Bind each Linux LeakSanitizer target log to an explicit post-command success marker, bounded size, SHA-256 digest, pinned toolchain, and final retained evidence path.
- [x] Emit candidate-bound iOS/Android native checksum, SBOM, and license-notice artifact fragments so final evidence assembly does not depend on undocumented external claims.
- [x] Define a machine-readable iOS/Android OS/API and security-patch policy, require matching physical-device metadata and hashed patch artifacts, and apply it in final release verification.
- [x] Bind every physical native test result to declared aggregate/host logs or matching categorized artifacts before accepting the release gate.
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
| Product-owned web custom UI | Product-controlled web rendering around the fallback contract | Browser/page-script limitations | Fallback only |

## Release policy

- UI packages use SemVer.
- Authentication protocol versions are independent from UI package versions.
- Major security-boundary changes require a threat-model update.
- Security fixes receive a changelog entry and coordinated disclosure notice.
- The project never advertises “impossible to steal”; it describes the tested threat model and platform limitations.
