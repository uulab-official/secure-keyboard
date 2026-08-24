# Changelog

All notable changes to the Secure Keypad SDK are recorded here. Until the
first stable release, entries remain under `Unreleased` and are tied to the
exact release-candidate commit by the release evidence manifest.

## Unreleased

- Verification: generated React Native and Flutter iOS Release UI smokes now
  background and reactivate the app after a public key tap, requiring an empty
  post-recovery state so wrapper lifecycle recovery cannot replay input.
- Verification: Android React Native and Flutter emulator smokes now use the
  lifecycle-aware public-key harness, requiring an empty state after
  background/relaunch recovery and retaining sanitized hierarchy evidence.
- Verification: the Flutter Android host smoke now builds and uploads a
  multi-ABI Release APK, so lifecycle and capture-boundary evidence does not
  come from a debug-only artifact.
- Verification: the Flutter iOS host build and UI smoke now use Release
  configuration for the plugin, simulator app, and lifecycle test.
- Security: iOS native and wrapper key activation now rejects both touch and
  Headless Host input while inactive or screen-captured presentation is protected.
- Security: iOS now releases a live native session when screen capture starts
  and recreates it only from retained public configuration after capture ends.
- Security: iOS lifecycle protection now follows the keypad's own window scene,
  preventing unrelated multi-window scenes from changing its session.
- Security: Android native views now recover a zeroized session on reattachment
  even when the host does not emit a focus or visibility callback.
- Security: Android touch and Headless Host input now reassert and verify
  `FLAG_SECURE` at the native input boundary; rejected commands cannot advance
  the headless replay floor.
- Security: Android input-boundary `FLAG_SECURE` failures now zeroize the
  native session before reporting the stable internal error.
- Security: Android focus and visibility lifecycle failures now zeroize the
  native session and emit an internal error without throwing into the host app.
- Security: Android reattachment failures now follow the same fail-closed
  zeroization path instead of throwing from the view lifecycle callback.
- Security: iOS protected-presentation transitions now zeroize any live native
  session before exposing the protected UI state.
- Security: Flutter Headless Host controller tokens now remain monotonic across
  Dart widget reattachment, preventing lifecycle resets below the native replay floor.
- Security: iOS Headless Host replay floors now advance only after native key
  activation succeeds across the standalone, React Native, and Flutter views.
- Security: native session errors now leave both iOS and Android Headless Host
  replay floors unchanged, allowing rejected commands to fail closed without
  consuming their token.
- Security: native cancel failures now release the session before reporting
  the error, preventing an uncertain cancellation state from retaining input.
- Security: native activation failures now release the session before reporting
  the error, covering touch, Headless Host, and action-key activation paths.
- Security: masked-state refresh failures now propagate as failed activation or
  cancellation results, so rejected commands cannot consume replay tokens.
- Security: the central native release path now publishes an empty masked state
  by default, while lifecycle-driven protection releases explicitly preserve
  the public `cancelled` result without making ordinary errors look cancelled.
- Security: iOS and Android now fail closed when native submission reports
  success without returning an opaque handle; the session is zeroized before
  the stable internal error is emitted.
- Security: iOS native masked-state refresh failures now release the native
  session before reporting the error, matching Android fail-closed behavior
  across the standalone, React Native, and Flutter source copies.
- Verification: the Android lifecycle harness now selects only clickable
  public key nodes before deriving tap coordinates, avoiding ambiguous
  accessibility labels.
- Verification: standalone Android and iOS native host UI smokes now tap only a
  public key identifier, background/foreground the host, and require the
  post-recovery public state to be empty while retaining sanitized screenshot
  and hierarchy evidence; no input value is queried by the harness.
- Added `pnpm verify:production-candidate`, a fail-closed aggregate command for deterministic Rust, package, adapter, browser, Flutter, parity, dependency, and security gates; it keeps physical, service, CI-provenance, signing, and independent-review evidence separate.
- The production-candidate aggregate now rejects a dirty or untracked checkout
  before running any deterministic gate, preserving commit-bound verification
  semantics.
- The protected release workflow now moves Flutter's generated `.dart_tool`,
  `build`, and `pubspec.lock` state outside the checkout before clean candidate
  metadata and source-bundle checks, preventing generated dependency/build
  state from invalidating or disguising release provenance.
- Security: external independent-review evidence now uses the same structured
  finding validator as the final trusted release verifier, rejecting malformed
  signed findings before an evidence artifact can be uploaded.
- The local durable-backend runner now removes its ephemeral Compose volumes on
  exit, preventing interrupted Redis/PostgreSQL campaigns from carrying replay,
  rate-limit, or migration state into a later run.
- Security: Redis rate-limit scripts now reject and remove wrong-type counter
  keys before any string operation, releasing their active-key index member so
  backend key poisoning cannot strand capacity.
- Security: Redis OPAQUE and WebAuthn adapters now validate and repair
  wrong-type state, credential, and active-index keys before sorted-set/string
  operations, with live interoperability regressions for capacity recovery.
- Security: Web custom-keypad fallback now requires a secure browser context
  even after its explicit lower-assurance acknowledgement, preventing the
  fallback from authorizing plaintext-origin input transport.
- Security: bound direct `secure-core` public key-ID construction and policy
  resolution to the same 64-byte contract enforced by native adapters.
- Security: React Native iOS and Android managers now release the native session
  and discard pending configuration whenever a required layout or theme prop
  disappears; static regression gates cover both canonical sources and package
  copies, while sequential initial layout/theme delivery remains buffered until
  a complete configuration is available.
- Security: React Native iOS now recreates a session when lifecycle protection or
  native validation has released it even if the public configuration fingerprint
  is unchanged.
- Security: React Native Android now requests fail-closed session recreation
  from retained public configuration after window-focus zeroization, using a
  callback that carries no input state.
- Security: all RN and Flutter native adapters now restore lifecycle-lost
  sessions from retained public configuration on iOS application/window and
  Android focus/visibility restoration; one-time Headless Host commands are
  never replayed during that recovery.
- Security: standalone iOS and Android native SDK views now perform the same
  lifecycle recovery without requiring a framework callback. Only validated
  public configuration is retained; lifecycle loss frees the native input
  session, and explicit `releaseSession()` clears the retained configuration
  so teardown cannot silently recreate a session.
- Security: direct iOS native views now enforce the canonical public key-ID
  grammar before allocating UI or a session, matching the bridge and Android
  fail-closed validation paths across all publishable source copies.
- Security: direct Android and iOS native views now bound optional public test
  IDs to the same canonical key-ID grammar before creating framework UI.
- Security: React Native Headless Host commands now reach the existing native
  session without reinitializing or replaying the public command, while a
  command received before initial configuration is applied once at startup.
- Security: native Headless Host replay floors now survive session release and
  lifecycle reconfiguration for the lifetime of each native view, preventing a
  delayed older command from becoming valid after zeroization.
- Security: WebAuthn browser failures from hostile exception objects are now
  normalized through trap-tolerant checks, preventing raw browser error text or
  proxy-thrown values from escaping the adapter.
- Security: caller-supplied WebAuthn environment getters and passkey controller
  errors now fail closed through the same trap-tolerant normalization boundary.
- Security: cancelled WebAuthn presentation operations now invalidate late
  browser results, so an abort race cannot publish or return a credential.
- Security: WebAuthn cancellation now settles the caller operation immediately
  even when the browser ignores the underlying abort signal.

### Server adapters

- Added publishable `@secure-keypad/server-node`. Its Fetch-compatible handler
  validates explicit TLS/proxy deployment facts, host CSRF/origin state, exact
  OPAQUE routes, JSON media type, and bounded streaming bodies before calling
  the pinned Rust/native delegate. It never implements OPAQUE or exposes a
  password API in JavaScript.
- Added fail-closed pre-buffering rate-limit admission to the Node, framework-
  neutral Rust, Axum, and Actix OPAQUE routes. Rate-limited requests receive a
  generic 429 response; omitted, unavailable, or malformed admission decisions
  cannot reach JSON parsing or the cryptographic delegate.
- Security: the Node transport now normalizes hostile request body-reader
  exceptions without allowing proxy-thrown values to escape its generic error
  boundary.
- Security: Node deployment-context validation now fails closed when a host
  configuration accessor throws an unexpected value.
- Security: Node request metadata, host handler options, and the validated
  body-limit snapshot now stay inside the generic fail-closed boundary,
  preventing hostile accessors from escaping raw errors or changing the bound
  mid-request.
- Added the compile-tested `secure-auth-actix` server adapter. It validates
  host CSRF/origin state before buffering, applies Actix's bounded payload
  collector, preserves generic OPAQUE errors/security headers, and leaves TLS,
  proxy validation, rate limits, sessions, and durable stores to the host. Its
  optional `webauthn` feature provides the same body-free host-principal and
  bounded passkey route boundary.
- Unified the Node, Axum, Actix, and optional WebAuthn body-boundary checks:
  malformed, overflowing, signed, comma-joined, invalid-byte, and duplicate
  `Content-Length` values now fail closed before request-body buffering, while
  valid declarations above the configured limit retain the 413 response.
- Added a machine-checked HTTP transport contract version parity gate. The
  framework-neutral Rust route is canonical at `HTTP_CONTRACT_VERSION = 1`,
  and the Node/TypeScript bridge must declare the same version in both CI and
  release-candidate source gates; this is independent from the OPAQUE
  `protocolVersion` carried inside the authentication envelope.
- Added deterministic iOS and Android native presentation snapshot contracts
  covering display state, masked text, accessibility text, and protected state;
  the snapshots reject invalid display codes and contain no secret-bearing
  input field.

### Compatibility

- Raised the declared workspace MSRV from Rust 1.85 to 1.88 to match the
  locked Actix, URL/ICU, and time dependency graph; CI and release-candidate
  source gates now compile the full all-features workspace with Rust 1.88.
- Clarified that the Web package ships WebAuthn plus an explicit lower-assurance
  fallback contract, not a browser DOM keypad that can provide native-like
  secret isolation.
- Added a secret-free Web passkey presentation controller with abortable
  registration/authentication ceremonies, stable `aborted` state, and no
  credential or browser exception text in UI state.

### Security

- Secure-auth now zeroizes the intermediate serialized server-login-state copy
  after packaging it for one-time storage, closing a transient native-memory
  duplicate of the OPAQUE state.
- PostgreSQL rate-limit reads now fail closed on malformed persisted attempt
  counters (zero, negative, or outside the `u32` contract) before applying
  policy arithmetic, matching the Redis adapter's poisoned-counter behavior.
- PostgreSQL OPAQUE one-time-state consume now atomically removes expired,
  oversized, and TTL-drifted records before materialization, matching Redis's
  replay-state retention and poisoned-record behavior.
- WebAuthn Redis ceremony consumption now rejects and removes keys with a
  missing, expired, or over-bound TTL before reading the record, preventing a
  persisted or recreated replay-state key from bypassing the 15-minute
  retention contract.
- Release evidence verification now rejects non-canonical relative paths
  containing dot, empty, or parent components, preventing multiple manifest
  strings from aliasing one hashed evidence file.
- Physical device evidence validation applies the same canonical relative-path
  rule to logs and artifacts before their digests or categorized test bindings
  are accepted.
- React Native no longer exports an unwrapped native view escape hatch. All
  public usage now goes through the prop allowlist and fail-closed masked-event
  boundary; custom rendering remains available only through the explicitly
  acknowledged Headless Host mode.
- OPAQUE HTTP credential persistence is now create-only: an existing account
  credential cannot be replaced by a replayed registration upload or an
  enrollment race, and conflicts use the generic invalid-request response.
- Release candidates now build, commit-bind, checksum-verify, and sign the
  Android `arm64-v8a` and `x86_64` FFI libraries alongside the iOS artifacts;
  the final Android checksum manifest and its exact `secure-keypad-android-ffi.commit`
  binding are required signed-source inputs, and the verified libraries are
  included in the publishable React Native npm and Flutter package paths, with
  staging-time byte comparison against the signed native source.
- iOS Podspecs and CI host builds now consume bundled release XCFrameworks by
  default while retaining explicit source/custom artifact overrides only when
  their SHA-256 content matches the staged package artifact; missing or
  mismatched native inputs still fail closed. Release staging also compares the
  published React Native iOS and Android FFI bytes against signed source
  package artifacts and verifies both native checksum manifests against the
  exact package bytes and release commit; both manifests and the Android commit
  binding are bounded before parsing.
- Clarified that OPAQUE credential repository reads are persistent copies; a
  login must not delete the reusable credential record while one-time protocol
  state remains consumable exactly once.
- Added opt-in native CSPRNG input-key randomization via
  `randomizeInputKeys`; only input-role positions move, while action roles,
  seeds, and accumulated input remain outside RN/Flutter bridges.
- Fixed the bounded in-memory one-time login store so a bound/unbound contract
  mismatch returns an error without consuming the pending state; only expiry
  or a successful type-matched take removes it.
- Numeric core input now accepts only canonical single-digit key IDs, rejecting
  aliases such as `digit-01` and `digit-+1` at the native boundary.
- Shared contracts and every native framework adapter now enforce the selected
  policy's canonical input IDs for numeric, printable-ASCII, and Hangul layouts.
- Fuzz campaigns now run against a temporary corpus copy outside the checkout,
  and the staging helper rejects checkout destinations, so libFuzzer's corpus
  growth cannot invalidate the clean-checkout evidence gate.
- Release evidence, merged manifests, and detached signing outputs now use
  exclusive file creation so a pre-existing path or symlink cannot be replaced
  during release assembly.
- Web browser release evidence now requires each checked-in smoke result line,
  records the actual Chromium/Firefox/WebKit runtime versions separately from
  the pinned Playwright version, rejects arbitrary sanitized log text, and
  fails closed when the CLI version argument differs from the workspace pin.
- Release evidence staging now bounds directory count and relative path depth
  in addition to file count and byte budgets, preventing empty or deeply nested
  untrusted artifact trees from exhausting finalization traversal resources;
  directory entries are streamed during traversal to avoid a large single
  directory being materialized at once.
- Release finalization now queries GitHub Actions run metadata and requires
  candidate, CI, and external evidence runs to match the repository, release
  commit, expected workflow path, and `completed`/`success` status before any
  artifact is downloaded.
- Release-candidate staging, archive validation, and signed-release evidence
  emission now execute from the immutable trusted verifier checkout; the
  verifier receives the candidate commit and package version explicitly so it
  cannot accidentally bind evidence to its own checkout.
- Linux LeakSanitizer release evidence now binds all four target logs to
  post-command success markers, the pinned nightly toolchain, run budget,
  bounded sizes, SHA-256 digests, and the final retained evidence paths; the
  marker must be the final meaningful log line.
- Android emulator smoke now retains UIAutomator hierarchy dumps and rejects
  editable-text or password accessibility nodes for both generated hosts.
- Physical native release evidence now requires distinct sanitized log files
  and SHA-256 digests for the React Native and Flutter host modes; the final
  verifier recomputes those nested digests and rejects shared or tampered host
  evidence.
- Final release evidence verification now checks the DER public-key type at the
  verifier boundary and rejects a signature descriptor backed by anything
  other than an Ed25519 key, even if its metadata claims `ed25519`.
- Physical iOS/Android evidence now binds to the machine-readable platform
  support policy, including OS/API and security-patch floors plus a hashed
  `platform-security-patch` artifact reviewed independently at release time.
- Physical-device test claims now bind to declared aggregate/host logs or
  matching categorized artifacts; unbound `pass` claims fail closed.
- Android RN/Flutter submission routing now closes an unconsumed opaque handle
  when a native consumer throws, while preserving transferred ownership.
- Native OPAQUE login/registration start and finish now reject aliased C ABI
  pointer slots before clearing output slots or consuming opaque handles.
- Native OPAQUE message construction/copy now rejects overlapping input and
  output-length buffers before mutating caller-owned transport memory.
- Expanded the native source audit and regression coverage to reject editable
  Android and iOS text controls in all publishable keypad implementations.
- Bounded the WebAuthn public base64url encoder to the same 8 KiB binary limit
  enforced by decoding and credential serialization.
- WebAuthn base64url decoding now bounds the encoded length before allocating
  its output buffer, preventing oversized-but-rejected input from creating a
  larger temporary decode allocation.
- WebAuthn default-environment discovery now fails closed on hostile browser
  getters instead of propagating their exception text.
- iOS native bridge configuration now rejects fractional schema versions before
  layout or theme materialization across the central and publishable copies.
- Android bridge theme numbers are now range-validated as `Double` before the
  native renderer narrows them to `Float`, closing a precision-rounding edge
  at public configuration bounds across all Android adapters.
- Normalized browser WebAuthn API rejections and hostile credential-object
  exceptions to stable generic error codes without propagating original
  messages.
- Added native FFI coverage for aborted OPAQUE registration flows and clarified
  that validated start calls consume and null the submission pointer even when
  protocol setup fails.
- Node transport responses are now byte-only at the TypeScript boundary and
  delegate-owned response buffers, including malformed typed-array buffers,
  are zeroized after copying into `Response` or before fail-closed rejection.
- Node request streams now reject non-byte chunks without creating a detached
  copy and clear supported typed-array backing bytes before failing closed.
- Final release evidence verification now rejects symlinked gate, artifact,
  signature, and nested device paths even when their targets stay inside the
  evidence root.
- Device, browser, CI, release-gate, and signed-release evidence emitters plus
  the fragment merger now reject symlinked input files and output parent
  directories before hashing or materialization.
- Increased the CI fuzz job budget to 60 minutes so the four extended
  campaigns and four Linux LeakSanitizer campaigns are not cut off by the
  workflow timeout.
- Release staging now rejects FIFO, device, socket, and other non-regular
  filesystem entries instead of silently omitting them from the scan.
- Signed archive inspection now independently rejects non-regular tar entry
  types, including hard links and special filesystem nodes.
- Signed archive inspection now rejects duplicate normalized paths instead of
  silently collapsing them during required-entry validation.
- Added a read-only `release-finalize` workflow that downloads the exact
  candidate/CI/external artifact runs, stages them without symlink or
  overwrite ambiguity, converts the signed-release record into a complete
  manifest fragment, and requires protected maintainer/reviewer fingerprints
  before publishing final evidence.
- Added an exclusive, regular-file-only release-evidence staging helper and a
  signed-release fragment converter so missing physical-device, sanitizer, or
  independent-review evidence fails closed.
- Release candidates now carry commit-bound artifact fragments for the iOS and
  Android FFI checksums, SPDX SBOM, and third-party notices; both verified
  native checksum manifests and the Android native commit binding are included
  inside the signed source bundle.
- Final evidence verification now rejects an independent-review signature that
  reuses the maintainer release public key.
- Final evidence verification now binds each physical native record's checksum
  manifest to the matching candidate iOS or Android native artifact.
- Physical native release evidence now requires React Native and Flutter host
  mode versions to match the manifest's pinned toolchains.
- Final evidence assembly now rechecks the signed tar entry contract,
  candidate checksum manifest, and byte equality of signed source evidence
  before accepting downloaded external inputs.
- Physical native release evidence now requires passing `hostModes` for both
  React Native and Flutter; a single framework/device run cannot close the
  iOS or Android release gate.
- CI release evidence now retains simulator/emulator screenshots, fuzz and
  LeakSanitizer logs, and dependency metadata inside the final evidence root;
  the staging copier also rejects oversized, over-budget, or over-counted
  untrusted evidence inputs before copying them.
- The WebAuthn base64url decoder now rejects caller-supplied limits that are
  non-integral, unbounded, negative, or above the global binary bound before
  allocating a decode buffer.
- React Native and Flutter now share the same conservative native session
  defaults: eight input tokens and a 60-second monotonic inactivity timeout.
- Added a reviewer-side independent-security-review fragment emitter that
  verifies signed report bytes, review identity, scope, decision, and public
  key binding without accepting private key material.
- Bound native public layout, theme, label, accessibility, and ABI
  configuration checks across the iOS, Android, React Native, and Flutter
  surfaces.
- Added a generated React Native iOS Release UI smoke test that taps a numeric
  key and verifies masked-length accessibility state without exposing the
  public key identifier; the host build also fixes the Swift bridge dictionary
  redeclaration that Release-only compilation could conceal.
- Renamed the Flutter package's canonical Dart library to match the published
  package name and excluded generated build state from pub.dev archives.
- Made Android React Native public-map conversion fail closed: malformed or
  over-budget layout/theme/command maps now release the native session and
  emit only the public `invalid` result instead of escaping as a bridge
  exception.
- Enforced monotonic React Native cancellation tokens on iOS and Android:
  delayed lower tokens are rejected, equal replays are coalesced, and only a
  newer token can clear the native session.
- Made native iOS/Android bridge parsers require the complete versioned theme
  color and metric maps; missing public fields now fail closed consistently with
  the RN, Flutter, and shared contract validators.
- Native bridge parsers now validate every required theme color value,
  including disabled-state colors, before configuration reaches UI allocation.
- Native renderers now preserve the public layout direction, display-slot
  visibility, and per-key test identifiers across iOS, Android, React Native,
  and Flutter instead of silently discarding those customization fields.
- Native renderers now apply the public key font weight consistently on iOS and
  Android, including framework-package mirrors.
- Native renderers now apply bounded press/mask animations and haptic/sound
  feedback preferences without moving input values across the framework
  boundary.
- Android color parsing now rejects signed and non-hex text so native validation
  matches the shared RN/Flutter color contract exactly.
- Bounded the Flutter native event backlog, coalesced masked-state updates,
  and preserved terminal result events under queue pressure.
- Capped WebAuthn pending ceremony retention at 15 minutes across all storage
  contracts.
- Added AES-256-GCM authenticated encryption for built-in Redis/PostgreSQL
  WebAuthn ceremony records, with host-managed `WebAuthnStateKey` and
  namespace-bound associated data.
- Bound built-in Redis/PostgreSQL OPAQUE login-state ciphertexts to their
  validated storage namespace with AES-GCM associated data, and advanced the
  durable protection format to v2; legacy unbound v1 records are rejected.
- Made the PostgreSQL ciphertext-size schema upgrade atomic and fail closed on
  malformed or tampered ceremony records.
- Redis one-time-state and rate-limit scripts now remove stale active-index
  members when their backing keys are missing, preventing eviction or partial
  cleanup from reserving capacity until the original TTL expires.
- Release candidate assembly now builds and checksum-verifies publishable iOS
  FFI artifacts, stages them into the React Native and Flutter packages, and
  signs npm/crate archives inside the same deterministic tarball as the source.
  A tarball-entry gate rejects source-only, mixed-version, or symbolic-link
  signed bundles.
- Device and browser evidence emitters and file verifiers now reject empty
  logs or artifacts before a release gate can hash them as valid evidence.
- Release evidence file verification now rejects empty gate and artifact files
  before accepting their SHA-256 digest.
- Independent review evidence now requires a signed, structured report bound to
  the exact commit, package version, reviewer key fingerprint, full review
  scope, findings, and an approving release decision.
- Independent review report parsing is bounded to 1 MiB before JSON
  deserialization.
- Release verification now rejects approving review reports with open
  critical/high findings.
- Final release evidence verification now bounds gate records, release
  artifacts, detached signatures, public keys, and signed reports before
  hashing, parsing, or cryptographic verification; oversized evidence fails
  closed.
- Intermediate release evidence emitters, fragment merging, browser-log
  ingestion, and release signing now enforce the same bounded-read policy
  before parsing, hashing, or signing input files.
- Top-level release manifests and device evidence records now fail closed at
  1 MiB before JSON parsing.
- Independent review findings now require affected scope, reproduction,
  remediation-owner, and retest-evidence fields before a signed report can
  satisfy the release gate.
- Release candidates now emit a commit-bound `signed-release` evidence record
  that verifies the detached signature before recording artifact digests.
- Bounded PostgreSQL credential loads at the configured per-account limit plus
  one row and the credential-record byte limit in SQL before materialization,
  so legacy or invalid excess rows/records cannot turn a credential read into
  an unbounded memory operation.
- Bounded PostgreSQL credential post-authentication updates and Redis credential
  reads before materialization; oversized legacy records now fail closed before
  JSON decoding, and accepted Redis buffers are zeroized on drop.
- Bounded Redis WebAuthn ceremony, OPAQUE one-time-state, and rate-limit reads
  with atomic pre-`GET` length checks; oversized legacy values are removed
  without entering the decoder or rate-limit counter path.
- Redis rate-limit cleanup now removes malformed, non-expiring, and expired
  counter/index pairs before failing closed, preventing poisoned legacy values
  from pinning bounded active-key capacity.
- Bounded PostgreSQL WebAuthn ceremony and OPAQUE one-time-state `RETURNING`
  values with SQL byte sentinels, deleting oversized legacy rows before their
  encrypted payloads can be materialized by the application.
- Hardened the Android JNI masked-state bridge so native refresh failures use a
  reserved sentinel instead of the valid empty-state value; Android and iOS
  native release paths now also clear retained masked presentation state.
- Migrated the Flutter Android plugin to Flutter's built-in Kotlin compiler
  contract, pinned its minimum Flutter/Dart versions, and verified both
  legacy-disabled and enabled built-in-Kotlin host builds.
- Fixed the Flutter iOS PlatformView factory to preserve standard creation
  arguments and aligned all iOS bridge parsers so numeric zero values cannot be
  rejected as Booleans at the native boundary.
- Fixed iOS reconfiguration cleanup so a failed native session constructor
  cannot leave a freed session pointer available for a later double free.
- Added a pre-copy 64-byte bound for Android JNI public key-ID arrays to avoid
  obtaining oversized JVM buffers before the Rust ABI can reject them.
- Bound release evidence CI records to their owning job check groups, sanitized
  runner labels, and commit-bound timestamps so an under-specified `pass`
  record cannot satisfy a CI release gate; direct durable/fuzz command groups
  remain accepted for the job-local emitter path.
- Added bounded, checked-in native FFI fuzz seeds for numeric, printable-ASCII,
  and Hangul constructor paths, with a CI contract test preventing any fuzz
  target from silently falling back to an empty corpus.
- Made the extended fuzz and Linux LeakSanitizer log pipelines fail closed on
  a failed campaign instead of allowing `tee` to mask the command status.

### Verification

- Added a pinned, loopback-only Docker Compose runner for local Redis/PostgreSQL
  durable interoperability tests; it executes all three ignored suites and
  cleans up test containers on exit.
- Added a CI contract test for the Flutter iOS host build and PlatformView
  codec, plus a simulator UI test and smoke path that verifies native keypad
  buttons and masked-length accessibility state without exposing input values.
- Release staging now requires this changelog, the pinned lockfiles, SBOM,
  third-party notices, and the complete candidate metadata set.
- Release evidence CLI verification now resolves gate, artifact, signature, and
  nested device files relative to the manifest's evidence root, matching the
  documented fragment-merge workflow.
- Secure-core now explicitly zeroizes the intermediate rendered Hangul
  code-point buffer after encoding it into the native secret buffer.
- Secure-auth now zeroizes OPAQUE serialization buffers, including GenericArray
  sources and rejected oversized message/setup/credential copies.
- Secure-auth now zeroizes GenericArray export/session-key sources before
  transferring them into the native-only `SecretOutput` container.
- Static security audit now rejects direct OPAQUE export/session-key
  `GenericArray` copies that bypass the zeroizing helper.
- CI and release-candidate workflows now run the pinned RustSec dependency
  audit alongside the existing JavaScript dependency audit.
- Durable Redis service gates now inject oversized legacy ceremony, OPAQUE
  state, credential, and rate-limit values and verify pre-materialization
  fail-closed cleanup against the live backend.
- Stabilized the live Redis WebAuthn TTL-drift evidence test with a scheduler
  margin larger than Redis's millisecond countdown, avoiding a false pass when
  an over-bound key reaches the consume script exactly at the configured limit.
- Release evidence tests now cover rejection of under-specified CI gate
  records before digest and signature verification is treated as sufficient.
- Standalone device evidence validation now requires an explicit top-level
  `status: "pass"`, matching the final release verifier's fail-closed policy.
- Added a native iOS/Android device-evidence emitter that requires the complete
  physical test matrix and artifact categories, hashes files in-place, and
  rejects the disposable sentinel before writing release fragments.
- Bounded native device evidence files to 32 MiB before hashing or content
  scanning to keep release verification fail-closed under oversized artifacts.
- Device evidence validation now requires canonical millisecond UTC timestamps
  and bounds device/browser metadata labels before accepting a record.
- Release evidence now rejects empty signed artifacts, including an empty
  independently signed security-review report.
