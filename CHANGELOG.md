# Changelog

All notable changes to the Secure Keypad SDK are recorded here. Until the
first stable release, entries remain under `Unreleased` and are tied to the
exact release-candidate commit by the release evidence manifest.

## Unreleased

### Server adapters

- Added publishable `@secure-keypad/server-node`. Its Fetch-compatible handler
  validates explicit TLS/proxy deployment facts, host CSRF/origin state, exact
  OPAQUE routes, JSON media type, and bounded streaming bodies before calling
  the pinned Rust/native delegate. It never implements OPAQUE or exposes a
  password API in JavaScript.
- Added the compile-tested `secure-auth-actix` server adapter. It validates
  host CSRF/origin state before buffering, applies Actix's bounded payload
  collector, preserves generic OPAQUE errors/security headers, and leaves TLS,
  proxy validation, rate limits, sessions, and durable stores to the host. Its
  optional `webauthn` feature provides the same body-free host-principal and
  bounded passkey route boundary.

### Security

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
  A tarball-entry gate rejects source-only or mixed-version signed bundles.
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
