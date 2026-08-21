# Changelog

All notable changes to the Secure Keypad SDK are recorded here. Until the
first stable release, entries remain under `Unreleased` and are tied to the
exact release-candidate commit by the release evidence manifest.

## Unreleased

### Security

- Bound native public layout, theme, label, accessibility, and ABI
  configuration checks across the iOS, Android, React Native, and Flutter
  surfaces.
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
- Bounded PostgreSQL WebAuthn ceremony and OPAQUE one-time-state `RETURNING`
  values with SQL byte sentinels, deleting oversized legacy rows before their
  encrypted payloads can be materialized by the application.
- Hardened the Android JNI masked-state bridge so native refresh failures use a
  reserved sentinel instead of the valid empty-state value; Android and iOS
  native release paths now also clear retained masked presentation state.
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
