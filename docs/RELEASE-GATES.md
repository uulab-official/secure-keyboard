# Release gates

The repository is a production candidate only when every applicable gate is
green and the platform/security review items are signed off. A passing unit
test suite alone is not a production claim.

Every GitHub Action in the release workflow is pinned to a 40-character commit
SHA, and CI jobs use the explicit `ubuntu-24.04` or `macos-15` runner image
labels. The adjacent action version comment is informational only; changing an
action or runner requires an explicit revision update and a passing security
audit.

The manual `.github/workflows/release-candidate.yml` workflow requires a
40-character lowercase commit SHA, proves that checkout `HEAD` equals that
SHA, and builds a deterministic candidate bundle from it. It fails closed
unless the protected `RELEASE_SIGNING_KEY_PEM` environment secret produces a
valid Ed25519 signature. It uploads a candidate artifact only; it does not
publish a GitHub release or bypass the external device, backend, and
independent-review gates below.

Before the source tree is archived, the workflow runs
`node scripts/check-release-bundle.mjs "$RELEASE_DIR"`. This staging gate
requires the candidate-only metadata, lockfiles, threat-model and deployment
policy documents, public README and security policy, security changelog, SPDX SBOM, third-party notices, all publishable npm
tarballs (including their license files), and every workspace crate archive.
It also rejects malformed archives, duplicate paths, symlinks, non-regular
filesystem entries, and private signing material in
the staging directory. This proves the input to the deterministic archive is
complete; it does not replace the protected signing step or external release
evidence.
The staging scan also rejects every non-regular filesystem entry, including
FIFOs, device nodes, sockets, and symlinks, before the archive is created.

The release job builds the iOS FFI XCFramework and device static library on the
pinned macOS runner, and builds the Android `arm64-v8a` and `x86_64` static
libraries on the pinned Ubuntu runner. Each native artifact set is published
through a checksum-verified workflow artifact bound to the requested commit.
The iOS artifacts are staged into both publishable mobile packages, and the
verified Android libraries are copied into the publishable React Native npm
archive and signed Flutter source package under their ABI-specific
`android/secure_ffi` paths. The same libraries are also retained under the
signed source bundle for reproducible host integration. `check-release-bundle`
and `check-release-archive` require these package paths. The staging checker
compares published React Native iOS XCFramework files and fallback library
bytes with the signed Flutter source package, and compares Android package
bytes with the signed Android native source, so a package that silently falls
back to an unverified or altered external library cannot pass the release
contract. It also parses both native checksum manifests, rejects unsafe or
duplicate paths, recomputes every listed checksum, and verifies the exact
Android `secure-keypad-android-ffi.commit` file against the candidate metadata
commit. Native checksum manifests and the Android commit binding are bounded
before parsing.
The signed tarball contains both `source/` and `packages/`; immediately before
signing, `node scripts/check-release-archive.mjs` verifies that the tarball
contains the staged Flutter iOS artifacts, every version-matched npm/crate
archive, and no symbolic links. Package archives therefore remain inside the
detached-signature scope.

The same immutable candidate job starts isolated Redis 7.2 and PostgreSQL 16
services and runs both durable `--ignored` interoperability suites before
building the bundle. Those services are test infrastructure only; production
deployments still require TLS-first configuration and an operator-reviewed
schema migration.

The fuzz job copies the checked-in seed corpus to the runner's temporary
directory before every smoke, extended, and LeakSanitizer campaign. This keeps
libFuzzer's automatically discovered corpus entries out of the checkout so
the subsequent commit-bound evidence emitter can enforce a clean tree.

Release evidence, merged manifests, and detached signing outputs use exclusive
file creation. A pre-existing output path is a release failure; do not reuse an
evidence directory or replace an existing record in place.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-features
cargo test --locked -p secure-webauthn-example
cargo test --locked -p secure-webauthn-example --test storage_contract
cargo test --locked -p secure-auth-axum --all-features
cargo test --locked -p secure-auth-actix --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo install cargo-audit --locked --version 0.22.2
cargo audit
cargo package --locked --workspace --all-features
pnpm install --frozen-lockfile
pnpm audit --audit-level high
pnpm test:native-parity
pnpm check:native-parity
pnpm test:release-version-parity
pnpm check:release-version-parity
pnpm test:release-evidence
pnpm test:release-bundle
pnpm test:release-archive
pnpm test:release-candidate-metadata
pnpm test:expo-development-build
pnpm test:sign-release
pnpm test:emit-signed-release-evidence
pnpm test:device-evidence
pnpm test:security-audit
pnpm security-audit
pnpm --dir packages/contracts typecheck
pnpm --dir packages/contracts test
pnpm --dir packages/contracts build
pnpm --dir packages/react-native typecheck
pnpm --dir packages/react-native test
pnpm --dir packages/react-native build
pnpm --dir packages/react-native pack --dry-run
pnpm --dir packages/web typecheck
pnpm --dir packages/web test
pnpm --dir packages/web build
pnpm --dir packages/server-node typecheck
pnpm --dir packages/server-node test
pnpm --dir packages/server-node build
pnpm --dir packages/server-node pack --dry-run
(cd packages/flutter && dart pub publish --dry-run)
pnpm exec playwright install --with-deps chromium firefox webkit
pnpm test:web-browser all
```

The workspace deliberately does not auto-install React Native peer runtimes.
The RN package is tested as a publishable contract with a local type-only seam;
an application must install and build its chosen React Native version as a
peer dependency. This keeps the SDK workspace audit from silently inheriting a
host bundler vulnerability.

For crates.io publication, publish the Rust dependency chain in order after
the exact commit is tagged: `secure-core`, `secure-auth`,
`secure-auth-server`, `secure-auth-http`, `secure-webauthn-example`, then
`secure-auth-axum` and `secure-auth-actix`. A local workspace path dependency
is not evidence that an individual crate can be published before its registry
dependency exists.

The compatibility matrix in `docs/COMPATIBILITY.md` is part of the release
input. A release must publish the exact commit, lockfiles, toolchain versions,
native static-library checksums, SBOM, and framework package manifests as one
set. HTTP deployments must also be reviewed against
`docs/HTTP-DEPLOYMENT.md`.
The Contracts package is the canonical UI/SDK release version; the version
parity gate rejects drift across public Cargo, npm (including the Node server
adapter), Flutter, and Podspec
artifacts. Authentication protocol and C ABI versions remain independent.
Password migrations must also follow `docs/MIGRATION-FROM-PASSWORD.md` and
must not introduce a client-side replayable hash.

## Release evidence manifest

Before a public release claim, produce a machine-readable evidence manifest and
validate its schema and detached signature:

```sh
node scripts/check-release-evidence.mjs path/to/release-evidence.json
```

When evidence is produced by separate CI, device, browser, and reviewer runs,
merge the fragments inside one evidence root before the final validation:

```sh
pnpm merge:release-evidence \
  release-evidence \
  release-evidence.json \
  source-gates.json \
  device-ios.json \
  device-android.json \
  browser-matrix.json \
  independent-review.json \
  signing.json
node scripts/check-release-evidence.mjs release-evidence/release-evidence.json
```

For the final production-candidate validation, provide the independently
verified, distinct SHA-256 fingerprints of the maintainer and reviewer DER
public keys and require both pins. These values must come from the protected
release process, not from the evidence bundle itself:

```sh
SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256=<maintainer-fingerprint> \
SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256=<reviewer-fingerprint> \
node scripts/check-release-evidence.mjs --require-trusted-keys \
  release-evidence/release-evidence.json
```

The merger requires one exact commit, package version, and toolchain set,
rejects duplicate gate names, artifact kinds, and referenced paths, refuses
all symlink traversal for referenced evidence and artifact files (including
symlinks whose targets remain inside the evidence root), and fails if the
resulting manifest is incomplete. It never
turns a skipped or missing fragment into a passing gate.

The device, browser, CI, release-gate, and signed-release evidence emitters,
as well as the fragment merger, apply the same symlink refusal before reading,
hashing, or writing evidence. A parent directory that is a symlink is rejected
even when its target remains inside the evidence root.

The source-level security audit rejects editable text controls in every native
keypad implementation (`EditText`-family Android widgets and
`UITextField`/`UITextView`-family iOS controls). Native keypad input must remain
key-ID based and native-owned; adding an ordinary text control is a release
failure even if the framework bridge still emits only masked events.

The final verifier bounds the top-level manifest and every referenced file
before parsing or hashing it: the manifest, gate records, and independent-
review reports are limited to 1 MiB, detached Ed25519 public keys to 1 KiB,
detached signatures to 64 bytes, and the signed release bundle and other
release artifacts to 512 MiB. Oversized files fail closed before materialization
or cryptographic verification.

The standalone device-evidence validator also bounds its top-level JSON record
to 1 MiB before parsing. It separately bounds every referenced device log and
artifact to 32 MiB before hashing or content scanning.

The checked-in gate-fragment emitter and evidence merger apply the same 1 MiB
bound to gate JSON and fragments before parsing them. The browser evidence
emitter bounds each browser log to the 32 MiB device-evidence limit, and the
release signer bounds the signed bundle to 512 MiB and the private-key input
to 64 KiB. The WebAuthn adapter bounds both directions of base64url conversion
to 8 KiB before allocation or string expansion, and normalizes browser API or
credential-object exceptions before they leave the adapter. Before any downloaded
candidate/CI/external root is copied, the
release-evidence stager rejects individual files over 512 MiB, more than 2 GiB
combined input, more than 16,384 regular files, more than 16,384 directories,
or a path deeper than 64 components. This protects the finalizer from an
untrusted artifact archive exhausting its workspace or traversal stack before
the normal manifest bounds can run; directory entries are read incrementally
instead of materializing an untrusted directory listing in one array.

The standalone device-evidence validator also requires `status: "pass"` on
every platform record; a record with passing test-case fields but a missing or
non-passing top-level status cannot be used as device evidence.

Physical iOS/Android operators should use
`scripts/emit-native-device-evidence.mjs` to produce the device record and
fragment. It requires all native test cases and categorized physical artifacts,
hashes the exact files inside the evidence root, and rejects the canonical test
sentinel before output is written. Native evidence files are bounded to 32 MiB
before they are materialized by the emitter or final verifier.

Every `gate.evidencePath` must point to a JSON object with
`{schemaVersion: 1, gate: <same gate name>, commit: <same gate SHA>, status: "pass"}`. CI-owned gates additionally
require `evidenceKind: "ci-command"`, a sanitized `runner`, an ISO-8601
`recordedAt`, and either the owning job check labels (`job-rust`,
`job-contracts`, the four framework host jobs, `job-fuzz`, or
`job-durable-backends`) or the complete direct command group for the durable
and fuzz jobs. The final file
verification recomputes its digest and checks that embedded commit, status, and
gate binding and secret-field policy, so a current manifest cannot be assembled
from an older, cross-gate, or secret-bearing gate record. The `ios-device-matrix` and
`android-device-matrix` records are then revalidated as physical native records
with both passing `react-native` and `flutter` entries in `hostModes`, all required
test cases, and categorized artifacts; one framework's device run cannot satisfy
the native gate. `web-browser-matrix` is revalidated as a Web record. The verifier
also revalidates nested log and artifact digests
inside those device records, so changing a screenshot, report,
or sanitized log invalidates the release gate. For native records, the nested
`native-checksum` digest must additionally equal the candidate
`native-checksum` artifact for iOS or `native-checksum-android` artifact for
Android; a physical run using a different native binary cannot satisfy the
release gate.

Nested device files also undergo a byte-level preflight for the canonical
disposable sentinel `secure-keypad-test-sentinel-7f2c4e` and common
secret-bearing text fields. This catches accidental retention in logs and
text artifacts; it cannot replace OCR, crash-dump, screenshot, or independent
review of the actual device evidence.

Use the checked-in emitter after the gate command has completed successfully;
it reads the current immutable checkout SHA and Contracts package version, then
hashes the exact evidence bytes without accepting a caller-supplied commit:

```sh
node scripts/emit-release-gate-evidence.mjs \
  "$RUNNER_TEMP/release-evidence" \
  "fragments/rust-workspace.json" \
  rust-workspace \
  "evidence/rust-workspace.json" \
  --toolchain rust=1.97.1
```

Repeat it for each gate and merge the resulting fragments. The emitter does not
claim that a command ran; the gate job remains responsible for producing and
reviewing the sanitized JSON record before invoking it.

The CI workflow now emits the `secure-keypad-ci-release-evidence` artifact after
all source, service, host-build, fuzz, and browser jobs succeed. It contains
commit-bound fragments for those CI gates and browser records whose log files
are referenced by digest rather than copied into JSON. Download that artifact
and merge its `fragments/*.json` with the separately collected physical-device,
independent-review, and signed-release fragments; the resulting manifest is
still expected to fail until every required external gate is present.

The checked-in `release-finalize.yml` workflow automates that last assembly as
a read-only, manually approved operation. Dispatch it with the exact commit
SHA, the run IDs for the release-candidate bundle and CI evidence, and an
external evidence artifact run containing the physical iOS/Android records,
the independent-review fragment, and every referenced log, screenshot/report,
review key, and review signature. The external artifact must use the same
relative evidence-root layout (`fragments/`, `evidence/`, and `artifacts/`).
The workflow validates the candidate staging contract, proves its metadata
commit equals the requested SHA, rejects symlinked/duplicate/special input
files, converts `evidence/signed-release.json` into the complete
`signed-release` gate/artifact/signature fragment, and then runs the merger and
`--require-trusted-keys` verifier. It retains the result as
`secure-keypad-production-release-evidence`; a missing or stale external
fragment fails the job and cannot become a production claim. The
`secure-keypad-release` environment must hold the protected
`SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256` and
`SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256` values and require its configured
reviewers.

Before staging, it independently checks the candidate tar entry contract,
verifies the candidate checksum manifest, and compares both native checksum
manifests, the SBOM, and the notices file byte-for-byte with the copies inside
the signed tarball. This prevents a separately downloaded evidence file from
silently replacing the signed source input.

The release-candidate artifact also contains
`fragments/candidate-artifacts.json`. It hashes the native iOS and Android FFI
checksum manifests, SPDX SBOM, and third-party notices; these are the required
`native-checksum`, `native-checksum-android`, `sbom`, and `license-notices`
artifact entries in the final manifest. Both native checksum manifests and the
Android commit binding are copied into `source/` before the deterministic
tarball is created, so the signed source bundle and final evidence refer to
the same verified native inputs. The Android manifest uses the final
signed-source paths and can be verified directly from the archive root with
`sha256sum -c`; staging and finalization also check that its commit file equals
the candidate metadata commit.

For a browser-only evidence root, the checked-in web emitter accepts the three
sanitized Playwright logs and creates the validator-compatible matrix record:

```sh
node scripts/emit-web-browser-evidence.mjs \
  "$RUNNER_TEMP/release-evidence" \
  "evidence/web-browser-matrix.json" \
  "fragments/web-browser-matrix.json" \
  --framework-version playwright-1.62.1 \
  --runner ubuntu-24.04 \
  --log chromium=browser/chromium.log \
  --log firefox=browser/firefox.log \
  --log webkit=browser/webkit.log
```

Create the detached Ed25519 signature and public-key material with a protected
maintainer key. The private key is read only and is never copied into the
release bundle or printed:

```sh
node scripts/sign-release.mjs \
  artifacts/secure-keypad-release.tar.gz \
  /protected/path/secure-keypad-release-signing-key.pem \
  artifacts/secure-keypad-release.sig \
  artifacts/secure-keypad-release.pub.der
```

After signing, emit the commit-bound `signed-release` gate record from the
same artifact root. The emitter verifies the Ed25519 signature before writing
only public metadata and SHA-256 digests:

```sh
node scripts/emit-signed-release-evidence.mjs \
  "$RUNNER_TEMP/secure-keypad-release" \
  "evidence/signed-release.json" \
  --bundle secure-keypad-release.tar.gz \
  --signature secure-keypad-release.sig \
  --public-key secure-keypad-release.pub.der
```

The checked-in release-candidate workflow runs the bundle job in the
`secure-keypad-release` GitHub Environment. Repository administrators must
configure that environment with required reviewers and the signing secret;
the workflow file alone cannot establish those GitHub-side protections.

The independently signed review artifact must be a structured JSON report, not
an arbitrary signed note. Its `schemaVersion` is `1`, `reportType` is
`independent-security-review`, and it must bind the exact manifest commit,
package version, and reviewer public-key SHA-256. Its scope must cover
`native-input-boundary`, `opaque-authentication`, `http-json-transport`,
`replay-rate-limit-backends`, `framework-adapters`, `device-runtime-evidence`,
and `release-process`; it must include bounded finding records. Every finding
must also declare `affectedScope`, `reproduction`, `remediationOwner`, and
`retestEvidence`, so an accepted residual risk cannot be recorded without an
accountable review trail. The report must end with an explicit `approved` or
`approved-with-residual-risk` decision. `not-approved`, malformed,
secret-bearing, scope-incomplete, or over-1 MiB reports fail closed before
release verification; critical/high findings must be `accepted` or
`remediated`, never `open`.

Reviewers can use the checked-in fragment emitter after signing the report
with the review key. The signing helper reads the private key only long enough
to produce the detached signature and DER public key; the fragment emitter
accepts only the report, signature, and public key, verifies the exact bytes,
and derives the checkout identity from a clean reviewed checkout:

```sh
node scripts/sign-release.mjs \
  "$RUNNER_TEMP/release-evidence/artifacts/independent-review.json" \
  "$REVIEWER_PRIVATE_KEY_PATH" \
  "$RUNNER_TEMP/release-evidence/artifacts/independent-review.sig" \
  "$RUNNER_TEMP/release-evidence/artifacts/independent-review.pub.der"
node scripts/emit-independent-review-fragment.mjs \
  "$RUNNER_TEMP/release-evidence" \
  "evidence/independent-security-review.json" \
  "fragments/independent-security-review.json" \
  --report artifacts/independent-review.json \
  --signature artifacts/independent-review.sig \
  --public-key artifacts/independent-review.pub.der
```

The emitter never accepts a private-key path, never copies private material,
and refuses a report whose reviewed commit, package version, scope, decision,
or reviewer-key fingerprint does not match the signed inputs. The final
trusted verifier remains authoritative for every finding-level review rule.

The workflow also embeds `release-candidate-metadata.json` inside the signed
source bundle. That record is deliberately marked `candidate-only`: it binds
the exact checkout and package version, enumerates every final gate, and
records the protected-key inputs and verifier command, but it does not mark
external device, sanitizer, or independent-review gates as passed. Operators
must merge the separately emitted evidence fragments and run the trusted-key
verification before making a production claim.
Metadata emission also fails if the checkout became dirty during the build, so
generated or locally modified files cannot silently enter an exact-SHA bundle.

The manifest requires pinned Rust/Node/Flutter/React Native/NDK versions,
hashed evidence for every required gate, native checksums, an SPDX SBOM, license
notices, a hashed release bundle, DER public key, and `release-signature`
artifacts, an independent-review report, reviewer DER public key, and
`independent-review-signature` artifacts, a Linux LeakSanitizer result,
physical iOS/Android and Web browser matrix results, an independent security
review, and signed-release evidence.
Every gate entry must also carry the exact 40-character commit SHA it verified;
the validator rejects a missing or mismatched gate commit before accepting the
manifest.
The `signature` descriptor must bind the listed release bundle, signature
artifact, and DER-encoded Ed25519 public key. The command checks shape, paths,
required statuses, recomputes SHA-256 for every referenced evidence/artifact
file, rejects duplicate evidence paths, ensures the manifest commit/version
match the current checkout, and verifies both the detached release signature and
the detached `independentReview` signature over the exact review report. The
`independentReview` descriptor must also carry `reviewedCommit` and
`reviewedPackageVersion`, each matching the manifest commit and package version;
a signed report for a different checkout or an empty referenced gate/artifact
file cannot satisfy the gate. Every referenced file must be a regular,
non-empty file; device and browser evidence files are additionally bounded by
the device-verification limits. It does not establish CI provenance; trusted
fingerprints, CI attestation, and reviewer identity must still be verified
independently against the exact commit. The
`--require-trusted-keys` mode fails closed when either protected fingerprint is
missing, does not match the corresponding descriptor, or is identical to the
other protected fingerprint.

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder, `fuzz/core_sequence` exercises the numeric, printable-ASCII, and
Hangul core state machines, `fuzz/ffi_sequence` exercises the exported native
C ABI and all three policy constructors, and
`fuzz/webauthn_state` exercises bounded versioned server-state deserialization.
CI builds all four with `cargo-fuzz` on pinned `nightly-2026-08-19` and runs a bounded
2,000-iteration smoke campaign plus a 1,000,000-iteration stability campaign
with a 1 GiB libFuzzer RSS guard. The fuzz job has a 60-minute timeout covering
the extended and Linux LeakSanitizer campaigns. A fresh local arm64 verification completed
1,000,000 iterations for all four targets without a crash artifact; the
WebAuthn run used `-max_len=131073` to exercise the 128 KiB rejection boundary.
Every target has at least one bounded, checked-in seed corpus under
`fuzz/corpus/`; the FFI corpus includes numeric, printable-ASCII, and Hangul
constructor paths. Generated campaign additions are ephemeral and must not be
treated as release evidence by themselves. A separate seeded FFI smoke run
completed 2,000 iterations with no crash artifact. These local arm64 results
are supplemental; Linux LeakSanitizer evidence remains mandatory.
Any new parser or
native-boundary decoder must add a corresponding target or corpus regression
before release. These smoke campaigns are not a substitute for the full
campaign and memory/leak testing listed in the roadmap.

On 2026-08-21, an earlier local arm64 run using the exact CI-pinned
`nightly-2026-08-19` toolchain and the same 1,000,000-iteration arguments
completed without a crash artifact: auth-envelope reached `cov 1130` with
469 MB final RSS, core-sequence reached `cov 96` with 476 MB, native FFI
sequence reached `cov 279` with 564 MB, and WebAuthn-state reached `cov 1269`
with 498 MB using `-max_len=131073`. The FFI boundary campaign is also
covered by the same CI stability and Linux leak-sanitizer commands.
Those RSS values are libFuzzer process measurements that include its evolving
corpus and coverage tables; they are not an SDK memory ceiling or a leak
result. The Linux leak-sanitizer job remains mandatory.
The CI fuzz job uploads the 1M and LeakSanitizer logs as the
`secure-keypad-fuzz-logs` artifact, including failed campaign output.

## Durable backend gate

The feature-gated Redis and PostgreSQL adapters must compile under
`cargo test --workspace --all-features`. The ignored interoperability tests
must run against isolated Redis and PostgreSQL services in CI or a release
environment with `--ignored`; they verify one-time consume, namespace/kind
isolation, replay rejection, and expired-state cleanup. The same service job
must run the feature-gated `RateLimiter` adapters and verify fixed-window
allowed/limited decisions. Durable adapters also bound pending ceremony count
per namespace, active rate-limit keys, and credential-record size. Built-in
WebAuthn ceremony adapters must encrypt/authenticate records with a
host-managed `WebAuthnStateKey` and perform a pre-`GET` byte check in Redis;
oversized legacy values must be removed atomically before client materialization.
Redis rate-limit counters must likewise be bounded before `GET`. OPAQUE
one-time-state adapters must use a host-managed `OpaqueStateKey` and enforce
the encrypted-record bound before Redis materialization. The ignored durable
service suites also inject oversized legacy Redis values and verify key/index
cleanup on the live service, including recovery when Redis has evicted a
backing state or counter key while leaving its active-index member. Release
evidence must show key provisioning,
same-key multi-instance consume, and retention through the maximum state TTL.
Plaintext Redis/`NoTls` constructors are allowed only in that isolated test
job, never in a production configuration.

The Linux fuzz job also runs all four targets under Rust's leak sanitizer.
The local macOS arm64 runner cannot execute that sanitizer because the target
does not support it; therefore a green Linux CI result is required before the
memory/leak gate can be closed.

Device execution follows `docs/DEVICE-VERIFICATION.md`. Host compilation alone
does not close screenshot, background, autofill, clipboard, accessibility, or
native opaque-handoff gates; physical-device evidence and an independent
reviewer sign-off are required.

## Artifact and platform gates

CI also builds the iOS `secure_ffi` device/simulator libraries into an
XCFramework, validates the C header and native Swift/Kotlin contracts, runs
Flutter analyze/tests, and compiles ephemeral Android arm64 and iOS Simulator
Flutter and React Native host apps against the publishable plugins and Rust FFI
library. The
React Native gate pins RN `0.87.0`, CLI `20.2.0`, Node `22.13.0`, and Java 17;
the Flutter gates pin Flutter `3.47.0`. These are reproducible host-link
baselines, not device behavior or accessibility sign-offs. CI emits file-level
SHA-256 manifests for the iOS XCFramework and Android native FFI host artifacts,
dependency metadata, and an SPDX SBOM through
Syft/Anchore. Before a public release, the artifact must include the exact
Rust/Node/Flutter/native toolchain versions, the notices in
`docs/THIRD-PARTY-NOTICES.md`, threat model, and signed checksums.

The macOS iOS host job also installs and launches both generated host apps in
an available iOS Simulator and uploads no-input runtime screenshots. This is
a supplemental launch/packaging signal; it does not close the physical-device
capture, autofill, accessibility, or opaque-handoff gates.
The Android host jobs additionally build the arm64 and x86_64 native FFI
variants, and a separate API 35 x86_64 emulator job installs and launches both
generated host APKs while retaining no-input screenshots. This is also
supplemental runtime evidence and does not replace the physical Android matrix.

The CI `web-browser-matrix` job runs the checked-in browser smoke harness against
the exact Playwright dependency in the lockfile on Chromium, Firefox, and
WebKit. It verifies secure-context detection, passkey support probing, strict
fallback acknowledgement, and binary encoding boundaries in a real browser
page. This is runtime adapter evidence only; it does not prove that a browser
page's JavaScript memory is confidential or replace a physical authenticator
and deployed-origin WebAuthn test. Each matrix leg retains its sanitized
versioned smoke log as a CI artifact, including failed runs.

The CI evidence aggregate also retains the Android emulator and iOS Simulator
runtime screenshots, the complete fuzz/LeakSanitizer campaign logs, and the
dependency metadata artifact under `retained/`. These files are copied into
the final production evidence artifact by the read-only finalizer. They remain
supporting evidence rather than untrusted JSON claims: gate records contain
only bounded, sanitized metadata and the final verifier still requires the
actual Linux LSAN, physical-device, and independent-review gates.

## Known release blockers

- Native RN view-manager and Flutter PlatformView/FFI registration reference
  source is included in both publishable packages and checked for parity, but
  all CI host-build gates must be green and each target host application must
  still compile it against its chosen RN/Flutter versions, install a native
  submission consumer, and run the device matrix.
- WebAuthn reference verification service, injectable storage contracts,
  feature-gated Redis/PostgreSQL adapters, bounded framework-neutral HTTP
  contract, required host-validated CSRF input, and compile-tested Axum
  Axum and Actix integrations are shipped. The deployed host-session/CSRF
  validator, deployment TLS configuration, and isolated durable-backend
  interoperability job remain deployment gates.
- Device accessibility/screenshot/autofill verification and an independent
  security review remain mandatory.
