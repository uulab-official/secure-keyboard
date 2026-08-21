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
It also rejects malformed archives, symlinks, and private signing material in
the staging directory. This proves the input to the deterministic archive is
complete; it does not replace the protected signing step or external release
evidence.

The same immutable candidate job starts isolated Redis 7.2 and PostgreSQL 16
services and runs both durable `--ignored` interoperability suites before
building the bundle. Those services are test infrastructure only; production
deployments still require TLS-first configuration and an operator-reviewed
schema migration.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-features
cargo test --locked -p secure-webauthn-example
cargo test --locked -p secure-webauthn-example --test storage_contract
cargo test --locked -p secure-auth-axum --all-features
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
pnpm test:release-candidate-metadata
pnpm test:expo-development-build
pnpm test:sign-release
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
`secure-auth-axum`. A local workspace path dependency is not evidence that an
individual crate can be published before its registry dependency exists.

The compatibility matrix in `docs/COMPATIBILITY.md` is part of the release
input. A release must publish the exact commit, lockfiles, toolchain versions,
native static-library checksums, SBOM, and framework package manifests as one
set. HTTP deployments must also be reviewed against
`docs/HTTP-DEPLOYMENT.md`.
The Contracts package is the canonical UI/SDK release version; the version
parity gate rejects drift across public Cargo, npm, Flutter, and Podspec
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
verified SHA-256 fingerprints of the maintainer and reviewer DER public keys
and require both pins. These values must come from the protected release
process, not from the evidence bundle itself:

```sh
SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256=<maintainer-fingerprint> \
SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256=<reviewer-fingerprint> \
node scripts/check-release-evidence.mjs --require-trusted-keys \
  release-evidence/release-evidence.json
```

The merger requires one exact commit, package version, and toolchain set,
rejects duplicate gate names, artifact kinds, and referenced paths, refuses
symlink escapes, and fails if the resulting manifest is incomplete. It never
turns a skipped or missing fragment into a passing gate.

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
with all required test cases and categorized artifacts; `web-browser-matrix` is
revalidated as a Web record. The verifier also revalidates nested log and artifact digests
inside those device records, so changing a screenshot, report,
or sanitized log invalidates the release gate.

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

The checked-in release-candidate workflow runs the bundle job in the
`secure-keypad-release` GitHub Environment. Repository administrators must
configure that environment with required reviewers and the signing secret;
the workflow file alone cannot establish those GitHub-side protections.

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
missing or does not match the corresponding descriptor.

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder, `fuzz/core_sequence` exercises the numeric, printable-ASCII, and
Hangul core state machines, `fuzz/ffi_sequence` exercises the exported native
C ABI and all three policy constructors, and
`fuzz/webauthn_state` exercises bounded versioned server-state deserialization.
CI builds all four with `cargo-fuzz` on pinned `nightly-2026-08-19` and runs a bounded
2,000-iteration smoke campaign plus a 1,000,000-iteration stability campaign
with a 1 GiB libFuzzer RSS guard. A fresh local arm64 verification completed
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
cleanup on the live service. Release evidence must show key provisioning,
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

## Known release blockers

- Native RN view-manager and Flutter PlatformView/FFI registration reference
  source is included in both publishable packages and checked for parity, but
  all CI host-build gates must be green and each target host application must
  still compile it against its chosen RN/Flutter versions, install a native
  submission consumer, and run the device matrix.
- WebAuthn reference verification service, injectable storage contracts,
  feature-gated Redis/PostgreSQL adapters, bounded framework-neutral HTTP
  contract, required host-validated CSRF input, and compile-tested Axum
  integration are shipped. The deployed host-session/CSRF validator,
  deployment TLS configuration, and isolated durable-backend interoperability
  job remain deployment gates.
- Device accessibility/screenshot/autofill verification and an independent
  security review remain mandatory.
