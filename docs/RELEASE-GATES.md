# Release gates

The repository is a production candidate only when every applicable gate is
green and the platform/security review items are signed off. A passing unit
test suite alone is not a production claim.

Every GitHub Action in the release workflow is pinned to a 40-character commit
SHA, and CI jobs use the explicit `ubuntu-24.04` or `macos-15` runner image
labels. The adjacent action version comment is informational only; changing an
action or runner requires an explicit revision update and a passing security
audit.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo test -p secure-webauthn-example
cargo test -p secure-webauthn-example --test storage_contract
cargo test -p secure-auth-axum --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
pnpm install --frozen-lockfile
pnpm audit --audit-level high
pnpm test:native-parity
pnpm check:native-parity
pnpm test:release-version-parity
pnpm check:release-version-parity
pnpm test:release-evidence
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
validate its schema:

```sh
node scripts/check-release-evidence.mjs path/to/release-evidence.json
```

The manifest requires pinned Rust/Node/Flutter/React Native/NDK versions,
hashed evidence for every required gate, native checksums, an SPDX SBOM, license
notices, a hashed `release-signature` artifact, a Linux LeakSanitizer result,
physical iOS/Android and Web browser matrix results, an independent security
review, and signed-release evidence.
The command checks shape, paths, required statuses, and recomputes SHA-256 for
every referenced evidence/artifact file. It does not verify CI provenance,
signatures, or reviewer identity; those references must still be verified
independently against the exact commit.

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder, `fuzz/core_sequence` exercises the core state machine,
`fuzz/ffi_sequence` exercises the exported native C ABI, and
`fuzz/webauthn_state` exercises bounded versioned server-state deserialization.
CI builds all four with `cargo-fuzz` on pinned `nightly-2026-08-19` and runs a bounded
2,000-iteration smoke campaign plus a 1,000,000-iteration stability campaign
with a 1 GiB libFuzzer RSS guard. The current local verification completed
100,000 iterations for the original three targets: auth-envelope,
core-sequence, and webauthn-state; the WebAuthn run used `-max_len=131073` to
exercise the 128 KiB rejection boundary. Their minimized seed corpora are
tracked under `fuzz/corpus/`; generated campaign additions are ephemeral and
must not be treated as release evidence by themselves. Those runs produced no
crash artifact and observed peak RSS below 131 MB on the local arm64 runner.
Any new parser or
native-boundary decoder must add a corresponding target or corpus regression
before release. These smoke campaigns are not a substitute for the full
campaign and memory/leak testing listed in the roadmap.

On 2026-08-21, a local arm64 run using the exact CI-pinned
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
per namespace, active rate-limit keys, and credential-record size.
Plaintext Redis/`NoTls` constructors are allowed only in that isolated test
job, never in a production configuration.

The Linux fuzz job also runs all three targets under Rust's leak sanitizer.
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
