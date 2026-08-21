# Release gates

The repository is a production candidate only when every applicable gate is
green and the platform/security review items are signed off. A passing unit
test suite alone is not a production claim.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo test -p secure-webauthn-example
cargo test -p secure-webauthn-example --test storage_contract
cargo test -p secure-auth-axum --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm install --frozen-lockfile
pnpm audit --audit-level high
pnpm test:native-parity
pnpm check:native-parity
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

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder, `fuzz/core_sequence` exercises the native/core state machine, and
`fuzz/webauthn_state` exercises bounded versioned server-state deserialization.
CI builds all three with `cargo-fuzz` on nightly and runs a bounded
2,000-iteration smoke campaign. The current local verification completed
100,000 iterations for all three targets: auth-envelope, core-sequence, and
webauthn-state; the WebAuthn run used `-max_len=131073` to exercise the
128 KiB rejection boundary. The extended runs retained their corpora under
`fuzz/corpus/`, produced no crash artifact, and observed peak RSS below
131 MB on the local arm64 runner. Any new parser or
native-boundary decoder must add a corresponding target or corpus regression
before release. These smoke campaigns are not a substitute for the full
campaign and memory/leak testing listed in the roadmap.

## Durable backend gate

The feature-gated Redis and PostgreSQL adapters must compile under
`cargo test --workspace --all-features`. The ignored interoperability tests
must run against isolated Redis and PostgreSQL services in CI or a release
environment with `--ignored`; they verify one-time consume, namespace/kind
isolation, replay rejection, and expired-state cleanup. Durable adapters also
bound pending ceremony count per namespace and credential-record size.
Plaintext Redis/`NoTls` constructors are allowed only in that isolated test
job, never in a production configuration.

The Linux fuzz job also runs all three targets under Rust's leak sanitizer.
The local macOS arm64 runner cannot execute that sanitizer because the target
does not support it; therefore a green Linux CI result is required before the
memory/leak gate can be closed.

## Artifact and platform gates

CI also builds the iOS `secure_ffi` device/simulator libraries into an
XCFramework, validates the C header and native Swift/Kotlin contracts, runs
Flutter analyze/tests, emits dependency metadata, and generates an SPDX SBOM through
Syft/Anchore. Before a public release, the artifact must include the exact
Rust/Node/Flutter/native toolchain versions, the notices in
`docs/THIRD-PARTY-NOTICES.md`, threat model, and signed checksums.

## Known release blockers

- Native RN view-manager and Flutter PlatformView/FFI registration reference
  source is included in both publishable packages and checked for parity, but
  each host application must compile it against its chosen RN/Flutter versions,
  install a native submission consumer, and run the device matrix.
- WebAuthn reference verification service, injectable storage contracts,
  feature-gated Redis/PostgreSQL adapters, bounded framework-neutral HTTP
  contract, and compile-tested Axum integration are shipped. Host-session/CSRF
  integration, deployment TLS configuration, and the isolated durable-backend
  interoperability job remain deployment gates.
- Device accessibility/screenshot/autofill verification and an independent
  security review remain mandatory.
