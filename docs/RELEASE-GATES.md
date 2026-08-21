# Release gates

The repository is a production candidate only when every applicable gate is
green and the platform/security review items are signed off. A passing unit
test suite alone is not a production claim.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo test -p secure-webauthn-example
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm install --frozen-lockfile
pnpm audit --audit-level high
pnpm test:native-parity
pnpm check:native-parity
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

The compatibility matrix in `docs/COMPATIBILITY.md` is part of the release
input. A release must publish the exact commit, lockfiles, toolchain versions,
native static-library checksums, SBOM, and framework package manifests as one
set.

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder. CI builds it with `cargo-fuzz` on nightly and runs a bounded smoke
campaign. Any new parser or native-boundary decoder must add a corresponding
target or corpus regression before release.

## Artifact and platform gates

CI also validates the C header, native Swift/Kotlin contracts, Flutter analyze
and tests, emits dependency metadata, and generates an SPDX SBOM through
Syft/Anchore. Before a public release, the artifact must include the exact
Rust/Node/Flutter/native toolchain versions, the notices in
`docs/THIRD-PARTY-NOTICES.md`, threat model, and signed checksums.

## Known release blockers

- Native RN view-manager and Flutter PlatformView/FFI registration reference
  source is included in both publishable packages and checked for parity, but
  each host application must compile it against its chosen RN/Flutter versions,
  install a native submission consumer, and run the device matrix.
- WebAuthn reference verification service and bounded framework-neutral HTTP
  contract are shipped, but framework-specific HTTP integration, durable
  credential storage, and distributed ceremony-state tests remain deployment
  gates.
- Device accessibility/screenshot/autofill verification and an independent
  security review remain mandatory.
