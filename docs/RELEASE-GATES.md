# Release gates

The repository is a production candidate only when every applicable gate is
green and the platform/security review items are signed off. A passing unit
test suite alone is not a production claim.

## Reproducible local gates

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm install --frozen-lockfile
pnpm audit --audit-level high
pnpm --dir packages/contracts typecheck
pnpm --dir packages/contracts test
pnpm --dir packages/contracts build
pnpm --dir packages/react-native typecheck
pnpm --dir packages/react-native test
pnpm --dir packages/react-native build
pnpm --dir packages/web typecheck
pnpm --dir packages/web test
pnpm --dir packages/web build
```

The workspace deliberately does not auto-install React Native peer runtimes.
The RN package is tested as a publishable contract with a local type-only seam;
an application must install and build its chosen React Native version as a
peer dependency. This keeps the SDK workspace audit from silently inheriting a
host bundler vulnerability.

## Fuzz gate

The `fuzz/auth_envelope` target exercises the raw-body and bounded-payload
decoder. CI builds it with `cargo-fuzz` on nightly and runs a bounded smoke
campaign. Any new parser or native-boundary decoder must add a corresponding
target or corpus regression before release.

## Artifact and platform gates

CI also validates the C header, native Swift/Kotlin contracts, Flutter analyze
and tests, emits dependency metadata, and generates an SPDX SBOM through
Syft/Anchore. Before a public release, the artifact must include the exact
Rust/Node/Flutter/native toolchain versions, license notices, threat model, and
signed checksums.

## Known release blockers

- Native RN view-manager and Flutter PlatformView/FFI registration are not yet
  complete.
- WebAuthn server-side challenge/origin/RP-ID verification examples are not
  yet shipped.
- Device accessibility/screenshot/autofill verification and an independent
  security review remain mandatory.
