# Secure Keypad SDK

Open-source, cross-platform virtual keypad SDK with a customizable UI contract and a secure native input path.

This project is under active development. It is not a security certification and must not be used as evidence of regulatory compliance without an independent review.

## Security model

Mobile Secure Native Mode keeps input handling in the native/core layer and exposes only key IDs, masked state, and authentication results to framework code. Headless host rendering is an opt-in compatibility mode with a lower assurance level. Web applications should prefer WebAuthn/passkeys; a web keypad cannot make a browser page's JavaScript memory a trusted security boundary.

Read the [security specification](docs/SECURITY-SPEC.md) and [roadmap](docs/ROADMAP.md) before integrating the SDK.

## Current packages

- `secure-core`: key-ID-only input state, masking state, Hangul composition, timeout, and explicit clearing.
- `secure-auth`: pinned OPAQUE 4.0.1 engine with Argon2 KSF for native/server Rust integrations.
- `secure-ffi`: C ABI with opaque session/submission handles for native iOS/Android bindings.
- `@secure-keypad/contracts`: publishable layout, theme, masked-state, and result-event contracts.

The native iOS/Android renderers and React Native/Flutter bindings are not released yet. Do not treat the current repository state as a drop-in production authentication component.

## Development

```sh
cargo test --workspace
pnpm install
pnpm --dir packages/contracts test
```

Do not use real credentials in tests, issues, logs, screenshots, or crash reports.
