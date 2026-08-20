# Secure Keypad SDK

Open-source, cross-platform virtual keypad SDK with a customizable UI contract and a secure native input path.

This project is under active development. It is not a security certification and must not be used as evidence of regulatory compliance without an independent review.

## Security model

Mobile Secure Native Mode keeps input handling in the native/core layer and exposes only key IDs, masked state, and authentication results to framework code. Headless host rendering is an opt-in compatibility mode with a lower assurance level. Web applications should prefer WebAuthn/passkeys; a web keypad cannot make a browser page's JavaScript memory a trusted security boundary.

Read the [security specification](docs/SECURITY-SPEC.md) and [roadmap](docs/ROADMAP.md) before integrating the SDK.

## Current packages

- `secure-core`: key-ID-only input state, masking state, Hangul composition, timeout, and explicit clearing.
- `secure-auth`: pinned OPAQUE 4.0.1 engine with Argon2 KSF, typed protocol envelopes, and native/server Rust integrations.
- `secure-auth-server`: transport-neutral OPAQUE server service plus bounded one-time state-store reference implementation; distributed deployments must provide an atomic Redis/DB adapter.
- `secure-ffi`: C ABI with opaque session/submission handles for native iOS/Android bindings.
- `@secure-keypad/contracts`: publishable layout, theme, masked-state, and result-event contracts.
- `@secure-keypad/react-native`: publishable React Native prop/event boundary for the native view manager; it rejects secret-bearing props and exposes only masked state/result codes.
- `@secure-keypad/web`: passkey-first WebAuthn adapter; it converts server JSON options and serializes ceremony results without exposing password/PIN APIs. Its custom browser-keypad fallback requires explicit lower-assurance acknowledgement.
- `secure_keypad_flutter`: publishable Flutter-facing layout/theme/policy contract; it exposes only masked state/result callbacks and has no `TextEditingController` or secret callback.

The contracts package exports `DEFAULT_NUMERIC_LAYOUT`,
`DEFAULT_HANGUL_LAYOUT`, and `DEFAULT_THEME` as safe starting points for
custom renderers. These objects contain labels and key IDs only; they do not
contain password values.

Native iOS/Android renderer sources now exist under `native/`. The React
Native package currently ships the public contract and lazy native-component
resolver; the platform view-manager registration, architecture-specific
release packaging, Flutter binding, WebAuthn server example, and device-level
security review remain release gates. Do not treat the current repository
state as a drop-in production authentication component.

## Development

```sh
cargo test --workspace
pnpm install
pnpm --dir packages/contracts test
pnpm --dir packages/react-native test
pnpm --dir packages/web test
cd packages/flutter && flutter test
```

Do not use real credentials in tests, issues, logs, screenshots, or crash reports.
