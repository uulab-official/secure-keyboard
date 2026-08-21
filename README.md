# Secure Keypad SDK

Open-source, cross-platform virtual keypad SDK with a customizable UI contract and a secure native input path.

This project is under active development. It is not a security certification and must not be used as evidence of regulatory compliance without an independent review.

## Security model

Mobile Secure Native Mode keeps input handling in the native/core layer and exposes only key IDs, masked state, and authentication results to framework code. An opt-in Headless Host Mode is available for custom RN/Flutter rendering, but it is lower assurance because the host observes each public key ID and must explicitly acknowledge that trade-off. Web applications should prefer WebAuthn/passkeys; a web keypad cannot make a browser page's JavaScript memory a trusted security boundary.

Read the [security specification](docs/SECURITY-SPEC.md) and [roadmap](docs/ROADMAP.md) before integrating the SDK.
Use the [release gates](docs/RELEASE-GATES.md) to distinguish verified checks from remaining production blockers, and review the [MASVS/MASTG evidence map](docs/MASVS-MAPPING.md) before an independent assessment.
Pin framework/native/protocol combinations using the [compatibility policy](docs/COMPATIBILITY.md).
Use the [HTTP deployment baseline](docs/HTTP-DEPLOYMENT.md) when embedding the
server routes behind TLS or a reverse proxy.
For multi-instance deployments, follow the [distributed backend contract](docs/DISTRIBUTED-BACKENDS.md)
and the [web deployment baseline](docs/WEB-DEPLOYMENT.md). WebAuthn server
implementations must also follow the [WebAuthn storage contract](docs/WEBAUTHN-STORAGE.md).
Systems migrating from ordinary password endpoints should follow the
[password migration guide](docs/MIGRATION-FROM-PASSWORD.md).

## Current packages

- `secure-core`: key-ID-only input state, numeric/printable-ASCII input, Hangul composition, timeout, and explicit clearing.
- `secure-auth`: pinned OPAQUE 4.0.1 engine with Argon2 KSF, typed protocol envelopes, and native/server Rust integrations.
- `secure-auth-server`: transport-neutral OPAQUE server service plus bounded one-time state-store reference implementation; distributed deployments must provide an atomic Redis/DB adapter.
- `secure-auth-http`: bounded framework-neutral HTTP/JSON route contract for OPAQUE registration/login; every call requires a validated TLS/proxy-limit deployment context and an explicit host-validated CSRF result, while rate limits, account enrollment, and session issuance remain host-server responsibilities.
- `secure-auth-axum`: compile-tested Axum adapter that requires request-parts CSRF validation before buffering, bounds streaming request bodies, and preserves the OPAQUE route's generic errors and security headers; its optional `webauthn` feature adds the passkey route adapter with body-free host-principal and CSRF resolvers.
- `secure-webauthn-example`: Rust 1.85-compatible, `webauthn-rs 0.5.4`-pinned passkey registration/authentication service with origin/RP-ID binding, bounded HTTP/JSON routes, host-principal binding, authenticated encrypted ceremony state, atomic one-time consume, and injectable credential/ceremony storage contracts.
- `secure-ffi`: ABI v2 with opaque session/submission handles and native-only OPAQUE registration/login handoff for iOS/Android bindings.
- `@secure-keypad/contracts`: publishable layout, theme, masked-state, and result-event contracts.
- `@secure-keypad/react-native`: publishable React Native prop/event boundary for the native view manager; it rejects secret-bearing props and exposes only masked state/result codes plus non-secret native cancellation/headless key-ID commands. Secure Native is the default.
- `@secure-keypad/web`: passkey-first WebAuthn adapter; it converts server JSON options and serializes ceremony results without exposing password/PIN APIs. Its custom browser-keypad fallback requires explicit lower-assurance acknowledgement.
- `secure_keypad_flutter`: publishable Flutter-facing layout/theme/policy contract; it exposes only masked state/result callbacks and native-only `SecureKeypadController.cancel()` plus an explicitly acknowledged headless `pressKey(keyId)`, with no `TextEditingController` or secret callback.

The contracts package exports `DEFAULT_NUMERIC_LAYOUT`,
`DEFAULT_HANGUL_LAYOUT`, and `DEFAULT_THEME` as safe starting points for
custom renderers. These objects contain labels and key IDs only; they do not
contain password values.

Native iOS/Android renderer sources exist under `native/` and are mirrored into
the publishable React Native and Flutter packages with a byte-for-byte parity
gate. The packages fail closed unless the host supplies matching Rust
`secure_ffi` artifacts for every shipped ABI. Durable WebAuthn storage,
host-app compilation, device-level security verification, and independent
review remain release gates; the Axum WebAuthn integration is compile-tested
behind the optional feature. Do not treat the current repository state as a
drop-in production authentication component.
See [customization examples](docs/CUSTOMIZATION-EXAMPLES.md) for numeric,
printable ASCII, Hangul, and branded native layouts.

## Development

```sh
cargo test --workspace
pnpm install
pnpm test:native-parity
pnpm test:release-version-parity
pnpm --dir packages/contracts test
pnpm --dir packages/react-native test
pnpm --dir packages/web test
cd packages/flutter && flutter test
```

Do not use real credentials in tests, issues, logs, screenshots, or crash reports.
