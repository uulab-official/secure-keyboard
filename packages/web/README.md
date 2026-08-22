# @secure-keypad/web

Passkey-first WebAuthn adapter for the Secure Keypad SDK.

The browser adapter accepts server-generated WebAuthn options, converts base64url JSON fields into browser binary values, and serializes the registration/assertion result back to base64url JSON. It does not accept a password, PIN, Hangul string, or other secret as an API value. Browser API rejections and hostile credential objects are converted to stable generic `WebAuthnClientError` codes; original exception messages are never exposed.

WebAuthn must run in a secure context. A custom browser keypad is intentionally not presented as a secure equivalent: page JavaScript can observe browser input and memory. If a product elects to ship that fallback, call `assertWebAuthnMode("custom-keypad-fallback", environment, true)` and display `getWebFallbackNotice()` to the user/operator.

This package is an adapter, not a WebAuthn server. The Rust reference service
is in `crates/secure-webauthn-example`; it delegates ceremony verification to
the pinned `webauthn-rs` engine and adds bounded JSON plus one-time state
consumption. The embedding server must pass the reference route's validated
TLS/proxy-limit deployment context and still provide durable credential
storage, account/session binding, CSRF protection, replay-safe distributed
storage, and its own rate limits.

For CSP, SRI, lockfile, and browser trust-boundary requirements, see
`docs/WEB-DEPLOYMENT.md`.
