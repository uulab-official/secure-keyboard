# @secure-keypad/web

Passkey-first WebAuthn adapter for the Secure Keypad SDK.

The browser adapter accepts server-generated WebAuthn options, converts base64url JSON fields into browser binary values, and serializes the registration/assertion result back to base64url JSON. It does not accept a password, PIN, Hangul string, or other secret as an API value. Browser API rejections and hostile credential objects are converted to stable generic `WebAuthnClientError` codes; original exception messages are never exposed.

All WebAuthn binary conversions are bounded to 8 KiB. The decoder rejects an
encoded value whose decoded size would exceed that limit before allocating the
output buffer; the encoder and credential serializer apply the same bound.
Hostile browser-environment getters fail closed as an unavailable passkey
environment rather than exposing their exception text.
The same fail-closed behavior applies to a caller-supplied WebAuthn environment
used by tests or controlled browser integrations.

WebAuthn must run in a secure context. A custom browser keypad is intentionally
not presented as a secure equivalent: page JavaScript can observe browser input
and memory. The SDK therefore does not ship a browser DOM keypad or a password/
PIN input API. For custom passkey UX, use `createPasskeyController()` and render
only its lifecycle state in the host application:

```ts
const controller = createPasskeyController();
const unsubscribe = controller.subscribe((state) => renderPasskey(state));

await controller.createPasskey(serverCreationOptions);
unsubscribe();
```

The controller state contains only `idle`, `pending`, `success`, or `error`,
the public operation kind, and a stable error code. It never contains a
credential result or user input. Call `controller.cancel()` to abort an
in-flight ceremony; the resulting state uses the generic `aborted` code and
does not expose browser exception text. If a product independently elects to ship a
custom browser keypad, call `assertWebAuthnMode("custom-keypad-fallback", environment, true)`
and display `getWebFallbackNotice()` to the user/operator; that path remains
lower assurance and is not a Secure Native Mode substitute.

This package is an adapter, not a WebAuthn server. The Rust reference service
is in `crates/secure-webauthn-example`; it delegates ceremony verification to
the pinned `webauthn-rs` engine and adds bounded JSON plus one-time state
consumption. The embedding server must pass the reference route's validated
TLS/proxy-limit deployment context and still provide durable credential
storage, account/session binding, CSRF protection, replay-safe distributed
storage, and its own rate limits.

For CSP, SRI, lockfile, and browser trust-boundary requirements, see
`docs/WEB-DEPLOYMENT.md`.
