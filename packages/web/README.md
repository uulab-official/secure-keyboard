# @secure-keypad/web

Passkey-first WebAuthn adapter for the Secure Keypad SDK.

The browser adapter accepts server-generated WebAuthn options, converts base64url JSON fields into browser binary values, and serializes the registration/assertion result back to base64url JSON. It does not accept a password, PIN, Hangul string, or other secret as an API value.

WebAuthn must run in a secure context. A custom browser keypad is intentionally not presented as a secure equivalent: page JavaScript can observe browser input and memory. If a product elects to ship that fallback, call `assertWebAuthnMode("custom-keypad-fallback", environment, true)` and display `getWebFallbackNotice()` to the user/operator.

This package is an adapter, not a WebAuthn server. The server must generate challenges, bind them to the relying-party origin and user/session, verify the returned ceremony, enforce replay protection, and apply its own rate limits.
