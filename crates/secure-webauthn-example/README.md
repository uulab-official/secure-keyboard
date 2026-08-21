# secure-webauthn-example

Passkey-first WebAuthn registration/authentication reference service for the
Secure Keypad SDK.

The example pins `webauthn-rs` to `0.5.4` for the workspace Rust toolchain and
delegates challenge, origin, RP-ID, user-verification, attestation, CBOR/COSE,
signature, counter, and backup-state verification to that library. The SDK
layer adds:

- fixed 32-byte lowercase-hex ceremony handles;
- bounded request bodies before JSON deserialization;
- atomic one-time consume semantics for registration/authentication state;
- generic public errors and unknown-account behavior;
- credential uniqueness and a bounded per-account credential count;
- persistence of authenticator counter/backup-state changes.
- a framework-neutral bounded HTTP/JSON route contract for registration and
  authentication, with host-session principal binding and generic responses.

`WebAuthnExampleService` is deliberately process-local. It is a reference
contract, not a drop-in production database. A deployment must replace both
stores with an encrypted/access-controlled credential store and an atomic
read-and-delete ceremony store. Never log ceremony handles, client responses,
credential IDs, or serialized passkeys.

The HTTP route contract does not implement a network listener. Production
framework integration must additionally enforce TLS, strict reverse-proxy
body/time limits, CSRF/session binding, account-enrollment authorization,
origin allowlisting, rate limits, durable encrypted stores, distributed
ceremony replay protection, and session-token policy. The service does not
issue application sessions.

See the browser client contract in `packages/web` and the release checklist in
`docs/RELEASE-GATES.md`.
