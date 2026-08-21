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
- a mandatory deployment context for TLS, pre-buffering body limits, and
  connection/read limits.
- static no-store, no-sniff, no-referrer, and API-safe CSP response headers.
- `WebAuthnService<C, S>` storage injection for durable credential records and
  serialized one-time ceremony state, with atomic backend contracts.
- opt-in `redis-backend` and `postgres-backend` adapters with bounded pools,
  per-namespace pending ceremony capacity, bounded credential records,
  TLS-first constructors, atomic ceremony consume, expiry cleanup, and
  credential CAS rules.

`WebAuthnExampleService` is deliberately process-local. It is a reference
configuration, not a drop-in production database. A production deployment
should construct `WebAuthnService<C, S>::new_with_stores` with an
encrypted/access-controlled `CredentialStore` and an atomic
`CeremonyStateStore`. Never log ceremony handles, client responses, credential
IDs, or serialized passkeys/ceremony states.

The concrete adapters are feature-gated because they add database client
dependencies:

```toml
secure-webauthn-example = { version = "0.1.0", features = ["redis-backend", "postgres-backend"] }
```

`RedisWebAuthnStore::from_url` requires `rediss://`; the explicit
`from_insecure_url_for_local_testing` and PostgreSQL `NoTls` constructors are
for isolated development only. Apply `POSTGRES_SCHEMA_SQL` through the host's
migration system before constructing a PostgreSQL store. These adapters expose
blocking operations and must run on a blocking worker when called from an
async framework.

The pinned `webauthn-rs` `danger-allow-state-serialisation` feature is enabled
because a distributed server must serialize ceremony state between instances.
This is safe only when the bytes remain server-side, bounded, access
controlled, and consumed once. Do not put them in cookies, browser storage, or
any client-controlled field. See [WebAuthn storage](../../docs/WEBAUTHN-STORAGE.md)
for the backend contract.

The HTTP route contract does not implement a network listener. Every call must
pass `WebAuthnDeploymentContext::direct_tls()` or
`WebAuthnDeploymentContext::trusted_proxy_tls()` after the host validates the
transport and trusted proxy. Production framework integration must additionally
enforce strict proxy source allowlisting, CSRF/session binding,
account-enrollment authorization, origin allowlisting, rate limits, durable
encrypted stores, distributed ceremony replay protection, and session-token
policy. The service does not issue application sessions.

See the browser client contract in `packages/web` and the release checklist in
`docs/RELEASE-GATES.md`.
