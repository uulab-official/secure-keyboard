# Authentication transport contract

`secure-auth` defines the cryptographic engine and a transport envelope. The
application server still owns HTTP, TLS, request authentication, rate limits,
replay state, account lockout, session-token issuance, and key rotation.

Each envelope carries:

```text
protocolVersion
suiteId
messageKind
serverKeyId
payload
```

The current suite is pinned as
`opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2`. Raw OPAQUE payloads are
limited to 16 KiB. The server must reject unsupported protocol versions and
suites before passing a payload to the state machine, and must bind the active
server key ID to the account and deployment configuration. Public client,
server, and credential identifiers are bounded to 256 bytes by the reference
SDK.

`server_login_start` returns an ephemeral server state. The state can be
serialized through `ServerLoginState::into_bytes()` and restored with
`ServerLoginStateBytes::into_state()`. Its container carries a separate state
format version and the pinned suite ID. The application must store those bytes
under an unguessable, short-lived handle and atomically consume/delete them
before restoration. Serialization alone is not replay protection; Redis,
database, or in-memory stores must provide the one-use operation.

The `secure-auth-server` crate includes `InMemoryOneTimeLoginStore` as a
bounded reference implementation with 32-byte handles, TTL, capacity, and
state-size limits. It is not a distributed production store; a multi-instance
deployment must replace it with an atomic backend adapter that preserves the
same `OneTimeLoginStateStore` `insert`/`take` semantics.

## Required server controls

- HTTPS/TLS with certificate and endpoint policy appropriate to the deployment;
- one-use server login state, atomic consumption, and replay detection;
- per-account, per-IP, and deployment-wide rate limits;
- dummy login processing for unknown accounts to reduce enumeration signals;
- constant-time proof checks and generic external authentication errors;
- key rotation with an explicit supported-version window and downgrade tests;
- protected storage for server setup and credential files;
- redaction of payloads, identifiers, and protocol errors from logs and traces.
- short TTL and atomic consume/delete for serialized server login state;

The envelope is deliberately transport-framework-neutral so a backend can use
Axum, Actix, Spring, ASP.NET, Go, or another server stack without changing the
cryptographic contract. It is not a complete HTTP server SDK until those
deployment controls are implemented and independently tested.
