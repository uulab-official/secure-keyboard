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
server key ID to the account and deployment configuration.

## Required server controls

- HTTPS/TLS with certificate and endpoint policy appropriate to the deployment;
- one-use server login state, atomic consumption, and replay detection;
- per-account, per-IP, and deployment-wide rate limits;
- dummy login processing for unknown accounts to reduce enumeration signals;
- constant-time proof checks and generic external authentication errors;
- key rotation with an explicit supported-version window and downgrade tests;
- protected storage for server setup and credential files;
- redaction of payloads, identifiers, and protocol errors from logs and traces.

The envelope is deliberately transport-framework-neutral so a backend can use
Axum, Actix, Spring, ASP.NET, Go, or another server stack without changing the
cryptographic contract. It is not a complete HTTP server SDK until those
deployment controls are implemented and independently tested.
