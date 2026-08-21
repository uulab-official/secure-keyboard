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

The typed message kinds are `RegistrationRequest`, `RegistrationResponse`,
`RegistrationUpload`, `CredentialRequest`, `CredentialResponse`, and
`CredentialFinalization`. `ServerAuthService` provides registration start and
finish methods as well as the one-time, identifier-bound login flow.

`AuthEnvelope` implements validating `serde::Deserialize`; JSON or another
Serde-supported transport cannot bypass the empty, 16 KiB, suite, and server
key identifier bounds enforced by `AuthEnvelope::from_parts`. Applications
should still enforce a request-body limit before parsing and reject malformed
requests without logging their payloads.

For JSON endpoints, use `AuthEnvelope::from_json`, which applies the 128 KiB
raw-body limit before parsing and returns generic `MalformedTransport` errors
for invalid input. Server integrations should map internal
`ServerAuthError` values through `PublicAuthCode` before returning an external
response; do not expose internal protocol, credential, or store messages.

The current suite is pinned as
`opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2`. Raw OPAQUE payloads are
limited to 16 KiB. The server must reject unsupported protocol versions and
suites before passing a payload to the state machine, and must bind the active
server key ID to the account and deployment configuration. Public client,
server, and credential identifiers are bounded to 256 bytes by the reference
SDK.

`Message::from_bytes`, `ServerSetupBytes::from_bytes`,
`CredentialFile::from_bytes`, and `ServerLoginStateBytes::from_bytes` reject
empty or oversized input before copying into their zeroizing containers. The
server-login state bound includes its version/suite header; malformed but
bounded records are still rejected when `into_state()` restores the protocol
state.

`server_login_start` returns an ephemeral server state. The state can be
serialized through `ServerLoginState::into_bytes()` and restored with
`ServerLoginStateBytes::into_state()`. Its container carries a separate state
format version and the pinned suite ID. The application must store those bytes
under an unguessable, short-lived handle and atomically consume/delete them
before restoration. Serialization alone is not replay protection; Redis,
database, or in-memory stores must provide the one-use operation.

For an unknown account, pass `None` as the credential file to
`server_login_start`; the pinned OPAQUE implementation produces the dummy
processing path. The reference tests pin the registered and missing-account
response shape to the same wire length. Applications must still use generic
external errors and apply account/IP/deployment rate limits.

The `secure-auth-server` crate includes `InMemoryOneTimeLoginStore` as a
bounded reference implementation with 32-byte handles, TTL, capacity, and
state-size limits. It is not a distributed production store; a multi-instance
deployment must replace it with an atomic backend adapter that preserves the
same `BoundOneTimeLoginStateStore` `insert_bound`/`take_bound` semantics.
Adapters generate opaque handles with `LoginStateHandle::generate()`, persist
the serialized state plus its bound identifiers, enforce the TTL, and retry a
rare handle collision without logging handles or state bytes. The executable
backend contract tests exercise atomic delete-and-return behavior under
concurrency.

It also includes `InMemoryRateLimiter` and the `RateLimiter` backend contract.
Use separate bounded key namespaces for account, IP, and deployment-wide
limits. The reference limiter is process-local; a multi-instance deployment
must implement the check-and-count operation atomically in a shared backend.

The framework-neutral HTTP request contract also requires a host-validated
`csrf_validated` result. The value must be derived from request metadata and
the host session/origin policy, never from JSON. The Axum adapter accepts this
as a request-parts callback and rejects a failed check before buffering the
body; framework adapters that cannot provide the same pre-buffering check must
not be treated as production-equivalent.

`ServerAuthService` provides the reference registration and
request/finalization orchestration: it validates the expected envelope kind and
server key, binds identifiers at login start, and consumes the bound state
before server finalization. The `secure-auth-http` crate adds a framework-neutral
route contract for `POST` JSON registration/login endpoints. It enforces the
128 KiB body limit, JSON media type, fixed-size hex handles, generic public
errors, and zeroizing response buffers. Its registration finish body includes
the public account identifier so the host repository can persist the protected
credential file; it never returns that file.

The HTTP route contract requires an explicit deployment context proving TLS,
pre-buffering body limits, and connection/read limits. Use the trusted-proxy
variant only after the host validates the proxy source and forwarded scheme;
the route never parses `X-Forwarded-Proto`. The route does not create
certificate configuration, rate limits, account enrollment authorization,
account lookup policy, or application session tokens. An embedding server must
provide those controls; registration finish must not be exposed before the
application's account creation policy has authorized it.

Use `ServerAuthService::new_with_key_rotation` for a bounded rotation window:
previous IDs are accepted only on inbound start messages, responses emit the
active ID, and login finalization requires the active ID. This policy is
covered by a downgrade regression test.

## Required server controls

- HTTPS/TLS with certificate and endpoint policy appropriate to the deployment,
  passed to the route as a validated deployment context;
- reverse-proxy source allowlisting, pre-buffering body limits, and connection
  read/time limits;
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
