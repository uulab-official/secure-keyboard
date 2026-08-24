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

The framework-neutral HTTP/JSON transport has its own contract version,
`HTTP_CONTRACT_VERSION = 1`. This is deliberately separate from the OPAQUE
`protocolVersion` inside `AuthEnvelope`: changing HTTP routing, request
validation, or response-shape guarantees must not be confused with changing
the cryptographic protocol. The Node/TypeScript transport bridge declares the
same value as `NODE_SERVER_CONTRACT_VERSION`; `pnpm test:http-contract-version-parity`
and `pnpm check:http-contract-version-parity` fail if either declaration is
missing or differs.

The typed message kinds are `RegistrationRequest`, `RegistrationResponse`,
`RegistrationUpload`, `CredentialRequest`, `CredentialResponse`, and
`CredentialFinalization`. `ServerAuthService` provides registration start and
finish methods as well as the one-time, identifier-bound login flow.

The Node transport bridge also exposes `OPAQUE_PROTOCOL_VERSION` and
`OPAQUE_CIPHER_SUITE_ID` as metadata for the Rust/native delegate it calls.
`pnpm test:opaque-protocol-parity` and
`pnpm check:opaque-protocol-parity` fail if those declarations drift from
`secure-auth::PROTOCOL_VERSION` or `secure-auth::CIPHER_SUITE_ID`; the Node
package does not implement OPAQUE itself.

`AuthEnvelope` implements validating `serde::Deserialize` with unknown-field
rejection; JSON or another Serde-supported transport cannot bypass the empty,
16 KiB, suite, and server key identifier bounds enforced by
`AuthEnvelope::from_parts`. The OPAQUE HTTP request DTOs also reject unknown
fields, so a `password`, `rawInput`, or similar secret-bearing field cannot be
silently accepted as an ignored extension. Applications should still enforce
a request-body limit before parsing and reject malformed requests without
logging their payloads.

For JSON endpoints, use `AuthEnvelope::from_json`, which applies the 128 KiB
raw-body limit before parsing and returns generic `MalformedTransport` errors
for invalid input. Server integrations should map internal
`ServerAuthError` values through `PublicAuthCode` before returning an external
response; do not expose internal protocol, credential, or store messages.

The Node, Axum, and Actix adapters reject malformed, non-decimal, overflowing,
comma-joined, invalid-byte, and duplicate `Content-Length` values before body
buffering. A valid declaration above the host's configured limit returns 413;
an invalid declaration returns a generic 400. Chunked or otherwise streaming
requests may omit `Content-Length`, but the bounded body collector remains
mandatory.

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
state-size limits. Its feature-gated `RedisOneTimeLoginStateStore` and
`PostgresOneTimeLoginStateStore` adapters use bounded versioned records,
AES-256-GCM authenticated encryption with a host-supplied `OpaqueStateKey`,
hashed handles, TLS-first constructors, and atomic consume/delete. A custom
multi-instance backend must preserve the same
`BoundOneTimeLoginStateStore` `insert_bound`/`take_bound` semantics. Adapters
generate opaque handles with `LoginStateHandle::generate()`, enforce the TTL,
and retry a rare handle collision without logging handles or state bytes. The
executable backend contract tests exercise atomic delete-and-return behavior
under concurrency; the Redis/PostgreSQL service tests are mandatory CI gates.

Credential lookups are persistent reads. A `CredentialRepository` must return a
protected copy without deleting the stored credential; only the one-time login
state handle is consumed during authentication. This permits a user to log in
again after a successful or failed attempt while retaining replay protection on
the protocol state.

It also includes `InMemoryRateLimiter` and the `RateLimiter` backend contract.
Use separate bounded key namespaces for account, IP, and deployment-wide
limits. The reference limiter is process-local; a multi-instance deployment
must implement the check-and-count operation atomically in a shared backend.

The framework-neutral HTTP request contract also requires a host-validated
`csrf_validated` result. The value must be derived from request metadata and
the host session/origin policy, never from JSON. The Axum and Actix adapters
accept this as a request-parts callback and reject a failed check before
buffering the body. The same adapters require a `RequestAdmission` callback
for account/IP/deployment rate-limit admission before buffering; denied or
unavailable decisions fail closed. Framework adapters that cannot provide both
pre-buffering checks must not be treated as production-equivalent.

`ServerAuthService` provides the reference registration and
request/finalization orchestration: it validates the expected envelope kind and
server key, binds identifiers at login start, and consumes the bound state
before server finalization. The `secure-auth-http` crate adds a framework-neutral
route contract for `POST` JSON registration/login endpoints. It enforces the
128 KiB body limit, JSON media type, fixed-size hex handles, generic public
errors, and zeroizing response buffers. Its registration finish body includes
the public account identifier so the host repository can persist the protected
credential file; it never returns that file.

Registration finish accepts the public identifier only as a bounded persistence
key. It rejects an empty or oversized identifier before finishing the OPAQUE
upload or invoking the credential repository; the identifier is never treated
as protocol secret material.

The credential repository operation is create-only: it must atomically reject
an existing identifier instead of replacing its credential file. This makes a
replayed registration upload or an enrollment race fail closed at the storage
boundary. The route maps an existing-record conflict to the same generic
`invalid_request` response; the host still must authorize account creation and
must not expose registration finish as an account-replacement endpoint.

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
- pre-buffering rate-limit admission with fail-closed behavior on limiter
  outage;
- server-verified device-integrity admission for financial authentication,
  bound to the account, operation, nonce, and deployment before body buffering;
- dummy login processing for unknown accounts to reduce enumeration signals;
- constant-time proof checks and generic external authentication errors;
- key rotation with an explicit supported-version window and downgrade tests;
- protected storage for server setup and credential files;
- atomic create-only credential persistence that cannot replace an existing
  account credential during registration;
- redaction of payloads, identifiers, and protocol errors from logs and traces.
- short TTL and atomic consume/delete for serialized server login state;

The envelope is deliberately transport-framework-neutral so a backend can use
Axum, Actix, Node/TypeScript, Spring, ASP.NET, Go, or another server stack
without changing the cryptographic contract. `@secure-keypad/server-node`
provides the Node Fetch-compatible boundary, but delegates cryptography to the
pinned Rust/native reference service; it is not an OPAQUE implementation in
JavaScript. These adapters are not a complete HTTP server deployment until
they are configured with the required host controls and independently tested.
Financial Node routes must use `securityProfile: "financial"`, resolve a fresh
one-use context, and return evidence bound to that context. The Node adapter
checks the route operation, subject, nonce, deployment, provider, issuance
time, expiry, five-minute maximum evidence lifetime, and local replay reuse
before body buffering. The host must still atomically consume the nonce in a
shared store for a multi-instance deployment. Axum and Actix expose the same
pre-buffering rule via their explicit `financial_router` constructors; their
callbacks must perform equivalent binding and freshness checks before returning
`Verified`. Platform attestation remains host/server responsibility; the SDK
does not claim to verify Google/Apple attestation credentials itself.
