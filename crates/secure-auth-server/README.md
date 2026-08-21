# secure-auth-server

Reference server-side storage primitives for the Secure Keypad OPAQUE flow.

`ServerAuthService` handles the versioned registration and login envelopes. It
stores the OPAQUE server state together with the client/server identifiers used
at login start, so the login finish call does not accept a second
caller-supplied context. Registration produces a `CredentialFile` that the
application must protect at rest.

Use `PublicAuthCode` for client-facing error responses. `ServerAuthError` and
its detailed display text are internal diagnostics and must not be returned to
callers.

`InMemoryRateLimiter` is a bounded fixed-window reference implementation. Use
separate namespaces or instances for account, IP, and deployment-wide limits.
It is atomic only within one process; a multi-instance deployment must
implement the `RateLimiter` trait with an atomic shared backend.

The opt-in `redis-backend` and `postgres-backend` features provide concrete
bounded adapters. Redis uses one Lua check-and-count script with a hashed key,
TTL, and an active-key index; PostgreSQL uses a namespace advisory transaction
lock and a bounded expiry-indexed table. Both have TLS-first constructors and
explicit plaintext local-test constructors. The adapters are blocking and
must run on a blocking worker when used from an async server.

For key rotation, use `ServerAuthService::new_with_key_rotation`. It accepts
active and explicitly configured previous IDs for start messages, emits only
the active ID, and requires the active ID for login finalization.

`InMemoryOneTimeLoginStore` provides bounded, process-local one-use storage for
`secure_auth::ServerLoginStateBytes`. It is useful for tests and single-process
development, but must not sit behind a load balancer.

The opt-in `redis-backend` and `postgres-backend` features provide concrete
`RedisOneTimeLoginStateStore` and `PostgresOneTimeLoginStateStore` adapters.
Both enforce a bounded namespace, pool, capacity, and 15-minute maximum TTL;
they serialize the bound state in a versioned, bounded record and hash handles
before persistence. Redis uses one `SET NX PX`/capacity Lua script and one
atomic consume script. PostgreSQL uses a namespace advisory transaction lock
for capacity and one `DELETE ... RETURNING` consume operation. Production
constructors require TLS; plaintext constructors are explicitly named for
isolated local tests. Both adapters are blocking and must run on a blocking
worker in an async host.

The `BoundOneTimeLoginStateStore` trait remains the interoperability contract
for another backend: `insert_bound` must use conditional insert semantics and
`take_bound` must atomically delete-and-return at most once, with a short TTL
and no logging of handles, identifiers, or state bytes.

The concrete rate-limit adapters do not replace account, IP, deployment, or
CSRF policy. Configure separate bounded namespaces and fail closed on backend
unavailability; never use a rate-limit decision as proof of account existence.
