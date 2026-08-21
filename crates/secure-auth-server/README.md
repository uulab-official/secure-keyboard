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
`secure_auth::ServerLoginStateBytes`. It is useful for tests, a single-process
deployment, or as an executable contract for another backend adapter.

An external adapter can call `LoginStateHandle::generate()` for a fresh bearer
key, persist the state and bound identifiers, and implement
`BoundOneTimeLoginStateStore::take_bound` as an atomic delete-and-return
operation. Collision retry, TTL enforcement, and no payload/handle logging are
adapter responsibilities.

It is not a distributed store. A production deployment behind a load balancer
must implement the `BoundOneTimeLoginStateStore` trait with Redis, a database,
or an equivalent backend. Its `take_bound` operation must be atomic, with a
short TTL and no logging of handles or state bytes.

The concrete rate-limit adapters do not replace account, IP, deployment, or
CSRF policy. Configure separate bounded namespaces and fail closed on backend
unavailability; never use a rate-limit decision as proof of account existence.
