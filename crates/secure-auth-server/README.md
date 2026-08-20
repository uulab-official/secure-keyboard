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

`InMemoryOneTimeLoginStore` provides bounded, process-local one-use storage for
`secure_auth::ServerLoginStateBytes`. It is useful for tests, a single-process
deployment, or as an executable contract for another backend adapter.

It is not a distributed store. A production deployment behind a load balancer
must implement the `BoundOneTimeLoginStateStore` trait with Redis, a database,
or an equivalent backend. Its `take_bound` operation must be atomic, with a
short TTL and no logging of handles or state bytes.
