# secure-auth-server

Reference server-side storage primitives for the Secure Keypad OPAQUE flow.

`InMemoryOneTimeLoginStore` provides bounded, process-local one-use storage for
`secure_auth::ServerLoginStateBytes`. It is useful for tests, a single-process
deployment, or as an executable contract for another backend adapter.

It is not a distributed store. A production deployment behind a load balancer
must implement the `OneTimeLoginStateStore` trait with Redis, a database, or an
equivalent backend. Its `take` operation must be atomic, with a short TTL and
no logging of handles or state bytes.
