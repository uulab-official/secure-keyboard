# Distributed replay and rate-limit backends

The reference stores in `secure-auth-server` are bounded and atomic only
inside one process. A multi-instance deployment must implement the same
contracts with a durable, access-controlled backend before it enables a load
balancer or failover.

## One-time OPAQUE ceremony state

Use a versioned, non-user-enumerating key namespace such as:

```text
skp:opaque:v1:login:{lowercase-hex-32-byte-handle}
```

The value should be an encrypted/authenticated record containing the serialized
server-login state, the bound client/server identifiers, and its storage
format version. The backend operation must:

1. validate the fixed 32-byte handle and bounded record size before writing;
2. insert with `NX` semantics and a short TTL;
3. consume with one atomic delete-and-return operation;
4. return the record at most once, including when two application instances
   race on the same handle;
5. delete expired or malformed records and map backend failures to a generic
   temporary-unavailable response; and
6. never log keys, handles, state bytes, credential IDs, or client responses.

Redis 6.2+ can use `GETDEL`. On older Redis, use a small server-side Lua
   transaction that reads and deletes the key in one operation; do not issue a
   separate `GET` followed by `DEL`. PostgreSQL-style stores should use
   `DELETE ... WHERE key = $1 AND expires_at > now() RETURNING value` inside a
   single transaction. The adapter must reconstruct `BoundLoginState` with its
   bounded identifiers before returning it to `ServerAuthService`.

## Atomic rate limiting

Implement `RateLimiter::check` as one atomic check-and-count operation. Use
separate bounded namespaces for account, source IP, and deployment-wide keys;
hash high-cardinality public identifiers before storing them if the backend
would otherwise expose them operationally. Preserve the reference semantics:
`Allowed { remaining }` until the fixed window is exhausted, then
`Limited { retry_after }`. Backend errors must fail closed for authentication
attempts and must not reveal whether an account exists.

The reference crate includes feature-gated implementations:

- `RedisRateLimiter` uses a single Lua script, a server-side fixed-window TTL,
  a bounded active-key sorted set, and SHA-256 key hashing. The production
  constructor requires `rediss://`; plaintext is available only through the
  explicitly named local-test constructor.
- `PostgresRateLimiter` uses a namespace advisory transaction lock, deletes
  expired rows before counting, and updates/inserts the hashed key in the same
  transaction. Its migration is exported as
  `POSTGRES_RATE_LIMIT_SCHEMA_SQL`, and production uses an explicit TLS
  connector.

Both adapters are blocking. Async hosts must run them on a blocking worker and
must configure separate namespaces for account, source IP, and deployment
limits. Distributed adapters reject windows longer than seven days so Redis
millisecond scores remain bounded and accidental long-lived key retention is
not silently accepted.

## Rotation and rollout

Store the active server-key ID and the explicitly allowed previous-key window
in deployment configuration, not in a client request. Deploy readers and
writers that understand the new state format before changing the active key;
then test old-start/new-finish, replay, malformed-state, and rollback paths.
Retire the previous key only after its maximum ceremony TTL and incident
recovery window have elapsed.

These are backend adapter requirements, not a claim that the process-local
reference stores are suitable for a distributed production deployment.
