# Distributed replay and rate-limit backends

The process-local reference stores in `secure-auth-server` are bounded and
atomic only inside one process. The crate also provides opt-in Redis and
PostgreSQL implementations of the OPAQUE one-time state contract and Redis
and PostgreSQL rate-limit implementations. A multi-instance deployment must
still choose the TLS constructor, apply the exported PostgreSQL migration,
and run the isolated interoperability tests before enabling a load balancer
or failover.

For a reproducible local run, use the pinned test-only services and runner:

```sh
pnpm test:durable-backends
```

This starts `redis:7.2-alpine` and `postgres:16-alpine` on loopback only,
executes all three ignored interoperability suites, and removes the Compose
containers on exit. The local plaintext URLs and credentials are test
infrastructure only; never copy them into a production deployment.

## One-time OPAQUE ceremony state

Use a versioned, non-user-enumerating key namespace such as:

```text
skp:opaque:v1:login:{lowercase-hex-32-byte-handle}
```

The built-in adapters use a host-supplied `OpaqueStateKey` and AES-256-GCM to
encrypt and authenticate a versioned record containing the serialized
server-login state and bound client/server identifiers before persistence. The
current durable record format is v2: the validated storage namespace is bound
into AES-GCM associated data, so a ciphertext copied between tenants cannot be
opened even when they share a key. v1 records are intentionally rejected and
must be allowed to expire before a v2 rollout is considered complete. Keep the
key in a secret manager or KMS-backed configuration, use the same key on every
instance that can consume a pending state, and retain it for at least the
maximum state TTL. A custom backend must provide equivalent authenticated
encryption and an explicit format/key-rotation overlap policy. The backend
operation must:

1. validate the fixed 32-byte handle and bounded record size before writing;
2. insert with `NX` semantics and a short TTL;
3. consume with one atomic delete-and-return operation;
4. return the record at most once, including when two application instances
   race on the same handle;
5. delete expired or malformed records and map backend failures to a generic
   temporary-unavailable response; and
6. never log keys, handles, state bytes, credential IDs, or client responses.

`RedisOneTimeLoginStateStore` uses a small server-side Lua transaction with
Redis type checks before every sorted-set or string operation, followed by
`STRLEN`-before-`GET` and `GETDEL`-equivalent read-and-delete semantics; do not
issue a separate `GET` followed by `DEL`. Wrong-type index/state keys and
oversized legacy values are deleted from the affected key and pending index
without being returned to the client. An index repair failure is reported as a
generic unavailable error, and the next operation can re-establish the bounded
sorted-set index.
If the state key has disappeared before consume (for example after an
eviction), the same script removes its stale pending-index member so a missing
key cannot reserve capacity until the original TTL expires.
PostgreSQL-style stores should use `DELETE ... WHERE key = $1 AND expires_at >
now() RETURNING value` inside a single atomic operation. The built-in
PostgreSQL adapter does this and also uses an advisory lock for insert
capacity; its `RETURNING` expression also applies the encrypted-record byte
bound before materialization. Both built-in adapters reconstruct
`BoundLoginState` with bounded identifiers before returning it to
`ServerAuthService`.

The process-local reference store exposes both bound and unbound contracts for
testability. If a caller uses the wrong contract, it returns
`StateTypeMismatch` without deleting the pending record; a matching successful
`take` or expiry is the only consuming path. Implementations that expose
multiple record kinds must preserve the same non-consuming type-mismatch
behavior while keeping the actual consume operation atomic.

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
  explicitly named local-test constructor. The counter path checks that the
  Redis key is a string before any string command, then checks a fixed 32-byte
  representation bound before `GET`; a wrong-type, oversized, or malformed
  legacy counter is removed from the counter and active-key index and fails
  closed.
  The script also validates the active-index key is a sorted set before any
  sorted-set command; a wrong-type index is removed and the operation fails
  closed so key poisoning cannot strand namespace capacity.
  Existing counters reject missing, zero, or longer-than-window TTLs and
  repair their active-index member when a prior Redis eviction removed the
  index key. This is recovery on access, not a substitute for Redis capacity
  policy: production Redis must use `maxmemory-policy noeviction` (or an
  equivalent provider guarantee), reserve memory for the namespace, and alert
  on eviction/configuration drift. An evicted active-index key can otherwise
  make the application-level active-key bound unverifiable.
  If Redis has evicted the counter while its sorted-set member remains, the
  script removes that stale member before enforcing active-key capacity.
- `PostgresRateLimiter` uses a namespace advisory transaction lock, deletes
  expired rows before counting, and updates/inserts the hashed key in the same
  transaction. Its migration is exported as
  `POSTGRES_RATE_LIMIT_SCHEMA_SQL`, and production uses an explicit TLS
  connector with `sslmode=require`; weaker PostgreSQL modes are rejected before
  pool construction, and the production constructor also rejects the built-in
  `NoTls` connector even if `sslmode=require` is present. The migration enforces
  the bounded safe namespace,
  32-byte key hash, and attempt-count range at the database layer and
  idempotently adds all three groups of constraints to an existing table; a
  deployment must treat a constraint-validation failure as a failed migration
  rather than bypassing the checks.

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
