# WebAuthn storage contract

`secure-webauthn-example` provides two injectable backend contracts:

- `CeremonyStateStore` stores bounded serialized registration/authentication
  state and must atomically consume a matching handle at most once.
- `CredentialStore` stores public passkey records and must atomically enforce
  credential uniqueness, the per-account limit, and post-authentication
  counter/backup-state updates.

All ceremony stores must reject a zero or over-bound TTL. The reference
implementation caps pending registration/authentication state at
`MAX_CEREMONY_TTL` (15 minutes), matching the OPAQUE one-time-state retention
policy and limiting replay-state exposure and backend occupancy.

`WebAuthnExampleService` uses bounded in-memory implementations only for tests
and single-process development. A production service must construct
`WebAuthnService<C, S>::new_with_stores` with protected implementations. The
framework-neutral HTTP router and the Axum adapter are generic over the same
service type, so a durable backend remains inside the server boundary.

The reference crate also ships opt-in `redis-backend` and `postgres-backend`
implementations. They use bounded `r2d2` pools with a five-second acquisition
timeout, bounded per-namespace pending ceremonies, bounded credential records,
TLS-first constructors, and host-managed `WebAuthnStateKey` encryption for
serialized ceremony records. Production constructors require the key so a
record cannot be persisted without authenticated at-rest protection; all
instances consuming one namespace must use the same key during the retention
window. Plaintext/`NoTls` constructors are explicitly named for local testing
and generate an ephemeral key. PostgreSQL production configuration also
requires `sslmode=require`; the adapter rejects weaker modes and the built-in
`NoTls` connector before pool construction. They are blocking adapters; async hosts must invoke them on a
blocking worker. The
PostgreSQL migration is exported as `POSTGRES_SCHEMA_SQL` and must be applied
by the deployment migration system. It enforces bounded safe namespaces,
  handle/kind/ciphertext-state limits, credential ID and passkey record limits, and
non-negative revisions in the database; the same constraints are idempotently
added when upgrading existing ceremony and credential tables.
Constraint-validation failures must fail the deployment migration.

## Ceremony state

The serialized state is server-owned challenge state wrapped in the pinned
`WEBAUTHN_CEREMONY_STATE_VERSION` envelope. It is not a password and
must never be sent to the browser. The built-in adapters wrap the complete
versioned kind/principal record in an AES-256-GCM envelope before persistence;
the 32-byte `WebAuthnStateKey` must remain in a secret manager or KMS-backed
configuration. Backend keys use a namespace such as:

```text
skp:webauthn:v1:registration:{lowercase-hex-32-byte-handle}
skp:webauthn:v1:authentication:{lowercase-hex-32-byte-handle}
```

The backend must:

1. reject empty or over-bound state before writing;
2. use `SET NX` plus a short TTL, or an equivalent conditional insert;
3. consume with one atomic delete-and-return operation;
4. treat a kind mismatch as a miss without consuming another namespace;
5. bind and verify the account principal before response parsing; and
6. map malformed, expired, or unavailable records to generic server errors.

The Redis adapter uses a server-side atomic `GET` + `DEL` script and an
atomic `SET NX PX`/pending-index capacity script. The pending sorted set is
cleaned by expiry score and the consumed key is removed from the index. For
PostgreSQL, the adapter serializes namespace inserts, deletes expired rows,
enforces the pending-row bound, and uses a single `DELETE ... WHERE namespace
= $1 AND handle = $2 AND kind = $3 AND expires_at > now() RETURNING user_id,
state`. Do not replace either consume operation with a separate read followed
by delete.

## Credential records

`webauthn-rs::Passkey` records contain public credential material and may be
serialized by the backend, but they still require access control and integrity
protection. The credential backend must use an atomic uniqueness constraint on
`(user_id, credential_id)` and enforce the bounded per-account count in the
same transaction as registration.

After a successful assertion, `CredentialStore::update_after_auth` must apply
counter and backup-state changes with an optimistic version/CAS or equivalent
transaction. A stale update must fail closed; last-writer-wins persistence can
weaken cloned-authenticator detection.

The PostgreSQL adapter bounds credential reads with `MAX_CREDENTIALS_PER_USER +
1` and `MAX_CREDENTIAL_RECORD_BYTES` at the SQL query before rows/JSONB values
are materialized. The extra row lets the adapter distinguish a valid limit from
an already-over-limit account without loading an unbounded legacy or corrupted
record set; an over-size value is returned as a sentinel and rejected.

The `danger-allow-state-serialisation` feature is enabled only because the
server-side ceremony contract needs it. It must never be used to serialize
state into a cookie, local storage, URL, analytics event, or client request.
