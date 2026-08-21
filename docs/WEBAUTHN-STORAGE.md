# WebAuthn storage contract

`secure-webauthn-example` provides two injectable backend contracts:

- `CeremonyStateStore` stores bounded serialized registration/authentication
  state and must atomically consume a matching handle at most once.
- `CredentialStore` stores public passkey records and must atomically enforce
  credential uniqueness, the per-account limit, and post-authentication
  counter/backup-state updates.

`WebAuthnExampleService` uses bounded in-memory implementations only for tests
and single-process development. A production service must construct
`WebAuthnService<C, S>::new_with_stores` with protected implementations. The
framework-neutral HTTP router and the Axum adapter are generic over the same
service type, so a durable backend remains inside the server boundary.

## Ceremony state

The serialized state is server-owned challenge state wrapped in the pinned
`WEBAUTHN_CEREMONY_STATE_VERSION` envelope. It is not a password and
must never be sent to the browser. Backend records should include a versioned
kind/principal envelope and use a namespace such as:

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

For Redis, use `GETDEL` or a server-side atomic script. For PostgreSQL, use a
single `DELETE ... WHERE handle = $1 AND kind = $2 AND expires_at > now()
RETURNING user_id, state`. Do not use a separate `GET` followed by `DEL`.

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

The `danger-allow-state-serialisation` feature is enabled only because the
server-side ceremony contract needs it. It must never be used to serialize
state into a cookie, local storage, URL, analytics event, or client request.
