# Migrating from ordinary password endpoints

This guide describes how to move an existing password-based account system to
the Secure Keypad OPAQUE or WebAuthn boundaries. It does not turn an existing
password hash into an OPAQUE credential file: the formats are different, and a
server must never receive a client-side hash that can be replayed as a
password.

## Non-negotiable rules

- Do not send a password, password-derived value, or keypad-rendered string
  through JavaScript, Dart, JSON telemetry, or ordinary text input.
- Do not store an OPAQUE client message, browser fallback value, or any
  client-side hash as a substitute password.
- Keep legacy hash verification behind the server's authenticated TLS boundary,
  with generic errors, account-enumeration resistance, and the same rate-limit
  policy as the new endpoint.
- Do not log legacy passwords, OPAQUE messages, WebAuthn challenges, ceremony
  handles, credential files, or migration decisions containing account secrets.

## Recommended rollout

1. Pin the UI/SDK release, OPAQUE protocol version, cipher-suite ID, server key
   ID, and storage schema together. Run the release gates before enabling a
   migration cohort.
2. Add passkey enrollment as the preferred web path. On mobile, deploy Secure
   Native Mode and install a host-native submission consumer before exposing a
   login action.
3. For users who can authenticate with the legacy password, verify it only in
   the existing server-side verifier. After successful verification, require a
   fresh OPAQUE registration or passkey ceremony and atomically mark the
   account as migrated. Do not return the legacy password or a derived value to
   the client.
4. For users who cannot complete an authenticated migration, use an existing
   account-recovery process with equivalent identity proofing. Do not silently
   downgrade to a browser custom-keypad fallback.
5. Keep a bounded, auditable legacy cohort during the rollout. Each account
   must have an explicit state such as `legacy`, `migration-pending`, or
   `migrated`; state transitions must be idempotent and must not expose the
   reason an account is in one state.
6. After the cohort window, disable the legacy verifier for migrated accounts,
   remove legacy password material according to the host's retention policy,
   and retain only the OPAQUE credential file or WebAuthn credential record.

## OPAQUE key rotation during migration

The server may accept an explicitly configured active/previous server key ID
window for inbound start messages. Finalization must require the active key
ID. Rotate the server setup and key ID through the same deployment pipeline as
the migration state change; never infer an accepted key from an untrusted
request field.

## Rollback and incident handling

Rollback must disable new migrations without re-enabling client-side password
transport. If a migration or storage incident occurs, keep the OPAQUE/passkey
path available, revoke affected sessions and ceremony handles, rotate the
server key when required, and follow `SECURITY.md` for private disclosure.
The migration dashboard may contain counts and result codes only; it must not
contain input values, credential files, challenges, handles, or raw protocol
messages.

The Web custom-keypad fallback remains lower assurance because browser page
JavaScript and extensions can observe its memory. It is not a migration
mechanism for raising the browser's security boundary.
