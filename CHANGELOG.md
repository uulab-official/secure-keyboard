# Changelog

All notable changes to the Secure Keypad SDK are recorded here. Until the
first stable release, entries remain under `Unreleased` and are tied to the
exact release-candidate commit by the release evidence manifest.

## Unreleased

### Security

- Bound native public layout, theme, label, accessibility, and ABI
  configuration checks across the iOS, Android, React Native, and Flutter
  surfaces.
- Made Android React Native public-map conversion fail closed: malformed or
  over-budget layout/theme/command maps now release the native session and
  emit only the public `invalid` result instead of escaping as a bridge
  exception.
- Bounded the Flutter native event backlog, coalesced masked-state updates,
  and preserved terminal result events under queue pressure.
- Capped WebAuthn pending ceremony retention at 15 minutes across all storage
  contracts.
- Added AES-256-GCM authenticated encryption for built-in Redis/PostgreSQL
  WebAuthn ceremony records, with host-managed `WebAuthnStateKey` and
  namespace-bound associated data.
- Bound built-in Redis/PostgreSQL OPAQUE login-state ciphertexts to their
  validated storage namespace with AES-GCM associated data, and advanced the
  durable protection format to v2; legacy unbound v1 records are rejected.
- Made the PostgreSQL ciphertext-size schema upgrade atomic and fail closed on
  malformed or tampered ceremony records.

### Verification

- Release staging now requires this changelog, the pinned lockfiles, SBOM,
  third-party notices, and the complete candidate metadata set.
