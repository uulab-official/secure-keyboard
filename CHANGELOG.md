# Changelog

All notable changes to the Secure Keypad SDK are recorded here. Until the
first stable release, entries remain under `Unreleased` and are tied to the
exact release-candidate commit by the release evidence manifest.

## Unreleased

### Security

- Bound native public layout, theme, label, accessibility, and ABI
  configuration checks across the iOS, Android, React Native, and Flutter
  surfaces.
- Bounded the Flutter native event backlog, coalesced masked-state updates,
  and preserved terminal result events under queue pressure.
- Capped WebAuthn pending ceremony retention at 15 minutes across all storage
  contracts.
- Added AES-256-GCM authenticated encryption for built-in Redis/PostgreSQL
  WebAuthn ceremony records, with host-managed `WebAuthnStateKey` and
  namespace-bound associated data.
- Made the PostgreSQL ciphertext-size schema upgrade atomic and fail closed on
  malformed or tampered ceremony records.

### Verification

- Release staging now requires this changelog, the pinned lockfiles, SBOM,
  third-party notices, and the complete candidate metadata set.
