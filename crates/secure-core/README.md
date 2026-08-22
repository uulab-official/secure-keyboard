# secure-core

`secure-core` is the framework-neutral input state machine for Secure Keypad.
It accepts public key IDs for numeric, printable-ASCII, and Hangul policies,
keeps accumulated input in a zeroizing native buffer, and exposes only masked
state plus opaque submission ownership. Use `KeyId::try_new` for untrusted
configuration; public key IDs are bounded to 64 UTF-8 bytes and the input
policy repeats that bound during resolution.

The crate intentionally has no API that returns the accumulated secret. Use
the native FFI boundary and a host-native authentication consumer for
submission. This crate is an open-source security component, not a security
certification; review the repository threat model and release gates before
deployment.
