# secure-ffi

`secure-ffi` is the C ABI v2 boundary for native iOS and Android hosts. It
exports opaque session and submission handles, public key-ID commands, masked
display state, cancellation, and native-only OPAQUE registration/login
handoff. No function returns accumulated password bytes or a derived client
session key to the caller.

Native hosts must compare `secure_keypad_abi_version()` with the header
constant, preserve handle ownership, and release every submission exactly
once. Build and ship the library from the same immutable source revision as
the native renderer; do not treat the C ABI alone as proof of device-level
capture, accessibility, or compromised-runtime protection.
