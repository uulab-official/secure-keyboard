# Native FFI ABI

`crates/secure-ffi/include/secure_keypad.h` is the native boundary for iOS,
Android, React Native, and Flutter adapters.

## Allowed across the boundary

- layout-selected public key IDs as bounded UTF-8 pointer/length inputs;
- numeric or structured Hangul policy selection;
- masked length and display state;
- stable error codes;
- opaque session and submission ownership handles.

## Forbidden across the boundary

- password strings or raw accumulated input;
- secret getters, callbacks, JSON, logs, analytics, or crash fields;
- concurrent use of a session handle;
- use-after-free or double-free of handles.

The submission handle is intentionally not serializable. Native authentication
code consumes it inside the native/Rust boundary or releases it. The C ABI
does not itself perform HTTP or expose OPAQUE session keys to framework code.

The ABI catches Rust panics and converts them to `SECURE_KEYPAD_PANIC`, but it
cannot make an invalid C pointer safe. Callers must satisfy the documented
pointer and ownership preconditions. The header uses fixed-width integer
representations for stable layout and is compiled in CI with a C11 contract
test.
