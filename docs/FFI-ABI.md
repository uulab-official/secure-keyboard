# Native FFI ABI

`crates/secure-ffi/include/secure_keypad.h` is the native boundary for iOS,
Android, React Native, and Flutter adapters.

## Allowed across the boundary

- layout-selected public key IDs as bounded UTF-8 pointer/length inputs;
- numeric or structured Hangul policy selection;
- masked length and display state;
- stable error codes;
- opaque session and submission ownership handles.
- opaque native OPAQUE registration and login state handles.

## Forbidden across the boundary

- password strings or raw accumulated input;
- secret getters, callbacks, JSON, logs, analytics, or crash fields;
- concurrent use of a session handle;
- use-after-free or double-free of handles.

The submission handle is intentionally not serializable. Native authentication
code consumes it inside the native/Rust boundary or releases it. The login and
registration start functions consume the submission pointer after argument
validation, set the caller's pointer to null, and release the submission even
when the protocol operation returns an error. The native
OPAQUE functions can turn that submission into registration/login request and
upload/finalization message handles for a native HTTP client; they never expose
a password, export key, or derived client session key. Registration and login
both stay inside the native boundary. The C ABI does not itself perform HTTP.
The submission, client-state, and request output slots passed to either native
start function must be distinct. The ABI rejects aliased slots before clearing
or consuming any caller-owned handle, preventing an aliased C output from
losing an opaque submission or one of the newly allocated handles.

`SECURE_KEYPAD_ABI_VERSION = 2` is required for the registration functions.
Hosts must reject an ABI mismatch before creating a session or accepting a
submission.

The ABI catches Rust panics and converts them to `SECURE_KEYPAD_PANIC`, but it
cannot make an invalid C pointer safe. Callers must satisfy the documented
pointer and ownership preconditions. The header uses fixed-width integer
representations for stable layout and is compiled in CI with a C11 contract
test.
