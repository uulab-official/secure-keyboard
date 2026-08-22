# Secure Keypad Security Specification

## Goal

Build an open-source, cross-platform virtual keypad SDK that lets consuming applications customize the complete visual experience while keeping the secret input out of JavaScript, Dart, ordinary text widgets, logs, clipboard, and server-side plaintext storage whenever the platform allows it.

## Security posture

The SDK minimizes exposure; it cannot guarantee that a password is absent from memory. A secret must exist briefly in the process in order to be processed. A rooted or jailbroken device, injected process, malicious accessibility service, compromised browser, hostile extension, or malicious host application can observe input. The SDK must document these limits and never claim absolute theft prevention.

## Product modes

### Secure Native Mode

The default mode for mobile. A native renderer receives a serializable layout and theme specification. Native code receives only key IDs from touch events, resolves the input symbol in the secure core, and returns only length/state/authentication results.

### Headless Host Mode

The SDK provides an opt-in compatibility mode for applications that render keys
in React Native or Flutter. It is fully composable, but the host runtime can
observe every public key ID and therefore receives a weaker security boundary.
The mode requires `acknowledgeLowerAssurance: true`, is rejected unless the
mode is explicitly `headless-host`, and must never be the default for
authentication. Native/core code still owns the composition buffer; the host
command contains only a bounded monotonic token and public `keyId`, never a
label-derived value or accumulated input. Duplicate tokens are ignored and
older tokens are rejected.

### Web Mode

WebAuthn/passkeys are the preferred authentication path. A custom web keypad is supported as a convenience fallback and must clearly document browser, page-script, extension, and memory limitations.

## Public customization contract

Consumers may provide:

- layout rows and key IDs;
- display labels, icons, and semantic roles;
- theme tokens for color, typography, spacing, radius, shadows, and states;
- header, display, footer, error, and action slots;
- masking style and reveal timing;
- optional native CSPRNG input-key randomization;
- animation and haptic policies;
- locale, direction, accessibility text, and input policy.

Consumers must not receive or provide:

- a password string;
- a password change callback;
- a getter for the accumulated input;
- a mapping callback that receives the secret value;
- raw secret values in analytics or error events.

Native renderers must revalidate all public layout and theme data at the
native entry point, even when a framework adapter already validated it. The
native boundary must reject oversized row/key collections, duplicate or
malformed public key IDs, key labels over 16 UTF-8 bytes, accessibility labels
over 80 UTF-8 bytes, and non-finite or out-of-range theme dimensions before
creating UI objects or a secure session.

The public controller is limited to operations such as `beginSession`, `pressKey(keyId)`, `backspace`, `clear`, `submit`, and `cancel`. The layout contract includes a `cancel` action role, and RN/Flutter host cancellation commands carry only a monotonic public token or method name; activating either path calls native cancellation, clears the core buffer, and emits only `displayState: cancelled` plus a `cancelled` result code. In acknowledged Headless Host Mode, `pressKey(keyId)` carries only a bounded monotonic token and public key ID; it is unavailable in Secure Native Mode. State events expose only length, masked display state, validation state, and result codes. Framework adapters must revalidate exact event keys, state length (`0..4096`), and stable result-code shapes before invoking application callbacks; malformed metadata fails closed as a generic error and is never echoed.

The native C ABI is an opaque-handle boundary. It accepts public key IDs as
bounded pointer/length inputs and returns only masked state or stable error
codes. A submission handle has no byte accessor; native OPAQUE registration and
login code must consume it inside the native boundary. ABI callers own each
handle and must not use a handle concurrently or after its matching free
function. ABI version 2 is required for the registration handoff; native hosts
must compare `secure_keypad_abi_version()` with the header's
`SECURE_KEYPAD_ABI_VERSION` before creating a session and fail closed on a
mismatch. The shipped iOS view and Android JNI bridge enforce this check.
ABI v1 is not a supported production registration path; hosts must ship the
ABI v2 header, native library, and registration handoff as one versioned set.

RN and Flutter bridges require an explicitly installed native submission
consumer. Without one, submit zeroizes/releases the opaque handle and emits an
error result. A framework success event is emitted only after the consumer has
actually taken ownership of the opaque handle; it still never means that server
authentication succeeded.

## Input policies

Numeric, printable-ASCII, and Hangul composition are separate native policies. Printable ASCII keys use a public `ascii-XX` identifier with a lowercase hexadecimal code point; labels are not interpreted as secret input. Hangul composition happens in the secure core, not in JavaScript or Dart. The initial core accepts structured jamo key IDs and emits canonical Hangul syllable code points; arbitrary Unicode normalization is not silently enabled. Future Unicode policies must lock the Unicode version and normalization behavior. NFKC must not be enabled implicitly because compatibility normalization can change the user's intended secret.

## Memory and leakage rules

The Rust core bounds each session to `MAX_INPUT_TOKENS`, uses fixed-capacity
token storage, zeroizes popped/cleared/dropped tokens, and provisions the
rendered UTF-8 buffer before copying secret bytes. These are implementation
controls that reduce residual-memory exposure; they do not make the absolute
memory-erasure claim that a hostile or compromised runtime would require.

- Never use a normal host-language string as the secret buffer.
- Prefer a native/Rust byte buffer with explicit clearing after cancel, submit, timeout, and error.
- Do not write the secret to persistent storage, clipboard, accessibility values, notifications, logs, analytics, crash breadcrumbs, or debug output.
- Never include the secret in exceptions, snapshots, test failure messages, or serialized component props.
- Clear intermediate buffers where the underlying platform permits; document that garbage-collected runtimes and optimized copies cannot be proven fully zeroized.
- Native submission and OPAQUE secret-output handoffs invoke a `FnOnce(&[u8])` callback that returns no value; callers must consume the bytes immediately in native/server cryptographic code and cannot use the public API as a secret getter.
- Mobile background snapshots must be masked. Android secure-window protection and iOS capture/background handling are platform-specific controls, not universal guarantees.
- Android Secure Native construction must fail closed if the host `Activity` window cannot be resolved for `FLAG_SECURE`; a keypad that cannot establish the secure window boundary must not accept input.

## Authentication boundary

The server integration uses a versioned PAKE contract. OPAQUE is the preferred protocol family. The server stores protocol records and key IDs, not plaintext passwords and not a client-side hash that can be replayed as a password. Protocol messages, errors, and timing-sensitive details must not be logged.

OPAQUE registration uploads, credential files, server setup material, and transport messages are sensitive. Registration uploads and credential files require protected transport/storage, while server setup material requires secret-store or HSM-backed handling. The protocol engine does not by itself provide HTTPS, rate limiting, replay policy, session-token issuance, or key rotation; those belong to the server integration layer.

The framework-neutral HTTP/JSON contracts require the host to provide an
explicit `csrf_validated` result derived from request metadata and the host
session/origin policy. Axum and Actix adapters require a request-parts CSRF
callback and reject a failed result before buffering JSON; no adapter may
infer CSRF state from a request body.

The publishable `@secure-keypad/server-node` adapter applies the same boundary
to Web Fetch requests: it requires an explicit TLS/proxy deployment context,
validates CSRF before reading the body, bounds streaming input at 128 KiB, and
emits only the generic response contract and security headers. It is a
transport bridge, not a JavaScript OPAQUE implementation. Its delegate must
keep the pinned OPAQUE engine in Rust/native code and must not log, persist, or
return password/PIN values. Delegate responses cross the TypeScript boundary
as bounded `Uint8Array` bytes; the adapter copies them into the Fetch response
and zeroizes the delegate-owned response buffer before returning. JavaScript
and Fetch runtime copies remain outside the strongest native secret boundary.

TLS/pinning ownership and compromised-runtime limits are defined in
`docs/PLATFORM-SECURITY-POLICY.md`; the SDK does not claim to implement
certificate pinning, root/jailbreak detection, or tamper resistance across
arbitrary host transports and operating systems.

Minimum protocol metadata:

```json
{
  "protocolVersion": 1,
  "suite": "opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2",
  "serverKeyId": "key-2026-01"
}
```

The server rejects unsupported versions and prevents downgrade. UI package versions and authentication protocol versions are released independently.

## Acceptance criteria

1. Secure Native Mode never emits a secret string across the RN or Flutter bridge.
2. No public API exposes accumulated secret input.
3. Numeric and Hangul composition have deterministic, cross-platform test vectors.
4. Theme/layout changes do not change the protocol or memory boundary.
5. Logs, analytics, crash reports, screenshots, and background snapshots contain no secret values in the test matrix.
6. Server integration has replay, downgrade, rate-limit, version-compatibility,
   and create-only credential-enrollment tests.
7. The README contains a threat model and an explicit limitation statement before the first release.
