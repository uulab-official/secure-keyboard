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
older tokens are rejected. Updating a command must not recreate an active
native session or discard its native-owned input; only initial configuration
may apply a command that arrived before the session was created.
The replay floor is retained for the lifetime of a native view instance across
session release, lifecycle recovery, and public reconfiguration; releasing the
secret-bearing session must not make an older delayed command valid again.
Flutter's public controller also preserves its monotonic token sequence across
Dart widget attach/detach cycles, so adapter reattachment cannot reset commands
below the native replay floor or make an older delayed command current again.
On iOS and Android, a Headless Host token is recorded only after the native
activation path returns success; a protected, unavailable, or native-rejected
activation therefore cannot advance the replay floor.

### Web Mode

WebAuthn/passkeys are the preferred authentication path. The SDK ships the
WebAuthn adapter and an explicit lower-assurance fallback-acknowledgement
contract; it does not ship a browser DOM keypad that could be mistaken for a
secure native input boundary. A product may build its own custom browser UI
around that contract, but must clearly document browser, page-script,
extension, and memory limitations before accepting any input.
The passkey presentation controller treats cancellation as terminal for the
active ceremony: late browser results are discarded and cannot transition the
controller to success or return a credential to the caller. The caller
operation also settles with the stable "aborted" error independently of whether
the browser honors the underlying abort signal. The direct registration and
authentication APIs apply the same abort check after the browser promise settles,
so a late credential is rejected before response data is serialized.
The controller retains its operation slot until the underlying browser promise
settles, so cancelling a ceremony cannot open a second concurrent ceremony while
the first browser operation is still active.

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
over 80 UTF-8 bytes, non-canonical optional test IDs, and non-finite or
out-of-range theme dimensions before creating UI objects or a secure session.

React Native managers must also fail closed during prop churn: if a required
layout or theme value is removed after a session was configured, the manager
must discard pending public configuration, clear its configuration fingerprint,
and release the native session before accepting a later complete configuration.
Before the first complete configuration, sequential layout/theme prop delivery
must remain pending rather than being mistaken for a valid session.
If iOS lifecycle protection has released the native session while public props
remain unchanged, the manager must detect the missing session and recreate it
from the same validated public configuration; a matching configuration
fingerprint alone is not proof that a session is live.
On Android, after window-focus protection has zeroized the session, the native
view must request the RN manager to reapply the retained public configuration on
focus or visibility regain. Reattachment must make the same recovery request
because a host can detach and reattach a view without a focus or visibility
callback; the lifecycle callback must not carry input or any secret state. The
same rule applies to Flutter's Android PlatformView. Direct native SDK
consumers use the native view's fallback recovery path when no framework
callback is installed. On iOS, application activation, screen-capture
protection clearing, or window reattachment must request the RN/Flutter adapter
to recreate a missing session from retained public configuration, with the
same direct-consumer fallback. Recovery must not replay a previously submitted
Headless Host command; only a new host command token may activate a key. An
explicit `releaseSession()` clears both the native session and retained public
configuration, so teardown remains terminal until the host configures again.
While iOS marks the presentation as protected because the app is inactive or
the screen is captured, both native button activation and Headless Host
`pressKey` commands are rejected. Explicit cancellation and session release
remain available so the host can clear state without accepting new input.
When screen capture starts, iOS also releases a live native session and emits
only the public cancelled/empty state; capture end may recreate a session from
retained public configuration, never from the previous secret input.
The shared native release helper publishes an empty `(length: 0,
displayState: 0)` state by default. Lifecycle and protected-presentation
callers may opt into the public cancelled state `(length: 0, displayState: 3)`;
they must use that centralized helper and must not emit a duplicate callback.
iOS lifecycle protection is scoped to the keypad's own `UIWindowScene`. A
different scene becoming inactive must not release or recreate this keypad's
session; activity is derived from that window scene's `activationState`.
This contract is enforced independently for the canonical native sources and
the publishable package copies.

The core exposes `MAX_KEY_ID_BYTES = 64` and a fallible `KeyId::try_new` for
untrusted public configuration. Policy resolution repeats the byte bound so a
direct core consumer cannot bypass the native adapter limit.

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
Every FFI byte range and every pointer-sized output slot must not overlap live
opaque handle objects or other output slots; finish identifier buffers must not
overlap any live handle or pointer slot. These are byte-range preconditions,
not merely exact-pointer checks, and violations fail with
`SECURE_KEYPAD_INVALID_ARGUMENT` before state is consumed or outputs are
cleared.

RN and Flutter bridges require an explicitly installed native submission
consumer. Without one, submit zeroizes/releases the opaque handle and emits an
error result. A framework success event is emitted only after the consumer has
actually taken ownership of the opaque handle; it still never means that server
authentication succeeded. If the native ABI reports submit success without an
opaque handle, the native view must release the session and emit only the
stable internal error; a missing handle is never treated as a successful submit.
The same fail-closed rule applies when a direct native consumer is not
installed: the opaque handle is released, the stable internal error is emitted,
and no successful submit result is published.
After a submit creates an opaque handle, the native view must refresh the
public masked state before handing the handle to the consumer. If that refresh
fails, the handle is released and the consumer/framework must not receive a
success result.

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
- Native cancellation is fail-closed: if the core cancellation call returns an error, the platform view must release the native session before reporting the stable error, while leaving the monotonic cancel replay floor unchanged.
- Native activation is fail-closed: if any core key/action operation returns an error, the platform view must release the native session before reporting the stable error; rejected touch and Headless Host commands must not advance their replay floor.
- Masked-state refresh is part of command success: if rendering the post-command state fails, activation or cancellation must return failure after zeroization, and the associated replay floor must remain unchanged.
- Native session release must clear the local display and publish only an empty masked state before returning; lifecycle and protected-presentation callers must use this central path rather than emitting a stale or duplicate state.
- Mobile background snapshots must be masked. Android secure-window protection and iOS capture/background handling are platform-specific controls, not universal guarantees.
- Android Secure Native construction must fail closed if the host `Activity` window cannot be resolved for `FLAG_SECURE`; a keypad that cannot establish the secure window boundary must not accept input.
- Android touch activation and Headless Host commands must reassert and verify `FLAG_SECURE` immediately before invoking the native session. If the host window cannot be resolved, reassertion fails, or verification fails, the input is rejected and the command replay floor must not advance.
- Android touch and Headless Host input-boundary protection failure is a zeroization boundary: if `FLAG_SECURE` cannot be re-established or verified, clear the native session before reporting the stable internal error.
- Android focus and visibility restoration must fail closed without throwing into the host: clear the native session and emit only the stable internal error when `FLAG_SECURE` cannot be re-established.
- Android view reattachment must apply the same rule: a failed secure-window restoration must clear the native session and return from the lifecycle callback without throwing.
- Android Secure Native views must enable obscured-touch filtering and reject both fully and partially obscured `MotionEvent`s before key activation; this is a tapjacking boundary, and rejection must clear the native session before emitting the stable internal error.
- iOS protected presentation is a zeroization boundary: whenever scene inactivity or screen capture makes the presentation protected, any live native session must be released before the protected state is rendered.
- iOS and Android Headless Host commands must record their replay token only after the native activation path returns success; protected, unavailable, or otherwise rejected activation must not advance the replay floor.

## Authentication boundary

The server integration uses a versioned PAKE contract. OPAQUE is the preferred protocol family. The server stores protocol records and key IDs, not plaintext passwords and not a client-side hash that can be replayed as a password. Protocol messages, errors, and timing-sensitive details must not be logged.

OPAQUE registration uploads, credential files, server setup material, and transport messages are sensitive. Registration uploads and credential files require protected transport/storage, while server setup material requires secret-store or HSM-backed handling. The protocol engine does not by itself provide HTTPS, rate limiting, replay policy, session-token issuance, or key rotation; those belong to the server integration layer.

The framework-neutral HTTP/JSON contracts require the host to provide an
explicit `csrf_validated` result derived from request metadata and the host
session/origin policy. Axum and Actix adapters require a request-parts CSRF
callback and reject a failed result before buffering JSON; no adapter may
infer CSRF state from a request body. OPAQUE adapters also require a
pre-buffering `RequestAdmission` result for account/IP/deployment rate-limit
admission and fail closed on a denied or unavailable decision.

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
