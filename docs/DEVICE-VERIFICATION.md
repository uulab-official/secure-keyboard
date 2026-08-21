# Device verification gate

Host-app compilation proves that the package links; it does not prove that a
device, system service, or accessibility surface cannot expose the entered
secret. A production release must attach the exact commit, native artifact
checksums, framework versions, device OS build, and sanitized test logs for
the matrix below.

## Required matrix

| Surface | Minimum coverage | Required host modes |
|---|---|---|
| iOS | iOS 15 and the current supported iOS release; at least one physical device | React Native native view and Flutter PlatformView |
| Android | API 24 and the current supported API; at least one physical device | React Native native view and Flutter PlatformView |
| Web | Current supported Chromium, WebKit, and Gecko in secure contexts | WebAuthn/passkey path; acknowledged custom fallback only when explicitly enabled |

Physical devices are required for screen recording, task-switcher snapshots,
autofill services, and VoiceOver/TalkBack behavior. Simulators/emulators may
supplement the matrix but cannot replace those checks.

The iOS CI host job additionally installs and launches the generated React
Native and Flutter hosts in an available Simulator and uploads no-input
screenshots. This catches packaging and launch regressions only; it is not
physical-device evidence and does not replace the matrix above.

The Android CI host jobs additionally build arm64 and x86_64 FFI variants. A
separate API 35 x86_64 emulator job installs and launches both generated host
APKs and uploads no-input screenshots. This catches packaging and launch
regressions only; it is not physical-device evidence and does not replace the
Android matrix above.

## Test cases

Use a disposable test account and a sentinel input that must never appear in a
log, clipboard, accessibility value, screenshot, crash report, analytics
event, or framework callback. The native authentication consumer must receive
only the opaque submission capability.

1. Enter, backspace, clear, timeout, cancel, and submit through numeric,
   printable-ASCII, and Hangul layouts. Verify that RN/JS and Flutter/Dart
   observe only masked length/state and generic result codes.
2. Capture the screen, start recording, background the app, open the task
   switcher, and return to the app. Verify that iOS remains protected while
   capture is still active after an active/inactive transition, that iOS
   releases the native session on resign-active, and that Android retains
   `FLAG_SECURE` through framework wrapper contexts while releasing the native
   session when its window loses focus or becomes invisible.
3. Attempt autofill and clipboard operations. Verify no editable text control,
   autofill suggestion, clipboard write, or password-manager value is created.
4. Exercise VoiceOver and TalkBack. Verify that labels expose key semantics and
   masked length only, never the sentinel or an accumulated input string.
5. Rotate, resize, detach, recreate, and kill the host view. Verify timeout,
   session release, native submission ownership, and zeroization behavior.
6. Run server registration/login, missing-account, replay, expired-state,
   rate-limit, key-rotation, and protocol-downgrade cases against the exact
   server SDK and durable backend configuration.
7. On Web, verify passkey-first behavior, secure-context enforcement, origin/RP
   ID binding, bounded option parsing, and the explicit lower-assurance warning
   before any custom keypad fallback.

## Evidence and exit rule

Store test metadata and sanitized logs as release artifacts. Do not upload
screenshots containing real or sentinel secrets. A failed, skipped, or
unavailable physical-device case keeps the device gate open; source inspection
and host compilation are not substitutes. The independent security reviewer
must re-run a representative sample and sign the exact evidence bundle.

## Machine-readable evidence record

Each platform/framework run should produce one JSON record containing:

- the exact 40-character commit SHA, framework version, timestamp, and
  `physicalDevice` flag;
- device/browser model, OS version/build, and `secureContext: true` for Web;
- every applicable test case with the exact status `pass`;
- `sanitizedLogs: true`, a relative `logPath`, and a SHA-256 log digest;
- at least one relative artifact path with a lowercase SHA-256 digest.

The record validator rejects secret-bearing field names, absolute/parent paths,
missing test passes, invalid hashes, and WebAuthn records without secure
context evidence:

```sh
pnpm test:device-evidence
node scripts/check-device-evidence.mjs path/to/device-evidence.json
# Use this form for the required iOS/Android physical-device release gate:
node scripts/check-device-evidence.mjs --require-physical path/to/device-evidence.json
```

The validator also recomputes the log and artifact digests inside the evidence
root and rejects symlinks that resolve outside it. This still does not replace
independent review of screenshots or the physical-device run.

The repository also contains a real-browser smoke harness:

```sh
pnpm --dir packages/web build
pnpm exec playwright install --with-deps chromium firefox webkit
pnpm test:web-browser all
```

It is supplemental evidence for the Web adapter's secure-context, passkey
support, fallback-acknowledgement, and binary-boundary behavior. It does not
turn browser JavaScript into a trusted secret-memory boundary and does not
close the deployed-origin authenticator or independent-review gates.
