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

## Test cases

Use a disposable test account and a sentinel input that must never appear in a
log, clipboard, accessibility value, screenshot, crash report, analytics
event, or framework callback. The native authentication consumer must receive
only the opaque submission capability.

1. Enter, backspace, clear, timeout, cancel, and submit through numeric and
   Hangul layouts. Verify that RN/JS and Flutter/Dart observe only masked
   length/state and generic result codes.
2. Capture the screen, start recording, background the app, open the task
   switcher, and return to the app. Verify that iOS remains protected while
   capture is still active after an active/inactive transition, and that
   Android retains `FLAG_SECURE` through framework wrapper contexts.
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
