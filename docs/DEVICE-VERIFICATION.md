# Device verification gate

Host-app compilation proves that the package links; it does not prove that a
device, system service, or accessibility surface cannot expose the entered
secret. A production release must attach the exact commit, native artifact
checksums, framework versions, device OS build, and sanitized test logs for
the matrix below.

## Required matrix

| Surface | Minimum coverage | Required host modes |
|---|---|---|
| iOS | iOS 15.1 and the current supported iOS release; at least one physical device | React Native native view and Flutter PlatformView |
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
   `FLAG_SECURE` through framework wrapper contexts, reassert it when focus
   returns after host flag changes, while releasing the native session when its
   window loses focus or becomes invisible. Injected or malformed native
   display-state codes must fail closed rather than being mapped to `empty`.
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

- `schemaVersion: 1`, `status: "pass"`, and the exact release gate name
  (`ios-device-matrix`, `android-device-matrix`, or
  `web-browser-matrix`), exact 40-character commit SHA, framework version, timestamp, and
  `physicalDevice` flag;
- device/browser model, OS version/build, and `secureContext: true` for Web;
- every applicable test case with the exact status `pass`;
- for native records, explicit `screenshotsAndBackgroundSnapshots`,
  `crashReportReview`, and `protocolDowngrade` pass results in addition to the
  input, accessibility, lifecycle, and replay/rate-limit cases;
- `sanitizedLogs: true`, a relative `logPath`, and a SHA-256 log digest;
- at least one relative artifact path with a lowercase SHA-256 digest. A
  physical native release record must additionally classify unique artifacts as
  `screen-capture`, `background-snapshot`, `accessibility-report`,
  `autofill-clipboard-report`, `crash-report-review`, and `native-checksum`.

The record validator rejects secret-bearing field names (including sentinel
values, raw input bytes, and credential byte fields), absolute/parent paths,
missing test passes, invalid hashes, and WebAuthn records without secure
context evidence:

```sh
pnpm test:device-evidence
node scripts/check-device-evidence.mjs path/to/device-evidence.json
# Use this form for the required iOS/Android physical-device release gate:
node scripts/check-device-evidence.mjs --require-physical \
  --expected-commit "$(git rev-parse HEAD)" path/to/device-evidence.json
```

The validator also recomputes the log and artifact digests inside the evidence
root and rejects symlinks that resolve outside it. This still does not replace
independent review of screenshots or the physical-device run.

Use the checked-in native emitter after the physical run. It requires every
native test case and every physical artifact category, reads files only inside
the evidence root, rejects the disposable sentinel before writing output, and
derives the current clean checkout commit and Contracts package version:

```sh
node scripts/emit-native-device-evidence.mjs \
  "$RUNNER_TEMP/release-evidence" \
  "evidence/ios-rn.json" \
  "fragments/ios-rn.json" \
  --platform ios \
  --framework react-native \
  --framework-version 0.87.0 \
  --model "iPhone 17 Pro" \
  --os-version 26.5 \
  --os-build 23A000 \
  --log logs/ios-rn.txt \
  --artifact screen-capture=artifacts/ios-screen.png \
  --artifact background-snapshot=artifacts/ios-task-switcher.png \
  --artifact accessibility-report=artifacts/ios-voiceover.txt \
  --artifact autofill-clipboard-report=artifacts/ios-autofill.txt \
  --artifact crash-report-review=artifacts/ios-crash-review.txt \
  --artifact native-checksum=artifacts/secure-ffi.sha256 \
  --test-case maskedStateOnly \
  --test-case captureAndBackground \
  --test-case screenshotsAndBackgroundSnapshots \
  --test-case autofillAndClipboard \
  --test-case accessibility \
  --test-case crashReportReview \
  --test-case lifecycleAndZeroization \
  --test-case serverReplayRateLimit \
  --test-case protocolDowngrade
```

Repeat with `--platform android` and the Android model/OS build. The emitter
creates only hashes and public metadata; it never embeds log, screenshot, or
crash-report bytes in the JSON record.

Use the checked-in disposable sentinel `secure-keypad-test-sentinel-7f2c4e` for
the device matrix. `check-device-evidence.mjs` recomputes every referenced
digest and rejects that sentinel plus common secret-bearing text fields in
NUL-free logs and artifacts. This is a byte-level preflight: it cannot detect
OCR-visible text in screenshots, compressed/binary leaks, or an operator's
different sentinel, so human screenshot/crash review and the independent
assessment remain mandatory.

When a device record is used as a release gate, its JSON `commit` is checked
again by `check-release-evidence.mjs` against the gate's exact commit. A valid
device record from another checkout therefore cannot satisfy the current
release manifest merely by being copied into the evidence root.

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
