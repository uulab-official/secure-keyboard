# Device verification gate

Host-app compilation proves that the package links; it does not prove that a
device, system service, or accessibility surface cannot expose the entered
secret. A production release must attach the exact commit, native artifact
checksums, framework versions, device OS build and security-patch evidence, and
sanitized test logs for the matrix below.

The authoritative build/runtime floor is
[`docs/PLATFORM-SUPPORT.json`](./PLATFORM-SUPPORT.json). The current policy
requires iOS 15.1 or newer with a dotted `securityPatchLevel` of at least
15.1, and Android API 24 or newer with an ISO `securityPatchLevel` of at least
2026-01-01. The patch value is an operator-supplied vendor value, not proof by
itself; the hashed `platform-security-patch` artifact must identify the device
settings or vendor bulletin, and the independent reviewer must inspect it.

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
Native and Flutter hosts in an available Simulator and uploads screenshots.
Both generated hosts also run a Release UI test that taps one numeric key and
asserts masked-length state while rejecting the public key label. This catches
packaging, launch, and basic masked-rendering regressions only; it is not
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

Each platform release run should produce one JSON record containing:

- `schemaVersion: 1`, `status: "pass"`, and the exact release gate name
  (`ios-device-matrix`, `android-device-matrix`, or
  `web-browser-matrix`), exact 40-character commit SHA, primary framework
  version, canonical millisecond UTC timestamp, and `physicalDevice` flag;
- for physical native records, `hostModes` with exactly one passing record for
  both `react-native` and `flutter`, including the version used for each host;
  a record for only one framework cannot satisfy the native release gate;
  the recorded host versions must match the release manifest's pinned React
  Native and Flutter toolchains. Each physical host-mode record must also
  include an `evidence` object containing only its own relative `logPath` and
  `logSha256`; those paths must be unique from the aggregate log and artifacts
  so a shared log cannot represent both adapter runs;
- device/browser model, OS version/build, `securityPatchLevel`, and
  `apiLevel` for Android; Web additionally requires `secureContext: true`;
- every applicable test case with the exact status `pass`;
- for native records, explicit `screenshotsAndBackgroundSnapshots`,
  `crashReportReview`, and `protocolDowngrade` pass results in addition to the
  input, accessibility, lifecycle, and replay/rate-limit cases;
- `sanitizedLogs: true`, a relative `logPath`, and a SHA-256 log digest;
- at least one relative artifact path with a lowercase SHA-256 digest. A
  physical native release record must additionally classify unique artifacts as
  `screen-capture`, `background-snapshot`, `accessibility-report`,
  `autofill-clipboard-report`, `crash-report-review`, and `native-checksum`.
  The native checksum must be the exact candidate iOS or Android checksum
  manifest; final release verification rejects a device record from a
  different native binary.
- `platform-security-patch` must be a distinct hashed artifact for each
  physical native record. It must contain sanitized, reviewable evidence of
  the recorded OS security level and must not contain the disposable sentinel.

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
# For an evidence root outside the repository, keep all referenced files
# relative to that root:
node scripts/check-device-evidence.mjs --root "$RUNNER_TEMP/release-evidence" \
  --expected-commit "$(git rev-parse HEAD)" evidence/ios-rn.json
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
  --host-mode react-native=0.87.0 \
  --host-mode flutter=3.47.0 \
  --host-log react-native=logs/ios-react-native-host.txt \
  --host-log flutter=logs/ios-flutter-host.txt \
  --model "iPhone 17 Pro" \
  --os-version 26.5 \
  --os-build 23A000 \
  --security-patch-level 26.5 \
  --log logs/ios-rn.txt \
  --artifact screen-capture=artifacts/ios-screen.png \
  --artifact background-snapshot=artifacts/ios-task-switcher.png \
  --artifact accessibility-report=artifacts/ios-voiceover.txt \
  --artifact autofill-clipboard-report=artifacts/ios-autofill.txt \
  --artifact crash-report-review=artifacts/ios-crash-review.txt \
  --artifact platform-security-patch=artifacts/ios-security-patch.txt \
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

Repeat with `--platform android` and the Android model/OS build. The two
`--host-log` files must be the sanitized logs from the matching RN and Flutter
host runs. Add `--api-level` and an ISO `--security-patch-level` for Android,
and provide the matching `platform-security-patch` artifact. The emitter
creates only hashes and public metadata; it never
embeds log, screenshot, or crash-report bytes in the JSON record. The
standalone record validator bounds
the top-level JSON record to 1 MiB; each referenced evidence file is bounded to
32 MiB and must be non-empty before hashing or content scanning.

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
