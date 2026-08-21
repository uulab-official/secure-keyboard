# @secure-keypad/react-native

The React Native public adapter for Secure Keypad. It exposes versioned layout/theme props and masked result events while keeping entered input inside the native Rust-backed session.

```tsx
import { useMemo } from "react";
import {
  getSecureKeypadView,
  type SecureKeypadProps,
} from "@secure-keypad/react-native";
import {
  DEFAULT_NUMERIC_LAYOUT,
  DEFAULT_THEME,
} from "@secure-keypad/contracts";

const SecureKeypadView = getSecureKeypadView();

export function PinEntry() {
  const props = useMemo<SecureKeypadProps>(() => ({
    layout: DEFAULT_NUMERIC_LAYOUT,
    theme: DEFAULT_THEME,
    inputPolicy: "numeric",
    maxTokens: 8,
    timeoutMs: 60_000,
    // Increment this public command token to cancel and zeroize natively.
    cancelRequest: 0,
    onMaskedStateChange: ({ nativeEvent }) => {
      // nativeEvent.length and nativeEvent.displayState only
      console.log(nativeEvent.length, nativeEvent.displayState);
    },
    onResult: ({ nativeEvent }) => {
      // nativeEvent.type and nativeEvent.code only
      console.log(nativeEvent.code);
    },
  }), []);

  return <SecureKeypadView style={{ flex: 1 }} {...props} />;
}
```

`style` is the presentation-only React Native layout prop. Give the view an
explicit size (for example, `flex: 1`) from the host layout; it is not part of
the native secret/session contract.

For native passwords containing letters and symbols, use `inputPolicy: "ascii"`
with public `ascii-XX` key IDs. The label is presentation-only; browser
JavaScript is not a trusted secret-memory boundary, so use the passkey adapter
on the web.

This adapter deliberately has no `value`, `password`, `secret`, `onChangeText`, or submitted-value callback. The app receives only masked state and result codes. `getSecureKeypadView()` installs a fail-closed event wrapper: masked lengths are limited to 4,096 and result payloads are restricted to stable codes before host callbacks run. `getSecureKeypadNativeView()` is a low-level unwrapped escape hatch for native host integration; applications should use the wrapped API. The npm package includes the iOS/Android view managers, JNI adapter, and FFI module map under `ios/` and `android/`; `scripts/check-native-package-parity.mjs` keeps these copies aligned with `native/`. Expo Go and browser runtimes are not supported.

`cancelRequest` is a monotonic, non-secret command token. The first value is
captured as the baseline; changing it calls the native cancellation path,
zeroizes the pending session, and emits only `cancelled` plus an empty masked
state. It never carries or derives an input value.

Build integration is intentionally fail-closed. Before `pod install`, copy the
matching Rust `secure_ffi` XCFramework into the installed package directory
as `secure_ffi.xcframework` (or stage `libsecure_ffi.a` there for a
single-platform fallback), then set `SECURE_KEYPAD_FFI_XCFRAMEWORK` or
`SECURE_KEYPAD_FFI_LIB` to the source artifact path. CocoaPods receives only
the staged relative path inside the package; an arbitrary absolute vendored
path is rejected.
Before the Android external-native build, set
`SECURE_KEYPAD_FFI_LIB_DIR` to a directory containing
`<abi>/libsecure_ffi.a` for every ABI shipped by the app. The library must be
built from the same source revision and release profile as the native view.

The `success` result means that the native keypad created an opaque submission
and an installed native submission consumer accepted ownership. Without a
consumer, the bridge releases the submission and reports `error`. It is not a
server authentication decision. A production app must install
`SecureKeypadNativeSubmissionRouter` in native code, call
`takeOpaqueHandle()` on the submission, and consume the handle inside a
host-native authentication service; no handle is exposed to JavaScript.

The package is MIT-licensed. See the repository security specification before exposing it to an authentication flow.
