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

For a fully custom host-rendered keypad, opt into the lower-assurance mode and
acknowledge the trade-off explicitly. The host observes public key IDs, while
native/core code still owns composition and the input buffer:

```tsx
<SecureKeypadView
  {...props}
  mode="headless-host"
  acknowledgeLowerAssurance
  headlessKeyPress={{ token: 0, keyId: "digit-1" }}
/>
```

Increment the bounded `token` for each command. Do not send labels, derived
values, or accumulated input. Secure Native remains the default and should be
used when the native renderer is acceptable.

For native passwords containing letters and symbols, use `inputPolicy: "ascii"`
with public `ascii-XX` key IDs. The label is presentation-only; browser
JavaScript is not a trusted secret-memory boundary, so use the passkey adapter
on the web.

This adapter deliberately has no `value`, `password`, `secret`, `onChangeText`, or submitted-value callback. The app receives only masked state and result codes. `getSecureKeypadView()` validates and allowlists props before native view creation, strips framework callbacks and unknown fields from the native map, and installs a fail-closed event wrapper: masked lengths are limited to 4,096 and result payloads are restricted to stable codes before host callbacks run. Invalid props emit only a generic `error` result and do not create a native view. The unwrapped native component is intentionally not exported, so applications cannot accidentally bypass the public validation and event boundary. The npm package includes the iOS/Android view managers, JNI adapter, and FFI module map under `ios/` and `android/`; `scripts/check-native-package-parity.mjs` keeps these copies aligned with `native/`. Expo Go and browser runtimes are not supported.

## Expo Development Build

Expo Development Builds are supported because Expo prebuild can autolink this
package's native view manager. The included config plugin uses the verified
native artifacts bundled in a published package. For a source checkout or a
custom artifact, provide the explicit paths below; otherwise the plugin
resolves the package's `secure_ffi.xcframework` and `android/secure_ffi`
directories and fails closed if either is missing:

```sh
export SECURE_KEYPAD_FFI_XCFRAMEWORK="$PWD/native-artifacts/secure_ffi.xcframework"
export SECURE_KEYPAD_FFI_LIB_DIR="$PWD/native-artifacts/android"
npx expo prebuild
npx expo run:ios   # or: npx expo run:android
```

The verified release Android matrix is `arm64-v8a` and `x86_64`; release npm
archives contain both `android/secure_ffi/<abi>/libsecure_ffi.a` files and the
build defaults to those two ABIs. A host selecting another ABI must provide a
matching `libsecure_ffi.a` and set `reactNativeArchitectures` explicitly. Any
custom FFI artifacts must come from the same source commit as the package. Expo Go is
intentionally unsupported: it cannot load the
custom native security boundary. Do not replace this native view with a
JavaScript keypad or a `TextInput` fallback when the secure native mode is
required.

`cancelRequest` is a monotonic, non-secret command token. The first value is
captured as the baseline; a newer value calls the native cancellation path,
zeroizes the pending session, and emits only `cancelled` plus an empty masked
state. An equal replay is ignored and a delayed lower value is rejected. It
never carries or derives an input value.

Build integration is intentionally fail-closed. For source checkouts or custom
native builds, set `SECURE_KEYPAD_FFI_XCFRAMEWORK`/`SECURE_KEYPAD_FFI_LIB` and
`SECURE_KEYPAD_FFI_LIB_DIR` to validated artifacts from the same source
revision and release profile. Published release packages already contain the
verified iOS XCFramework and Android `arm64-v8a`/`x86_64` libraries, so no
absolute path is required. CocoaPods still receives only the staged relative
path inside the package; an arbitrary absolute vendored path is rejected.

The `success` result means that the native keypad created an opaque submission
and an installed native submission consumer accepted ownership. Without a
consumer, the bridge releases the submission and reports `error`. It is not a
server authentication decision. A production app must install
`SecureKeypadNativeSubmissionRouter` in native code. Its consumer receives the
originating native view and submission; it must bind authentication state to
that view instance, call `takeOpaqueHandle()`, and consume the handle inside a
host-native authentication service. Do not route through a mutable global
account context; no handle is exposed to JavaScript.

The package is MIT-licensed. See the repository security specification before exposing it to an authentication flow.
