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
    onMaskedStateChange: ({ nativeEvent }) => {
      // nativeEvent.length and nativeEvent.displayState only
      console.log(nativeEvent.length, nativeEvent.displayState);
    },
    onResult: ({ nativeEvent }) => {
      // nativeEvent.type and nativeEvent.code only
      console.log(nativeEvent.code);
    },
  }), []);

  return <SecureKeypadView {...props} />;
}
```

This adapter deliberately has no `value`, `password`, `secret`, `onChangeText`, or submitted-value callback. The app receives only masked state and result codes. The reference iOS/Android view managers are under `native/ios/react-native` and `native/android/.../reactnative`; add them to the host target and link the matching `secure_ffi` artifact for each ABI. Expo Go and browser runtimes are not supported.

The `success` result means that the native keypad created an opaque submission
and the native bridge accepted ownership. It is not a server authentication
decision. A production app must consume that handle inside a host-native
authentication service and report its own server result out-of-band.

The package is MIT-licensed. See the repository security specification before exposing it to an authentication flow.
