# secure_keypad_flutter

Flutter-facing Secure Native contract for the Secure Keypad SDK.

The package exposes versioned layout/theme/policy configuration and masked
state/result callbacks. It intentionally has no password value, secret getter,
`TextEditingController`, or raw submit callback. A platform implementation
must keep key events and Hangul composition in native/core code and implement
`SecureKeypadNativeAdapter` without sending the accumulated input through Dart.

Reference registration is provided in `native/ios/flutter/SecureKeypadFlutterPlugin.swift`
and `native/android/.../flutter/SecureKeypadFlutterPlugin.kt`; the view type is
`secure_keypad/native` and its event channel is `secure_keypad/events/<viewId>`.
The native implementation keeps key events and Hangul composition outside
Dart and emits only masked state/result codes. The `success` result means that
the native keypad created an opaque submission and the native bridge accepted
ownership; it is not a server authentication decision. Host-native
authentication must consume the handle out-of-band.

Host-app PlatformView/FFI wiring, example apps, and device
accessibility/security verification remain release gates.
