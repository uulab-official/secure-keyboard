# secure_keypad_flutter

Flutter-facing Secure Native contract for the Secure Keypad SDK.

The package exposes versioned layout/theme/policy configuration and masked
state/result callbacks. It intentionally has no password value, secret getter,
`TextEditingController`, or raw submit callback. A platform implementation
must keep key events and Hangul composition in native/core code and implement
`SecureKeypadNativeAdapter` without sending the accumulated input through Dart.

The package includes the registration source under `ios/Classes` and
`android/src/main`, plus a `SecureKeypad` widget. The view type is
`secure_keypad/native` and its event channel is `secure_keypad/events/<viewId>`.
The native implementation keeps key events and Hangul composition outside
Dart and emits only masked state/result codes. The `success` result means that
the native keypad created an opaque submission and an installed native
submission consumer accepted ownership. Without a consumer, the plugin
releases the submission and emits `error`; it is not a server authentication
decision. Host-native authentication must install
`SecureKeypadNativeSubmissionRouter`, call `takeOpaqueHandle()` on iOS or
`takeNativeHandle()` on Android, and consume the handle out-of-band. No handle
is exposed to Dart.

The plugin build is fail-closed. Set `SECURE_KEYPAD_FFI_LIB` to the matching
Rust `secure_ffi` static library before iOS CocoaPods integration. Set
`SECURE_KEYPAD_FFI_LIB_DIR` to a directory containing
`<abi>/libsecure_ffi.a` before the Android external-native build. Build the
library from the same source revision and release profile as the plugin.

Host-app compilation against the selected Flutter toolchain, example apps,
and device accessibility/security verification remain release gates.
