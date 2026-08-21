# secure_keypad_flutter

Flutter-facing Secure Native contract for the Secure Keypad SDK.

The package exposes versioned layout/theme/policy configuration and masked
state/result callbacks for numeric, printable-ASCII, and Hangul native policies. It intentionally has no password value, secret getter,
`TextEditingController`, or raw submit callback. A platform implementation
must keep key events, printable-ASCII resolution, and Hangul composition in native/core code and implement
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

For host-driven cancellation, pass a `SecureKeypadController` to the widget
and call `await controller.cancel()`. The controller contains no input and
uses the per-view native method channel; native code clears and zeroizes the
session before emitting the normal masked `cancelled` state/result events.

The plugin build is fail-closed. Set `SECURE_KEYPAD_FFI_XCFRAMEWORK` to the
matching Rust `secure_ffi` XCFramework before iOS CocoaPods integration.
`SECURE_KEYPAD_FFI_LIB` is supported only for a single-platform host build. Set
`SECURE_KEYPAD_FFI_LIB_DIR` to a directory containing
`<abi>/libsecure_ffi.a` before the Android external-native build. Build the
library from the same source revision and release profile as the plugin.

Host-app compilation against the selected Flutter toolchain, example apps,
and device accessibility/security verification remain release gates.
