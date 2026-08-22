# secure_keypad_flutter

Flutter-facing Secure Native contract for the Secure Keypad SDK.

Compatibility: Flutter `>=3.44.0`, Dart `>=3.12.0 <4.0.0`. The Android plugin
uses Flutter's built-in Kotlin compiler contract and JVM 17; it does not apply
the legacy Kotlin Gradle Plugin itself.

The package exposes versioned layout/theme/policy configuration and masked
state/result callbacks for numeric, printable-ASCII, and Hangul native policies. It intentionally has no password value, secret getter,
`TextEditingController`, or raw submit callback. A platform implementation
must keep key events, printable-ASCII resolution, and Hangul composition in native/core code and implement
`SecureKeypadNativeAdapter` without sending the accumulated input through Dart.

The package includes the registration source under `ios/Classes` and
`android/src/main`, plus a `SecureKeypad` widget. The view type is
`secure_keypad/native` and its event channel is `secure_keypad/events/<viewId>`.
The native implementation keeps key events and Hangul composition outside
Dart and emits only exact masked state/result event shapes. The Dart boundary
rejects unexpected fields, bounds masked length to 4,096, and converts malformed
events to a generic `error`; no event payload is echoed. The `success` result means that
the native keypad created an opaque submission and an installed native
submission consumer accepted ownership. Without a consumer, the plugin
releases the submission and emits `error`; it is not a server authentication
decision. Host-native authentication must install
`SecureKeypadNativeSubmissionRouter`. Its consumer receives the originating
native view and submission; it must bind authentication state to that view
instance, call `takeOpaqueHandle()` on iOS or `takeNativeHandle()` on Android,
and consume the handle out-of-band. Do not route through a mutable global
account context. No handle is exposed to Dart. If the Dart listener is temporarily unavailable, each
native event bridge retains a bounded backlog of 32 public events, coalesces
adjacent masked-state updates, and evicts state before terminal result events.
The backlog is cleared when the native view is disposed.

Set `KeypadLayout(randomizeInputKeys: true)` when the native renderer should
randomize input-key positions with the platform CSPRNG. The seed and input
remain native-only; this option does not protect against a compromised host or
device.

For host-driven cancellation, pass a `SecureKeypadController` to the widget
and call `await controller.cancel()`. The controller contains no input and
uses the per-view native method channel; native code clears and zeroizes the
session before emitting the normal masked `cancelled` state/result events.

For a fully custom host-rendered keypad, set
`mode: SecureKeypadMode.headlessHost` and
`acknowledgeLowerAssurance: true`, then call `await controller.pressKey("digit-1")`.
This lower-assurance path lets the host observe public key IDs; it never sends
labels, derived values, or accumulated input. Secure Native is the default.
Headless command tokens are monotonic for the lifetime of the native view;
native session/lifecycle recovery retains the replay floor, so a host must not
restart its token sequence while reusing the same view instance.

The plugin build is fail-closed. Published release packages contain the
verified iOS `ios/secure_ffi.xcframework` and Android
`android/secure_ffi/{arm64-v8a,x86_64}/libsecure_ffi.a` artifacts, so the
default build does not need absolute paths. For a source checkout or custom
native build, set `SECURE_KEYPAD_FFI_XCFRAMEWORK`/`SECURE_KEYPAD_FFI_LIB` and
`SECURE_KEYPAD_FFI_LIB_DIR` to artifacts built from the same source revision
and release profile. CocoaPods receives only the staged relative path inside
the plugin package.

Host-app compilation against the selected Flutter toolchain, example apps,
and device accessibility/security verification remain release gates.
