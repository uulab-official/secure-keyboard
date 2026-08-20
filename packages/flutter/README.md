# secure_keypad_flutter

Flutter-facing Secure Native contract for the Secure Keypad SDK.

The package exposes versioned layout/theme/policy configuration and masked
state/result callbacks. It intentionally has no password value, secret getter,
`TextEditingController`, or raw submit callback. A platform implementation
must keep key events and Hangul composition in native/core code and implement
`SecureKeypadNativeAdapter` without sending the accumulated input through Dart.

This initial package is the public contract. Platform-view registration, native
FFI wiring, example apps, and device accessibility/security verification remain
release gates.
