# Native platform integration

The first Secure Native renderers are under `native/ios` and
`native/android`. They share `crates/secure-ffi/include/secure_keypad.h` and
never use a text input widget for the secret. The repository pins Rust
1.97.1 and the device/simulator targets in `rust-toolchain.toml`.

## iOS

`native/ios/SecureKeypadView.swift` is a UIKit view that accepts public layout
and theme values, sends key IDs to the Rust C ABI, and renders only bullets and
non-secret state. It masks presentation while the app is inactive or the
screen is captured. The submission callback is native-only.

`native/ios/react-native/SecureKeypadViewManager.swift` and its Objective-C
export file register the same view with React Native. The manager decodes only
versioned public layout/theme dictionaries and exports masked state/result
events. It never exports the opaque submission handle. Add both files to the
host iOS target and link React Native plus the matching `secure-ffi` artifact.

`native/ios/flutter/SecureKeypadFlutterPlugin.swift` registers a
`secure_keypad/native` PlatformView and a per-view event channel. Creation
arguments are public configuration only; the event channel carries masked state
and result codes only. Add the file to the host Flutter iOS target and register
the plugin with the same Rust artifact.

Local typecheck:

```sh
IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
swiftc -warnings-as-errors -typecheck \
  -sdk "$IOS_SDK" \
  -target arm64-apple-ios26.0 \
  -I native/ios/SecureKeypadFFI \
  native/ios/SecureKeypadPresentation.swift \
  native/ios/SecureKeypadBridgeConfig.swift \
  native/ios/SecureKeypadView.swift
```

The Foundation-only presentation contract can be executed without an iOS SDK:

```sh
swiftc -warnings-as-errors \
  native/ios/SecureKeypadPresentation.swift \
  native/ios/SecureKeypadPresentationContractTest.swift \
  -o /tmp/secure-keypad-presentation-contract
/tmp/secure-keypad-presentation-contract
```

An application target must link the Rust `secure-ffi` static library built for
the matching iOS device/simulator architectures and expose the same module
map. The library and Swift view must be built in the same release pipeline;
the Swift source alone is not a security boundary.

Reference Rust artifacts:

```sh
cargo build --release -p secure-ffi --target aarch64-apple-ios
cargo build --release -p secure-ffi --target aarch64-apple-ios-sim
```

For a release artifact, combine the device and simulator libraries into an
XCFramework and pass its path as `SECURE_KEYPAD_FFI_XCFRAMEWORK`; CI performs
this assembly and parses both package Podspecs against the result.

## Android

`native/android/src/main/kotlin/.../SecureKeypadView.kt` is a custom
`FrameLayout` with public key/layout/theme models. It resolves the host
`Activity` through framework `ContextWrapper` chains before applying
`FLAG_SECURE`, so React Native and Flutter wrapper contexts do not silently
lose screenshot protection. The JNI adapter in
`native/android/src/main/cpp/secure_keypad_jni.c` owns only pointer handles and
calls the C ABI. The Activity window receives `FLAG_SECURE`, autofill is
excluded, and no `EditText` is created.

`native/android/.../reactnative/SecureKeypadViewManager.kt` registers the
`SecureKeypadView` React Native component. Its `ReadableMap` conversion is
bounded to public configuration fields and its events contain only masked
length/state or non-secret result codes. `native/android/.../flutter/
SecureKeypadFlutterPlugin.kt` registers the `secure_keypad/native`
PlatformView and per-view EventChannel with the same restriction. Add the
appropriate source set to the host Gradle module and link the matching JNI and
Rust artifacts for every shipped ABI.

Local checks with the Android SDK installed:

```sh
ANDROID_JAR="$HOME/Library/Android/sdk/platforms/android-37.0/android.jar"
KOTLINC="/Applications/Android Studio.app/Contents/plugins/Kotlin/kotlinc/bin/kotlinc"
"$KOTLINC" native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt \
  native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt \
  native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt \
  -classpath "$ANDROID_JAR" -jvm-target 17 -Werror -d /tmp/secure-keypad-android.jar
```

The ownership contract is also executable without Android:

```sh
KOTLINC="/Applications/Android Studio.app/Contents/plugins/Kotlin/kotlinc/bin/kotlinc"
"$KOTLINC" \
  native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt \
  native/android/SubmissionOwnershipContractTest.kt \
  -include-runtime -d /tmp/secure-keypad-submission-contract.jar
java -jar /tmp/secure-keypad-submission-contract.jar
```

The application must link the JNI adapter with the Rust `secure-ffi` library
for every ABI it ships. The CMake file intentionally does not invent a Rust
library path; the host build must provide the architecture-specific artifact.

For an arm64 Android build, configure the NDK linker explicitly:

```sh
NDK="$HOME/Library/Android/sdk/ndk/27.1.12297006"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
cargo build --release -p secure-ffi --target aarch64-linux-android
```

## Framework adapters

React Native and Flutter publishable packages now contain the native
registration source, JNI adapter, FFI header/module map, and fail-closed build
manifests. `scripts/check-native-package-parity.mjs` verifies that central
native sources and package copies are byte-for-byte identical.

Before rendering an authentication keypad, the host-native layer must install
`SecureKeypadNativeSubmissionRouter` with a consumer. The consumer calls
`takeOpaqueHandle()` on iOS or `takeNativeHandle()` on Android and passes that
opaque capability to native OPAQUE/credential code. If no consumer is
installed, submit is released and the framework receives `error`; a framework
`success` event therefore means only that native ownership was accepted. The
handle and the consumer callback never cross JavaScript, Dart, or JSON.

React Native package paths:

- `packages/react-native/ios` contains the UIKit view manager and FFI module.
- `packages/react-native/android` contains the Kotlin view manager and JNI
  CMake target.
- `packages/react-native/SecureKeypadReactNative.podspec` prefers
  `SECURE_KEYPAD_FFI_XCFRAMEWORK` and supports `SECURE_KEYPAD_FFI_LIB` only as
  a single-platform fallback.
- Android CMake requires `SECURE_KEYPAD_FFI_LIB_DIR` with one
  `libsecure_ffi.a` per shipped ABI.
- The Android module respects the host's `android.builtInKotlin` setting;
  legacy hosts must expose the Kotlin Gradle plugin, while AGP 9 built-in
  Kotlin hosts must enable that property.

Flutter package paths:

- `packages/flutter/ios/Classes` contains the PlatformView plugin and FFI
  module; the podspec uses the same XCFramework-first FFI contract.
- `packages/flutter/android` contains the PlatformView plugin and JNI CMake
  target with the same ABI directory contract.
- `SecureKeypad` creates the native PlatformView and forwards only public
  creation parameters and masked/result events.
- The Android module respects the host's `android.builtInKotlin` setting;
  legacy hosts must expose the Kotlin Gradle plugin, while AGP 9 built-in
  Kotlin hosts must enable that property.

Build the Rust library for every device/simulator ABI in the host release
pipeline. Never substitute a debug, simulator-only, or architecture-mismatched
library. Expo Go and ordinary Flutter hot-reload runtimes cannot host this
security boundary without a custom native build. A host app must still compile
the package against its chosen RN/Flutter versions and run the device matrix
before release.
