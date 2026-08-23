# Native platform integration

The first Secure Native renderers are under `native/ios` and
`native/android`. They share `crates/secure-ffi/include/secure_keypad.h` and
never use a text input widget for the secret. The repository pins Rust
1.97.1 and the device/simulator targets in `rust-toolchain.toml`.

## iOS

### Direct native SDK consumption

Applications that do not use React Native or Flutter can consume the native
UIKit SDK directly:

```ruby
pod 'SecureKeypadKit', :path => '../native/ios'
```

`SecureKeypadKit` contains the native renderer and native-only submission
router, but no framework bridge manager. The host must provide a matching
`secure_ffi.xcframework` (or `libsecure_ffi.a`) built from the same commit and
must install a native authentication consumer before treating submission as a
success. The Podspec rejects missing artifacts and rejects explicit artifact
paths whose content does not match the staged package artifact.

`native/ios/SecureKeypadView.swift` is a UIKit view that accepts public layout
and theme values, sends key IDs to the Rust C ABI, and renders only bullets and
non-secret state. It masks presentation while the app is inactive or the
screen is captured, and releases the native session when the app resigns
active so pending input is zeroized rather than resumed after backgrounding.
The submission callback is native-only. Before creating a session it
revalidates the public configuration even when called without a framework
adapter: layouts are limited to 16 rows, 32 keys per row, 512 total keys, and
16-byte key labels and 80-byte accessibility labels; theme dimensions and font size must be finite
and within the same bounds as the versioned public contract. Required theme
color and metric maps use exact key sets and validate every color value, so
missing or malformed fields fail closed instead of receiving platform-specific
defaults.

When iOS releases the session during an inactive, captured, or detached-window
transition, the native view requests its adapter to reapply retained public
configuration after protection clears. The callback carries no input state.
React Native and Flutter adapters retain only the validated public
configuration and deliberately do not replay a stored Headless Host command
during lifecycle recovery; a fresh monotonic host command is required.

`native/ios/react-native/SecureKeypadViewManager.swift` and its Objective-C
export file register the same view with React Native. The manager decodes only
versioned public layout/theme dictionaries and exports masked state/result
events. It never exports the opaque submission handle. Add both files to the
host iOS target and link React Native plus the matching `secure-ffi` artifact.

`native/ios/flutter/SecureKeypadFlutterPlugin.swift` registers a
`secure_keypad/native` PlatformView and a per-view event channel. Creation
arguments are public configuration only; the event channel carries masked state
and result codes only. Each Flutter native event bridge uses a bounded 32-entry
backlog while the Dart listener is unavailable, coalesces adjacent state events,
and preferentially evicts state metadata so a terminal result is not overwritten.
Add the file to the host Flutter iOS target and register
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
XCFramework. For a source checkout or custom artifact, stage a copy beside its
Podspec and pass the source path as `SECURE_KEYPAD_FFI_XCFRAMEWORK`:

```sh
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsecure_ffi.a \
  -headers crates/secure-ffi/include \
  -library target/aarch64-apple-ios-sim/release/libsecure_ffi.a \
  -headers crates/secure-ffi/include \
  -output /tmp/secure_ffi.xcframework
cp -R /tmp/secure_ffi.xcframework packages/react-native/secure_ffi.xcframework
cp -R /tmp/secure_ffi.xcframework packages/flutter/ios/secure_ffi.xcframework
```

The React Native podspec consumes `secure_ffi.xcframework` from its package
root; the Flutter podspec consumes `ios/secure_ffi.xcframework` from the
plugin package. Published packages select these bundled paths without an
environment variable; an explicit source path remains available for custom
builds only when its SHA-256 content matches the staged package artifact. CI
performs the same staging and parses both Podspecs against the result. Absolute
paths are used only as validated source inputs, never as CocoaPods vendored
paths.

## Android

### Direct native SDK consumption

Applications that do not use React Native or Flutter can include the Android
native library module directly and publish it as an AAR:

```gradle
include ':secure-keypad-native'
project(':secure-keypad-native').projectDir = file('../native/android')
```

The module has no React Native or Flutter dependency. It accepts
`secureKeypadAndroidArchitectures` (default `arm64-v8a,x86_64`) and requires a
matching `secure_ffi/<ABI>/libsecure_ffi.a` for every selected ABI. CMake fails
closed when a slice is missing; it never substitutes a stub or a different
architecture. The host must also install the native submission consumer and
keep the native SDK, JNI adapter, and Rust FFI artifacts on one release
commit.

`native/android/src/main/kotlin/.../SecureKeypadView.kt` is a custom
`FrameLayout` with public key/layout/theme models. It resolves the host
`Activity` through framework `ContextWrapper` chains before applying
`FLAG_SECURE`, so React Native and Flutter wrapper contexts do not silently
lose screenshot protection. Construction and attachment fail closed when no
`Activity` window can be resolved, and attachment plus every focus regain
reassert `FLAG_SECURE` if a host changed the window flags. It releases the
native session when the window loses focus or becomes invisible, which
zeroizes pending input instead of keeping it through an app/window transition.
The JNI adapter in
`native/android/src/main/cpp/secure_keypad_jni.c` owns only pointer handles and
calls the C ABI. The Activity window receives `FLAG_SECURE`, autofill is
excluded, and no `EditText` is created. Before allocating native rows/buttons,
the view repeats the public bounds: 16 rows, 32 keys per row, 512 total keys,
16-byte key labels, 80-byte accessibility labels, and finite and bounded theme dimensions.
Required theme color and metric maps use exact key sets and validate every
color value before native UI allocation.

The packed JNI masked-state return reserves `Long.MIN_VALUE` for a native
refresh failure; Android decodes that sentinel before interpreting the valid
empty state, so an FFI error cannot silently become a normal empty display.
Releasing a session clears the retained masked presentation text as well as the
Rust-owned input buffer. JNI also rejects public key-ID arrays over 64 bytes
before obtaining their JVM backing pointer, matching the Rust FFI bound.

`native/android/.../reactnative/SecureKeypadViewManager.kt` registers the
`SecureKeypadView` React Native component. Its `ReadableMap` conversion is
bounded to public configuration fields, runs inside a fail-closed exception
boundary, and releases the native session before reporting malformed input.
Its events contain only masked length/state or non-secret result codes.
`native/android/.../flutter/
SecureKeypadFlutterPlugin.kt` registers the `secure_keypad/native`
PlatformView and per-view EventChannel with the same restriction. Add the
appropriate source set to the host Gradle module and link the matching JNI and
Rust artifacts for every shipped ABI. The Android submission router uses an
exception-safe ownership reporter: if a native consumer throws before taking
the opaque handle, the handle is released exactly once; if ownership was
transferred, the failure is rethrown without a second release.

Local checks with the Android SDK installed:

```sh
ANDROID_JAR="$HOME/Library/Android/sdk/platforms/android-37.0/android.jar"
KOTLINC="/Applications/Android Studio.app/Contents/plugins/Kotlin/kotlinc/bin/kotlinc"
"$KOTLINC" native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt \
  native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadPresentation.kt \
  native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadBridgeConfig.kt \
  native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt \
  -classpath "$ANDROID_JAR" -jvm-target 17 -Werror -d /tmp/secure-keypad-android.jar
```

`SecureKeypadPresentation.kt` centralizes the bounded masked display and
accessibility announcements. It accepts only the native masked length and a
protected-state flag; it cannot format or retain an input value. Native display
state codes outside `empty`/`masked`/`submitted`/`cancelled` release the session
and emit an internal error instead of being mapped to `empty`. The standalone
`native/android/SecureKeypadPresentationContractTest.kt` checks empty/masked/
protected announcements and rejects lengths outside the native 4,096-token
display bound without requiring an Android runtime. Both native contract tests
also compare a deterministic security-facing presentation snapshot containing
only display state, masked text, accessibility text, and the protection bit;
invalid display codes produce no snapshot. The equivalent iOS helper and
`SecureKeypadPresentationContractTest.swift` apply the same bound before
allocating masked text. These snapshots are source/runtime contract evidence,
not a substitute for physical-device VoiceOver/TalkBack or screenshot review.

The ownership contract is also executable without Android:

```sh
KOTLINC="/Applications/Android Studio.app/Contents/plugins/Kotlin/kotlinc/bin/kotlinc"
"$KOTLINC" \
  native/android/src/main/kotlin/com/uulab/securekeypad/SubmissionOwnership.kt \
  native/android/SubmissionOwnershipContractTest.kt \
  -include-runtime -d /tmp/secure-keypad-submission-contract.jar
java -jar /tmp/secure-keypad-submission-contract.jar
```

The native renderer applies the public layout direction to the key matrix and
honors `slots.display` by showing or collapsing the native masked display.
`slots.header`, `slots.footer`, and `slots.error` are host-composition signals:
they reserve surrounding content for the framework/native host and never carry
input. A key's optional `testId` becomes a native UI test identifier (or view
tag); it is public metadata only and is not used as an input value. Bounded
press/mask animation durations and haptic/sound feedback preferences are
applied by the native renderer; the mask animation operates on bullets only
and never materializes an input character.

For resistance to coordinate replay or casual shoulder surfing, set
`randomizeInputKeys: true`. The native renderer shuffles only `input`-role keys
with the platform CSPRNG when rendering; action keys retain their configured
roles and positions. No random seed, key order, or input value crosses the
RN/Flutter bridge. This mitigates observation, but does not protect against a
compromised device, accessibility service, screen camera, or malicious host.

The application must link the JNI adapter with the Rust `secure-ffi` library
for every ABI it ships. The CMake file intentionally does not invent a Rust
library path; the host build must provide the architecture-specific artifact.

CI exercises this direct path with a framework-free Kotlin host: it includes
the Android library module, stages the matching arm64-v8a and x86_64 FFI
slices, builds a Release APK, and launches it in an API 35 x86_64 emulator.
The retained screenshot and accessibility hierarchy prove packaging and
`FLAG_SECURE` wiring only; they do not replace physical-device verification.

The protected release-candidate workflow also builds the standalone
`secure-keypad-native.aar` from this module, binds it to the release commit,
and carries its checksum into the signed source bundle. Consumers may use the
AAR directly, but must still provide the matching native submission consumer
and keep the AAR, Rust FFI slices, and SDK source on one immutable commit.

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
`SecureKeypadNativeSubmissionRouter` with a consumer. The consumer receives
the originating native view and submission, and must bind its account/session
state to that exact view instance before calling `takeOpaqueHandle()` on iOS or
`takeNativeHandle()` on Android. It then passes the opaque capability to the
ABI v2 native OPAQUE registration or login handoff
(`secure_keypad_client_registration_start` or
`secure_keypad_client_login_start`). A mutable global account context is not a
valid binding. If no consumer is installed, submit is released and the
framework receives `error`; a framework `success` event is emitted only when
the consumer both accepts the callback and transfers the opaque handle. The
bridge releases an unconsumed handle and the handle/callback never cross
JavaScript, Dart, or JSON.

Adapter teardown must detach framework callbacks before releasing the native
session so a callback cannot retain a disposed view or its host event bridge.
The Android adapters use `clearBridgeCallbacks()` before `releaseSession()`;
the iOS Flutter adapter weakly captures the native keypad and closes a
submission if that view has already gone away.

React Native package paths:

- `packages/react-native/ios` contains the UIKit view manager and FFI module.
- `packages/react-native/android` contains the Kotlin view manager and JNI
  CMake target.
- `packages/react-native/SecureKeypadReactNative.podspec` prefers
  `SECURE_KEYPAD_FFI_XCFRAMEWORK` and supports `SECURE_KEYPAD_FFI_LIB` only as
  a single-platform fallback.
- Android CMake uses the package-bundled `android/secure_ffi` directory when
  present, or an explicit `SECURE_KEYPAD_FFI_LIB_DIR`, with one
  `libsecure_ffi.a` per shipped ABI. It remains fail-closed when neither input
  exists. The verified release matrix is `arm64-v8a` and `x86_64`; React Native
  and Flutter release packages contain both, while a host selecting another
  ABI must provide its matching library explicitly.
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
- The Android module uses Flutter's built-in Kotlin compiler contract
  (`kotlin.compilerOptions` with JVM 17) and requires Flutter 3.44/Dart 3.12
  or newer; AGP 9 hosts can enable `android.builtInKotlin` without a plugin-
  supplied Kotlin Gradle Plugin.

Build the Rust library for every device/simulator ABI in the host release
pipeline. Never substitute a debug, simulator-only, or architecture-mismatched
library. Expo Go and ordinary Flutter hot-reload runtimes cannot host this
security boundary without a custom native build. A host app must still compile
the package against its chosen RN/Flutter versions and run the device matrix
before release.
