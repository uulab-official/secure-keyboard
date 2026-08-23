# Native SDK First Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the existing iOS and Android native keypad surfaces as versioned SDK modules and keep React Native and Flutter as thin, parity-checked adapters over the same Rust/FFI contract.

**Architecture:** `secure-core` and `secure-ffi` remain the only input/security implementation. A standalone iOS Podspec/Swift surface and Android Gradle/AAR surface package the canonical native renderer without framework dependencies; RN and Flutter continue to package only their bridge sources and link the same verified FFI artifacts.

**Tech Stack:** Rust 1.97.1 / C11 FFI, Swift 5.9/UIKit, Kotlin/JVM 17/Android Gradle, CMake 3.22.1/NDK, TypeScript Node test runner, pnpm, CocoaPods Podspec contracts.

**Spec:** `docs/superpowers/specs/2026-08-23-native-sdk-first-design.md`

## Global Constraints

- During active input, the minimum required token state exists in native/core memory; no implementation may claim that processing occurs without memory.
- `clear`, `backspace` removal, cancel, timeout, submit transfer, session free, and submission free must clear SDK-owned secret buffers through the Rust zeroization boundary.
- Public framework state may contain only layout/theme metadata, masked length, display state, and result/error codes.
- No wrapper may construct a password `String`, `TextEditingController`, JSON payload, log field, analytics property, clipboard value, or crash-report field from keypad input.
- `SECURE_KEYPAD_ABI_VERSION` and `secure_keypad_abi_version()` must match before session creation.
- Secure Native Mode is the default; Headless Host Mode is explicitly lower assurance.
- The native artifact matrix is iOS 15.1+ and Android API 24+ with `arm64-v8a` and `x86_64` release ABIs.
- Local tests and simulator/emulator tests do not constitute a production approval; physical-device evidence, LeakSanitizer evidence, signing, and independent review remain external release gates.

## File Structure

- Create `native/sdk-contract.json`: machine-readable native SDK, ABI, platform, and artifact contract.
- Create `native/ios/SecureKeypadKit.podspec`: standalone iOS native SDK Podspec that excludes RN/Flutter bridge managers.
- Create `native/android/build.gradle`: standalone Android native SDK library module definition.
- Create `native/android/src/main/AndroidManifest.xml`: standalone library manifest with no framework registration.
- Create `native/android/consumer-rules.pro`: native SDK shrinker rules for JNI entry points and opaque handle classes.
- Modify `native/android/CMakeLists.txt`: canonical fail-closed FFI artifact linking for every Android ABI.
- Create `scripts/check-native-sdk-contract.mjs`: validates metadata against headers, manifests, package versions, and platform rules.
- Create `scripts/check-native-sdk-contract.test.mjs`: contract tests for valid metadata and fail-closed mismatch cases.
- Create `scripts/native-sdk-package-contract.test.mjs`: verifies standalone iOS/Android package boundaries and artifact requirements.
- Modify `package.json`: expose native SDK contract checks.
- Modify `docs/NATIVE-PLATFORMS.md`: document direct native SDK consumption and wrapper layering.
- Modify `docs/COMPATIBILITY.md`: bind native SDK package versions to ABI and platform matrices.
- Modify `docs/ROADMAP.md`: record the native SDK packaging milestone and remaining external gates.

---

### Task 1: Define the machine-readable native SDK contract

**Files:**
- Create: `native/sdk-contract.json`
- Create: `scripts/check-native-sdk-contract.mjs`
- Create: `scripts/check-native-sdk-contract.test.mjs`
- Modify: `package.json`

**Interfaces:**
- `native/sdk-contract.json` exports `schemaVersion`, `nativeSdkVersion`, `abiVersion`, `ios.minimum`, `android.minimumApi`, `android.releaseAbis`, and `artifactNames`.
- `checkNativeSdkContract(root)` returns `0` for a valid checkout and `1` after writing one concise failure per violated contract.

- [ ] **Step 1: Write failing metadata and mismatch tests**

Add tests that copy the repository into a temporary directory, mutate one contract input, and assert a non-zero result:

```js
test("native contract accepts the checked-in ABI and package matrix", () => {
  assert.equal(checkNativeSdkContract(), 0);
});

test("native contract rejects an ABI mismatch before packaging", () => {
  const root = copyFixture();
  const header = path.join(root, "crates/secure-ffi/include/secure_keypad.h");
  writeFileSync(header, readFileSync(header, "utf8").replace("UINT32_C(2)", "UINT32_C(3)"));
  assert.equal(checkNativeSdkContract(root), 1);
});

test("native contract rejects a package version drift", () => {
  const root = copyFixture();
  const packageJson = path.join(root, "packages/react-native/package.json");
  writeFileSync(packageJson, readFileSync(packageJson, "utf8").replace('"version": "0.1.0"', '"version": "0.2.0"'));
  assert.equal(checkNativeSdkContract(root), 1);
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `node --test scripts/check-native-sdk-contract.test.mjs`

Expected: FAIL because the metadata file and checker do not exist.

- [ ] **Step 3: Add the contract metadata and checker**

Use this checked-in metadata:

```json
{
  "schemaVersion": 1,
  "nativeSdkVersion": "0.1.0",
  "abiVersion": 2,
  "ios": { "minimum": "15.1", "artifact": "secure_ffi.xcframework" },
  "android": {
    "minimumApi": 24,
    "releaseAbis": ["arm64-v8a", "x86_64"],
    "artifact": "secure_ffi"
  }
}
```

The checker must parse the C header ABI constant, both framework package
versions, both Podspec versions, both Android Gradle versions, the Flutter
pubspec version, the documented platform minima, and the declared Android ABI
filters. It must compare every value to `native/sdk-contract.json` and reject
unsupported or missing values before any package build.

- [ ] **Step 4: Register and run the checker**

Add these scripts to `package.json`:

```json
"check:native-sdk-contract": "node scripts/check-native-sdk-contract.mjs",
"test:native-sdk-contract": "node --test scripts/check-native-sdk-contract.test.mjs"
```

Run: `pnpm test:native-sdk-contract && pnpm check:native-sdk-contract`

Expected: PASS with exit code `0` for the checked-in repository.

- [ ] **Step 5: Commit the contract**

```sh
git add native/sdk-contract.json scripts/check-native-sdk-contract.mjs scripts/check-native-sdk-contract.test.mjs package.json
git commit -m "build: add native sdk contract parity gate"
```

### Task 2: Add the standalone iOS native SDK package surface

**Files:**
- Create: `native/ios/SecureKeypadKit.podspec`
- Create: `scripts/native-sdk-package-contract.test.mjs`
- Modify: `docs/NATIVE-PLATFORMS.md`

**Interfaces:**
- `SecureKeypadKit.podspec` packages `SecureKeypadView.swift`, `SecureKeypadPresentation.swift`, and `SecureKeypadBridgeConfig.swift` plus the staged FFI artifact.
- The Podspec must not include `native/ios/react-native/*`, `native/ios/flutter/*`, React dependency declarations, or Flutter dependency declarations.
- The existing RN and Flutter Podspecs remain unchanged in behavior and continue to consume their own verified package copies.

- [ ] **Step 1: Write the package boundary tests**

Assert the Podspec has iOS 15.1, Swift 5.9, relative source files, the staged XCFramework/library hash check, and no framework bridge source or dependency:

```js
const podspec = readFileSync(path.join(root, "native/ios/SecureKeypadKit.podspec"), "utf8");
assert.match(podspec, /spec\.platforms\s*=\s*\{\s*:ios\s*=>\s*['"]15\.1['"]\s*\}/);
assert.match(podspec, /spec\.source_files\s*=\s*['"]SecureKeypad\*\.swift/);
assert.match(podspec, /spec\.vendored_frameworks\s*=\s*['"]secure_ffi\.xcframework['"]/);
assert.doesNotMatch(podspec, /React-Core|Flutter|react-native|SecureKeypadViewManager/);
```

- [ ] **Step 2: Run the package contract test and verify it fails**

Run: `node --test scripts/native-sdk-package-contract.test.mjs`

Expected: FAIL because the standalone Podspec does not exist.

- [ ] **Step 3: Implement the standalone Podspec**

Mirror the existing staged-artifact verification used by the framework
Podspecs. The Podspec must resolve `secure_ffi.xcframework` or `libsecure_ffi.a`
from its own package root, accept an explicit custom path only when its
contents match the staged artifact, and raise before installation on a missing
or mismatched artifact. Keep all bridge managers outside `spec.source_files`.

- [ ] **Step 4: Document direct iOS consumption**

Add a direct-consumption section to `docs/NATIVE-PLATFORMS.md` showing:

```ruby
pod 'SecureKeypadKit', :path => '../native/ios'
```

and the required native-only submission consumer rule. State that the Swift
native SDK and matching XCFramework must be built from the same commit.

- [ ] **Step 5: Run and commit the iOS package contract**

Run: `node --test scripts/native-sdk-package-contract.test.mjs scripts/check-native-sdk-contract.test.mjs`

Expected: PASS.

```sh
git add native/ios/SecureKeypadKit.podspec scripts/native-sdk-package-contract.test.mjs docs/NATIVE-PLATFORMS.md
git commit -m "feat: add standalone iOS native sdk package"
```

### Task 3: Add the standalone Android native SDK library surface

**Files:**
- Create: `native/android/build.gradle`
- Create: `native/android/src/main/AndroidManifest.xml`
- Create: `native/android/consumer-rules.pro`
- Modify: `native/android/CMakeLists.txt`
- Modify: `scripts/native-sdk-package-contract.test.mjs`
- Modify: `docs/NATIVE-PLATFORMS.md`

**Interfaces:**
- The module publishes an Android library/AAR with namespace `com.uulab.securekeypad`.
- The module includes only canonical native Kotlin, JNI, and presentation sources; it has no React Native or Flutter dependency.
- CMake receives `SECURE_KEYPAD_FFI_LIB_DIR` or the package-bundled `secure_ffi/<ABI>/libsecure_ffi.a` and fails closed when a declared ABI artifact is absent.

- [ ] **Step 1: Extend failing package tests**

Add assertions for the Android module:

```js
const gradle = readFileSync(path.join(root, "native/android/build.gradle"), "utf8");
assert.match(gradle, /com\.android\.library/);
assert.match(gradle, /namespace ['"]com\.uulab\.securekeypad['"]/);
assert.match(gradle, /minSdk[^\n]*24/);
assert.match(gradle, /arm64-v8a,x86_64/);
assert.doesNotMatch(gradle, /react-native|com\.facebook\.react|Flutter/);

const manifest = readFileSync(path.join(root, "native/android/src/main/AndroidManifest.xml"), "utf8");
assert.doesNotMatch(manifest, /activity|service|receiver/);
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `node --test scripts/native-sdk-package-contract.test.mjs`

Expected: FAIL because the standalone Gradle module and manifest do not exist.

- [ ] **Step 3: Implement the Android library module**

Use the same compile/target SDK defaults, Java/Kotlin 17 target, CMake 3.22.1,
API 24 minimum, and `arm64-v8a,x86_64` filters as the existing framework
packages. Register only the native view/Kotlin/JNI source set and use
`consumer-rules.pro` for the JNI and opaque-handle keep rules. Do not add
React Native or Flutter dependencies.

Replace the canonical CMake input path with the package-independent native
contract: include `../../crates/secure-ffi/include`, resolve
`SECURE_KEYPAD_FFI_LIB_DIR` from a Gradle property or environment variable,
default to `native/android/secure_ffi`, reject a missing
`${ANDROID_ABI}/libsecure_ffi.a` using `message(FATAL_ERROR ...)`, and link
the imported static library to `secure_keypad_jni` with `log` and `android`.
The JNI adapter must never build without the matching Rust FFI slice.

- [ ] **Step 4: Document direct Android consumption**

Add a Gradle dependency example to `docs/NATIVE-PLATFORMS.md` and state that
the host must install a native submission consumer and link the matching
`secure-ffi` ABI slices. Explain that missing FFI slices are build failures.

- [ ] **Step 5: Run and commit the Android package contract**

Run: `node --test scripts/native-sdk-package-contract.test.mjs scripts/check-native-sdk-contract.test.mjs`

Expected: PASS.

```sh
git add native/android/build.gradle native/android/src/main/AndroidManifest.xml native/android/consumer-rules.pro native/android/CMakeLists.txt scripts/native-sdk-package-contract.test.mjs docs/NATIVE-PLATFORMS.md
git commit -m "feat: add standalone Android native sdk module"
```

### Task 4: Bind compatibility and release documentation to the native contract

**Files:**
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/ROADMAP.md`
- Modify: `docs/PRODUCTION-READINESS.md`
- Modify: `README.md`

**Interfaces:**
- Documentation names `native/sdk-contract.json` as the source of truth for native SDK version, ABI, minimum OS/API, and Android ABI matrix.
- Release documentation requires standalone native artifacts and framework package mirrors to be checked together.

- [ ] **Step 1: Add documentation assertions**

Extend `scripts/native-sdk-package-contract.test.mjs` to assert that the
README, compatibility document, and production handoff link the native SDK
contract and explicitly distinguish source/local checks from physical-device
release evidence.

- [ ] **Step 2: Update the documents**

Add the native SDK row to `docs/COMPATIBILITY.md`, mark the native package
milestone complete in `docs/ROADMAP.md`, and add the direct native SDK artifact
to the release handoff in `docs/PRODUCTION-READINESS.md`. Keep the existing
statement that the checkout is not production-approved without external
evidence. Link the native-first usage path from `README.md`.

- [ ] **Step 3: Run documentation and contract checks**

Run: `pnpm test:native-sdk-contract && pnpm test:native-parity && pnpm test:release-version-parity`

Expected: PASS.

- [ ] **Step 4: Commit compatibility documentation**

```sh
git add docs/COMPATIBILITY.md docs/ROADMAP.md docs/PRODUCTION-READINESS.md README.md scripts/native-sdk-package-contract.test.mjs
git commit -m "docs: bind native sdk to compatibility and release gates"
```

### Task 5: Execute the production-candidate verification

**Files:**
- Modify: none unless a failing check identifies an implementation defect.
- Evidence: command output and existing release-gate artifacts only; do not fabricate external evidence.

- [ ] **Step 1: Run focused native checks**

Run:

```sh
pnpm test:native-sdk-contract
    node --test scripts/native-sdk-package-contract.test.mjs
pnpm test:native-parity
cargo test --workspace
```

Expected: all commands pass.

- [ ] **Step 2: Run the full deterministic candidate gate**

Run: `mise exec -- pnpm verify:production-candidate`

Expected: the deterministic source/package/native checks pass. If the command
reports missing external evidence, preserve that result as a release blocker;
do not convert it into a production-ready claim.

- [ ] **Step 3: Review the final diff and status**

Run: `git diff HEAD~4 --check` and `git status --short --branch`.

Expected: no whitespace errors, no generated host state, no native secret
artifacts, and a clean working tree after the final commit.

- [ ] **Step 4: Report the implementation and remaining release gates**

Report the exact commit, focused checks, full candidate-gate result, and the
remaining physical-device, LeakSanitizer, signing, and independent-review
requirements.
