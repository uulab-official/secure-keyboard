# Secure Keypad Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first testable foundation of an open-source cross-platform secure keypad SDK with a strict native security boundary and a versioned, externally customizable UI contract.

**Architecture:** A Rust core owns the input state machine, Hangul composition, policy validation, and zeroization boundary. Native iOS/Android renderers own touch handling and rendering in Secure Native Mode; React Native and Flutter adapters pass only serializable customization data and masked state. Web and server authentication are separate follow-up subprojects.

**Tech Stack:** Rust workspace, C-compatible core boundary, Swift, Kotlin/NDK, TypeScript for RN contracts, Dart for Flutter contracts, pnpm for JavaScript packages, Cargo test, platform snapshot tests.

**Spec:** `docs/SECURITY-SPEC.md`

## Global Constraints

- Do not expose accumulated secret input through any public API, callback, event, log, exception, serialized prop, or test output.
- Secure Native Mode is the default mobile mode; Headless Host Mode is opt-in and lower assurance.
- UI/UX customization may change presentation and policy but not the memory or authentication boundary.
- Do not implement password authentication by sending `SHA-256(password)` or another replayable client-side hash.
- Do not claim absolute protection against a rooted, jailbroken, injected, or compromised runtime.
- Use versioned schemas and deterministic test vectors for numeric and Hangul behavior.
- Distribute the initial code under the MIT license with the full license text in `LICENSE-MIT`.

## File Structure

- Create `Cargo.toml`: Rust workspace manifest.
- Create `crates/secure-core/src/lib.rs`: opaque session/controller API.
- Create `crates/secure-core/src/input.rs`: numeric and policy-driven input state machine.
- Create `crates/secure-core/src/hangul.rs`: Hangul composition and normalization policy.
- Create `crates/secure-core/src/secret_buffer.rs`: native byte buffer and clearing operations.
- Create `crates/secure-core/tests/core_contract.rs`: public API and leakage contract tests.
- Create `schema/layout.schema.json`: versioned public layout schema.
- Create `schema/theme.schema.json`: versioned public theme token schema.
- Create `packages/contracts/src/index.ts`: RN/Flutter-neutral serializable types.
- Create `packages/contracts/test/schema-contract.test.ts`: schema and event contract tests.
- Create `packages/contracts/test/bootstrap.test.ts`: initial package smoke test.
- Create `README.md`: public project overview and security limitations.
- Modify `docs/SECURITY-SPEC.md`: record decisions discovered during implementation.
- Modify `docs/ROADMAP.md`: mark completed milestones and record release notes.

This plan intentionally stops after the shared foundation. Native renderers, RN/Flutter adapters, web, and server SDK each need their own implementation plan because they have independent build systems and security review surfaces.

### Task 1: Bootstrap the repository and security checks

**Files:**
- Create: `Cargo.toml`
- Create: `crates/secure-core/Cargo.toml`
- Create: `packages/contracts/package.json`
- Create: `pnpm-workspace.yaml`
- Create: `.gitignore`
- Create: `SECURITY.md`
- Create: `README.md`
- Create: `LICENSE-MIT`
- Create: `crates/secure-core/src/lib.rs`
- Create: `packages/contracts/src/index.ts`
- Create: `packages/contracts/test/bootstrap.test.ts`

**Interfaces:**
- Produces a buildable Cargo workspace and a TypeScript contracts package.

- [ ] **Step 1: Write the failing repository checks**

```sh
test -f Cargo.toml
test -f packages/contracts/package.json
cargo test --workspace
pnpm --dir packages/contracts test
```

- [ ] **Step 2: Run checks to verify the repository is not bootstrapped**

Run: `cargo test --workspace`
Expected: FAIL because the workspace and crate do not exist.

- [ ] **Step 3: Add the minimal workspace, package manifests, and buildable stubs**

Use a Cargo workspace with `crates/secure-core` and a pnpm workspace with `packages/contracts`. Add a no-op `crates/secure-core/src/lib.rs`, a `packages/contracts/src/index.ts` that exports an empty version constant, and a passing `packages/contracts/test/bootstrap.test.ts`. Pin toolchain floors in the manifests and do not add runtime dependencies until a test requires them.

- [ ] **Step 4: Add security policy, public README, and permissive open-source licensing**

`README.md` must link to `docs/SECURITY-SPEC.md` and state that Secure Native Mode is the default mobile path. `SECURITY.md` must define private vulnerability reporting, supported release branches, and the prohibition on submitting real credentials in issues. Use the MIT license for the initial open-source distribution.

- [ ] **Step 5: Run checks to verify the bootstrap**

Run: `cargo test --workspace && pnpm --dir packages/contracts test`
Expected: PASS with zero tests and no warnings treated as errors.

- [ ] **Step 6: Commit the bootstrap**

```sh
git add Cargo.toml crates packages pnpm-workspace.yaml .gitignore SECURITY.md LICENSE-MIT
git commit -m "chore: bootstrap secure keypad workspace"
```

### Task 2: Define the opaque core session contract

**Files:**
- Create: `crates/secure-core/src/lib.rs`
- Create: `crates/secure-core/src/input.rs`
- Create: `crates/secure-core/src/secret_buffer.rs`
- Create: `crates/secure-core/tests/core_contract.rs`

**Interfaces:**
- Produces `SecureSession::begin`, `press_key`, `backspace`, `clear`, `submit`, `cancel`, and `masked_state`.
- `press_key` consumes a `KeyId`, never a character string.
- `masked_state` returns `{ length, display_state }`, never input bytes.

- [ ] **Step 1: Write tests proving the public API cannot return the secret and the buffer can be cleared**

```rust
#[test]
fn key_events_accept_ids_and_state_is_masked() {
    let mut session = SecureSession::begin(InputPolicy::numeric(8));
    session.press_key(KeyId::new("digit-1")).unwrap();
    session.press_key(KeyId::new("digit-2")).unwrap();
    assert_eq!(session.masked_state().length, 2);
    assert_eq!(session.masked_state().display_state, DisplayState::Masked);
}

#[test]
fn secret_buffer_is_empty_after_clear() {
    let mut buffer = SecretBuffer::from_bytes(&[0x31, 0x32]);
    buffer.clear();
    assert!(buffer.is_empty());
}

#[test]
fn no_secret_getter_exists_in_the_public_contract() {
    let public_api = include_str!("../src/lib.rs");
    assert!(!public_api.contains("get_password"));
    assert!(!public_api.contains("password: String"));
}
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `cargo test -p secure-core --test core_contract`
Expected: FAIL because `SecureSession`, `KeyId`, and the masked state do not exist.

- [ ] **Step 3: Implement the minimal opaque session API and clearable secret buffer**

Store only key IDs and policy state in the public-facing type. Keep actual symbol resolution private to the input policy implementation. Use a dedicated byte buffer with the `zeroize` crate for explicit clearing after cancel, submit, timeout, and error. Return typed errors for invalid key IDs, locked sessions, overlong input, and repeated submit. Do not implement a `Deref<Target = str>` or any string conversion for the buffer.

- [ ] **Step 4: Run the focused tests and verify success**

Run: `cargo test -p secure-core --test core_contract`
Expected: PASS.

- [ ] **Step 5: Commit the core contract**

```sh
git add crates/secure-core
git commit -m "feat: add opaque secure session contract"
```

### Task 3: Add deterministic numeric and Hangul policies

**Files:**
- Create: `crates/secure-core/src/hangul.rs`
- Modify: `crates/secure-core/src/input.rs`
- Modify: `crates/secure-core/tests/core_contract.rs`
- Create: `crates/secure-core/tests/hangul_vectors.rs`

**Interfaces:**
- Produces `InputPolicy::numeric`, `InputPolicy::hangul`, and deterministic test-vector execution.
- Hangul composition remains inside Rust and returns no intermediate secret string to the caller.

- [ ] **Step 1: Write numeric and Hangul vector tests**

```rust
#[test]
fn numeric_policy_accepts_only_declared_key_ids() {
    let policy = InputPolicy::numeric(6);
    assert!(policy.resolve(KeyId::new("digit-1")).is_ok());
    assert!(policy.resolve(KeyId::new("jamo-giyeok")).is_err());
}

#[test]
fn hangul_policy_composes_the_declared_vector() {
    let mut session = SecureSession::begin(InputPolicy::hangul(32));
    for key in ["jamo-giyeok", "vowel-a"] {
        session.press_key(KeyId::new(key)).unwrap();
    }
    assert_eq!(session.masked_state().length, 1);
}
```

- [ ] **Step 2: Run vector tests to verify failure**

Run: `cargo test -p secure-core --test hangul_vectors`
Expected: FAIL because the policies and composition engine are missing.

- [ ] **Step 3: Implement the minimum deterministic policies**

Define an explicit key-ID table, maximum length, delete behavior, and normalization mode. Reject undeclared IDs. Lock the Unicode/normalization version in the policy metadata. Do not use implicit NFKC.

- [ ] **Step 4: Run vector tests to verify success**

Run: `cargo test -p secure-core --test hangul_vectors`
Expected: PASS for numeric rejection, Hangul composition, delete, maximum length, and cancellation.

- [ ] **Step 5: Commit input policies**

```sh
git add crates/secure-core
git commit -m "feat: add deterministic numeric and Hangul input policies"
```

### Task 4: Define the public layout and theme schemas

**Files:**
- Create: `schema/layout.schema.json`
- Create: `schema/theme.schema.json`
- Create: `packages/contracts/src/index.ts`
- Create: `packages/contracts/test/schema-contract.test.ts`

**Interfaces:**
- Produces `KeypadLayout`, `KeySpec`, `ThemeTokens`, `MaskedState`, and `SecureKeypadEvent`.
- Layout and theme data are serializable and contain no accumulated secret.

- [ ] **Step 1: Write schema tests for customization and secret exclusion**

```ts
import { describe, expect, it } from "vitest";
import { validateLayout, validateTheme } from "../src";

const exampleLayout = {
  schemaVersion: 1,
  rows: [[{ id: "digit-1", label: "1", role: "input" }]],
};

const exampleTheme = {
  schemaVersion: 1,
  colors: { keyBackground: "#111111", keyForeground: "#ffffff" },
};

describe("public customization contract", () => {
  it("accepts branded layout and theme data", () => {
    expect(validateLayout(exampleLayout).valid).toBe(true);
    expect(validateTheme(exampleTheme).valid).toBe(true);
  });

  it("rejects secret-bearing fields", () => {
    expect(validateLayout({ ...exampleLayout, password: "secret" }).valid).toBe(false);
    expect(validateLayout({ ...exampleLayout, value: "secret" }).valid).toBe(false);
  });
});
```

- [ ] **Step 2: Run schema tests to verify failure**

Run: `pnpm --dir packages/contracts test`
Expected: FAIL because schemas and validators do not exist.

- [ ] **Step 3: Implement versioned layout/theme schemas**

Include rows, key IDs, display labels, semantic roles, icons, state tokens, slots, animation policy, haptic policy, locale, direction, and accessibility labels. Exclude `password`, `secret`, `value`, and accumulated input fields.

- [ ] **Step 4: Run schema tests to verify success**

Run: `pnpm --dir packages/contracts test`
Expected: PASS.

- [ ] **Step 5: Commit public schemas**

```sh
git add schema packages/contracts
git commit -m "feat: define customizable layout and theme contracts"
```

### Task 5: Review the foundation before platform work

**Files:**
- Modify: `docs/SECURITY-SPEC.md`
- Modify: `docs/ROADMAP.md`
- Create: `README.md`

**Interfaces:**
- Consumes the core and schema contracts from Tasks 1–4.
- Produces a reviewable foundation with explicit limitations and a decision record for native versus headless rendering.

- [ ] **Step 1: Write the documentation acceptance checklist**

```text
[ ] Secure Native Mode is documented as the mobile default
[ ] Headless Host Mode is documented as lower assurance
[ ] No API returns accumulated secret input
[ ] Numeric and Hangul policy versions are documented
[ ] License and vulnerability reporting instructions exist
[ ] Web limitations and WebAuthn recommendation exist
```

- [ ] **Step 2: Run repository checks**

Run: `cargo test --workspace && pnpm --dir packages/contracts test`
Expected: PASS.

- [ ] **Step 3: Update documentation with actual package names and test commands**

Replace generic wording with the concrete package/API names created in Tasks 1–4. Keep the limitation statement prominent in the README.

- [ ] **Step 4: Commit the foundation review**

```sh
git add README.md docs
git commit -m "docs: publish secure keypad foundation and roadmap"
```

## Handoff

After this foundation plan is reviewed, create separate implementation plans for:

1. iOS/Android Secure Native renderer;
2. React Native adapter;
3. Flutter adapter;
4. OPAQUE server SDK;
5. WebAuthn and web fallback;
6. MASVS/MASTG verification and release.

Each sub-plan must preserve `docs/SECURITY-SPEC.md`, use the same key-ID/layout contracts, and add platform-specific tests before claiming support.
