# MASVS/MASTG evidence map

This is an evidence index for an independent mobile security assessment. It
is not an OWASP certification or a claim that every control is satisfied.
OWASP MASVS groups the mobile surface into storage, cryptography,
authentication, network, platform, code, resilience, and privacy controls;
MASTG provides the associated test guidance. See the [MASVS overview](https://mas.owasp.org/MASVS/03-Using_the_MASVS/)
and the [OWASP MAS checklist](https://mas.owasp.org/checklists/).

Status values:

- `evidence`: repository evidence exists for the scoped SDK behavior;
- `partial`: a code/test contract exists but device, deployment, or assessor
  evidence is still required;
- `pending`: no evidence sufficient for an assessor sign-off yet.

| Control | Scoped SDK evidence | Status | Assessor action remaining |
|---|---|---|---|
| MASVS-STORAGE-1 | `ServerSetupBytes`, `CredentialFile`, and serialized login state are bounded and zeroizing; protected persistence is an explicit host contract. | partial | Inspect real secret-store/HSM and mobile storage configuration. |
| MASVS-STORAGE-2 | No secret getter, framework secret callback, payload logging, or credential-file HTTP response; FFI/core tests cover ownership and clearing. | partial | Inspect logs, crash reports, backups, screenshots, and release binaries. |
| MASVS-CRYPTO-1 | OPAQUE suite is pinned, CSPRNG-backed handles are used, and parser fuzzing is in CI. | partial | Review algorithm choices, compiler flags, and native binary symbols. |
| MASVS-CRYPTO-2 | Active/previous key rotation, setup persistence, state versioning, and key-ID downgrade tests exist. | partial | Verify HSM/secret-store lifecycle, rotation runbook, and incident recovery. |
| MASVS-AUTH-1 | Native OPAQUE handoff, generic errors, missing-account dummy path, one-time state, rate-limit contract, passkey-first Web adapter, pinned WebAuthn reference service/HTTP contract, required host-validated `csrf_validated` request field, compile-tested Axum integration, and injectable WebAuthn storage contracts exist with host-principal binding. | partial | Verify the deployed backend implementation, account policy, actual CSRF/session validator, durable credential/ceremony records, and distributed replay controls. |
| MASVS-NETWORK-1 | `secure-auth-http` and the WebAuthn route require an explicit TLS/proxy-limit deployment context; the host still owns certificates, proxy source allowlisting, and TLS versions. | partial | Test endpoint identity, TLS versions, proxy limits, and cleartext rejection in each host app. |
| MASVS-NETWORK-2 | Key IDs and downgrade windows are explicit in the protocol contract. | pending | Decide and test certificate/public-key pinning policy where applicable. |
| MASVS-PLATFORM-1 | C ABI uses opaque handles; Android ownership and FFI null/ownership tests are executable; CI compiles and launches the RN/Flutter host apps in iOS Simulator and Android API 35 x86_64 emulator smoke jobs. | partial | Inspect native bridges and run the required physical-device host matrix. |
| MASVS-PLATFORM-3 | iOS background/capture masking, Android `FLAG_SECURE`, autofill exclusion, and accessibility contracts exist; CI retains supplemental no-input simulator/emulator screenshots. | partial | Run screenshot, task-switcher, screen-recording, autofill, and accessibility tests on physical devices. |
| MASVS-CODE-1 | Rust toolchain, protocol suite, package versions, lockfiles, audit, fuzz, SBOM, native checksums, and machine-readable release evidence gates are pinned. | partial | Define supported OS/API matrix and enforce minimum patched platform versions in the release policy. |
| MASVS-RESILIENCE-1 | The SDK documents compromised/rooted runtime limitations and makes no impossible-theft claim. | pending | Product must choose and test root/jailbreak/tamper response policy. |
| MASVS-PRIVACY-1 | Public state events expose only masked length/display state/result codes; web fallback warning is explicit. | partial | Inspect telemetry, analytics, diagnostics, and data-retention configuration. |

## Required assessor package

The independent reviewer should receive the exact commit SHA, SBOM, lockfiles,
toolchain versions, threat model, native build artifacts, CI logs, device test
captures, and this document with every `partial`/`pending` row resolved or
accepted as a documented residual risk. Findings must include severity,
affected scope, reproduction steps, remediation owner, and retest evidence.

No release may change a `partial` or `pending` row to `evidence` based only on
source inspection; the appropriate runtime or deployment test must be attached.
