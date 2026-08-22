# Secure Keypad threat model

Document version: 1

This document defines the security claims that the Secure Keypad SDK may make
and the evidence required before a production release. It is a candidate
threat model, not a certification or a guarantee that a compromised device
cannot observe a secret.

## Assets

The primary asset is the user-entered authentication secret: numeric PINs,
printable-ASCII passwords, and Hangul-composed input. Related assets include
OPAQUE registration/login messages, credential records, one-time ceremony
state, rate-limit state, native signing artifacts, release evidence, and
reviewer/maintainer signing identities.

The SDK must not place the primary secret in framework callbacks, ordinary text
widgets, clipboard/autofill data, accessibility values, analytics, logs,
screenshots, crash reports, persistent storage, or public authentication
responses. A native cryptographic consumer may briefly receive the bytes
inside the native boundary; no public secret getter exists.

## Trust boundaries

1. **Native/core boundary.** Native code receives public key IDs and owns the
   bounded composition buffer. Rust/core and the native cryptographic consumer
   are the strongest supported mobile boundary. Opaque FFI handles carry
   ownership but expose no secret-byte accessor.
2. **Framework boundary.** React Native and Flutter receive only public
   configuration, masked length/state, cancellation state, and generic result
   codes in Secure Native Mode. Headless Host Mode is explicitly lower
   assurance because the host observes public key IDs.
3. **Server boundary.** The pinned Rust OPAQUE implementation handles the
   protocol. HTTP/JSON and Node adapters transport bounded messages but do not
   implement OPAQUE or retain plaintext passwords. Durable stores must provide
   atomic consume, replay expiry, namespace isolation, and rate-limit
   admission.
4. **Browser boundary.** WebAuthn/passkeys are preferred. Browser JavaScript,
   extensions, injected scripts, and page memory are outside the native trust
   boundary; a custom browser keypad is therefore a lower-assurance fallback.
5. **Release boundary.** Candidate code and externally supplied evidence are
   untrusted until checked. Release signing, reviewer fingerprints, and the
   trusted external-evidence verifier are protected process inputs.

## Adversaries

The model covers a malicious or buggy host integration, accidental secret
logging, replay or downgrade attempts, malformed public configuration, a
tampered release artifact, a malicious evidence bundle, a compromised network
path without valid TLS/proxy controls, and a malicious browser page or
extension. It also considers a casual shoulder-surfing or screen-capture
observer on a supported mobile device.

The model does not claim to defeat a rooted/jailbroken device, a kernel or
hypervisor compromise, an injected process with equivalent privileges, a
malicious accessibility service with platform-level authority, a compromised
host application, a malicious server operator, a stolen server key, or a
browser runtime that is already compromised. Those cases are residual risks
and must remain visible in product documentation.

## Security objectives and controls

| Objective | Required control | Release evidence |
|---|---|---|
| Keep input out of framework memory | Native key-ID input, opaque FFI ownership, no secret callbacks/getters | Native/RN/Flutter parity and host tests |
| Reduce residual memory | Bounded buffers, zeroization on clear/cancel/timeout/error, no plaintext persistence | Rust tests, FFI ownership tests, Linux LSAN |
| Prevent mobile visual leakage | iOS capture/background masking and Android `FLAG_SECURE` lifecycle handling | Physical screenshots, task-switcher, recording evidence |
| Prevent side channels | No editable controls, clipboard/autofill writes, secret accessibility values, logs, or crash breadcrumbs | Physical autofill/clipboard/accessibility/crash review |
| Prevent authentication replay | Versioned OPAQUE, one-time state consume, expiry, atomic durable adapters, rate-limit admission | Rust/service tests and Redis/PostgreSQL interoperability |
| Prevent protocol downgrade | Exact protocol/suite/key IDs and parity gates; generic errors | OPAQUE and HTTP parity evidence |
| Prevent release substitution | Immutable commit binding, checksums, SBOM, detached signatures, trusted-key separation | Signed candidate and final manifest |
| Prevent evidence forgery | External evidence digest verification and independently signed review | Self-hosted device-lab run and reviewer signature |

## Residual risk and operator duties

The host application owns TLS termination/proxy correctness, session-token
issuance, account and IP rate limits, secret-store/HSM protection, certificate
pinning if selected, device compromise policy, and production log/telemetry
configuration. The host must install the matching native ABI, framework
versions, protocol metadata, and platform support policy as one reviewed set.

The product must use Secure Native Mode by default on mobile, explicitly warn
before enabling Headless Host Mode or a custom web fallback, use passkeys on
the web where possible, and never place real credentials in tests or evidence.
Every release must retain the exact commit, package/protocol versions, native
checksums, SBOM, license notices, sanitized CI/device logs, release signature,
and distinct independent-review signature.

## Change and review rule

Changes to native input ownership, public event shapes, protocol versions,
durable-state semantics, platform capture controls, or release verification
require an update to this document and a new independent review scope. A
passing unit-test suite alone cannot close a physical-device or independent
review gate. The project must not advertise absolute theft prevention; it may
only claim the tested controls and their documented platform limitations.
