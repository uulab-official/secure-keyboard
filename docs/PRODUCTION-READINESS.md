# Production readiness handoff

This document is an operational handoff for a release candidate. It is not a
security certification, an independent review, or a production approval.

## Candidate versus release

Run the deterministic source and adapter gate from the exact checkout that is
being evaluated:

```sh
mise exec -- pnpm verify:production-candidate
```

A successful command proves the pinned local toolchain, Rust workspace,
JavaScript packages, native/framework contracts, browser smoke matrix, and
Flutter package checks. It does not prove physical-device behavior, live
service or CI provenance, Linux LeakSanitizer results, signing, or an
independent security review.

The native package version, C ABI, iOS/Android platform floors, and Android
artifact matrix are defined by [`native/sdk-contract.json`](../native/sdk-contract.json).
The standalone iOS and Android native SDK artifacts and the Flutter/React
Native wrapper artifacts must be produced from the same immutable commit.

The current checkout must not be described as production-ready until a
complete release-evidence manifest passes the trusted-key verifier:

```sh
SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256=<maintainer-fingerprint> \
SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256=<reviewer-fingerprint> \
node scripts/check-release-evidence.mjs --require-trusted-keys \
  /absolute/path/to/release-evidence/release-evidence.json
```

The two fingerprints must come from the protected release process and must be
different. The manifest must bind every record and artifact to one immutable
commit and package version.

## Evidence still required for a public release claim

| Gate | Required producer | Required evidence |
| --- | --- | --- |
| CI and durable backends | pinned CI workflow | successful run provenance, sanitized gate fragments, and isolated Redis/PostgreSQL interoperability records |
| Linux LeakSanitizer | Linux fuzz job | all four target records with the checked-in toolchain, run count, success marker, and verified log digests |
| iOS device matrix | separately administered device lab | physical device records for React Native and Flutter, accessibility/capture/autofill/background/crash/replay/downgrade artifacts, and matching native checksums |
| Android device matrix | separately administered device lab | physical device records for React Native and Flutter, API/security-patch evidence, accessibility/capture/autofill/background/crash/replay/downgrade artifacts, and matching native checksums |
| Signed release | protected release workflow | exact-commit candidate bundle, detached Ed25519 signature, maintainer public key, SBOM, notices, and package/archive checks |
| Independent security review | reviewer independent of the maintainer key | signed review report covering the complete scope in [INDEPENDENT-REVIEW-PACKET.md](./INDEPENDENT-REVIEW-PACKET.md) |

Source inspection, simulator/emulator smoke tests, generated screenshots,
local sanitizer substitutes, or a passing unit test cannot be substituted for
the physical-device, CI, or reviewer evidence above.

## Assembly order

1. Build the immutable candidate with the protected
   `release-candidate.yml` workflow.
2. Collect CI and browser fragments for the same commit.
3. Run the separately administered `external-release-evidence.yml` workflow
   with the physical-device evidence root and signed reviewer report.
4. Use the read-only `release-finalize.yml` workflow to verify run provenance,
   stage artifacts, merge fragments, and run the trusted-key verifier.
5. Retain the final manifest, signed bundle, signatures, public keys, logs,
   screenshots/reports, SBOM, notices, and exact commit together.

No emitter or merge command may synthesize a passing gate. Missing, stale,
cross-commit, unsigned, symlinked, secret-bearing, or incomplete evidence must
remain a release failure.

## Security claim boundary

Secure Native Mode keeps the accumulated input out of ordinary framework
callbacks and does not expose a secret getter. This is a tested boundary, not
a guarantee that an uncompromised operating system, debugger, native crash
dump, or browser runtime can never observe memory. Web integrations should
prefer WebAuthn/passkeys; the browser keypad fallback is lower assurance.

See [RELEASE-GATES.md](./RELEASE-GATES.md),
[DEVICE-VERIFICATION.md](./DEVICE-VERIFICATION.md),
[INDEPENDENT-REVIEW-PACKET.md](./INDEPENDENT-REVIEW-PACKET.md), and the
[roadmap](./ROADMAP.md) for the authoritative procedures and remaining gates.
