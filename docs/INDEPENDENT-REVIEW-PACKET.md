# Independent security review packet

This document is the handoff contract for the independent security assessment
required by the production release gate. It is not an approval, a
certification, or a substitute for the signed review artifact. The reviewer
must assess the exact immutable commit that will be released and must not use
the current branch tip as an implicit substitute.

## Review input

The maintainer supplies one immutable candidate package containing:

- the exact 40-character release commit and package version;
- the signed release-candidate bundle, detached release signature, and DER
  Ed25519 release public key;
- the Rust and JavaScript lockfiles, pinned toolchains, SBOM, and license
  notices;
- the threat model, security specification, platform policy, compatibility
  policy, device-verification procedure, and release-gate verifier;
- CI evidence for the Rust/TypeScript contracts, native package parity,
  framework host builds, browser matrix, fuzz stability, Linux LSAN, and
  Redis/PostgreSQL interoperability; and
- the separately collected physical iOS/Android evidence, including the
  React Native and Flutter host-mode logs and the native checksum artifact.

The reviewer must verify that every input is bound to the same commit and
package version. A source checkout, test result, or screenshot from another
commit is out of scope for the release decision.

## Mandatory review scope

| Scope | Minimum review surface |
| --- | --- |
| Native input boundary | `secure-core`, `secure-ffi`, iOS/Android native views, ownership/zeroization, masked state, capture/autofill/accessibility behavior |
| OPAQUE authentication | pinned `opaque-ke` suite, protocol/version envelopes, key rotation, native handoff, generic errors, downgrade resistance |
| HTTP/JSON transport | body limits before parsing, strict headers/media type, TLS/proxy context, CSRF and rate-limit admission, Node/Axum/Actix parity |
| Replay and durable state | one-time consume semantics, TTL/capacity bounds, Redis/PostgreSQL atomicity, authenticated encryption, TLS-first production constructors |
| Framework adapters | RN/Flutter public props and events, no secret getter, native package parity, headless-mode acknowledgement, WebAuthn-first web behavior |
| Device/runtime evidence | physical iOS/Android matrix, screen capture/background snapshots, autofill/clipboard, VoiceOver/TalkBack, crash review, protocol downgrade checks |
| Release process | immutable provenance, artifact hashes, SBOM/notices, detached signatures, trusted-key separation, finalizer fail-closed behavior |

The reviewer should use the [MASVS/MASTG evidence map](./MASVS-MAPPING.md)
as the checklist and record any accepted residual risk against the exact
scope row above. The [security specification](./SECURITY-SPEC.md) and
[platform security policy](./PLATFORM-SECURITY-POLICY.md) define the claims
that may and may not be made.

## Required reviewer actions

1. Inspect the source, lockfiles, generated native artifacts, and release
   scripts at the candidate commit.
2. Re-run the relevant source and contract gates from
   [RELEASE-GATES.md](./RELEASE-GATES.md), and independently inspect the
   physical-device artifacts described by
   [DEVICE-VERIFICATION.md](./DEVICE-VERIFICATION.md).
3. Attempt to reproduce secret exposure, framework-boundary escape, replay,
   downgrade, malformed-input, capture, autofill, accessibility, and release
   provenance failures. Use only disposable values; never place a real
   credential in a log, screenshot, crash report, or review file.
4. Confirm that the release public key and reviewer public key are controlled
   by different parties and have different SHA-256 fingerprints.
5. Issue a structured report with an explicit `approved` or
   `approved-with-residual-risk` decision. `not-approved`, malformed, unsigned,
   scope-incomplete, or secret-bearing reports cannot satisfy the release gate.

## Reviewer deliverables

The external evidence artifact must contain these files, all relative to its
evidence root:

```text
artifacts/independent-review.json
artifacts/independent-review.sig
artifacts/independent-review.pub.der
fragments/independent-security-review.json
```

The report is schema version `1` with report type
`independent-security-review`. It must bind `reviewedCommit`,
`reviewedPackageVersion`, and `reviewerPublicKeySha256`, cover every mandatory
scope listed above, and include bounded findings. Every finding declares its
severity, status, affected scope, reproduction, remediation owner, and retest
evidence. Critical and high findings must be `accepted` or `remediated`; they
must never remain `open`.

The reviewer signs the exact report bytes with an Ed25519 private key. The
private key is never uploaded and is never passed to the fragment emitter:

```sh
node scripts/sign-release.mjs \
  "$EVIDENCE_ROOT/artifacts/independent-review.json" \
  "$REVIEWER_PRIVATE_KEY" \
  "$EVIDENCE_ROOT/artifacts/independent-review.sig" \
  "$EVIDENCE_ROOT/artifacts/independent-review.pub.der"

node scripts/emit-independent-review-fragment.mjs \
  "$EVIDENCE_ROOT" \
  "evidence/independent-security-review.json" \
  "fragments/independent-security-review.json" \
  --report artifacts/independent-review.json \
  --signature artifacts/independent-review.sig \
  --public-key artifacts/independent-review.pub.der
```

The emitter derives the checkout identity from a clean checkout and verifies
the report, signature, package version, scope, and reviewer key binding. Run
the independent-review emitter tests before handing the artifact to the
finalizer:

```sh
pnpm test:emit-independent-review-fragment
```

The finalizer additionally verifies GitHub run provenance for the candidate,
CI, and external-evidence workflows, hashes every retained file, checks both
trusted public-key fingerprints, and runs the complete release manifest
validator. Until that finalizer succeeds, the project must not claim
production readiness.

## Independence and retention

The reviewer must be a person or organization that did not implement the
reviewed security boundary and does not control the maintainer release key.
The review report, detached signature, reviewer public key, exact commit, and
all referenced evidence must be retained with the final release evidence
artifact. A review performed on an earlier commit must be repeated or
explicitly re-approved for the candidate commit; copying an earlier fragment
is rejected by the commit-bound verifier.
