# Production Release Trust Chain Design

## Status

Approved direction for the production-release hardening work that follows the
`0.1.0` candidate at commit
`59b7e0731b7d79654bdfd81f223d6ccfef496f02`. This design does not declare that
the candidate is production-ready, certified, or equivalent to a commercial
mobile application shielding product. Those claims remain prohibited until
the complete evidence and approval exit rule below is satisfied.

## Goal

Make the release path executable and fail-closed, retain verifiable evidence
from CI and separately administered device/reviewer systems, and produce an
offline-verifiable production approval for one exact commit and package
version. The approval uses three distinct Ed25519 trust domains:

1. the maintainer release-bundle signing key;
2. the independent security-review key; and
3. the production-approval key available only to the final approval workflow.

## Fixed release contract

- Public package version: `0.1.0`.
- Native ABI version: `2`.
- iOS minimum: `15.1`.
- Android minimum API: `24`.
- Android release ABIs: `arm64-v8a` and `x86_64`.
- Rust release toolchain: `1.97.1`; MSRV test toolchain: `1.88.0`.
- Node: `22.13.0`; pnpm: `11.19.0`; Flutter: `3.47.0`;
  React Native host: `0.87.0`; Android NDK: `27.1.12297006`.
- Linux LeakSanitizer toolchain: `nightly-2026-08-19`.
- The release identity is always a full 40-character lowercase commit SHA and
  one version. Branch names, tags, and moving references are not identities.

Changing any value above is a separate compatibility decision and requires
the existing parity gates, documentation, and evidence fixtures to change as
one reviewed set.

## Current verified defects

The public GitHub runs for commit `59b7e07` show the CI, candidate, and
finalizer workflows failing before any job is created. Local `actionlint`
identifies job-level uses of the unavailable `runner` context:

- one in the CI fuzz job;
- seven in the release-candidate workflow; and
- four in the release-finalize workflow.

The workflow action references also contain two supply-chain errors:

- five `actions/upload-artifact@v4.6.2` references use the nonexistent
  `ea165f8f65b6e75b540449e92b4886f43607fa02` object instead of commit
  `ea165f8d65b6e75b540449e92b4886f43607fa02`;
- six `pnpm/action-setup@v4.4.0` references use annotated-tag object
  `a15d269cd4658e1107c09f1fabf4cbd7bd1f308a` instead of the peeled commit
  `fc06bc1257f339d1d5d8b3a19a8cae5388b55320`.

The release evidence contract has a second gap. It verifies GitHub run
provenance transiently, but does not retain that provenance in the final
evidence root. It signs the candidate bundle and independent review report,
but does not sign the final manifest or issue a cryptographically bound
production decision. An offline recipient therefore cannot prove the origin
of unsigned CI/device records or the final approval from the downloaded
artifact alone.

## Scope decomposition

The work is split into five independently reviewable phases. A later phase
cannot weaken or bypass an earlier phase.

1. **Workflow execution and action trust policy** restores parseable workflows
   and prevents recurrence of the known context and action-pin failures.
2. **CI evidence production** executes live Redis/PostgreSQL, LeakSanitizer,
   framework host builds, browser tests, and retains commit-bound artifacts.
3. **External evidence production** validates physical iOS/Android React
   Native and Flutter evidence plus an independently signed review on a
   separately administered runner.
4. **Provenance-bound finalization** records the exact successful GitHub runs
   and artifact identities in the evidence root before manifest merging.
5. **Production approval** signs the final verified manifest with a third,
   protected key and exposes one offline verification entry point.

## Phase 1: workflow execution and action trust policy

### Action lock

Add `.github/actions-lock.json` with schema version `1`. Every external
`uses:` target in `.github/workflows/*.yml` must appear exactly once as an
owner/repository, release label, allowed human comments, and full commit SHA.
The lock records the peeled Git commit, never an annotated-tag object. Local
actions beginning with `./` are outside the external lock but must remain
inside the checkout. The `dtolnay/rust-toolchain` entry allows the two existing
toolchain-purpose comments (`Rust 1.97.1` and `Rust 1.88.0 MSRV`); those
comments describe action inputs, while the locked SHA identifies the action
implementation.

The initial allowlist contains these exact commits:

| Action | Release | Commit |
| --- | --- | --- |
| `actions/checkout` | `v4.4.0` | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/download-artifact` | `v4.3.0` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| `actions/setup-java` | `v4.9.1` | `cf277c60eb25467037889841efdb72551f06f6c3` |
| `actions/setup-node` | `v4.4.0` | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `actions/upload-artifact` | `v4.6.2` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `anchore/sbom-action` | `v0.24.0` | `e22c389904149dbc22b58101806040fa8d37a610` |
| `dtolnay/rust-toolchain` | reviewed action revision | `032958afbdc797a9164d3bc0b56325c1308924a5` |
| `pnpm/action-setup` | `v4.4.0` | `fc06bc1257f339d1d5d8b3a19a8cae5388b55320` |
| `reactivecircus/android-emulator-runner` | `v2.38.0` | `a421e43855164a8197daf9d8d40fe71c6996bb0d` |
| `subosito/flutter-action` | `v2.23.0` | `1a449444c387b1966244ae4d4f8c696479add0b2` |

### Deterministic policy checker

Add `scripts/check-workflow-policy.mjs` and behavioral tests. The checker reads
all workflow files and the lock without network access and fails when:

- an external action is absent from the lock;
- an action uses a branch, tag, abbreviated SHA, tag-object SHA, or a commit
  different from the lock;
- a lock entry is unused or duplicated;
- a human version/purpose comment is not in the lock entry's allowed comments;
- a job-level `env` value uses `${{ runner.* }}`;
- checkout steps omit `persist-credentials: false`; or
- the workflow set is empty, unreadable, or contains an unsupported extension.

The production-candidate aggregate and repository security audit run this
checker. Tests use temporary workflow roots and assert exit status/findings;
they do not merely search the checker source. Add `.github/actionlint.yaml`
with `secure-keypad-device-lab` as the single custom self-hosted runner label
so local and CI linting distinguish that reviewed label from a typo.

### Temporary paths

Job-level environment values retain only contexts allowed at job evaluation.
Runner-temporary paths are initialized by the first shell step of each
affected job using `$RUNNER_TEMP` and append-only `$GITHUB_ENV`. Checkout and
toolchain setup actions may precede that shell step because they do not consume
the derived paths. Each value is a fixed child name, contains no
caller-controlled component, and is then consumed through the existing
environment variable. Step-level `${{ runner.temp }}` values may remain
because the `runner` context is available there.

### Phase 1 exit rule

- The policy checker and regression tests pass.
- `actionlint` reports no expression or syntax findings; the configured
  `secure-keypad-device-lab` self-hosted label is the only custom-label entry.
- The workflow files contain no invalid action object and no job-level runner
  context.
- A push to `main` creates real jobs instead of zero-job workflow failures.

## Phase 2: CI evidence production

The CI workflow remains the producer for these required gates:

- Rust workspace and MSRV tests;
- JavaScript/contracts and protocol parity;
- native/package parity and framework host builds;
- Redis 7.2 and PostgreSQL 16 durable-backend interoperability;
- browser matrix;
- four extended fuzz campaigns; and
- four Linux LeakSanitizer campaigns with verified logs.

Each job emits or retains data only after its real command ran. `if: always()`
may retain failure logs, but a failed producer cannot emit a passing gate or
satisfy the aggregate `needs` chain. The aggregate artifact is
`secure-keypad-ci-release-evidence`, bound to the workflow run's `head_sha`.

Phase 2 exits only when a successful `main` CI run for the exact release commit
contains non-empty durable-backend and LSAN records whose nested log digests
pass the checked-in validators. Simulator/emulator output remains supporting
evidence and cannot satisfy a physical-device gate.

## Phase 3: physical devices and independent review

The external evidence root is produced outside the source checkout and must
contain:

- one iOS physical record covering both React Native `0.87.0` and Flutter
  `3.47.0` host modes;
- one Android physical record covering both host modes and the required API
  and security-patch fields;
- unique per-host logs plus aggregate logs;
- categorized capture, background, accessibility, autofill/clipboard,
  crash-review, platform-security-patch, and native-checksum artifacts; and
- the independent review report, Ed25519 signature, and DER public key.

All records bind commit, package version, platform build, native checksum, and
test evidence. The independent reviewer covers every scope in
`docs/INDEPENDENT-REVIEW-PACKET.md` and issues `approved` or
`approved-with-residual-risk`. A `not-approved` report, an open critical/high
finding, one missing framework host mode, a simulator-only record, or a stale
commit keeps the release closed.

The external workflow uses the protected `secure-keypad-external-evidence`
environment and a self-hosted runner labeled `secure-keypad-device-lab`. Its
trusted verifier checkout is distinct from candidate data. The reviewer key
fingerprint is supplied by the protected environment, not by the evidence
bundle.

## Phase 4: retained GitHub provenance

### Record

After the finalizer verifies the candidate, CI, and external runs through the
GitHub API, trusted verifier code writes
`evidence/github-run-provenance.json` by exclusive creation. Schema version
`1` contains:

```json
{
  "schemaVersion": 1,
  "repository": "uulab-official/secure-keyboard",
  "commit": "59b7e0731b7d79654bdfd81f223d6ccfef496f02",
  "runs": [
    {
      "role": "candidate",
      "runId": 1,
      "runAttempt": 1,
      "workflowPath": ".github/workflows/release-candidate.yml",
      "event": "workflow_dispatch",
      "status": "completed",
      "conclusion": "success",
      "headSha": "59b7e0731b7d79654bdfd81f223d6ccfef496f02",
      "artifactName": "secure-keypad-release-candidate",
      "artifactId": 1,
      "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

The numeric values and zero digest above are schema examples only and are not
release evidence. A valid record has exactly three roles (`candidate`, `ci`,
`external`), positive safe IDs/attempts, canonical workflow paths, the
expected event, successful completion, exact commit, exact artifact name, and
the digest returned for the artifact downloaded by the finalizer. Duplicate
roles, IDs, artifact names, or paths fail.

### Gate

The trusted emitter also creates
`fragments/github-run-provenance.json` for a new required
`github-run-provenance` gate. The fragment hashes the record and carries the
same commit/version as every other fragment. The final manifest validator
revalidates the record rather than trusting the `pass` label.

API responses and artifact metadata are bounded before parsing. Tokens,
headers, actor email, secret names, and environment secrets are never written
to evidence. The retained record is sanitized provenance, not a GitHub access
credential.

## Phase 5: production approval

### Key separation

The `release-candidate.yml` bundle job remains in the existing
`secure-keypad-release` environment. The `release-finalize.yml` approval job
uses a distinct protected environment named
`secure-keypad-production-approval`. That environment contains:

- `SECURE_KEYPAD_PRODUCTION_APPROVAL_KEY_PEM`;
- `SECURE_KEYPAD_PRODUCTION_APPROVAL_PUBLIC_KEY_SHA256`;
- the existing trusted maintainer and reviewer public-key fingerprints; and
- `SECURE_KEYPAD_TRUSTED_VERIFIER_REF`.

The approval key is Ed25519, is never present in candidate/CI/external jobs,
and is different from the release and reviewer keys. The finalizer executes
candidate files only as bounded data; signing, provenance emission, manifest
merging, and approval verification run from the separately pinned verifier
checkout. The verifier rejects any pair of equal fingerprints. Environment
protection requires designated human reviewers and prevents self-approval by
the initiating actor. Repository and environment settings are operational
controls that must be exported or screenshotted into the retained approval
packet; source code cannot prove that they are configured.

### Approval envelope

After trusted-key verification of the complete manifest, verifier code writes
`approval/production-approval.json` by exclusive creation. It contains:

- schema version `1` and decision `approved`;
- exact repository, commit, and package version;
- finalizer run ID and attempt;
- candidate, CI, and external run IDs copied from the verified provenance
  record;
- relative manifest path and SHA-256 of its exact bytes;
- the three distinct public-key fingerprints;
- canonical UTC approval time; and
- policy ID `secure-keypad-production-approval-v1`.

The finalizer signs the exact approval-envelope bytes with the production
approval key and writes:

```text
approval/production-approval.json
approval/production-approval.sig
approval/production-approval.pub.der
```

The envelope signs the manifest digest instead of embedding itself in the
manifest, avoiding a circular hash. The public key is retained; its trust
comes only from the separately configured protected fingerprint.

### Offline verifier

Add one command that accepts the evidence root and three protected
fingerprints. It:

1. validates every existing release gate and referenced file;
2. verifies the candidate and reviewer signatures;
3. validates the retained GitHub provenance gate;
4. recomputes the final manifest digest;
5. verifies the production approval signature and Ed25519 key type;
6. checks repository/commit/version/run binding and the three-key separation;
7. requires decision `approved`; and
8. exits nonzero for missing, stale, malformed, unsigned, duplicate,
   symlinked, oversized, or secret-bearing input.

The verifier does not infer approval from a GitHub run conclusion, an
environment name, or the presence of a signature file.

## End-to-end data flow

1. Push the exact candidate commit to protected `main`.
2. Obtain a successful CI run and its aggregate evidence artifact.
3. Dispatch the candidate workflow for the same SHA and obtain the signed
   candidate artifact.
4. Execute physical iOS/Android RN/Flutter tests and independent review.
5. Dispatch the external workflow and obtain the validated external artifact.
6. Dispatch the finalizer with the three successful run IDs.
7. Trusted verifier code validates run and artifact provenance and writes the
   provenance gate.
8. Stage all roots, merge the canonical gate set, and run trusted release and
   reviewer fingerprint verification.
9. Enter the separately protected approval environment and sign the approval
   envelope over the final manifest digest.
10. Run the offline verifier and retain/upload the complete evidence root.

No command may synthesize a device pass, review approval, CI success,
environment approval, or key fingerprint. A skipped or unavailable producer
keeps the release closed.

## Testing strategy

Every behavior change follows red-green-refactor:

- workflow policy tests first demonstrate rejection of the current invalid
  SHA, annotated-tag object, unregistered action, and job-level runner context;
- provenance tests use complete literal GitHub run/artifact fixtures and
  reject wrong repository, workflow, event, commit, run attempt, artifact,
  digest, duplicates, and failed conclusions;
- manifest tests require the new provenance gate and verify its nested record;
- approval tests generate disposable Ed25519 keys and prove success, then
  mutate manifest bytes, each fingerprint, decision, run binding, signature,
  path, and size to prove fail-closed behavior;
- workflow contract tests verify environment separation and that only trusted
  verifier scripts receive approval key material;
- the full repository script suite, security audit, Rust workspace, package
  tests, actionlint, and production-candidate aggregate run before merge; and
- after push, public GitHub run/job/artifact state is observed directly rather
  than inferred from local tests.

Tests never contain production keys or real credentials. Temporary private
key buffers are zeroed after parsing where the runtime permits, never logged,
and never copied into an evidence root.

## Operational evidence not producible from source code

The following remain required external inputs and cannot be checked off by a
repository commit:

- a successful live CI run containing Redis/PostgreSQL and LSAN artifacts;
- RN and Flutter runs on physical iOS and Android devices at the support
  boundaries and current supported releases;
- an independent review performed by a party that did not implement the
  boundary and does not control either maintainer key;
- configured branch protection, required checks, protected environments,
  reviewer restrictions, and protected secret fingerprints;
- retained key-custody and rotation records; and
- a successful finalizer run plus offline verification of the downloaded
  production evidence artifact.

If GitHub authentication or the physical lab is unavailable, repository work
continues through schema, verifier, fixture, and workflow hardening, but the
project remains a production candidate rather than an approved release.

## Production exit rule

The SDK may be described as an approved production release only when one
immutable commit has all of the following evidence:

- every canonical source, backend, sanitizer, host, browser, and physical
  device gate passes;
- the independent review is signed and acceptable under its finding policy;
- the candidate bundle signature verifies under the protected release
  fingerprint;
- the final manifest includes validated GitHub run/artifact provenance;
- the approval envelope verifies under the distinct protected approval
  fingerprint and says `approved`;
- the three key fingerprints are distinct;
- the offline verifier passes against the retained artifact; and
- no required external or operational control is represented by a source-only
  test or an unverified assertion.

Even after this exit rule, product language must describe the documented
security controls and reviewed scope. It must not claim that plaintext can
never exist anywhere in a compromised OS/runtime, that rooted devices are
defeated, or that the SDK is certified/equivalent to a named commercial
product unless an authorized independent certification specifically supports
that claim.
