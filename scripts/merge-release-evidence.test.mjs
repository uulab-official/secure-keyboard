import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { REQUIRED_RELEASE_GATES, validateReleaseEvidence } from "./check-release-evidence.mjs";
import { mergeReleaseEvidence, writeMergedEvidence } from "./merge-release-evidence.mjs";

const SHA256 = "a".repeat(64);
const MERGE_SCRIPT = fileURLToPath(new URL("./merge-release-evidence.mjs", import.meta.url));

function baseContext() {
  return {
    schemaVersion: 1,
    commit: "b".repeat(40),
    packageVersion: "0.1.0",
    toolchains: {
      rust: "1.97.1",
      node: "22.13.0",
      flutter: "3.47.0",
      reactNative: "0.87.0",
      ndk: "27.1.12297006",
    },
  };
}

function completeFragments() {
  const context = baseContext();
  const gates = REQUIRED_RELEASE_GATES.map((name) => ({
    name,
    status: "pass",
    evidencePath: `evidence/${name}.json`,
    sha256: SHA256,
  }));
  const artifacts = [
    { kind: "native-checksum", path: "artifacts/native.sha256", sha256: SHA256 },
    { kind: "sbom", path: "artifacts/sbom.json", sha256: SHA256 },
    { kind: "license-notices", path: "artifacts/notices.md", sha256: SHA256 },
    { kind: "release-bundle", path: "artifacts/release.tar.gz", sha256: SHA256 },
    { kind: "release-public-key", path: "artifacts/release.pub.der", sha256: SHA256 },
    { kind: "release-signature", path: "artifacts/release.sig", sha256: SHA256 },
    { kind: "independent-review-report", path: "artifacts/review.json", sha256: SHA256 },
    { kind: "independent-review-public-key", path: "artifacts/review.pub.der", sha256: SHA256 },
    { kind: "independent-review-signature", path: "artifacts/review.sig", sha256: SHA256 },
  ];
  return [
    { ...context, gates: gates.slice(0, 5) },
    { ...context, gates: gates.slice(5), artifacts: artifacts.slice(0, 3) },
    {
      ...context,
      artifacts: artifacts.slice(3),
      signature: {
        algorithm: "ed25519",
        publicKeyPath: "artifacts/release.pub.der",
        signedArtifactPath: "artifacts/release.tar.gz",
      signaturePath: "artifacts/release.sig",
      publicKeySha256: SHA256,
      },
      independentReview: {
        algorithm: "ed25519",
        publicKeyPath: "artifacts/review.pub.der",
        signedArtifactPath: "artifacts/review.json",
        signaturePath: "artifacts/review.sig",
        publicKeySha256: SHA256,
      },
    },
  ];
}

test("merges split gates, artifacts, and signature into a complete manifest", () => {
  const merged = mergeReleaseEvidence(completeFragments(), { createdAt: "2026-08-21T00:00:00.000Z" });

  assert.deepEqual(validateReleaseEvidence(merged), []);
  assert.equal(merged.gates.length, REQUIRED_RELEASE_GATES.length);
  assert.equal(merged.artifacts.length, 9);
  assert.equal(merged.signature.algorithm, "ed25519");
  assert.equal(merged.independentReview.algorithm, "ed25519");
});

test("rejects conflicting context and duplicate evidence paths", () => {
  const fragments = completeFragments();
  fragments[1].commit = "c".repeat(40);
  assert.throws(() => mergeReleaseEvidence(fragments), /conflicts on commit/);

  const duplicatePath = completeFragments();
  duplicatePath[1].gates[0].evidencePath = duplicatePath[0].gates[0].evidencePath;
  assert.throws(() => mergeReleaseEvidence(duplicatePath), /duplicate release evidence path/);
});

test("preserves merged file references for a shared evidence root", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-evidence-merge-"));
  const fragments = completeFragments();
  mkdirSync(join(root, "evidence"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  for (const fragment of fragments) {
    for (const gate of fragment.gates ?? []) writeFileSync(join(root, gate.evidencePath), Buffer.from("evidence"));
    for (const artifact of fragment.artifacts ?? []) writeFileSync(join(root, artifact.path), Buffer.from("artifact"));
  }
  const merged = mergeReleaseEvidence(fragments);
  assert.equal(merged.gates.every((gate) => gate.sha256 === SHA256), true);
  assert.equal(merged.artifacts.every((artifact) => artifact.path.startsWith("artifacts/")), true);
});

test("rejects an output path that escapes the evidence root through a symlink", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-evidence-root-"));
  const outside = mkdtempSync(join(tmpdir(), "secure-keypad-evidence-outside-"));
  symlinkSync(outside, join(root, "escape"), "dir");

  assert.throws(
    () => writeMergedEvidence(root, "escape/release-evidence.json", {}),
    /inside the evidence root/,
  );
});

test("rejects a dangling output symlink before writing through it", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-evidence-dangling-"));
  const outside = join(tmpdir(), "secure-keypad-evidence-dangling-target");
  symlinkSync(outside, join(root, "release-evidence.json"));

  assert.throws(
    () => writeMergedEvidence(root, "release-evidence.json", {}),
    /output path must not already exist/,
  );
});

test("CLI assembles and verifies a signed evidence root", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-evidence-cli-"));
  mkdirSync(join(root, "evidence"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  mkdirSync(join(root, "fragments"), { recursive: true });

  const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const context = { ...baseContext(), commit };
  const evidenceBytes = Buffer.from("sanitized evidence", "utf8");
  const evidenceHash = createHash("sha256").update(evidenceBytes).digest("hex");
  const releaseBytes = Buffer.from("signed release bundle", "utf8");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  const releaseSignature = sign(null, releaseBytes, privateKey);
  const reviewBytes = Buffer.from("independent review report", "utf8");
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPublicKeyBytes = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewSignature = sign(null, reviewBytes, reviewPrivateKey);
  const hash = (value) => createHash("sha256").update(value).digest("hex");

  const gates = REQUIRED_RELEASE_GATES.map((name) => ({
    name,
    status: "pass",
    evidencePath: `evidence/${name}.json`,
    sha256: evidenceHash,
  }));
  for (const gate of gates) writeFileSync(join(root, gate.evidencePath), evidenceBytes);

  const artifacts = [
    { kind: "native-checksum", path: "artifacts/native.sha256", bytes: Buffer.from("native") },
    { kind: "sbom", path: "artifacts/sbom.json", bytes: Buffer.from("sbom") },
    { kind: "license-notices", path: "artifacts/notices.md", bytes: Buffer.from("notices") },
    { kind: "release-bundle", path: "artifacts/release.tar.gz", bytes: releaseBytes },
    { kind: "release-public-key", path: "artifacts/release.pub.der", bytes: publicKeyBytes },
    { kind: "release-signature", path: "artifacts/release.sig", bytes: releaseSignature },
    { kind: "independent-review-report", path: "artifacts/review.json", bytes: reviewBytes },
    { kind: "independent-review-public-key", path: "artifacts/review.pub.der", bytes: reviewPublicKeyBytes },
    { kind: "independent-review-signature", path: "artifacts/review.sig", bytes: reviewSignature },
  ].map(({ bytes, ...artifact }) => {
    writeFileSync(join(root, artifact.path), bytes);
    return { ...artifact, sha256: hash(bytes) };
  });
  const fragments = [
    { ...context, gates: gates.slice(0, 5) },
    { ...context, gates: gates.slice(5), artifacts: artifacts.slice(0, 3) },
    {
      ...context,
      artifacts: artifacts.slice(3),
      signature: {
        algorithm: "ed25519",
        publicKeyPath: "artifacts/release.pub.der",
        signedArtifactPath: "artifacts/release.tar.gz",
        signaturePath: "artifacts/release.sig",
        publicKeySha256: hash(publicKeyBytes),
      },
      independentReview: {
        algorithm: "ed25519",
        publicKeyPath: "artifacts/review.pub.der",
        signedArtifactPath: "artifacts/review.json",
        signaturePath: "artifacts/review.sig",
        publicKeySha256: hash(reviewPublicKeyBytes),
      },
    },
  ];
  const fragmentPaths = fragments.map((fragment, index) => {
    const relativePath = `fragments/fragment-${index}.json`;
    writeFileSync(join(root, relativePath), `${JSON.stringify(fragment)}\n`);
    return relativePath;
  });

  const output = execFileSync(process.execPath, [MERGE_SCRIPT, root, "release-evidence.json", ...fragmentPaths], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    encoding: "utf8",
  });
  assert.match(output, /release evidence merged and verified/);
  const manifest = JSON.parse(readFileSync(join(root, "release-evidence.json"), "utf8"));
  assert.deepEqual(validateReleaseEvidence(manifest, { expectedCommit: commit, expectedPackageVersion: "0.1.0" }), []);
});
