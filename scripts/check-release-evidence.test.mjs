import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  REQUIRED_RELEASE_GATES,
  verifyReleaseEvidenceFiles,
  validateReleaseEvidence,
} from "./check-release-evidence.mjs";

const SHA256 = "a".repeat(64);
const CHECK_SCRIPT = fileURLToPath(new URL("./check-release-evidence.mjs", import.meta.url));

function completeEvidence() {
  return {
    schemaVersion: 1,
    commit: "b".repeat(40),
    createdAt: "2026-08-21T00:00:00.000Z",
    packageVersion: "0.1.0",
    toolchains: {
      rust: "1.97.1",
      node: "22.13.0",
      flutter: "3.47.0",
      reactNative: "0.87.0",
      ndk: "27.1.12297006",
    },
    gates: REQUIRED_RELEASE_GATES.map((name) => ({
      name,
      status: "pass",
      evidencePath: `evidence/${name}.json`,
      sha256: SHA256,
    })),
    artifacts: [
      { kind: "native-checksum", path: "artifacts/native.sha256", sha256: SHA256 },
      { kind: "sbom", path: "artifacts/secure-keypad.sbom.spdx.json", sha256: SHA256 },
      { kind: "license-notices", path: "artifacts/THIRD-PARTY-NOTICES.md", sha256: SHA256 },
      { kind: "release-bundle", path: "artifacts/secure-keypad-release.tar.gz", sha256: SHA256 },
      { kind: "release-signature", path: "artifacts/secure-keypad-release.sig", sha256: SHA256 },
      { kind: "release-public-key", path: "artifacts/secure-keypad-release.pub.der", sha256: SHA256 },
      { kind: "independent-review-report", path: "artifacts/independent-review.json", sha256: SHA256 },
      { kind: "independent-review-signature", path: "artifacts/independent-review.sig", sha256: SHA256 },
      { kind: "independent-review-public-key", path: "artifacts/independent-review.pub.der", sha256: SHA256 },
    ],
    signature: {
      algorithm: "ed25519",
      publicKeyPath: "artifacts/secure-keypad-release.pub.der",
      signedArtifactPath: "artifacts/secure-keypad-release.tar.gz",
      signaturePath: "artifacts/secure-keypad-release.sig",
      publicKeySha256: SHA256,
    },
    independentReview: {
      algorithm: "ed25519",
      publicKeyPath: "artifacts/independent-review.pub.der",
      signedArtifactPath: "artifacts/independent-review.json",
      signaturePath: "artifacts/independent-review.sig",
      publicKeySha256: SHA256,
    },
  };
}

test("accepts a complete release evidence manifest", () => {
  assert.deepEqual(validateReleaseEvidence(completeEvidence()), []);
});

test("rejects missing production gates and release artifacts", () => {
  const evidence = completeEvidence();
  evidence.gates = evidence.gates.filter(
    (gate) => gate.name !== "linux-leak-sanitizer" && gate.name !== "independent-security-review",
  );
  evidence.artifacts = evidence.artifacts.filter(
    (artifact) => artifact.kind !== "sbom" && artifact.kind !== "release-signature",
  );

  const findings = validateReleaseEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("linux-leak-sanitizer")));
  assert.ok(findings.some((finding) => finding.includes("independent-security-review")));
  assert.ok(findings.some((finding) => finding.includes("sbom")));
  assert.ok(findings.some((finding) => finding.includes("release-signature")));
});

test("rejects unsafe paths, bad hashes, failed statuses, and secret-bearing fields", () => {
  const evidence = completeEvidence();
  evidence.commit = "not-a-commit";
  evidence.gates[0].status = "skipped";
  evidence.gates[0].evidencePath = "../private.log";
  evidence.gates[0].sha256 = "not-a-hash";
  evidence.artifacts[0].path = "/tmp/native.sha256";
  evidence.password = "must never be recorded";

  const findings = validateReleaseEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("commit")));
  assert.ok(findings.some((finding) => finding.includes("status")));
  assert.ok(findings.some((finding) => finding.includes("evidencePath")));
  assert.ok(findings.some((finding) => finding.includes("sha256")));
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].path")));
  assert.ok(findings.some((finding) => finding.includes("password")));
});

test("rejects duplicate evidence paths and an unbound signature", () => {
  const evidence = completeEvidence();
  evidence.gates[1].evidencePath = evidence.gates[0].evidencePath;
  evidence.artifacts[0].path = evidence.gates[0].evidencePath;
  evidence.signature.signedArtifactPath = "artifacts/not-listed.bin";
  evidence.signature.publicKeyPath = "artifacts/native.sha256";

  const findings = validateReleaseEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("evidencePath") && finding.includes("unique")));
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].path") && finding.includes("unique")));
  assert.ok(findings.some((finding) => finding.includes("signedArtifactPath") && finding.includes("artifact")));
  assert.ok(findings.some((finding) => finding.includes("publicKeyPath") && finding.includes("release-public-key")));
});

test("binds release evidence to the exact commit and package version", () => {
  const evidence = completeEvidence();
  const findings = validateReleaseEvidence(evidence, {
    expectedCommit: "c".repeat(40),
    expectedPackageVersion: "0.1.1",
  });

  assert.ok(findings.some((finding) => finding.includes("commit") && finding.includes("current")));
  assert.ok(findings.some((finding) => finding.includes("packageVersion") && finding.includes("current")));
});

test("binds release and reviewer signatures to trusted public-key fingerprints", () => {
  const findings = validateReleaseEvidence(completeEvidence(), {
    expectedReleasePublicKeySha256: "b".repeat(64),
    expectedReviewerPublicKeySha256: "c".repeat(64),
  });

  assert.ok(findings.some((finding) => finding.includes("signature.publicKeySha256") && finding.includes("trusted")));
  assert.ok(
    findings.some(
      (finding) => finding.includes("independentReview.publicKeySha256") && finding.includes("trusted"),
    ),
  );
});

test("trusted-key CLI mode fails closed when protected fingerprints are absent", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-trusted-release-"));
  const manifestPath = join(root, "manifest.json");
  writeFileSync(manifestPath, "{}\n");
  const environment = { ...process.env };
  delete environment.SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256;
  delete environment.SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256;

  const result = spawnSync(process.execPath, [CHECK_SCRIPT, "--require-trusted-keys", manifestPath], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    env: environment,
    encoding: "utf8",
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256/);
  assert.match(result.stderr, /SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256/);
});

test("verifies every referenced release evidence and artifact digest", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-evidence-"));
  const evidence = completeEvidence();
  const payload = Buffer.from("release-evidence-fixture", "utf8");
  const sha256 = createHash("sha256").update(payload).digest("hex");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const releasePayload = Buffer.from("signed-release-fixture", "utf8");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const signature = sign(null, releasePayload, privateKey);
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPayload = Buffer.from("independent-review-fixture", "utf8");
  const reviewPublicKeyDer = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewSignature = sign(null, reviewPayload, reviewPrivateKey);
  const reviewPublicKeySha256 = createHash("sha256").update(reviewPublicKeyDer).digest("hex");

  for (const gate of evidence.gates) {
    mkdirSync(join(root, "evidence"), { recursive: true });
    writeFileSync(join(root, gate.evidencePath), payload);
    gate.sha256 = sha256;
  }
  for (const artifact of evidence.artifacts) {
    mkdirSync(join(root, "artifacts"), { recursive: true });
    if (artifact.kind === "release-bundle") {
      writeFileSync(join(root, artifact.path), releasePayload);
      artifact.sha256 = createHash("sha256").update(releasePayload).digest("hex");
    } else if (artifact.kind === "release-signature") {
      writeFileSync(join(root, artifact.path), signature);
      artifact.sha256 = createHash("sha256").update(signature).digest("hex");
    } else if (artifact.kind === "independent-review-report") {
      writeFileSync(join(root, artifact.path), reviewPayload);
      artifact.sha256 = createHash("sha256").update(reviewPayload).digest("hex");
    } else if (artifact.kind === "independent-review-signature") {
      writeFileSync(join(root, artifact.path), reviewSignature);
      artifact.sha256 = createHash("sha256").update(reviewSignature).digest("hex");
    } else {
      writeFileSync(join(root, artifact.path), payload);
      artifact.sha256 = sha256;
    }
  }
  writeFileSync(join(root, evidence.signature.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), reviewPublicKeyDer);
  evidence.signature.publicKeySha256 = publicKeySha256;
  evidence.independentReview.publicKeySha256 = reviewPublicKeySha256;
  evidence.artifacts.find((artifact) => artifact.kind === "release-public-key").sha256 = publicKeySha256;
  evidence.artifacts.find((artifact) => artifact.kind === "independent-review-public-key").sha256 = reviewPublicKeySha256;

  assert.deepEqual(verifyReleaseEvidenceFiles(evidence, root), []);

  writeFileSync(join(root, evidence.artifacts[0].path), Buffer.from("tampered", "utf8"));
  const findings = verifyReleaseEvidenceFiles(evidence, root);
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].sha256")));
});

test("rejects a tampered detached release signature", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-signature-"));
  const evidence = completeEvidence();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const releasePayload = Buffer.from("signed-release-fixture", "utf8");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const signature = sign(null, releasePayload, privateKey);
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, evidence.signature.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.signature.signedArtifactPath), releasePayload);
  writeFileSync(join(root, evidence.signature.signaturePath), Buffer.from(signature).reverse());
  evidence.signature.publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  evidence.artifacts.find((artifact) => artifact.kind === "release-bundle").sha256 = createHash("sha256")
    .update(releasePayload)
    .digest("hex");
  evidence.artifacts.find((artifact) => artifact.kind === "release-signature").sha256 = createHash("sha256")
    .update(Buffer.from(signature).reverse())
    .digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("signature")));
});

test("rejects a tampered independent-review attestation", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-review-signature-"));
  const evidence = completeEvidence();
  const { privateKey: releasePrivateKey, publicKey: releasePublicKey } = generateKeyPairSync("ed25519");
  const releasePayload = Buffer.from("signed-release-fixture", "utf8");
  const releasePublicKeyDer = releasePublicKey.export({ format: "der", type: "spki" });
  const releaseSignature = sign(null, releasePayload, releasePrivateKey);
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPayload = Buffer.from("independent-review-fixture", "utf8");
  const reviewPublicKeyDer = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewSignature = sign(null, reviewPayload, reviewPrivateKey);
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, evidence.signature.publicKeyPath), releasePublicKeyDer);
  writeFileSync(join(root, evidence.signature.signedArtifactPath), releasePayload);
  writeFileSync(join(root, evidence.signature.signaturePath), releaseSignature);
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), reviewPublicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signedArtifactPath), reviewPayload);
  writeFileSync(join(root, evidence.independentReview.signaturePath), Buffer.from(reviewSignature).reverse());
  evidence.signature.publicKeySha256 = createHash("sha256").update(releasePublicKeyDer).digest("hex");
  evidence.independentReview.publicKeySha256 = createHash("sha256").update(reviewPublicKeyDer).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("independentReview")));
});
