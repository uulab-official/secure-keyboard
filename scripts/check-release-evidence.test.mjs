import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import {
  REQUIRED_RELEASE_GATES,
  verifyReleaseEvidenceFiles,
  validateReleaseEvidence,
} from "./check-release-evidence.mjs";

const SHA256 = "a".repeat(64);

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
      { kind: "release-signature", path: "artifacts/secure-keypad.release.sigstore.json", sha256: SHA256 },
    ],
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

test("verifies every referenced release evidence and artifact digest", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-evidence-"));
  const evidence = completeEvidence();
  const payload = Buffer.from("release-evidence-fixture", "utf8");
  const sha256 = createHash("sha256").update(payload).digest("hex");

  for (const gate of evidence.gates) {
    mkdirSync(join(root, "evidence"), { recursive: true });
    writeFileSync(join(root, gate.evidencePath), payload);
    gate.sha256 = sha256;
  }
  for (const artifact of evidence.artifacts) {
    mkdirSync(join(root, "artifacts"), { recursive: true });
    writeFileSync(join(root, artifact.path), payload);
    artifact.sha256 = sha256;
  }

  assert.deepEqual(verifyReleaseEvidenceFiles(evidence, root), []);

  writeFileSync(join(root, evidence.artifacts[0].path), Buffer.from("tampered", "utf8"));
  const findings = verifyReleaseEvidenceFiles(evidence, root);
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].sha256")));
});
