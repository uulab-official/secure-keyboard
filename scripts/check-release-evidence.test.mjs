import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  CI_RELEASE_GATE_CHECKS,
  REQUIRED_RELEASE_GATES,
  verifyReleaseEvidenceFiles,
  validateReleaseEvidence,
} from "./check-release-evidence.mjs";

const SHA256 = "a".repeat(64);
const CHECK_SCRIPT = fileURLToPath(new URL("./check-release-evidence.mjs", import.meta.url));

const NATIVE_TEST_CASES = [
  "maskedStateOnly",
  "captureAndBackground",
  "screenshotsAndBackgroundSnapshots",
  "autofillAndClipboard",
  "accessibility",
  "crashReportReview",
  "lifecycleAndZeroization",
  "serverReplayRateLimit",
  "protocolDowngrade",
];
const WEB_TEST_CASES = ["passkeySecureContext", "originAndRpId", "boundedOptions", "fallbackWarning"];
const PHYSICAL_ARTIFACT_KINDS = [
  "screen-capture",
  "background-snapshot",
  "accessibility-report",
  "autofill-clipboard-report",
  "crash-report-review",
  "native-checksum",
];

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
      commit: "b".repeat(40),
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
      reviewedCommit: "b".repeat(40),
      reviewedPackageVersion: "0.1.0",
    },
  };
}

function writeDeviceGateEvidence(root, gate, platform) {
  const isWeb = platform === "web";
  const directory = join(root, "device");
  mkdirSync(directory, { recursive: true });
  const logPath = `device/${gate.name}.log`;
  const logBytes = Buffer.from(`${gate.name} sanitized log\n`, "utf8");
  writeFileSync(join(root, logPath), logBytes);
  const artifacts = (isWeb ? [{ kind: "browser-report" }] : PHYSICAL_ARTIFACT_KINDS.map((kind) => ({ kind }))).map(
    ({ kind }, index) => {
      const artifactPath = `device/${gate.name}-${index}.bin`;
      const bytes = Buffer.from(`${gate.name}:${kind}\n`, "utf8");
      writeFileSync(join(root, artifactPath), bytes);
      return {
        kind,
        path: artifactPath,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
    },
  );
  const record = {
    schemaVersion: 1,
    commit: gate.commit,
    gate: gate.name,
    status: "pass",
    platform,
    framework: isWeb ? "web" : "native",
    frameworkVersion: isWeb ? "chromium-140.0.0" : "1.0.0",
    recordedAt: "2026-08-21T00:00:00.000Z",
    physicalDevice: !isWeb,
    device: isWeb
      ? { browser: "Chromium", browserVersion: "140.0.0", osVersion: "macOS 15", secureContext: true }
      : { model: platform === "ios" ? "iPhone 16" : "Pixel 9", osVersion: "15", osBuild: "release" },
    testCases: Object.fromEntries((isWeb ? WEB_TEST_CASES : NATIVE_TEST_CASES).map((name) => [name, "pass"])),
    sanitizedLogs: true,
    logPath,
    logSha256: createHash("sha256").update(logBytes).digest("hex"),
    artifacts,
  };
  const payload = Buffer.from(JSON.stringify(record), "utf8");
  mkdirSync(join(root, "evidence"), { recursive: true });
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");
  return record;
}

function writeCompleteEvidenceFixture(root) {
  const evidence = completeEvidence();
  const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
  evidence.commit = commit;
  evidence.gates.forEach((gate) => {
    gate.commit = commit;
  });
  evidence.independentReview.reviewedCommit = commit;

  const payload = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit, gate: "rust-workspace", status: "pass" }),
    "utf8",
  );
  const sha256 = createHash("sha256").update(payload).digest("hex");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const releasePayload = Buffer.from("signed-release-fixture", "utf8");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const signature = sign(null, releasePayload, privateKey);
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPublicKeyDer = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewPublicKeySha256 = createHash("sha256").update(reviewPublicKeyDer).digest("hex");
  const reviewPayload = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      reportType: "independent-security-review",
      reviewedCommit: commit,
      reviewedPackageVersion: evidence.packageVersion,
      reviewerPublicKeySha256: reviewPublicKeySha256,
      scope: [
        "native-input-boundary",
        "opaque-authentication",
        "http-json-transport",
        "replay-rate-limit-backends",
        "framework-adapters",
        "device-runtime-evidence",
        "release-process",
      ],
      findings: [],
      decision: "approved",
    }),
    "utf8",
  );
  const reviewSignature = sign(null, reviewPayload, reviewPrivateKey);

  mkdirSync(join(root, "evidence"), { recursive: true });
  const platformByGate = {
    "ios-device-matrix": "ios",
    "android-device-matrix": "android",
    "web-browser-matrix": "web",
  };
  for (const gate of evidence.gates) {
    const platform = platformByGate[gate.name];
    if (platform) {
      writeDeviceGateEvidence(root, gate, platform);
    } else {
      const ciChecks = CI_RELEASE_GATE_CHECKS[gate.name];
      const gatePayload = Buffer.from(
        JSON.stringify({
          schemaVersion: 1,
          commit,
          gate: gate.name,
          status: "pass",
          ...(ciChecks === undefined
            ? {}
            : {
                evidenceKind: "ci-command",
                runner: "ci-aggregate",
                recordedAt: "2026-08-21T00:00:00.000Z",
                checks: ciChecks[0],
              }),
        }),
        "utf8",
      );
      writeFileSync(join(root, gate.evidencePath), gatePayload);
      gate.sha256 = createHash("sha256").update(gatePayload).digest("hex");
    }
  }

  mkdirSync(join(root, "artifacts"), { recursive: true });
  for (const artifact of evidence.artifacts) {
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
  return evidence;
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
  evidence.sanitized = { sentinel: "fixture-only-sentinel", inputBytes: [1, 2, 3] };
  evidence.value = "must never be recorded";

  const findings = validateReleaseEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("commit")));
  assert.ok(findings.some((finding) => finding.includes("status")));
  assert.ok(findings.some((finding) => finding.includes("evidencePath")));
  assert.ok(findings.some((finding) => finding.includes("sha256")));
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].path")));
  assert.ok(findings.some((finding) => finding.includes("password")));
  assert.ok(findings.some((finding) => finding.includes("sentinel")));
  assert.ok(findings.some((finding) => finding.includes("inputBytes")));
  assert.ok(findings.some((finding) => finding.includes("value")));
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
  assert.ok(findings.some((finding) => finding.includes("reviewedCommit") && finding.includes("manifest")));
  assert.ok(
    findings.some(
      (finding) => finding.includes("reviewedPackageVersion") && finding.includes("manifest"),
    ),
  );
});

test("requires every release gate to bind the exact manifest commit", () => {
  const missingCommit = completeEvidence();
  delete missingCommit.gates[0].commit;
  const missingFindings = validateReleaseEvidence(missingCommit);
  assert.ok(missingFindings.some((finding) => finding.includes("gates[0].commit")));

  const mismatchedCommit = completeEvidence();
  mismatchedCommit.gates[1].commit = "c".repeat(40);
  const mismatchFindings = validateReleaseEvidence(mismatchedCommit);
  assert.ok(
    mismatchFindings.some(
      (finding) => finding.includes("gates[1].commit") && finding.includes("manifest"),
    ),
  );
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

test("requires an independent review to bind the exact commit and package version", () => {
  const evidence = completeEvidence();
  delete evidence.independentReview.reviewedCommit;
  delete evidence.independentReview.reviewedPackageVersion;

  const findings = validateReleaseEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("independentReview.reviewedCommit")));
  assert.ok(findings.some((finding) => finding.includes("independentReview.reviewedPackageVersion")));
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

test("CLI verifies referenced files relative to a nested evidence manifest", () => {
  const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
  const container = mkdtempSync(join(tmpdir(), "secure-keypad-nested-release-evidence-"));
  const evidenceRoot = join(container, "release-evidence");
  mkdirSync(evidenceRoot, { recursive: true });
  const evidence = writeCompleteEvidenceFixture(evidenceRoot);
  const manifestPath = join(evidenceRoot, "release-evidence.json");
  writeFileSync(manifestPath, `${JSON.stringify(evidence, null, 2)}\n`);

  const result = spawnSync(process.execPath, [CHECK_SCRIPT, manifestPath], {
    cwd: repositoryRoot,
    env: process.env,
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /release evidence schema valid/);
});

test("verifies every referenced release evidence and artifact digest", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-evidence-"));
  const evidence = completeEvidence();
  const payload = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit: evidence.commit, gate: "rust-workspace", status: "pass" }),
    "utf8",
  );
  const sha256 = createHash("sha256").update(payload).digest("hex");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const releasePayload = Buffer.from("signed-release-fixture", "utf8");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const signature = sign(null, releasePayload, privateKey);
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPublicKeyDer = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewPublicKeySha256 = createHash("sha256").update(reviewPublicKeyDer).digest("hex");
  const reviewPayload = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      reportType: "independent-security-review",
      reviewedCommit: evidence.commit,
      reviewedPackageVersion: evidence.packageVersion,
      reviewerPublicKeySha256: reviewPublicKeySha256,
      scope: [
        "native-input-boundary",
        "opaque-authentication",
        "http-json-transport",
        "replay-rate-limit-backends",
        "framework-adapters",
        "device-runtime-evidence",
        "release-process",
      ],
      findings: [],
      decision: "approved",
    }),
    "utf8",
  );
  const reviewSignature = sign(null, reviewPayload, reviewPrivateKey);

  for (const gate of evidence.gates) {
    mkdirSync(join(root, "evidence"), { recursive: true });
    const platformByGate = {
      "ios-device-matrix": "ios",
      "android-device-matrix": "android",
      "web-browser-matrix": "web",
    };
    if (platformByGate[gate.name]) {
      writeDeviceGateEvidence(root, gate, platformByGate[gate.name]);
    } else {
      const ciChecks = CI_RELEASE_GATE_CHECKS[gate.name];
      const gatePayload = Buffer.from(
        JSON.stringify({
          schemaVersion: 1,
          commit: evidence.commit,
          gate: gate.name,
          status: "pass",
          ...(ciChecks === undefined
            ? {}
            : {
                evidenceKind: "ci-command",
                runner: "ci-aggregate",
                recordedAt: "2026-08-21T00:00:00.000Z",
                checks: ciChecks[0],
              }),
        }),
        "utf8",
      );
      writeFileSync(join(root, gate.evidencePath), gatePayload);
      gate.sha256 = createHash("sha256").update(gatePayload).digest("hex");
    }
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

test("rejects empty release artifacts before accepting their digest", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-empty-release-artifact-"));
  const evidence = writeCompleteEvidenceFixture(root);
  const artifactIndex = evidence.artifacts.findIndex(({ kind }) => kind === "sbom");
  const artifact = evidence.artifacts[artifactIndex];
  const emptyBytes = Buffer.alloc(0);

  writeFileSync(join(root, artifact.path), emptyBytes);
  artifact.sha256 = createHash("sha256").update(emptyBytes).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(
    findings.some(
      (finding) => finding.includes(`artifacts[${artifactIndex}].path`) && finding.includes("must not be empty"),
    ),
  );
});

test("rejects a gate evidence record bound to a different commit", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-evidence-commit-"));
  const evidence = completeEvidence();
  const gate = evidence.gates[0];
  const payload = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit: "c".repeat(40), gate: gate.name, status: "pass" }),
    "utf8",
  );
  mkdirSync(join(root, "evidence"), { recursive: true });
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("gate evidence commit")));
});

test("rejects a gate evidence record reused for a different release gate", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-evidence-gate-"));
  const evidence = completeEvidence();
  const gate = evidence.gates[0];
  const payload = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit: gate.commit, gate: "javascript-contracts", status: "pass" }),
    "utf8",
  );
  mkdirSync(join(root, "evidence"), { recursive: true });
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("gate evidence gate")));
});

test("rejects an under-specified CI gate evidence record", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-ci-gate-"));
  const evidence = completeEvidence();
  const gate = evidence.gates.find((candidate) => candidate.name === "fuzz-stability");
  const payload = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      status: "pass",
      commit: gate.commit,
      gate: gate.name,
      evidenceKind: "ci-command",
      runner: "ubuntu-24.04",
      recordedAt: "2026-08-22T00:00:00.000Z",
      checks: ["unrelated-check"],
    }),
    "utf8",
  );
  mkdirSync(join(root, "evidence"), { recursive: true });
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("gates[5].evidence.checks")));
});

test("does not allow a minimal JSON object to satisfy a physical device gate", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-device-gate-"));
  const evidence = completeEvidence();
  const gate = evidence.gates.find((candidate) => candidate.name === "ios-device-matrix");
  const payload = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit: gate.commit, gate: gate.name, status: "pass" }),
    "utf8",
  );
  mkdirSync(join(root, "evidence"), { recursive: true });
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("gates[8].device")));
});

test("binds each device gate to its platform and nested evidence files", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-device-binding-"));
  const evidence = completeEvidence();
  const iosGate = evidence.gates.find((candidate) => candidate.name === "ios-device-matrix");
  writeDeviceGateEvidence(root, iosGate, "ios");
  const recordPath = join(root, "evidence", "ios-device-matrix.json");
  const record = JSON.parse(readFileSync(recordPath, "utf8"));
  record.platform = "android";
  writeFileSync(recordPath, JSON.stringify(record));
  const findings = verifyReleaseEvidenceFiles(evidence, root);
  assert.ok(findings.some((finding) => finding.includes("must equal ios")));

  writeFileSync(join(root, record.logPath), Buffer.from("tampered\n", "utf8"));
  const tamperedFindings = verifyReleaseEvidenceFiles(evidence, root);
  assert.ok(tamperedFindings.some((finding) => finding.includes("device.files") && finding.includes("logSha256")));
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

test("rejects an empty independently signed review report", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-empty-review-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const emptyReport = Buffer.alloc(0);
  const signature = sign(null, emptyReport, privateKey);
  const evidence = {
    gates: [],
    artifacts: [],
    independentReview: {
      algorithm: "ed25519",
      publicKeyPath: "review/reviewer.pub.der",
      signedArtifactPath: "review/report.bin",
      signaturePath: "review/report.sig",
      publicKeySha256: createHash("sha256").update(publicKeyDer).digest("hex"),
    },
  };
  mkdirSync(join(root, "review"), { recursive: true });
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signedArtifactPath), emptyReport);
  writeFileSync(join(root, evidence.independentReview.signaturePath), signature);

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("independentReview") && finding.includes("non-empty")));
});

test("rejects a signed review report without structured scope and release decision", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-unstructured-review-"));
  const evidence = writeCompleteEvidenceFixture(root);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  const report = Buffer.from(
    JSON.stringify({ schemaVersion: 1, reportType: "independent-security-review" }),
    "utf8",
  );
  const reportArtifact = evidence.artifacts.find(({ kind }) => kind === "independent-review-report");
  writeFileSync(join(root, reportArtifact.path), report);
  reportArtifact.sha256 = createHash("sha256").update(report).digest("hex");
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signaturePath), sign(null, report, privateKey));
  evidence.independentReview.publicKeySha256 = publicKeySha256;
  evidence.artifacts.find(({ kind }) => kind === "independent-review-public-key").sha256 = publicKeySha256;

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("independentReview.report.reviewedCommit")));
  assert.ok(findings.some((finding) => finding.includes("independentReview.report.scope")));
  assert.ok(findings.some((finding) => finding.includes("independentReview.report.decision")));
});

test("rejects an oversized signed review report before parsing it", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-oversized-review-"));
  const evidence = writeCompleteEvidenceFixture(root);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  const report = Buffer.from(JSON.stringify({ padding: "x".repeat(1_048_576) }), "utf8");
  const reportArtifact = evidence.artifacts.find(({ kind }) => kind === "independent-review-report");
  writeFileSync(join(root, reportArtifact.path), report);
  reportArtifact.sha256 = createHash("sha256").update(report).digest("hex");
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signaturePath), sign(null, report, privateKey));
  evidence.independentReview.publicKeySha256 = publicKeySha256;
  evidence.artifacts.find(({ kind }) => kind === "independent-review-public-key").sha256 = publicKeySha256;

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("independentReview.report") && finding.includes("must not exceed")));
});

test("rejects an approving review report with an open critical finding", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-open-critical-review-"));
  const evidence = writeCompleteEvidenceFixture(root);
  const reportArtifact = evidence.artifacts.find(({ kind }) => kind === "independent-review-report");
  const report = JSON.parse(readFileSync(join(root, reportArtifact.path), "utf8"));
  report.findings = [{
    id: "CRITICAL-1",
    severity: "critical",
    status: "open",
    summary: "Unresolved critical issue",
    affectedScope: ["native-input-boundary"],
    reproduction: "Review the native submission handoff under the stated device conditions",
    remediationOwner: "security-team",
    retestEvidence: "Pending remediation and independent retest",
  }];
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  report.reviewerPublicKeySha256 = publicKeySha256;
  const signedReportBytes = Buffer.from(JSON.stringify(report), "utf8");

  writeFileSync(join(root, reportArtifact.path), signedReportBytes);
  reportArtifact.sha256 = createHash("sha256").update(signedReportBytes).digest("hex");
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signaturePath), sign(null, signedReportBytes, privateKey));
  evidence.independentReview.publicKeySha256 = publicKeySha256;
  evidence.artifacts.find(({ kind }) => kind === "independent-review-public-key").sha256 = publicKeySha256;

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("CRITICAL-1") && finding.includes("accepted or remediated")));
});

test("rejects a review finding without scope, reproduction, ownership, and retest evidence", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-incomplete-review-finding-"));
  const evidence = writeCompleteEvidenceFixture(root);
  const reportArtifact = evidence.artifacts.find(({ kind }) => kind === "independent-review-report");
  const report = JSON.parse(readFileSync(join(root, reportArtifact.path), "utf8"));
  report.findings = [{
    id: "MEDIUM-1",
    severity: "medium",
    status: "accepted",
    summary: "Residual risk requires explicit reviewer accountability",
  }];
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = createHash("sha256").update(publicKeyDer).digest("hex");
  report.reviewerPublicKeySha256 = publicKeySha256;
  const signedReportBytes = Buffer.from(JSON.stringify(report), "utf8");

  writeFileSync(join(root, reportArtifact.path), signedReportBytes);
  reportArtifact.sha256 = createHash("sha256").update(signedReportBytes).digest("hex");
  writeFileSync(join(root, evidence.independentReview.publicKeyPath), publicKeyDer);
  writeFileSync(join(root, evidence.independentReview.signaturePath), sign(null, signedReportBytes, privateKey));
  evidence.independentReview.publicKeySha256 = publicKeySha256;
  evidence.artifacts.find(({ kind }) => kind === "independent-review-public-key").sha256 = publicKeySha256;

  const findings = verifyReleaseEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("findings[0].affectedScope")));
  assert.ok(findings.some((finding) => finding.includes("findings[0].reproduction")));
  assert.ok(findings.some((finding) => finding.includes("findings[0].remediationOwner")));
  assert.ok(findings.some((finding) => finding.includes("findings[0].retestEvidence")));
});
