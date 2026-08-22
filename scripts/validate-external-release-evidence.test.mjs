import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { buildNativeDeviceEvidence } from "./emit-native-device-evidence.mjs";
import { buildIndependentReviewFragment } from "./emit-independent-review-fragment.mjs";
import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";

const COMMIT = "f".repeat(40);
const PACKAGE_VERSION = "0.1.0";
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
const ARTIFACT_KINDS = [
  "screen-capture",
  "background-snapshot",
  "accessibility-report",
  "autofill-clipboard-report",
  "crash-report-review",
  "platform-security-patch",
  "native-checksum",
];

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function nativeRecord(root, platform) {
  const prefix = platform === "ios" ? "ios" : "android";
  const artifactPaths = ARTIFACT_KINDS.map((kind, index) => ({
    kind,
    path: `artifacts/${prefix}-${index}.bin`,
    bytes: Buffer.from(`${prefix}:${kind}:sanitized\n`, "utf8"),
  }));
  const aggregateLog = {
    path: `logs/${prefix}-aggregate.log`,
    bytes: Buffer.from(`${prefix}:sanitized aggregate log\n`, "utf8"),
  };
  const hostModes = ["react-native", "flutter"].map((framework) => {
    const bytes = Buffer.from(`${prefix}:${framework}:sanitized host log\n`, "utf8");
    return {
      framework,
      frameworkVersion: framework === "react-native" ? "0.87.0" : "3.47.0",
      status: "pass",
      evidence: {
        logPath: `logs/${prefix}-${framework}.log`,
        logSha256: hash(bytes),
      },
    };
  });
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, aggregateLog.path), aggregateLog.bytes);
  for (const hostMode of hostModes) {
    writeFileSync(
      join(root, hostMode.evidence.logPath),
      Buffer.from(`${prefix}:${hostMode.framework}:sanitized host log\n`, "utf8"),
    );
  }
  for (const artifact of artifactPaths) writeFileSync(join(root, artifact.path), artifact.bytes);

  const artifactPath = (kind) => artifactPaths.find((artifact) => artifact.kind === kind).path;
  const testEvidence = {
    maskedStateOnly: [aggregateLog.path],
    captureAndBackground: [artifactPath("screen-capture"), artifactPath("background-snapshot")],
    screenshotsAndBackgroundSnapshots: [artifactPath("screen-capture"), artifactPath("background-snapshot")],
    autofillAndClipboard: [artifactPath("autofill-clipboard-report")],
    accessibility: [artifactPath("accessibility-report")],
    crashReportReview: [artifactPath("crash-report-review")],
    lifecycleAndZeroization: [aggregateLog.path],
    serverReplayRateLimit: [aggregateLog.path],
    protocolDowngrade: [aggregateLog.path],
  };
  return buildNativeDeviceEvidence({
    commit: COMMIT,
    platform,
    framework: "native",
    frameworkVersion: "0.1.0",
    hostModes,
    model: platform === "ios" ? "iPhone 17 Pro" : "Pixel 9",
    osVersion: platform === "ios" ? "26.5" : "15",
    osBuild: "release-build",
    securityPatchLevel: platform === "ios" ? "26.5" : "2026-01-01",
    ...(platform === "android" ? { apiLevel: 35 } : {}),
    recordedAt: "2026-08-23T00:00:00.000Z",
    log: aggregateLog,
    testCases: Object.fromEntries(NATIVE_TEST_CASES.map((name) => [name, "pass"])),
    testEvidence,
    artifacts: artifactPaths,
  });
}

function writeNativeGate(root, platform) {
  const record = nativeRecord(root, platform);
  const evidencePath = `evidence/${platform}-device.json`;
  const fragmentPath = `fragments/${platform}-device.json`;
  mkdirSync(join(root, "evidence"), { recursive: true });
  mkdirSync(join(root, "fragments"), { recursive: true });
  const evidenceBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  writeFileSync(join(root, evidencePath), evidenceBytes);
  writeFileSync(
    join(root, fragmentPath),
    `${JSON.stringify(
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: PACKAGE_VERSION,
        gateName: record.gate,
        evidencePath,
        evidenceBytes,
      }),
      null,
      2,
    )}\n`,
  );
}

function writeReviewGate(root, overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  const report = {
    schemaVersion: 1,
    reportType: "independent-security-review",
    reviewedCommit: COMMIT,
    reviewedPackageVersion: PACKAGE_VERSION,
    reviewerPublicKeySha256: hash(publicKeyBytes),
    scope: [
      "native-input-boundary",
      "opaque-authentication",
      "http-json-transport",
      "replay-rate-limit-backends",
      "framework-adapters",
      "device-runtime-evidence",
      "release-process",
    ],
    findings: overrides.findings ?? [],
    decision: "approved-with-residual-risk",
  };
  const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`, "utf8");
  const signatureBytes = sign(null, reportBytes, privateKey);
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, "artifacts/independent-review.json"), reportBytes);
  writeFileSync(join(root, "artifacts/independent-review.sig"), signatureBytes);
  writeFileSync(join(root, "artifacts/independent-review.pub.der"), publicKeyBytes);

  const fragment = overrides.skipBuilder
    ? (() => {
        const evidence = {
          schemaVersion: 1,
          gate: "independent-security-review",
          status: "pass",
          evidenceKind: "independent-security-review",
          commit: COMMIT,
          packageVersion: PACKAGE_VERSION,
          reviewedCommit: COMMIT,
          reviewedPackageVersion: PACKAGE_VERSION,
          reviewerPublicKeySha256: hash(publicKeyBytes),
          reportPath: "artifacts/independent-review.json",
          reportSha256: hash(reportBytes),
          signaturePath: "artifacts/independent-review.sig",
          signatureSha256: hash(signatureBytes),
          publicKeyPath: "artifacts/independent-review.pub.der",
        };
        const evidenceBytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
        return {
          ...buildReleaseGateFragment({
            commit: COMMIT,
            packageVersion: PACKAGE_VERSION,
            gateName: "independent-security-review",
            evidencePath: "evidence/independent-security-review.json",
            evidenceBytes,
          }),
          evidence,
          artifacts: [
            { kind: "independent-review-report", path: "artifacts/independent-review.json", sha256: hash(reportBytes) },
            { kind: "independent-review-public-key", path: "artifacts/independent-review.pub.der", sha256: hash(publicKeyBytes) },
            { kind: "independent-review-signature", path: "artifacts/independent-review.sig", sha256: hash(signatureBytes) },
          ],
          independentReview: {
            algorithm: "ed25519",
            publicKeyPath: "artifacts/independent-review.pub.der",
            signedArtifactPath: "artifacts/independent-review.json",
            signaturePath: "artifacts/independent-review.sig",
            publicKeySha256: hash(publicKeyBytes),
            reviewedCommit: COMMIT,
            reviewedPackageVersion: PACKAGE_VERSION,
          },
        };
      })()
    : buildIndependentReviewFragment({
        commit: COMMIT,
        packageVersion: PACKAGE_VERSION,
        reportPath: "artifacts/independent-review.json",
        reportBytes,
        signaturePath: "artifacts/independent-review.sig",
        signatureBytes,
        publicKeyPath: "artifacts/independent-review.pub.der",
        publicKeyBytes,
        evidencePath: "evidence/independent-security-review.json",
      });
  writeFileSync(join(root, "evidence/independent-security-review.json"), `${JSON.stringify(fragment.evidence, null, 2)}\n`);
  writeFileSync(join(root, "fragments/independent-security-review.json"), `${JSON.stringify(fragment, null, 2)}\n`);
}

async function loadValidator() {
  return import("./validate-external-release-evidence.mjs");
}

function completeFixture() {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-external-evidence-"));
  writeNativeGate(root, "ios");
  writeNativeGate(root, "android");
  writeReviewGate(root);
  return root;
}

test("accepts physical iOS/Android and independently signed review evidence for one commit", async () => {
  const { validateExternalReleaseEvidence } = await loadValidator();
  const root = completeFixture();
  try {
    const result = validateExternalReleaseEvidence(root, {
      expectedCommit: COMMIT,
      expectedPackageVersion: PACKAGE_VERSION,
    });
    assert.deepEqual(result.gates, [
      "android-device-matrix",
      "independent-security-review",
      "ios-device-matrix",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects external evidence from a different commit before upload", async () => {
  const { validateExternalReleaseEvidence } = await loadValidator();
  const root = completeFixture();
  try {
    const evidencePath = join(root, "evidence/android-device.json");
    const record = JSON.parse(await import("node:fs/promises").then(({ readFile }) => readFile(evidencePath, "utf8")));
    record.commit = "a".repeat(40);
    writeFileSync(evidencePath, JSON.stringify(record));
    assert.throws(
      () => validateExternalReleaseEvidence(root, { expectedCommit: COMMIT, expectedPackageVersion: PACKAGE_VERSION }),
      /android-device\.json|commit|fragment/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects an external gate fragment with a different package version", async () => {
  const { validateExternalReleaseEvidence } = await loadValidator();
  const root = completeFixture();
  try {
    const fragmentPath = join(root, "fragments/ios-device.json");
    const fragment = JSON.parse(readFileSync(fragmentPath, "utf8"));
    fragment.packageVersion = "9.9.9";
    writeFileSync(fragmentPath, JSON.stringify(fragment));
    assert.throws(
      () => validateExternalReleaseEvidence(root, { expectedCommit: COMMIT, expectedPackageVersion: PACKAGE_VERSION }),
      /package version/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects symlinked external evidence before artifact upload", async () => {
  const { validateExternalReleaseEvidence } = await loadValidator();
  const root = completeFixture();
  try {
    symlinkSync("independent-review.json", join(root, "artifacts/private-link.json"));
    assert.throws(
      () => validateExternalReleaseEvidence(root, { expectedCommit: COMMIT, expectedPackageVersion: PACKAGE_VERSION }),
      /symbolic link|symlink/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a signed independent review with a malformed finding before artifact upload", async () => {
  const { validateExternalReleaseEvidence } = await loadValidator();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-malformed-review-"));
  writeNativeGate(root, "ios");
  writeNativeGate(root, "android");
  writeReviewGate(root, { findings: [{}], skipBuilder: true });
  try {
    assert.throws(
      () => validateExternalReleaseEvidence(root, { expectedCommit: COMMIT, expectedPackageVersion: PACKAGE_VERSION }),
      /finding|severity|status|affectedScope/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
