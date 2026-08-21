import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  CI_RELEASE_GATE_CHECKS,
  REQUIRED_RELEASE_GATES,
  validateReleaseEvidence,
} from "./check-release-evidence.mjs";
import { mergeReleaseEvidence, writeMergedEvidence } from "./merge-release-evidence.mjs";

const SHA256 = "a".repeat(64);
const MERGE_SCRIPT = fileURLToPath(new URL("./merge-release-evidence.mjs", import.meta.url));
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

function writeDeviceGateEvidence(
  root,
  gate,
  platform = { "ios-device-matrix": "ios", "android-device-matrix": "android", "web-browser-matrix": "web" }[
    gate.name
  ],
) {
  const isWeb = platform === "web";
  mkdirSync(join(root, "device"), { recursive: true });
  const logPath = `device/${gate.name}.log`;
  const logBytes = Buffer.from(`${gate.name} sanitized log\n`, "utf8");
  writeFileSync(join(root, logPath), logBytes);
  const artifacts = (isWeb ? [{ kind: "browser-report" }] : PHYSICAL_ARTIFACT_KINDS.map((kind) => ({ kind }))).map(
    ({ kind }, index) => {
      const artifactPath = `device/${gate.name}-${index}.bin`;
      const bytes = Buffer.from(`${gate.name}:${kind}\n`, "utf8");
      writeFileSync(join(root, artifactPath), bytes);
      return { kind, path: artifactPath, sha256: createHash("sha256").update(bytes).digest("hex") };
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
  writeFileSync(join(root, gate.evidencePath), payload);
  gate.sha256 = createHash("sha256").update(payload).digest("hex");
}

function completeFragments() {
  const context = baseContext();
  const gates = REQUIRED_RELEASE_GATES.map((name) => ({
    name,
    commit: context.commit,
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
        reviewedCommit: context.commit,
        reviewedPackageVersion: context.packageVersion,
      },
    },
  ];
}

function gateEvidence(gateName, commit) {
  const checks = CI_RELEASE_GATE_CHECKS[gateName];
  return {
    schemaVersion: 1,
    commit,
    gate: gateName,
    status: "pass",
    ...(checks === undefined
      ? {}
      : {
          evidenceKind: "ci-command",
          runner: "ci-aggregate",
          recordedAt: "2026-08-21T00:00:00.000Z",
          checks: checks[0],
        }),
  };
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
  const evidenceBytes = Buffer.from(
    JSON.stringify({ schemaVersion: 1, commit, gate: "rust-workspace", status: "pass" }),
    "utf8",
  );
  const releaseBytes = Buffer.from("signed release bundle", "utf8");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  const releaseSignature = sign(null, releaseBytes, privateKey);
  const { privateKey: reviewPrivateKey, publicKey: reviewPublicKey } = generateKeyPairSync("ed25519");
  const reviewPublicKeyBytes = reviewPublicKey.export({ format: "der", type: "spki" });
  const reviewPublicKeySha256 = createHash("sha256").update(reviewPublicKeyBytes).digest("hex");
  const reviewBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      reportType: "independent-security-review",
      reviewedCommit: commit,
      reviewedPackageVersion: context.packageVersion,
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
  const reviewSignature = sign(null, reviewBytes, reviewPrivateKey);
  const hash = (value) => createHash("sha256").update(value).digest("hex");

  const gates = REQUIRED_RELEASE_GATES.map((name) => ({
    name,
    commit,
    status: "pass",
    evidencePath: `evidence/${name}.json`,
    sha256: SHA256,
  }));
  const platformByGate = {
    "ios-device-matrix": "ios",
    "android-device-matrix": "android",
    "web-browser-matrix": "web",
  };
  for (const gate of gates) {
    if (platformByGate[gate.name]) {
      writeDeviceGateEvidence(root, gate, platformByGate[gate]);
    } else {
      const gateEvidenceBytes = Buffer.from(
        JSON.stringify(gateEvidence(gate.name, commit)),
        "utf8",
      );
      writeFileSync(join(root, gate.evidencePath), gateEvidenceBytes);
      gate.sha256 = hash(gateEvidenceBytes);
    }
  }

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
        reviewedCommit: commit,
        reviewedPackageVersion: context.packageVersion,
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
