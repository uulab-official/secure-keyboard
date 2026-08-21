import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { validateDeviceEvidence, verifyDeviceEvidenceFiles } from "./check-device-evidence.mjs";

const COMMIT = "e".repeat(40);
const TEST_CASES = [
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
  "native-checksum",
];

async function loadEmitter() {
  try {
    return await import("./emit-native-device-evidence.mjs");
  } catch (error) {
    assert.fail(`native evidence emitter is missing: ${error.message}`);
  }
}

function completeInput() {
  return {
    commit: COMMIT,
    platform: "ios",
    framework: "react-native",
    frameworkVersion: "0.87.0",
    model: "iPhone 17 Pro",
    osVersion: "26.5",
    osBuild: "23A000",
    recordedAt: "2026-08-22T00:00:00.000Z",
    log: { path: "logs/ios-rn.txt", bytes: Buffer.from("sanitized physical-device log\n") },
    testCases: Object.fromEntries(TEST_CASES.map((name) => [name, "pass"])),
    artifacts: ARTIFACT_KINDS.map((kind, index) => ({
      kind,
      path: `artifacts/${index}.bin`,
      bytes: Buffer.from(`sanitized:${kind}\n`),
    })),
  };
}

test("builds complete sanitized physical native evidence with hashed artifacts", async () => {
  const { buildNativeDeviceEvidence } = await loadEmitter();
  const record = buildNativeDeviceEvidence(completeInput());

  assert.deepEqual(
    validateDeviceEvidence(record, { expectedCommit: COMMIT, requirePhysicalDevice: true }),
    [],
  );
  assert.equal(record.status, "pass");
  assert.equal(record.gate, "ios-device-matrix");
  assert.equal(record.physicalDevice, true);
  assert.equal(record.logSha256, createHash("sha256").update(completeInput().log.bytes).digest("hex"));
  assert.equal(Object.hasOwn(record, "rawLogs"), false);
  assert.equal(Object.hasOwn(record, "rawInput"), false);
});

test("writes a commit-bound native evidence record and fragment from files", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-native-evidence-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  for (const artifact of input.artifacts) writeFileSync(join(root, artifact.path), artifact.bytes);

  const result = writeNativeDeviceEvidence({
    root,
    packageVersion: "0.1.0",
    evidencePath: "device/ios-rn.json",
    fragmentPath: "fragments/ios-rn.json",
    ...input,
    logPath: input.log.path,
    artifactPaths: input.artifacts.map(({ kind, path }) => ({ kind, path })),
  });
  const evidence = JSON.parse(readFileSync(join(root, "device/ios-rn.json"), "utf8"));
  const fragment = JSON.parse(readFileSync(join(root, "fragments/ios-rn.json"), "utf8"));

  assert.deepEqual(evidence, result.record);
  assert.equal(fragment.gates[0].evidencePath, "device/ios-rn.json");
  assert.deepEqual(verifyDeviceEvidenceFiles(evidence, root), []);
});

test("rejects incomplete test cases and required physical artifact categories", async () => {
  const { buildNativeDeviceEvidence } = await loadEmitter();
  const incomplete = completeInput();
  delete incomplete.testCases.protocolDowngrade;
  incomplete.artifacts = incomplete.artifacts.filter(({ kind }) => kind !== "crash-report-review");

  assert.throws(() => buildNativeDeviceEvidence(incomplete), /testCases\.protocolDowngrade/);
  assert.throws(() => buildNativeDeviceEvidence({ ...completeInput(), artifacts: incomplete.artifacts }), /crash-report-review/);
});

test("rejects oversized physical evidence bytes before hashing", async () => {
  const { MAX_NATIVE_EVIDENCE_FILE_BYTES, buildNativeDeviceEvidence } = await loadEmitter();
  const oversized = completeInput();
  const maxBytes = MAX_NATIVE_EVIDENCE_FILE_BYTES ?? 32 * 1024 * 1024;
  oversized.log.bytes = Buffer.alloc(maxBytes + 1);

  assert.throws(() => buildNativeDeviceEvidence(oversized), /log bytes must not exceed/);
});

test("rejects a sentinel in a referenced physical-device artifact before writing evidence", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-native-sentinel-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  for (const artifact of input.artifacts) {
    writeFileSync(
      join(root, artifact.path),
      artifact.kind === "screen-capture" ? "secure-keypad-test-sentinel-7f2c4e" : artifact.bytes,
    );
  }

  assert.throws(
    () =>
      writeNativeDeviceEvidence({
        root,
        packageVersion: "0.1.0",
        evidencePath: "device/ios-rn.json",
        fragmentPath: "fragments/ios-rn.json",
        ...input,
        logPath: input.log.path,
        artifactPaths: input.artifacts.map(({ kind, path }) => ({ kind, path })),
      }),
    /canonical test sentinel/,
  );
  assert.equal(existsSync(join(root, "device/ios-rn.json")), false);
  assert.equal(existsSync(join(root, "fragments/ios-rn.json")), false);
});
