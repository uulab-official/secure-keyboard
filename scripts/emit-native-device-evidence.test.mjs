import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
    hostModes: [
      {
        framework: "react-native",
        frameworkVersion: "0.87.0",
        status: "pass",
        evidence: {
          logPath: "logs/react-native-host.txt",
          logSha256: createHash("sha256").update("react-native sanitized host log\n").digest("hex"),
        },
      },
      {
        framework: "flutter",
        frameworkVersion: "3.47.0",
        status: "pass",
        evidence: {
          logPath: "logs/flutter-host.txt",
          logSha256: createHash("sha256").update("flutter sanitized host log\n").digest("hex"),
        },
      },
    ],
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

function writeHostModeLogs(root) {
  mkdirSync(join(root, "logs"), { recursive: true });
  for (const framework of ["react-native", "flutter"]) {
    writeFileSync(join(root, `logs/${framework}-host.txt`), `${framework} sanitized host log\n`, "utf8");
  }
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
  writeHostModeLogs(root);
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

test("binds separate React Native and Flutter host logs without embedding their contents", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-host-log-emitter-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  writeHostModeLogs(root);
  const hostModeLogPaths = [
    { framework: "react-native", path: "logs/react-native-host.txt" },
    { framework: "flutter", path: "logs/flutter-host.txt" },
  ];
  for (const { framework, path } of hostModeLogPaths) {
    writeFileSync(join(root, path), Buffer.from(`${framework} sanitized host log\n`, "utf8"));
  }
  for (const artifact of input.artifacts) writeFileSync(join(root, artifact.path), artifact.bytes);

  const result = writeNativeDeviceEvidence({
    root,
    packageVersion: "0.1.0",
    evidencePath: "device/ios-rn.json",
    fragmentPath: "fragments/ios-rn.json",
    ...input,
    logPath: input.log.path,
    artifactPaths: input.artifacts.map(({ kind, path }) => ({ kind, path })),
    hostModeLogPaths,
  });

  assert.equal(result.record.hostModes[0].evidence.logPath, "logs/react-native-host.txt");
  assert.equal(result.record.hostModes[1].evidence.logPath, "logs/flutter-host.txt");
  assert.equal(Object.hasOwn(result.record.hostModes[0].evidence, "bytes"), false);
  assert.deepEqual(verifyDeviceEvidenceFiles(result.record, root), []);
});

test("rejects a host log for a framework not declared in the native record", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-unknown-host-log-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  writeHostModeLogs(root);
  for (const artifact of input.artifacts) writeFileSync(join(root, artifact.path), artifact.bytes);

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
        hostModeLogPaths: [
          { framework: "react-native", path: "logs/react-native-host.txt" },
          { framework: "flutter", path: "logs/flutter-host.txt" },
          { framework: "unknown", path: "logs/unknown-host.txt" },
        ],
      }),
    /not declared/,
  );
});

test("rejects native evidence outputs reached through an in-root symlinked parent", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-native-output-symlink-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  writeHostModeLogs(root);
  for (const artifact of input.artifacts) writeFileSync(join(root, artifact.path), artifact.bytes);
  mkdirSync(join(root, "real-output"), { recursive: true });
  symlinkSync("real-output", join(root, "output"), "dir");

  assert.throws(
    () =>
      writeNativeDeviceEvidence({
        root,
        packageVersion: "0.1.0",
        evidencePath: "output/ios-rn.json",
        fragmentPath: "output/ios-rn-fragment.json",
        ...input,
        logPath: input.log.path,
        artifactPaths: input.artifacts.map(({ kind, path }) => ({ kind, path })),
      }),
    /symbolic link/,
  );
});

test("rejects symlinked native evidence files even when the target stays inside the evidence root", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-native-evidence-symlink-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  writeHostModeLogs(root);
  for (const [index, artifact] of input.artifacts.entries()) {
    if (index === 0) {
      writeFileSync(join(root, "artifacts/actual-screen-capture.bin"), artifact.bytes);
      symlinkSync("actual-screen-capture.bin", join(root, artifact.path));
    } else {
      writeFileSync(join(root, artifact.path), artifact.bytes);
    }
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
    /symbolic link/,
  );
  rmSync(root, { recursive: true, force: true });
});

test("rejects incomplete test cases and required physical artifact categories", async () => {
  const { buildNativeDeviceEvidence } = await loadEmitter();
  const incomplete = completeInput();
  delete incomplete.testCases.protocolDowngrade;
  incomplete.artifacts = incomplete.artifacts.filter(({ kind }) => kind !== "crash-report-review");

  assert.throws(() => buildNativeDeviceEvidence(incomplete), /testCases\.protocolDowngrade/);
  assert.throws(() => buildNativeDeviceEvidence({ ...completeInput(), artifacts: incomplete.artifacts }), /crash-report-review/);
});

test("rejects a physical record that omits one required host mode", async () => {
  const { buildNativeDeviceEvidence } = await loadEmitter();
  const incomplete = completeInput();
  incomplete.hostModes = incomplete.hostModes.filter(({ framework }) => framework !== "flutter");

  assert.throws(() => buildNativeDeviceEvidence(incomplete), /hostModes.*flutter/);
});

test("rejects oversized physical evidence bytes before hashing", async () => {
  const { MAX_NATIVE_EVIDENCE_FILE_BYTES, buildNativeDeviceEvidence } = await loadEmitter();
  const oversized = completeInput();
  const maxBytes = MAX_NATIVE_EVIDENCE_FILE_BYTES ?? 32 * 1024 * 1024;
  oversized.log.bytes = Buffer.alloc(maxBytes + 1);

  assert.throws(() => buildNativeDeviceEvidence(oversized), /log bytes must not exceed/);
});

test("rejects empty physical evidence bytes before hashing", async () => {
  const { buildNativeDeviceEvidence } = await loadEmitter();
  const empty = completeInput();
  empty.log.bytes = Buffer.alloc(0);

  assert.throws(() => buildNativeDeviceEvidence(empty), /log bytes must not be empty/);
});

test("rejects a sentinel in a referenced physical-device artifact before writing evidence", async () => {
  const { writeNativeDeviceEvidence } = await loadEmitter();
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-native-sentinel-"));
  const input = completeInput();
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, input.log.path), input.log.bytes);
  writeHostModeLogs(root);
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
