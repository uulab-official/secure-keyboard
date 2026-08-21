import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, truncateSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import assert from "node:assert/strict";

import {
  SANITIZED_TEST_SENTINEL,
  validateDeviceEvidence,
  verifyDeviceEvidenceFiles,
} from "./check-device-evidence.mjs";

const VALID_NATIVE = {
  schemaVersion: 1,
  status: "pass",
  commit: "0123456789abcdef0123456789abcdef01234567",
  gate: "ios-device-matrix",
  platform: "ios",
  framework: "react-native",
  frameworkVersion: "0.87.0",
  recordedAt: "2026-08-21T12:00:00.000Z",
  physicalDevice: true,
  device: { model: "iPhone", osVersion: "26.5", osBuild: "23A000" },
  testCases: {
    maskedStateOnly: "pass",
    captureAndBackground: "pass",
    screenshotsAndBackgroundSnapshots: "pass",
    autofillAndClipboard: "pass",
    accessibility: "pass",
    crashReportReview: "pass",
    lifecycleAndZeroization: "pass",
    serverReplayRateLimit: "pass",
    protocolDowngrade: "pass",
  },
  sanitizedLogs: true,
  logPath: "logs/ios-rn.txt",
  logSha256: "a".repeat(64),
  artifacts: [{ kind: "native-checksum", path: "native/secure-ffi.sha256", sha256: "b".repeat(64) }],
};

test("accepts a complete sanitized native evidence record", () => {
  assert.deepEqual(validateDeviceEvidence(VALID_NATIVE), []);
});

test("can require a physical device for a native release gate", () => {
  const simulator = structuredClone(VALID_NATIVE);
  simulator.physicalDevice = false;

  assert.deepEqual(validateDeviceEvidence(simulator), []);
  const findings = validateDeviceEvidence(simulator, { requirePhysicalDevice: true });
  assert.ok(findings.some((finding) => finding.includes("physicalDevice")));
});

test("can bind a device record to an expected checkout commit", () => {
  const findings = validateDeviceEvidence(VALID_NATIVE, { expectedCommit: "f".repeat(40) });

  assert.ok(findings.some((finding) => finding.includes("commit") && finding.includes("expected")));
});

test("requires an explicit passing device evidence status", () => {
  const missing = structuredClone(VALID_NATIVE);
  delete missing.status;
  const failed = { ...structuredClone(VALID_NATIVE), status: "failed" };

  assert.ok(validateDeviceEvidence(missing).some((finding) => finding.includes("status")));
  assert.ok(validateDeviceEvidence(failed).some((finding) => finding.includes("status")));
});

test("rejects noncanonical timestamps and oversized device metadata", () => {
  const noncanonical = structuredClone(VALID_NATIVE);
  noncanonical.recordedAt = "2026-08-21T12:00:00Z";
  const oversized = structuredClone(VALID_NATIVE);
  oversized.device.model = "m".repeat(121);

  assert.ok(validateDeviceEvidence(noncanonical).some((finding) => finding.includes("recordedAt")));
  assert.ok(validateDeviceEvidence(oversized).some((finding) => finding.includes("device.model")));
});

test("rejects missing pass status, secret fields, and unsafe paths", () => {
  const invalid = structuredClone(VALID_NATIVE);
  invalid.testCases.accessibility = "skipped";
  invalid.sentinel = "must never be stored";
  invalid.value = "must never be stored";
  invalid.logPath = "/tmp/raw.log";
  invalid.artifacts[0].sha256 = "not-a-hash";

  const findings = validateDeviceEvidence(invalid);
  assert.ok(findings.some((finding) => finding.includes("testCases.accessibility")));
  assert.ok(findings.some((finding) => finding.includes("secret-bearing")));
  assert.ok(findings.some((finding) => finding.includes("root.value")));
  assert.ok(findings.some((finding) => finding.includes("logPath")));
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].sha256")));
});

test("requires secure context and passkey-specific checks for web evidence", () => {
  const web = {
    ...structuredClone(VALID_NATIVE),
    gate: "web-browser-matrix",
    platform: "web",
    framework: "web",
    physicalDevice: false,
    device: { browser: "Chromium", browserVersion: "140", osVersion: "macOS", secureContext: false },
    testCases: {
      passkeySecureContext: "pass",
      originAndRpId: "pass",
      boundedOptions: "pass",
      fallbackWarning: "pass",
    },
  };
  const findings = validateDeviceEvidence(web);
  assert.ok(findings.some((finding) => finding.includes("device.secureContext")));
});

test("binds a device record to its declared release gate and platform", () => {
  const wrongGate = structuredClone(VALID_NATIVE);
  wrongGate.gate = "android-device-matrix";
  const wrongGateFindings = validateDeviceEvidence(wrongGate);
  assert.ok(wrongGateFindings.some((finding) => finding.includes("gate")));

  const missingGate = structuredClone(VALID_NATIVE);
  delete missingGate.gate;
  const missingGateFindings = validateDeviceEvidence(missingGate);
  assert.ok(missingGateFindings.some((finding) => finding.includes("gate")));
});

test("recomputes log and artifact digests inside the evidence root", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-device-evidence-"));
  const evidence = structuredClone(VALID_NATIVE);
  const log = Buffer.from("sanitized runtime log", "utf8");
  const artifact = Buffer.from("native checksum manifest", "utf8");
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "native"), { recursive: true });
  writeFileSync(join(root, evidence.logPath), log);
  writeFileSync(join(root, evidence.artifacts[0].path), artifact);
  evidence.logSha256 = createHash("sha256").update(log).digest("hex");
  evidence.artifacts[0].sha256 = createHash("sha256").update(artifact).digest("hex");

  assert.deepEqual(verifyDeviceEvidenceFiles(evidence, root), []);

  writeFileSync(join(root, evidence.logPath), Buffer.from("tampered", "utf8"));
  const findings = verifyDeviceEvidenceFiles(evidence, root);
  assert.ok(findings.some((finding) => finding.includes("logSha256")));
});

test("rejects the canonical sentinel and secret-bearing fields in referenced text artifacts", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-device-evidence-content-"));
  const evidence = structuredClone(VALID_NATIVE);
  const log = Buffer.from(`sanitized runtime log: ${SANITIZED_TEST_SENTINEL}\n`, "utf8");
  const artifact = Buffer.from('{"secret":"must not be uploaded"}\n', "utf8");
  mkdirSync(join(root, "logs"), { recursive: true });
  mkdirSync(join(root, "native"), { recursive: true });
  writeFileSync(join(root, evidence.logPath), log);
  writeFileSync(join(root, evidence.artifacts[0].path), artifact);
  evidence.logSha256 = createHash("sha256").update(log).digest("hex");
  evidence.artifacts[0].sha256 = createHash("sha256").update(artifact).digest("hex");

  const findings = verifyDeviceEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("canonical test sentinel")));
  assert.ok(findings.some((finding) => finding.includes("secret-bearing content")));
});

test("rejects duplicate evidence paths before file verification", () => {
  const evidence = structuredClone(VALID_NATIVE);
  evidence.artifacts[0].path = evidence.logPath;

  const findings = validateDeviceEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("artifacts[0].path") && finding.includes("unique")));
});

test("rejects oversized evidence files before reading their contents", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-oversized-device-evidence-"));
  const evidence = structuredClone(VALID_NATIVE);
  mkdirSync(join(root, "logs"), { recursive: true });
  writeFileSync(join(root, evidence.logPath), Buffer.alloc(0));
  truncateSync(join(root, evidence.logPath), 32 * 1024 * 1024 + 1);

  const findings = verifyDeviceEvidenceFiles(evidence, root);

  assert.ok(findings.some((finding) => finding.includes("must not exceed")));
});

test("requires explicit screenshot, crash-review, and protocol-downgrade checks", () => {
  const incomplete = structuredClone(VALID_NATIVE);
  delete incomplete.testCases.screenshotsAndBackgroundSnapshots;
  delete incomplete.testCases.crashReportReview;
  delete incomplete.testCases.protocolDowngrade;

  const findings = validateDeviceEvidence(incomplete);

  assert.ok(findings.some((finding) => finding.includes("testCases.screenshotsAndBackgroundSnapshots")));
  assert.ok(findings.some((finding) => finding.includes("testCases.crashReportReview")));
  assert.ok(findings.some((finding) => finding.includes("testCases.protocolDowngrade")));
});

test("requires categorized artifacts for a physical native release gate", () => {
  const incomplete = structuredClone(VALID_NATIVE);

  const findings = validateDeviceEvidence(incomplete, { requirePhysicalDevice: true });

  assert.ok(findings.some((finding) => finding.includes("screen-capture")));
  assert.ok(findings.some((finding) => finding.includes("background-snapshot")));
  assert.ok(findings.some((finding) => finding.includes("accessibility-report")));
  assert.ok(findings.some((finding) => finding.includes("autofill-clipboard-report")));
  assert.ok(findings.some((finding) => finding.includes("crash-report-review")));

  const complete = structuredClone(VALID_NATIVE);
  complete.artifacts = [
    "screen-capture",
    "background-snapshot",
    "accessibility-report",
    "autofill-clipboard-report",
    "crash-report-review",
    "native-checksum",
  ].map((kind, index) => ({
    kind,
    path: `native/artifact-${index}.bin`,
    sha256: "b".repeat(64),
  }));
  assert.deepEqual(validateDeviceEvidence(complete, { requirePhysicalDevice: true }), []);
});
