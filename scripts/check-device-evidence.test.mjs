import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import assert from "node:assert/strict";

import { validateDeviceEvidence, verifyDeviceEvidenceFiles } from "./check-device-evidence.mjs";

const VALID_NATIVE = {
  schemaVersion: 1,
  commit: "0123456789abcdef0123456789abcdef01234567",
  platform: "ios",
  framework: "react-native",
  frameworkVersion: "0.87.0",
  recordedAt: "2026-08-21T12:00:00Z",
  physicalDevice: true,
  device: { model: "iPhone", osVersion: "26.5", osBuild: "23A000" },
  testCases: {
    maskedStateOnly: "pass",
    captureAndBackground: "pass",
    autofillAndClipboard: "pass",
    accessibility: "pass",
    lifecycleAndZeroization: "pass",
    serverReplayRateLimit: "pass",
  },
  sanitizedLogs: true,
  logPath: "logs/ios-rn.txt",
  logSha256: "a".repeat(64),
  artifacts: [{ path: "native/secure-ffi.sha256", sha256: "b".repeat(64) }],
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

test("rejects missing pass status, secret fields, and unsafe paths", () => {
  const invalid = structuredClone(VALID_NATIVE);
  invalid.testCases.accessibility = "skipped";
  invalid.sentinel = "must never be stored";
  invalid.logPath = "/tmp/raw.log";
  invalid.artifacts[0].sha256 = "not-a-hash";

  const findings = validateDeviceEvidence(invalid);
  assert.ok(findings.some((finding) => finding.includes("testCases.accessibility")));
  assert.ok(findings.some((finding) => finding.includes("secret-bearing")));
  assert.ok(findings.some((finding) => finding.includes("logPath")));
  assert.ok(findings.some((finding) => finding.includes("artifacts[0].sha256")));
});

test("requires secure context and passkey-specific checks for web evidence", () => {
  const web = {
    ...structuredClone(VALID_NATIVE),
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

test("rejects duplicate evidence paths before file verification", () => {
  const evidence = structuredClone(VALID_NATIVE);
  evidence.artifacts[0].path = evidence.logPath;

  const findings = validateDeviceEvidence(evidence);

  assert.ok(findings.some((finding) => finding.includes("artifacts[0].path") && finding.includes("unique")));
});
