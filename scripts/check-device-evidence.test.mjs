import test from "node:test";
import assert from "node:assert/strict";

import { validateDeviceEvidence } from "./check-device-evidence.mjs";

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
