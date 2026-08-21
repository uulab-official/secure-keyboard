import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const NATIVE_TESTS = Object.freeze([
  "maskedStateOnly",
  "captureAndBackground",
  "autofillAndClipboard",
  "accessibility",
  "lifecycleAndZeroization",
  "serverReplayRateLimit",
]);
const WEB_TESTS = Object.freeze([
  "passkeySecureContext",
  "originAndRpId",
  "boundedOptions",
  "fallbackWarning",
]);
const ALLOWED_FRAMEWORKS = Object.freeze({
  ios: new Set(["native", "react-native", "flutter"]),
  android: new Set(["native", "react-native", "flutter"]),
  web: new Set(["web"]),
});
const FORBIDDEN_KEYS = /password|secret|passphrase|sentinel|plaintext|credentialValue|input(?:Value|Text|Bytes)/i;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function add(findings, pathName, detail) {
  findings.push(`${pathName}: ${detail}`);
}

function rejectSecretKeys(value, pathName, findings) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSecretKeys(item, `${pathName}[${index}]`, findings));
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${pathName}.${key}`;
    if (FORBIDDEN_KEYS.test(key)) add(findings, childPath, "secret-bearing evidence fields are forbidden");
    rejectSecretKeys(child, childPath, findings);
  }
}

function validateTests(testCases, required, findings) {
  if (!isRecord(testCases)) {
    add(findings, "testCases", "must be an object");
    return;
  }
  for (const name of required) {
    if (testCases[name] !== "pass") add(findings, `testCases.${name}`, "must be exactly 'pass'");
  }
}

/**
 * Validates one sanitized device/browser verification record.
 *
 * The validator checks metadata and hashes only; it does not treat a record as
 * proof that the underlying test actually happened. An independent reviewer
 * must still inspect the attached logs and artifacts.
 *
 * @param {unknown} evidence
 * @returns {string[]}
 */
export function validateDeviceEvidence(evidence) {
  const findings = [];
  if (!isRecord(evidence)) return ["root: must be an object"];
  rejectSecretKeys(evidence, "root", findings);

  if (evidence.schemaVersion !== 1) add(findings, "schemaVersion", "must be 1");
  if (typeof evidence.commit !== "string" || !COMMIT.test(evidence.commit)) {
    add(findings, "commit", "must be a 40-character lowercase commit SHA");
  }
  if (!Object.hasOwn(ALLOWED_FRAMEWORKS, evidence.platform)) {
    add(findings, "platform", "must be ios, android, or web");
  } else if (!ALLOWED_FRAMEWORKS[evidence.platform].has(evidence.framework)) {
    add(findings, "framework", "is not supported for the selected platform");
  }
  if (!nonEmptyString(evidence.frameworkVersion)) add(findings, "frameworkVersion", "must be non-empty");
  if (!nonEmptyString(evidence.recordedAt) || Number.isNaN(Date.parse(evidence.recordedAt))) {
    add(findings, "recordedAt", "must be an ISO-8601 timestamp");
  }
  if (typeof evidence.physicalDevice !== "boolean") add(findings, "physicalDevice", "must be boolean");

  if (!isRecord(evidence.device)) {
    add(findings, "device", "must be an object");
  } else if (evidence.platform === "web") {
    for (const field of ["browser", "browserVersion", "osVersion"]) {
      if (!nonEmptyString(evidence.device[field])) add(findings, `device.${field}`, "must be non-empty");
    }
    if (evidence.device.secureContext !== true) add(findings, "device.secureContext", "must be true");
  } else {
    for (const field of ["model", "osVersion", "osBuild"]) {
      if (!nonEmptyString(evidence.device[field])) add(findings, `device.${field}`, "must be non-empty");
    }
  }

  validateTests(evidence.testCases, evidence.platform === "web" ? WEB_TESTS : NATIVE_TESTS, findings);
  if (evidence.sanitizedLogs !== true) add(findings, "sanitizedLogs", "must be true");
  if (typeof evidence.logPath !== "string" || path.isAbsolute(evidence.logPath) || evidence.logPath.includes("..")) {
    add(findings, "logPath", "must be a relative, non-parent path");
  }
  if (typeof evidence.logSha256 !== "string" || !SHA256.test(evidence.logSha256)) {
    add(findings, "logSha256", "must be a lowercase SHA-256 digest");
  }
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length === 0) {
    add(findings, "artifacts", "must contain at least one hashed artifact");
  } else {
    evidence.artifacts.forEach((artifact, index) => {
      const artifactPath = `artifacts[${index}]`;
      if (!isRecord(artifact)) {
        add(findings, artifactPath, "must be an object");
        return;
      }
      if (typeof artifact.path !== "string" || path.isAbsolute(artifact.path) || artifact.path.includes("..")) {
        add(findings, `${artifactPath}.path`, "must be a relative, non-parent path");
      }
      if (typeof artifact.sha256 !== "string" || !SHA256.test(artifact.sha256)) {
        add(findings, `${artifactPath}.sha256`, "must be a lowercase SHA-256 digest");
      }
    });
  }
  return findings;
}

function checkFile(filePath) {
  let evidence;
  try {
    evidence = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    process.stderr.write(`device evidence could not be read: ${error.message}\n`);
    return 1;
  }
  const findings = validateDeviceEvidence(evidence);
  for (const finding of findings) process.stderr.write(`device evidence: ${finding}\n`);
  return findings.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const filePath = process.argv[2];
  if (!filePath) {
    process.stderr.write("usage: node scripts/check-device-evidence.mjs <relative-json-file>\n");
    process.exitCode = 2;
  } else {
    process.exitCode = checkFile(path.resolve(ROOT, filePath));
  }
}
