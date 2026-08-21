import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
/**
 * Public disposable value for device runs. Evidence scanners reject this
 * literal so a test sentinel cannot accidentally be retained in an artifact.
 */
export const SANITIZED_TEST_SENTINEL = "secure-keypad-test-sentinel-7f2c4e";
const NATIVE_TESTS = Object.freeze([
  "maskedStateOnly",
  "captureAndBackground",
  "screenshotsAndBackgroundSnapshots",
  "autofillAndClipboard",
  "accessibility",
  "crashReportReview",
  "lifecycleAndZeroization",
  "serverReplayRateLimit",
  "protocolDowngrade",
]);
const WEB_TESTS = Object.freeze([
  "passkeySecureContext",
  "originAndRpId",
  "boundedOptions",
  "fallbackWarning",
]);
const REQUIRED_PHYSICAL_NATIVE_ARTIFACT_KINDS = Object.freeze([
  "screen-capture",
  "background-snapshot",
  "accessibility-report",
  "autofill-clipboard-report",
  "crash-report-review",
  "native-checksum",
]);
const ALLOWED_FRAMEWORKS = Object.freeze({
  ios: new Set(["native", "react-native", "flutter"]),
  android: new Set(["native", "react-native", "flutter"]),
  web: new Set(["web"]),
});
const DEVICE_RELEASE_GATES = Object.freeze({
  "ios-device-matrix": "ios",
  "android-device-matrix": "android",
  "web-browser-matrix": "web",
});
const FORBIDDEN_KEYS = /password|secret|passphrase|sentinel|plaintext|credentialValue|input(?:Value|Text|Bytes)|^value$/i;
const FORBIDDEN_TEXT_FIELDS = /["']?(?:password|secret|passphrase|sentinel|plaintext|credential(?:Value|Bytes)|rawInput|input(?:Value|Text|Bytes))["']?\s*[:=]/i;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
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
 * The validator checks metadata and digest fields but does not treat a record
 * as proof that the underlying test actually happened. An independent
 * reviewer must still inspect the attached logs and artifacts; use
 * `verifyDeviceEvidenceFiles` to recompute their digests.
 *
 * @param {unknown} evidence
 * @param {{requirePhysicalDevice?: boolean, expectedCommit?: string, expectedGate?: string}} [options]
 * @returns {string[]}
 */
export function validateDeviceEvidence(evidence, options = {}) {
  const findings = [];
  if (!isRecord(evidence)) return ["root: must be an object"];
  rejectSecretKeys(evidence, "root", findings);

  if (evidence.schemaVersion !== 1) add(findings, "schemaVersion", "must be 1");
  if (typeof evidence.commit !== "string" || !COMMIT.test(evidence.commit)) {
    add(findings, "commit", "must be a 40-character lowercase commit SHA");
  } else if (options.expectedCommit !== undefined && evidence.commit !== options.expectedCommit) {
    add(findings, "commit", "must match the expected checkout commit");
  }
  if (options.expectedCommit !== undefined && !COMMIT.test(String(options.expectedCommit))) {
    add(findings, "expectedCommit", "must be a 40-character lowercase commit SHA");
  }
  if (typeof evidence.gate !== "string" || !Object.hasOwn(DEVICE_RELEASE_GATES, evidence.gate)) {
    add(findings, "gate", "must be a supported device release gate");
  } else if (options.expectedGate !== undefined && evidence.gate !== options.expectedGate) {
    add(findings, "gate", "must match the expected release gate");
  }
  if (!Object.hasOwn(ALLOWED_FRAMEWORKS, evidence.platform)) {
    add(findings, "platform", "must be ios, android, or web");
  } else if (!ALLOWED_FRAMEWORKS[evidence.platform].has(evidence.framework)) {
    add(findings, "framework", "is not supported for the selected platform");
  } else if (typeof evidence.gate === "string" && DEVICE_RELEASE_GATES[evidence.gate] !== evidence.platform) {
    add(findings, "gate", "must match the evidence platform");
  }
  if (!nonEmptyString(evidence.frameworkVersion)) add(findings, "frameworkVersion", "must be non-empty");
  if (!nonEmptyString(evidence.recordedAt) || Number.isNaN(Date.parse(evidence.recordedAt))) {
    add(findings, "recordedAt", "must be an ISO-8601 timestamp");
  }
  if (typeof evidence.physicalDevice !== "boolean") add(findings, "physicalDevice", "must be boolean");
  if (
    options.requirePhysicalDevice === true &&
    (evidence.platform === "ios" || evidence.platform === "android") &&
    evidence.physicalDevice !== true
  ) {
    add(findings, "physicalDevice", "must be true for the physical-device release gate");
  }

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
  const referencedPaths = new Set();
  if (!isSafeRelativePath(evidence.logPath)) {
    add(findings, "logPath", "must be a relative, non-parent path");
  } else {
    referencedPaths.add(evidence.logPath);
  }
  if (typeof evidence.logSha256 !== "string" || !SHA256.test(evidence.logSha256)) {
    add(findings, "logSha256", "must be a lowercase SHA-256 digest");
  }
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length === 0) {
    add(findings, "artifacts", "must contain at least one hashed artifact");
  } else {
    const artifactKinds = new Set();
    evidence.artifacts.forEach((artifact, index) => {
      const artifactPath = `artifacts[${index}]`;
      if (!isRecord(artifact)) {
        add(findings, artifactPath, "must be an object");
        return;
      }
      if (!isSafeRelativePath(artifact.path)) {
        add(findings, `${artifactPath}.path`, "must be a relative, non-parent path");
      } else if (referencedPaths.has(artifact.path)) {
        add(findings, `${artifactPath}.path`, "must be unique across evidence files");
      } else {
        referencedPaths.add(artifact.path);
      }
      if (typeof artifact.sha256 !== "string" || !SHA256.test(artifact.sha256)) {
        add(findings, `${artifactPath}.sha256`, "must be a lowercase SHA-256 digest");
      }
      if (options.requirePhysicalDevice === true && (evidence.platform === "ios" || evidence.platform === "android")) {
        if (!nonEmptyString(artifact.kind)) {
          add(findings, `${artifactPath}.kind`, "must be a non-empty artifact kind for a physical-device gate");
        } else if (artifactKinds.has(artifact.kind)) {
          add(findings, `${artifactPath}.kind`, "must be unique for a physical-device gate");
        } else {
          artifactKinds.add(artifact.kind);
        }
      }
    });
    if (
      options.requirePhysicalDevice === true &&
      (evidence.platform === "ios" || evidence.platform === "android")
    ) {
      for (const kind of REQUIRED_PHYSICAL_NATIVE_ARTIFACT_KINDS) {
        if (!artifactKinds.has(kind)) add(findings, "artifacts", `must contain physical-device artifact kind ${kind}`);
      }
    }
  }
  return findings;
}

function containedFilePath(findings, root, field, relativePath) {
  if (!isSafeRelativePath(relativePath)) return undefined;
  try {
    const realRoot = realpathSync(root);
    const realFile = realpathSync(path.resolve(realRoot, relativePath));
    const relative = path.relative(realRoot, realFile);
    if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      add(findings, `${field}.path`, "must resolve inside the evidence root");
      return undefined;
    }
    return realFile;
  } catch (error) {
    add(findings, `${field}.path`, `could not resolve ${relativePath}: ${error.message}`);
    return undefined;
  }
}

function verifyDigest(findings, root, field, relativePath, expectedHash) {
  if (!isSafeRelativePath(relativePath) || !SHA256.test(String(expectedHash))) return;
  const filePath = containedFilePath(findings, root, field, relativePath);
  if (!filePath) return;
  try {
    const actualHash = createHash("sha256").update(readFileSync(filePath)).digest("hex");
    if (actualHash !== expectedHash) add(findings, `${field}Sha256`, `does not match ${relativePath}`);
  } catch (error) {
    add(findings, `${field}Path`, `could not read ${relativePath}: ${error.message}`);
  }
}

function scanEvidenceFileContent(findings, root, field, relativePath) {
  if (!isSafeRelativePath(relativePath)) return;
  const filePath = containedFilePath(findings, root, field, relativePath);
  if (!filePath) return;
  let bytes;
  try {
    bytes = readFileSync(filePath);
  } catch (error) {
    add(findings, `${field}.path`, `could not read ${relativePath}: ${error.message}`);
    return;
  }

  if (bytes.includes(Buffer.from(SANITIZED_TEST_SENTINEL, "utf8"))) {
    add(findings, `${field}.content`, "contains the canonical test sentinel");
  }

  // Binary artifacts are still checked for the canonical sentinel, but text
  // field heuristics are limited to NUL-free files to avoid decoding arbitrary
  // native/image bytes as evidence text. OCR and human artifact review remain
  // required for screenshots and crash reports.
  if (!bytes.includes(0) && FORBIDDEN_TEXT_FIELDS.test(bytes.toString("utf8"))) {
    add(findings, `${field}.content`, "contains secret-bearing content fields");
  }
}

/**
 * Recomputes the digest of every log and native artifact referenced by an
 * otherwise valid evidence record. Symlinks resolving outside the evidence
 * root are rejected so a record cannot hash an unrelated host file.
 *
 * @param {unknown} evidence
 * @param {string} root
 * @returns {string[]}
 */
export function verifyDeviceEvidenceFiles(evidence, root) {
  if (!isRecord(evidence)) return ["root: file verification requires an evidence object"];
  const findings = [];
  verifyDigest(findings, root, "log", evidence.logPath, evidence.logSha256);
  scanEvidenceFileContent(findings, root, "log", evidence.logPath);
  if (Array.isArray(evidence.artifacts)) {
    evidence.artifacts.forEach((artifact, index) => {
      if (!isRecord(artifact)) return;
      verifyDigest(findings, root, `artifacts[${index}]`, artifact.path, artifact.sha256);
      scanEvidenceFileContent(findings, root, `artifacts[${index}]`, artifact.path);
    });
  }
  return findings;
}

function checkFile(filePath, options) {
  let evidence;
  try {
    evidence = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    process.stderr.write(`device evidence could not be read: ${error.message}\n`);
    return 1;
  }
  const findings = [...validateDeviceEvidence(evidence, options), ...verifyDeviceEvidenceFiles(evidence, ROOT)];
  for (const finding of findings) process.stderr.write(`device evidence: ${finding}\n`);
  return findings.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const positional = [];
  let requirePhysicalDevice = false;
  let expectedCommit;
  const argumentsList = process.argv.slice(2);
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    if (argument === "--require-physical") {
      requirePhysicalDevice = true;
    } else if (argument === "--expected-commit") {
      expectedCommit = argumentsList[index + 1];
      index += 1;
    } else {
      positional.push(argument);
    }
  }
  const filePath = positional[0];
  if (!filePath || positional.length !== 1 || expectedCommit === undefined && argumentsList.includes("--expected-commit")) {
    process.stderr.write(
      "usage: node scripts/check-device-evidence.mjs [--require-physical] [--expected-commit <sha>] <relative-json-file>\n",
    );
    process.exitCode = 2;
  } else {
    process.exitCode = checkFile(path.resolve(ROOT, filePath), { requirePhysicalDevice, expectedCommit });
  }
}
