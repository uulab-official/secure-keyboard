import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MAX_DEVICE_EVIDENCE_FILE_BYTES,
  validateDeviceEvidence,
  verifyDeviceEvidenceFiles,
} from "./check-device-evidence.mjs";
import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LABEL = /^[^\r\n]{1,120}$/;
const KIND = /^[a-z0-9][a-z0-9._:-]{0,80}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const MAX_NATIVE_EVIDENCE_FILE_BYTES = MAX_DEVICE_EVIDENCE_FILE_BYTES;
const NATIVE_TEST_CASES = Object.freeze([
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
const REQUIRED_NATIVE_ARTIFACT_KINDS = Object.freeze([
  "screen-capture",
  "background-snapshot",
  "accessibility-report",
  "autofill-clipboard-report",
  "crash-report-review",
  "native-checksum",
]);
const FRAMEWORKS = Object.freeze({
  ios: new Set(["native", "react-native", "flutter"]),
  android: new Set(["native", "react-native", "flutter"]),
});
const GATES = Object.freeze({ ios: "ios-device-matrix", android: "android-device-matrix" });

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function validateLabel(value, field) {
  if (typeof value !== "string" || !LABEL.test(value) || value.trim().length === 0) {
    throw new Error(`${field} must be a bounded single-line label`);
  }
}

function validateTimestamp(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    throw new Error("recordedAt must be an ISO-8601 UTC timestamp");
  }
}

function validateBytes(value, field) {
  if (!(typeof value === "string" || value instanceof Uint8Array)) {
    throw new Error(`${field} must be a string or byte array`);
  }
  const byteLength = typeof value === "string" ? Buffer.byteLength(value, "utf8") : value.byteLength;
  if (byteLength === 0) throw new Error(`${field} must not be empty`);
  if (byteLength > MAX_NATIVE_EVIDENCE_FILE_BYTES) {
    throw new Error(`${field} must not exceed ${MAX_NATIVE_EVIDENCE_FILE_BYTES} bytes`);
  }
}

function normalizeTestCases(testCases) {
  if (!isRecord(testCases)) throw new Error("testCases must be an object");
  for (const name of Object.keys(testCases)) {
    if (!NATIVE_TEST_CASES.includes(name)) throw new Error(`unsupported test case ${name}`);
  }
  for (const name of NATIVE_TEST_CASES) {
    if (testCases[name] !== "pass") throw new Error(`testCases.${name} must be exactly 'pass'`);
  }
  return Object.fromEntries(NATIVE_TEST_CASES.map((name) => [name, "pass"]));
}

function validateArtifactInputs(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length === 0 || artifacts.length > 64) {
    throw new Error("artifacts must contain one to 64 entries");
  }
  const kinds = new Set();
  const paths = new Set();
  const normalized = [];
  for (const artifact of artifacts) {
    if (!isRecord(artifact)) throw new Error("artifact must be an object");
    validateLabel(artifact.kind, "artifact kind");
    if (!KIND.test(artifact.kind)) throw new Error("artifact kind must be a sanitized label");
    if (!isSafeRelativePath(artifact.path)) throw new Error("artifact path must be safe and relative");
    validateBytes(artifact.bytes, `artifact ${artifact.kind} bytes`);
    if (kinds.has(artifact.kind)) throw new Error(`duplicate artifact kind ${artifact.kind}`);
    if (paths.has(artifact.path)) throw new Error(`duplicate artifact path ${artifact.path}`);
    kinds.add(artifact.kind);
    paths.add(artifact.path);
    normalized.push({
      kind: artifact.kind,
      path: artifact.path,
      sha256: createHash("sha256").update(artifact.bytes).digest("hex"),
    });
  }
  for (const kind of REQUIRED_NATIVE_ARTIFACT_KINDS) {
    if (!kinds.has(kind)) throw new Error(`artifacts must contain ${kind}`);
  }
  return normalized;
}

/**
 * Builds a sanitized physical iOS/Android evidence record. Raw logs and
 * artifact bytes are accepted only long enough to hash them and are never
 * copied into the returned JSON record.
 *
 * @param {{commit: string, platform: "ios"|"android", framework: string, frameworkVersion: string, model: string, osVersion: string, osBuild: string, recordedAt: string, log: {path: string, bytes: Uint8Array|string}, testCases: Record<string, string>, artifacts: Array<{kind: string, path: string, bytes: Uint8Array|string}>}} input
 * @returns {Record<string, unknown>}
 */
export function buildNativeDeviceEvidence(input) {
  if (!isRecord(input)) throw new Error("native evidence input must be an object");
  const { commit, platform, framework, frameworkVersion, model, osVersion, osBuild, recordedAt, log } = input;
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (!Object.hasOwn(FRAMEWORKS, platform)) throw new Error("platform must be ios or android");
  if (!FRAMEWORKS[platform].has(framework)) throw new Error("framework is not supported for the selected platform");
  validateLabel(frameworkVersion, "frameworkVersion");
  validateLabel(model, "model");
  validateLabel(osVersion, "osVersion");
  validateLabel(osBuild, "osBuild");
  validateTimestamp(recordedAt);
  if (!isRecord(log)) throw new Error("log must be an object");
  if (!isSafeRelativePath(log.path)) throw new Error("log path must be safe and relative");
  validateBytes(log.bytes, "log bytes");

  const record = {
    schemaVersion: 1,
    status: "pass",
    commit,
    gate: GATES[platform],
    platform,
    framework,
    frameworkVersion,
    recordedAt,
    physicalDevice: true,
    device: { model, osVersion, osBuild },
    testCases: normalizeTestCases(input.testCases),
    sanitizedLogs: true,
    logPath: log.path,
    logSha256: createHash("sha256").update(log.bytes).digest("hex"),
    artifacts: validateArtifactInputs(input.artifacts),
  };
  const findings = validateDeviceEvidence(record, { requirePhysicalDevice: true, expectedCommit: commit });
  if (findings.length > 0) throw new Error(findings.join("\n"));
  return record;
}

function containedFile(root, relativePath, field) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${field} must be a safe relative path`);
  const realRoot = realpathSync(root);
  const absoluteFile = path.resolve(realRoot, relativePath);
  if (pathHasSymlinkComponent(realRoot, absoluteFile)) {
    throw new Error(`${field} must not resolve through symbolic links`);
  }
  const realFile = realpathSync(absoluteFile);
  const relative = path.relative(realRoot, realFile);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve inside the evidence root`);
  }
  return realFile;
}

function readEvidenceFile(root, relativePath, field) {
  const filePath = containedFile(root, relativePath, field);
  const stat = lstatSync(filePath);
  if (!stat.isFile()) throw new Error(`${field} must resolve to a regular file`);
  if (stat.size === 0) throw new Error(`${field} must not be empty`);
  if (stat.size > MAX_NATIVE_EVIDENCE_FILE_BYTES) {
    throw new Error(`${field} must not exceed ${MAX_NATIVE_EVIDENCE_FILE_BYTES} bytes`);
  }
  return readFileSync(filePath);
}

function writeJson(root, relativePath, bytes) {
  if (!isSafeRelativePath(relativePath)) throw new Error("output path must be safe and relative");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(realRoot, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(realRoot, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  const realParent = realpathSync(parent);
  const relativeParent = path.relative(realRoot, realParent);
  if (relativeParent.startsWith(`..${path.sep}`) || path.isAbsolute(relativeParent)) {
    throw new Error("output path must resolve inside the evidence root");
  }
  try {
    lstatSync(absolutePath);
    throw new Error("output path must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, bytes, { mode: 0o600, flag: "wx" });
}

/**
 * Reads physical-device files from an evidence root, rejects leaked sentinel
 * content, then writes the device record and its commit-bound release fragment.
 *
 * @param {{root: string, commit: string, packageVersion: string, platform: "ios"|"android", framework: string, frameworkVersion: string, model: string, osVersion: string, osBuild: string, recordedAt: string, testCases: Record<string, string>, logPath: string, artifactPaths: Array<{kind: string, path: string}>, evidencePath: string, fragmentPath: string}} input
 * @returns {{record: Record<string, unknown>, fragment: Record<string, unknown>}}
 */
export function writeNativeDeviceEvidence(input) {
  if (!isRecord(input)) throw new Error("native evidence input must be an object");
  const { root, packageVersion, evidencePath, fragmentPath, logPath, artifactPaths } = input;
  if (typeof root !== "string" || root.length === 0) throw new Error("evidence root is required");
  if (!VERSION.test(String(packageVersion))) throw new Error("packageVersion must be a semantic version");
  if (!isSafeRelativePath(evidencePath) || !isSafeRelativePath(fragmentPath)) {
    throw new Error("output paths must be safe and relative");
  }
  if (evidencePath === fragmentPath) throw new Error("fragment output must not overwrite the evidence record");
  if (!Array.isArray(artifactPaths)) throw new Error("artifactPaths must be an array");

  const log = { path: logPath, bytes: readEvidenceFile(root, logPath, "log path") };
  const artifacts = artifactPaths.map((artifact) => {
    if (!isRecord(artifact)) throw new Error("artifact path must be an object");
    return {
      kind: artifact.kind,
      path: artifact.path,
      bytes: readEvidenceFile(root, artifact.path, `artifact ${artifact.kind} path`),
    };
  });
  const record = buildNativeDeviceEvidence({ ...input, log, artifacts });
  const fileFindings = verifyDeviceEvidenceFiles(record, root);
  if (fileFindings.length > 0) throw new Error(fileFindings.join("\n"));
  const evidenceBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  const fragment = buildReleaseGateFragment({
    commit: input.commit,
    packageVersion,
    gateName: record.gate,
    evidencePath,
    evidenceBytes,
  });
  writeJson(root, evidencePath, evidenceBytes);
  writeJson(root, fragmentPath, Buffer.from(`${JSON.stringify(fragment, null, 2)}\n`, "utf8"));
  return { record, fragment };
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting native evidence");
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  if (!COMMIT.test(commit)) throw new Error("current checkout commit is not an immutable SHA");
  return commit;
}

function currentPackageVersion() {
  const packageJson = JSON.parse(readFileSync(path.join(ROOT, "packages/contracts/package.json"), "utf8"));
  if (typeof packageJson.version !== "string" || !VERSION.test(packageJson.version)) {
    throw new Error("current contracts package version is invalid");
  }
  return packageJson.version;
}

function parseOptions(argumentsList) {
  const values = { testCases: {}, artifactPaths: [] };
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      ["--platform", "--framework", "--framework-version", "--model", "--os-version", "--os-build", "--log"].includes(
        option,
      ) &&
      typeof value === "string"
    ) {
      const field = {
        "--platform": "platform",
        "--framework": "framework",
        "--framework-version": "frameworkVersion",
        "--model": "model",
        "--os-version": "osVersion",
        "--os-build": "osBuild",
        "--log": "logPath",
      }[option];
      values[field] = value;
      index += 1;
      continue;
    }
    if (option === "--test-case" && typeof value === "string") {
      values.testCases[value] = "pass";
      index += 1;
      continue;
    }
    if (option === "--artifact" && typeof value === "string") {
      const separator = value.indexOf("=");
      if (separator <= 0) throw new Error("artifacts must use --artifact kind=relative/path");
      values.artifactPaths.push({ kind: value.slice(0, separator), path: value.slice(separator + 1) });
      index += 1;
      continue;
    }
    throw new Error(
      "options must use --platform, --framework, --framework-version, --model, --os-version, --os-build, --log, --artifact, and --test-case",
    );
  }
  return values;
}

function main() {
  const [rootArgument, evidencePath, fragmentPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !evidencePath || !fragmentPath) {
    console.error(
      "usage: node scripts/emit-native-device-evidence.mjs <evidence-root> <evidence-json> <fragment-json> --platform <ios|android> --framework <native|react-native|flutter> --framework-version <label> --model <label> --os-version <label> --os-build <label> --log <relative/path> --artifact <kind=relative/path> --test-case <name>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = path.resolve(process.cwd(), rootArgument);
    mkdirSync(root, { recursive: true });
    const values = parseOptions(options);
    writeNativeDeviceEvidence({
      root,
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      evidencePath,
      fragmentPath,
      recordedAt: new Date().toISOString(),
      ...values,
    });
    console.log(`native device release evidence emitted: ${path.relative(process.cwd(), root)}`);
  } catch (error) {
    console.error(`native device release evidence failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
