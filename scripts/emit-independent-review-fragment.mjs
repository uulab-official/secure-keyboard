import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MAX_GATE_EVIDENCE_BYTES, buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PRIVATE_MATERIAL_PATH = /(?:private|signing[-_]?key|password|secret|\.pem$|\.key$)/i;
const MAX_REVIEW_REPORT_BYTES = MAX_GATE_EVIDENCE_BYTES;
const MAX_PUBLIC_KEY_BYTES = 1_024;
const SIGNATURE_BYTES = 64;
const REVIEW_SCOPE = Object.freeze([
  "native-input-boundary",
  "opaque-authentication",
  "http-json-transport",
  "replay-rate-limit-backends",
  "framework-adapters",
  "device-runtime-evidence",
  "release-process",
]);
const REVIEW_DECISIONS = new Set(["approved", "approved-with-residual-risk"]);
const SECRET_KEY = /password|passphrase|secret|sentinel|plaintext|credential(?:Value|Bytes)|rawInput|input(?:Value|Text|Bytes)|^value$/i;

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

function validateIdentity(commit, packageVersion) {
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
}

function rejectSecretKeys(value, field = "report") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => rejectSecretKeys(child, `${field}[${index}]`));
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) throw new Error(`${field}.${key}: secret-bearing review fields are forbidden`);
    rejectSecretKeys(child, `${field}.${key}`);
  }
}

function parseReviewReport(reportBytes, commit, packageVersion, publicKeySha256) {
  let report;
  try {
    report = JSON.parse(reportBytes.toString("utf8"));
  } catch (error) {
    throw new Error(`review report must be valid JSON: ${error.message}`);
  }
  if (!isRecord(report)) throw new Error("review report must be a JSON object");
  rejectSecretKeys(report);
  if (report.schemaVersion !== 1) throw new Error("review report schemaVersion must equal 1");
  if (report.reportType !== "independent-security-review") {
    throw new Error("review report reportType must equal independent-security-review");
  }
  if (report.reviewedCommit !== commit) throw new Error("review report reviewedCommit must match the checkout commit");
  if (report.reviewedPackageVersion !== packageVersion) {
    throw new Error("review report reviewedPackageVersion must match the package version");
  }
  if (report.reviewerPublicKeySha256 !== publicKeySha256) {
    throw new Error("review report reviewerPublicKeySha256 must match the public key");
  }
  if (
    !Array.isArray(report.scope) ||
    report.scope.length !== REVIEW_SCOPE.length ||
    new Set(report.scope).size !== REVIEW_SCOPE.length ||
    REVIEW_SCOPE.some((scope) => !report.scope.includes(scope))
  ) {
    throw new Error("review report scope must contain the complete independent-review scope");
  }
  if (!Array.isArray(report.findings) || report.findings.length > 256) {
    throw new Error("review report findings must be an array with at most 256 entries");
  }
  if (!REVIEW_DECISIONS.has(report.decision)) {
    throw new Error("review report decision must approve the reviewed release");
  }
  return report;
}

function containedPath(root, relativePath, field) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${field} must be a safe relative path`);
  if (PRIVATE_MATERIAL_PATH.test(relativePath)) {
    throw new Error(`${field} must not reference private signing material`);
  }
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  if (pathHasSymlinkComponent(realRoot, absolutePath)) {
    throw new Error(`${field} must not resolve through symbolic links`);
  }
  const relative = path.relative(realRoot, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve inside the evidence root`);
  }
  const entry = lstatSync(absolutePath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${field} must reference a regular file`);
  return absolutePath;
}

function readBoundedFile(root, relativePath, field, maximumBytes) {
  const absolutePath = containedPath(root, relativePath, field);
  const size = statSync(absolutePath).size;
  if (size === 0) throw new Error(`${field} must not be empty`);
  if (size > maximumBytes) throw new Error(`${field} must not exceed ${maximumBytes} bytes`);
  return readFileSync(absolutePath);
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateOutputPath(root, relativePath, field) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${field} must be a safe relative path`);
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(realRoot, parent)) throw new Error(`${field} must not resolve through symbolic links`);
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(realRoot, parent)) throw new Error(`${field} must not resolve through symbolic links`);
  try {
    lstatSync(absolutePath);
    throw new Error(`${field} must not already exist`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return absolutePath;
}

/**
 * Verifies an independently signed review report and builds the complete
 * release fragment needed by the final trusted-key verifier. Private reviewer
 * key material is never accepted by this function.
 *
 * @param {{commit: string, packageVersion: string, reportPath: string, reportBytes: Uint8Array, signaturePath: string, signatureBytes: Uint8Array, publicKeyPath: string, publicKeyBytes: Uint8Array, evidencePath: string}} input
 * @returns {Record<string, unknown>}
 */
export function buildIndependentReviewFragment(input) {
  if (!isRecord(input)) throw new Error("independent review input must be an object");
  const {
    commit,
    packageVersion,
    reportPath,
    reportBytes,
    signaturePath,
    signatureBytes,
    publicKeyPath,
    publicKeyBytes,
    evidencePath,
  } = input;
  validateIdentity(commit, packageVersion);
  for (const [field, value] of [
    ["reportBytes", reportBytes],
    ["signatureBytes", signatureBytes],
    ["publicKeyBytes", publicKeyBytes],
  ]) {
    if (!(value instanceof Uint8Array)) throw new Error(`${field} must be a byte array`);
    if (value.length === 0) throw new Error(`${field} must not be empty`);
  }
  if (reportBytes.length > MAX_REVIEW_REPORT_BYTES) throw new Error("reportBytes must not exceed 1048576 bytes");
  if (signatureBytes.length !== SIGNATURE_BYTES) throw new Error("signatureBytes must contain exactly 64 bytes");
  if (publicKeyBytes.length > MAX_PUBLIC_KEY_BYTES) throw new Error("publicKeyBytes must not exceed 1024 bytes");
  if (!isSafeRelativePath(evidencePath) || PRIVATE_MATERIAL_PATH.test(evidencePath)) {
    throw new Error("evidencePath must be a safe relative non-secret path");
  }
  if (new Set([reportPath, signaturePath, publicKeyPath, evidencePath]).size !== 4) {
    throw new Error("review evidence paths must be distinct");
  }
  for (const [field, value] of [
    ["reportPath", reportPath],
    ["signaturePath", signaturePath],
    ["publicKeyPath", publicKeyPath],
  ]) {
    if (!isSafeRelativePath(value) || PRIVATE_MATERIAL_PATH.test(value)) {
      throw new Error(`${field} must be a safe relative non-secret path`);
    }
  }

  let publicKey;
  try {
    publicKey = createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
  } catch (error) {
    throw new Error(`publicKeyBytes must contain a valid DER public key: ${error.message}`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("review public key must be Ed25519");
  const publicKeySha256 = hash(publicKeyBytes);
  const report = parseReviewReport(Buffer.from(reportBytes), commit, packageVersion, publicKeySha256);
  if (!verify(null, reportBytes, publicKey, signatureBytes)) {
    throw new Error("review signature does not verify the report");
  }

  const evidenceRecord = {
    schemaVersion: 1,
    gate: "independent-security-review",
    status: "pass",
    evidenceKind: "independent-security-review",
    commit,
    packageVersion,
    reviewedCommit: report.reviewedCommit,
    reviewedPackageVersion: report.reviewedPackageVersion,
    reviewerPublicKeySha256: publicKeySha256,
    reportPath,
    reportSha256: hash(reportBytes),
    signaturePath,
    signatureSha256: hash(signatureBytes),
    publicKeyPath,
  };
  const evidenceBytes = Buffer.from(`${JSON.stringify(evidenceRecord, null, 2)}\n`, "utf8");
  const gateFragment = buildReleaseGateFragment({
    commit,
    packageVersion,
    gateName: "independent-security-review",
    evidencePath,
    evidenceBytes,
  });
  return {
    ...gateFragment,
    evidence: evidenceRecord,
    artifacts: [
      { kind: "independent-review-report", path: reportPath, sha256: hash(reportBytes) },
      { kind: "independent-review-public-key", path: publicKeyPath, sha256: publicKeySha256 },
      { kind: "independent-review-signature", path: signaturePath, sha256: hash(signatureBytes) },
    ],
    independentReview: {
      algorithm: "ed25519",
      publicKeyPath,
      signedArtifactPath: reportPath,
      signaturePath,
      publicKeySha256,
      reviewedCommit: report.reviewedCommit,
      reviewedPackageVersion: report.reviewedPackageVersion,
    },
  };
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting review evidence");
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
  const values = {};
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!["--report", "--signature", "--public-key"].includes(option) || typeof value !== "string") {
      throw new Error("options must use --report, --signature, and --public-key");
    }
    if (values[option]) throw new Error(`${option} must be specified once`);
    values[option] = value;
    index += 1;
  }
  if (!values["--report"] || !values["--signature"] || !values["--public-key"]) {
    throw new Error("report, signature, and public-key paths are required");
  }
  return values;
}

function main() {
  const [rootArgument, evidencePath, fragmentPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !evidencePath || !fragmentPath) {
    console.error(
      "usage: node scripts/emit-independent-review-fragment.mjs <evidence-root> <evidence-json> <fragment-json> --report <relative-path> --signature <relative-path> --public-key <relative-path>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const values = parseOptions(options);
    const reportPath = values["--report"];
    const signaturePath = values["--signature"];
    const publicKeyPath = values["--public-key"];
    const fragment = buildIndependentReviewFragment({
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      reportPath,
      reportBytes: readBoundedFile(root, reportPath, "report path", MAX_REVIEW_REPORT_BYTES),
      signaturePath,
      signatureBytes: readBoundedFile(root, signaturePath, "signature path", SIGNATURE_BYTES),
      publicKeyPath,
      publicKeyBytes: readBoundedFile(root, publicKeyPath, "public key path", MAX_PUBLIC_KEY_BYTES),
      evidencePath,
    });
    const evidencePathOnDisk = validateOutputPath(root, evidencePath, "evidence path");
    const fragmentPathOnDisk = validateOutputPath(root, fragmentPath, "fragment path");
    writeFileSync(evidencePathOnDisk, `${JSON.stringify(fragment.evidence, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    writeFileSync(fragmentPathOnDisk, `${JSON.stringify(fragment, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    console.log(`independent-review fragment emitted: ${path.relative(process.cwd(), fragmentPathOnDisk)}`);
  } catch (error) {
    console.error(`independent-review fragment failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
