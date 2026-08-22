import { createHash } from "node:crypto";
import {
  opendirSync,
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  validateDeviceEvidence,
  verifyDeviceEvidenceFiles,
} from "./check-device-evidence.mjs";
import { buildIndependentReviewFragment } from "./emit-independent-review-fragment.mjs";

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PRIVATE_MATERIAL_PATH = /(?:private|signing[-_]?key|password|secret|\.pem$|\.key$)/i;
const MAX_JSON_BYTES = 1 * 1024 * 1024;
const MAX_REVIEW_SIGNATURE_BYTES = 64;
const MAX_REVIEW_PUBLIC_KEY_BYTES = 1_024;
const MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_EXTERNAL_FILE_BYTES = 512 * 1024 * 1024;
const MAX_EXTERNAL_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const REQUIRED_NATIVE_GATES = Object.freeze([
  Object.freeze({
    gate: "ios-device-matrix",
    evidencePath: "evidence/ios-device.json",
    fragmentPath: "fragments/ios-device.json",
  }),
  Object.freeze({
    gate: "android-device-matrix",
    evidencePath: "evidence/android-device.json",
    fragmentPath: "fragments/android-device.json",
  }),
]);
const REVIEW_INPUTS = Object.freeze({
  evidencePath: "evidence/independent-security-review.json",
  fragmentPath: "fragments/independent-security-review.json",
  reportPath: "artifacts/independent-review.json",
  signaturePath: "artifacts/independent-review.sig",
  publicKeyPath: "artifacts/independent-review.pub.der",
});

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

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateOptions(root, options) {
  if (typeof root !== "string" || root.length === 0) throw new Error("external evidence root is required");
  if (!isRecord(options)) throw new Error("external evidence options are required");
  if (typeof options.expectedCommit !== "string" || !COMMIT.test(options.expectedCommit)) {
    throw new Error("expectedCommit must be a 40-character lowercase commit SHA");
  }
  if (typeof options.expectedPackageVersion !== "string" || !VERSION.test(options.expectedPackageVersion)) {
    throw new Error("expectedPackageVersion must be a semantic version");
  }
  if (
    options.expectedReviewerPublicKeySha256 !== undefined &&
    (typeof options.expectedReviewerPublicKeySha256 !== "string" ||
      !SHA256.test(options.expectedReviewerPublicKeySha256))
  ) {
    throw new Error("expectedReviewerPublicKeySha256 must be a lowercase SHA-256 digest");
  }
}

function requireRoot(root) {
  let entry;
  try {
    entry = lstatSync(root);
  } catch (error) {
    throw new Error(`external evidence root could not be read: ${error.message}`);
  }
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error("external evidence root must be a real directory");
  }
  return realpathSync(root);
}

function walkExternalRoot(root) {
  const state = { files: 0, directories: 0, bytes: 0 };

  function visit(relativePath) {
    state.directories += 1;
    if (state.directories > 16_384) throw new Error("external evidence contains too many directories");
    const directory = relativePath ? path.join(root, relativePath) : root;
    const handle = opendirSync(directory);
    try {
      let entry;
      while ((entry = handle.readSync()) !== null) {
        const childPath = relativePath ? path.posix.join(relativePath, entry.name) : entry.name;
        if (entry.isSymbolicLink()) throw new Error(`${childPath}: symbolic links are not allowed`);
        if (entry.isDirectory()) {
          visit(childPath);
          continue;
        }
        if (!entry.isFile()) throw new Error(`${childPath}: only regular files are allowed`);
        if (PRIVATE_MATERIAL_PATH.test(childPath)) {
          throw new Error(`${childPath}: private signing material is not allowed`);
        }
        const filePath = path.join(root, childPath);
        const size = statSync(filePath).size;
        if (size > MAX_EXTERNAL_FILE_BYTES) {
          throw new Error(`${childPath}: file exceeds ${MAX_EXTERNAL_FILE_BYTES} bytes`);
        }
        if (state.bytes > MAX_EXTERNAL_TOTAL_BYTES - size) {
          throw new Error(`external evidence exceeds ${MAX_EXTERNAL_TOTAL_BYTES} bytes`);
        }
        state.files += 1;
        if (state.files > 16_384) throw new Error("external evidence contains too many files");
        state.bytes += size;
      }
    } finally {
      handle.closeSync();
    }
  }

  visit("");
  return state;
}

function readBounded(root, relativePath, field, maximumBytes) {
  if (!isSafeRelativePath(relativePath) || PRIVATE_MATERIAL_PATH.test(relativePath)) {
    throw new Error(`${field} must be a safe, non-secret relative path`);
  }
  const absolutePath = path.resolve(root, relativePath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve inside the external evidence root`);
  }
  const entry = lstatSync(absolutePath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${field} must be a regular file`);
  const size = statSync(absolutePath).size;
  if (size === 0) throw new Error(`${field} must not be empty`);
  if (size > maximumBytes) throw new Error(`${field} exceeds ${maximumBytes} bytes`);
  return readFileSync(absolutePath);
}

function readJson(root, relativePath, field, maximumBytes = MAX_JSON_BYTES) {
  let parsed;
  try {
    parsed = JSON.parse(readBounded(root, relativePath, field, maximumBytes));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${field} must contain valid JSON: ${error.message}`);
    throw error;
  }
  if (!isRecord(parsed)) throw new Error(`${field} must contain a JSON object`);
  return parsed;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
}

function assertSameJson(actual, expected, field) {
  if (JSON.stringify(canonicalize(actual)) !== JSON.stringify(canonicalize(expected))) {
    throw new Error(`${field} does not match the verified evidence bytes`);
  }
}

function verifyNativeGate(root, expectedCommit, expectedPackageVersion, gateSpec) {
  const evidenceBytes = readBounded(root, gateSpec.evidencePath, `${gateSpec.gate} evidence`, MAX_JSON_BYTES);
  const record = readJson(root, gateSpec.evidencePath, `${gateSpec.gate} evidence`);
  const findings = [
    ...validateDeviceEvidence(record, {
      expectedCommit,
      expectedGate: gateSpec.gate,
      requirePhysicalDevice: true,
      requirePlatformSupport: true,
      requireNativeHostModes: true,
    }),
    ...verifyDeviceEvidenceFiles(record, root),
  ];
  if (findings.length > 0) throw new Error(`${gateSpec.gate} evidence invalid: ${findings.join("; ")}`);

  const fragment = readJson(root, gateSpec.fragmentPath, `${gateSpec.gate} fragment`);
  if (
    fragment.schemaVersion !== 1 ||
    fragment.commit !== expectedCommit ||
    fragment.packageVersion !== expectedPackageVersion
  ) {
    throw new Error(
      `${gateSpec.gate} fragment must bind schema version 1, the expected commit, and package version`,
    );
  }
  if (!Array.isArray(fragment.gates) || fragment.gates.length !== 1) {
    throw new Error(`${gateSpec.gate} fragment must contain exactly one gate`);
  }
  const gate = fragment.gates[0];
  if (
    !isRecord(gate) ||
    gate.name !== gateSpec.gate ||
    gate.commit !== expectedCommit ||
    gate.status !== "pass" ||
    gate.evidencePath !== gateSpec.evidencePath ||
    gate.sha256 !== hash(evidenceBytes)
  ) {
    throw new Error(`${gateSpec.gate} fragment does not bind the verified evidence record`);
  }
  return gateSpec.gate;
}

function verifyReviewGate(root, expectedCommit, expectedPackageVersion, expectedReviewerPublicKeySha256) {
  const reportBytes = readBounded(root, REVIEW_INPUTS.reportPath, "independent review report", MAX_JSON_BYTES);
  const signatureBytes = readBounded(
    root,
    REVIEW_INPUTS.signaturePath,
    "independent review signature",
    MAX_REVIEW_SIGNATURE_BYTES,
  );
  const publicKeyBytes = readBounded(
    root,
    REVIEW_INPUTS.publicKeyPath,
    "independent review public key",
    MAX_REVIEW_PUBLIC_KEY_BYTES,
  );
  const fragment = buildIndependentReviewFragment({
    commit: expectedCommit,
    packageVersion: expectedPackageVersion,
    reportPath: REVIEW_INPUTS.reportPath,
    reportBytes,
    signaturePath: REVIEW_INPUTS.signaturePath,
    signatureBytes,
    publicKeyPath: REVIEW_INPUTS.publicKeyPath,
    publicKeyBytes,
    evidencePath: REVIEW_INPUTS.evidencePath,
  });
  const reviewerKeyHash = fragment.independentReview.publicKeySha256;
  if (
    expectedReviewerPublicKeySha256 !== undefined &&
    reviewerKeyHash !== expectedReviewerPublicKeySha256
  ) {
    throw new Error("independent review public key does not match the protected reviewer fingerprint");
  }
  assertSameJson(
    readJson(root, REVIEW_INPUTS.evidencePath, "independent review evidence"),
    fragment.evidence,
    "independent review evidence",
  );
  assertSameJson(
    readJson(root, REVIEW_INPUTS.fragmentPath, "independent review fragment"),
    fragment,
    "independent review fragment",
  );
  return "independent-security-review";
}

/**
 * Validates the complete external evidence artifact before GitHub uploads it.
 * This gate deliberately verifies physical-device records and the signed
 * independent review, but never synthesizes either one.
 *
 * @param {string} root
 * @param {{expectedCommit: string, expectedPackageVersion: string, expectedReviewerPublicKeySha256?: string}} options
 * @returns {{files: number, bytes: number, gates: string[]}}
 */
export function validateExternalReleaseEvidence(root, options) {
  validateOptions(root, options);
  const realRoot = requireRoot(root);
  const totals = walkExternalRoot(realRoot);
  const gates = REQUIRED_NATIVE_GATES.map((gateSpec) =>
    verifyNativeGate(realRoot, options.expectedCommit, options.expectedPackageVersion, gateSpec),
  );
  gates.push(
    verifyReviewGate(
      realRoot,
      options.expectedCommit,
      options.expectedPackageVersion,
      options.expectedReviewerPublicKeySha256,
    ),
  );
  return { ...totals, gates: gates.sort() };
}

function main() {
  const [root, expectedCommit, expectedPackageVersion, ...argumentsList] = process.argv.slice(2);
  if (!root || !expectedCommit || !expectedPackageVersion || argumentsList.length % 2 !== 0) {
    console.error(
      "usage: node scripts/validate-external-release-evidence.mjs <root> <commit-sha> <package-version> [--reviewer-public-key-sha256 <sha256>]",
    );
    process.exitCode = 64;
    return;
  }
  const options = { expectedCommit, expectedPackageVersion };
  for (let index = 0; index < argumentsList.length; index += 2) {
    if (argumentsList[index] !== "--reviewer-public-key-sha256" || !SHA256.test(argumentsList[index + 1])) {
      console.error("external evidence validation failed: unsupported or invalid option");
      process.exitCode = 64;
      return;
    }
    options.expectedReviewerPublicKeySha256 = argumentsList[index + 1];
  }
  try {
    const result = validateExternalReleaseEvidence(path.resolve(process.cwd(), root), options);
    console.log(`external release evidence verified: ${result.gates.join(" ")} files=${result.files} bytes=${result.bytes}`);
  } catch (error) {
    console.error(`external evidence validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
