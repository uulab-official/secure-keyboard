import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_RELEASE_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES = 1_024;
const ED25519_SIGNATURE_BYTES = 64;

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
}

function containedPath(root, relativePath, field) {
  if (!isSafeRelativePath(relativePath)) {
    throw new Error(`${field} must be a safe relative path`);
  }
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  const relative = path.relative(realRoot, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve inside the evidence root`);
  }
  let entry;
  try {
    entry = lstatSync(absolutePath);
  } catch (error) {
    throw new Error(`${field} could not be read: ${error.message}`);
  }
  if (entry.isSymbolicLink() || !entry.isFile()) {
    throw new Error(`${field} must reference a regular file`);
  }
  return absolutePath;
}

function readArtifact(root, relativePath, field, maximumBytes = MAX_RELEASE_ARTIFACT_BYTES) {
  const absolutePath = containedPath(root, relativePath, field);
  const size = statSync(absolutePath).size;
  if (size === 0) throw new Error(`${field} must not be empty`);
  if (size > maximumBytes) {
    throw new Error(`${field} must not exceed ${maximumBytes} bytes`);
  }
  return readFileSync(absolutePath);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateCommit(commit) {
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
}

function validatePackageVersion(packageVersion) {
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
}

function validateTimestamp(recordedAt) {
  if (
    typeof recordedAt !== "string" ||
    !ISO_TIMESTAMP.test(recordedAt) ||
    Number.isNaN(Date.parse(recordedAt)) ||
    new Date(recordedAt).toISOString() !== recordedAt
  ) {
    throw new Error("recordedAt must be an ISO-8601 UTC timestamp");
  }
}

/**
 * Verifies the exact signed release files and builds a sanitized gate record.
 * The returned object contains public metadata and hashes only.
 *
 * @param {{root: string, commit: string, packageVersion: string, bundlePath: string, signaturePath: string, publicKeyPath: string, recordedAt?: string}} input
 * @returns {Record<string, unknown>}
 */
export function buildSignedReleaseEvidence(input) {
  if (!input || typeof input !== "object") throw new Error("signed-release input must be an object");
  const { root, commit, packageVersion, bundlePath, signaturePath, publicKeyPath } = input;
  const recordedAt = input.recordedAt ?? new Date().toISOString();
  if (typeof root !== "string" || root.length === 0) throw new Error("root must be a directory");
  validateCommit(commit);
  validatePackageVersion(packageVersion);
  validateTimestamp(recordedAt);
  if (bundlePath === signaturePath || bundlePath === publicKeyPath || signaturePath === publicKeyPath) {
    throw new Error("signed-release artifact paths must be distinct");
  }

  const bundle = readArtifact(root, bundlePath, "bundlePath");
  const signature = readArtifact(root, signaturePath, "signaturePath", ED25519_SIGNATURE_BYTES);
  const publicKeyDer = readArtifact(root, publicKeyPath, "publicKeyPath", MAX_PUBLIC_KEY_BYTES);
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error("signaturePath must contain a 64-byte Ed25519 signature");
  }

  let publicKey;
  try {
    publicKey = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });
  } catch (error) {
    throw new Error(`publicKeyPath must contain a valid DER public key: ${error.message}`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("publicKeyPath must contain an Ed25519 public key");
  }
  if (!verify(null, bundle, publicKey, signature)) {
    throw new Error("signaturePath does not verify the release bundle");
  }

  return {
    schemaVersion: 1,
    gate: "signed-release",
    status: "pass",
    evidenceKind: "signed-release",
    recordedAt,
    commit,
    packageVersion,
    algorithm: "ed25519",
    bundlePath,
    bundleSha256: sha256(bundle),
    signaturePath,
    signatureSha256: sha256(signature),
    publicKeyPath,
    publicKeySha256: sha256(publicKeyDer),
  };
}

function currentCommit() {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  validateCommit(commit);
  return commit;
}

function currentPackageVersion() {
  const packageJson = JSON.parse(readFileSync(path.join(ROOT, "packages/contracts/package.json"), "utf8"));
  validatePackageVersion(packageJson.version);
  return packageJson.version;
}

function writeEvidence(root, outputPath, record) {
  if (!isSafeRelativePath(outputPath)) throw new Error("outputPath must be a safe relative path");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, outputPath);
  const relative = path.relative(realRoot, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("outputPath must resolve inside the evidence root");
  }
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  try {
    lstatSync(absolutePath);
    throw new Error("outputPath must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
}

function parseOptions(argumentsList) {
  const values = {};
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!["--bundle", "--signature", "--public-key"].includes(option) || typeof value !== "string") {
      throw new Error("options must use --bundle, --signature, and --public-key");
    }
    if (values[option]) throw new Error(`${option} must be specified once`);
    values[option] = value;
    index += 1;
  }
  if (!values["--bundle"] || !values["--signature"] || !values["--public-key"]) {
    throw new Error("bundle, signature, and public-key paths are required");
  }
  return values;
}

function main() {
  const [rootArgument, outputPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !outputPath) {
    console.error(
      "usage: node scripts/emit-signed-release-evidence.mjs <evidence-root> <evidence-json> --bundle <relative-path> --signature <relative-path> --public-key <relative-path>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const values = parseOptions(options);
    const record = buildSignedReleaseEvidence({
      root,
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      bundlePath: values["--bundle"],
      signaturePath: values["--signature"],
      publicKeyPath: values["--public-key"],
    });
    writeEvidence(root, outputPath, record);
    console.log(`signed-release evidence emitted: ${path.relative(process.cwd(), path.join(root, outputPath))}`);
  } catch (error) {
    console.error(`signed-release evidence failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
