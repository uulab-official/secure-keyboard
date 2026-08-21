import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SECRET_KEY = /password|passphrase|secret|plaintext|credentialValue|inputValue|inputText/i;

/**
 * Gates that must be independently evidenced before a public release claim.
 * The validator intentionally requires external evidence for device, Linux
 * sanitizer, reviewer, and signing steps; source inspection cannot satisfy
 * those gates.
 */
export const REQUIRED_RELEASE_GATES = Object.freeze([
  "rust-workspace",
  "javascript-contracts",
  "native-parity",
  "release-version-parity",
  "framework-host-builds",
  "fuzz-stability",
  "linux-leak-sanitizer",
  "durable-backends",
  "ios-device-matrix",
  "android-device-matrix",
  "web-browser-matrix",
  "independent-security-review",
  "signed-release",
]);

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

function add(findings, field, detail) {
  findings.push(`${field}: ${detail}`);
}

function checkHash(findings, field, value) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    add(findings, field, "must be a lowercase SHA-256 digest");
  }
}

function checkEvidencePath(findings, field, value) {
  if (!isSafeRelativePath(value)) {
    add(findings, field, "must be a relative, non-parent path");
  }
}

function checkUniquePath(findings, paths, field, value) {
  if (!isSafeRelativePath(value)) return;
  if (paths.has(value)) {
    add(findings, field, "must be unique across release evidence");
  } else {
    paths.add(value);
  }
}

function checkSecretKeys(findings, value, field = "manifest") {
  if (!isRecord(value) && !Array.isArray(value)) {
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const nestedField = field === "manifest" ? key : `${field}.${key}`;
    if (SECRET_KEY.test(key)) {
      add(findings, nestedField, "secret-bearing fields are forbidden");
    }
    checkSecretKeys(findings, nested, nestedField);
  }
}

/**
 * Validates the shape of a release evidence manifest.
 *
 * This is a schema and policy check. Referenced file digests and the detached
 * signature are verified separately by [`verifyReleaseEvidenceFiles`]. CI
 * provenance, trusted-key identity, and reviewer identity remain external
 * release-process responsibilities.
 *
 * @param {unknown} evidence
 * @param {{expectedCommit?: string, expectedPackageVersion?: string}} [context]
 * @returns {string[]}
 */
export function validateReleaseEvidence(evidence, context = {}) {
  const findings = [];

  if (!isRecord(evidence)) {
    return ["manifest: must be a JSON object"];
  }

  checkSecretKeys(findings, evidence);

  if (evidence.schemaVersion !== 1) {
    add(findings, "schemaVersion", "must equal 1");
  }
  if (typeof evidence.commit !== "string" || !COMMIT.test(evidence.commit)) {
    add(findings, "commit", "must be a 40-character lowercase commit SHA");
  } else if (context.expectedCommit && evidence.commit !== context.expectedCommit) {
    add(findings, "commit", "must match the current checkout commit");
  }
  if (
    typeof evidence.createdAt !== "string" ||
    Number.isNaN(Date.parse(evidence.createdAt)) ||
    new Date(evidence.createdAt).toISOString() !== evidence.createdAt
  ) {
    add(findings, "createdAt", "must be an ISO-8601 UTC timestamp");
  }
  if (typeof evidence.packageVersion !== "string" || !VERSION.test(evidence.packageVersion)) {
    add(findings, "packageVersion", "must be a semantic version");
  } else if (context.expectedPackageVersion && evidence.packageVersion !== context.expectedPackageVersion) {
    add(findings, "packageVersion", "must match the current release version");
  }

  const requiredToolchains = ["rust", "node", "flutter", "reactNative", "ndk"];
  if (!isRecord(evidence.toolchains)) {
    add(findings, "toolchains", "must contain pinned toolchain versions");
  } else {
    for (const toolchain of requiredToolchains) {
      if (typeof evidence.toolchains[toolchain] !== "string" || evidence.toolchains[toolchain].length === 0) {
        add(findings, `toolchains.${toolchain}`, "must be a non-empty pinned version");
      }
    }
  }

  const gatesByName = new Map();
  const referencedPaths = new Set();
  if (!Array.isArray(evidence.gates)) {
    add(findings, "gates", "must contain every required release gate");
  } else {
    evidence.gates.forEach((gate, index) => {
      const field = `gates[${index}]`;
      if (!isRecord(gate)) {
        add(findings, field, "must be an object");
        return;
      }
      if (typeof gate.name !== "string" || gate.name.length === 0) {
        add(findings, `${field}.name`, "must be a non-empty gate name");
      } else if (gatesByName.has(gate.name)) {
        add(findings, `${field}.name`, "must not be duplicated");
      } else {
        gatesByName.set(gate.name, gate);
      }
      if (gate.status !== "pass") {
        add(findings, `${field}.status`, "must equal pass");
      }
      checkEvidencePath(findings, `${field}.evidencePath`, gate.evidencePath);
      checkUniquePath(findings, referencedPaths, `${field}.evidencePath`, gate.evidencePath);
      checkHash(findings, `${field}.sha256`, gate.sha256);
    });
  }
  for (const requiredGate of REQUIRED_RELEASE_GATES) {
    if (!gatesByName.has(requiredGate)) {
      add(findings, "gates", `missing required gate ${requiredGate}`);
    }
  }

  const artifactKinds = new Set();
  const artifactsByPath = new Map();
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length === 0) {
    add(findings, "artifacts", "must contain hashed release artifacts");
  } else {
    evidence.artifacts.forEach((artifact, index) => {
      const field = `artifacts[${index}]`;
      if (!isRecord(artifact)) {
        add(findings, field, "must be an object");
        return;
      }
      if (typeof artifact.kind !== "string" || artifact.kind.length === 0) {
        add(findings, `${field}.kind`, "must be a non-empty artifact kind");
      } else if (artifactKinds.has(artifact.kind)) {
        add(findings, `${field}.kind`, "must not be duplicated");
      } else {
        artifactKinds.add(artifact.kind);
      }
      checkEvidencePath(findings, `${field}.path`, artifact.path);
      checkUniquePath(findings, referencedPaths, `${field}.path`, artifact.path);
      if (isSafeRelativePath(artifact.path)) artifactsByPath.set(artifact.path, artifact);
      checkHash(findings, `${field}.sha256`, artifact.sha256);
    });
  }
  for (const requiredArtifact of [
    "native-checksum",
    "sbom",
    "license-notices",
    "release-bundle",
    "release-public-key",
    "release-signature",
  ]) {
    if (!artifactKinds.has(requiredArtifact)) {
      add(findings, "artifacts", `missing required artifact ${requiredArtifact}`);
    }
  }

  if (!isRecord(evidence.signature)) {
    add(findings, "signature", "must contain an Ed25519 detached-signature descriptor");
  } else {
    if (evidence.signature.algorithm !== "ed25519") {
      add(findings, "signature.algorithm", "must equal ed25519");
    }
    for (const field of ["publicKeyPath", "signedArtifactPath", "signaturePath"]) {
      checkEvidencePath(findings, `signature.${field}`, evidence.signature[field]);
    }
    checkHash(findings, "signature.publicKeySha256", evidence.signature.publicKeySha256);
    const signedArtifact = artifactsByPath.get(evidence.signature.signedArtifactPath);
    if (signedArtifact?.kind !== "release-bundle") {
      add(findings, "signature.signedArtifactPath", "must reference the release-bundle artifact");
    }
    const publicKeyArtifact = artifactsByPath.get(evidence.signature.publicKeyPath);
    if (publicKeyArtifact?.kind !== "release-public-key") {
      add(findings, "signature.publicKeyPath", "must reference the release-public-key artifact");
    }
    const signatureArtifact = artifactsByPath.get(evidence.signature.signaturePath);
    if (signatureArtifact?.kind !== "release-signature") {
      add(findings, "signature.signaturePath", "must reference the release-signature artifact");
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

function verifyFileDigest(findings, root, field, relativePath, expectedHash) {
  if (!isSafeRelativePath(relativePath) || !SHA256.test(String(expectedHash))) {
    return;
  }
  const absolutePath = containedFilePath(findings, root, field, relativePath);
  if (!absolutePath) return;
  try {
    const actualHash = createHash("sha256").update(readFileSync(absolutePath)).digest("hex");
    if (actualHash !== expectedHash) {
      add(findings, `${field}.sha256`, `does not match ${relativePath}`);
    }
  } catch (error) {
    add(findings, `${field}.path`, `could not read ${relativePath}: ${error.message}`);
  }
}

function verifyDetachedSignature(findings, evidence, root) {
  if (!isRecord(evidence?.signature)) return;
  const descriptor = evidence.signature;
  const publicKeyPath = containedFilePath(findings, root, "signature.publicKeyPath", descriptor.publicKeyPath);
  const signedArtifactPath = containedFilePath(
    findings,
    root,
    "signature.signedArtifactPath",
    descriptor.signedArtifactPath,
  );
  const signaturePath = containedFilePath(findings, root, "signature.signaturePath", descriptor.signaturePath);
  if (!publicKeyPath || !signedArtifactPath || !signaturePath || !SHA256.test(String(descriptor.publicKeySha256))) {
    return;
  }
  try {
    const publicKeyBytes = readFileSync(publicKeyPath);
    const publicKeyHash = createHash("sha256").update(publicKeyBytes).digest("hex");
    if (publicKeyHash !== descriptor.publicKeySha256) {
      add(findings, "signature.publicKeySha256", "does not match the referenced public key");
      return;
    }
    const publicKey = createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
    const valid = verify(null, readFileSync(signedArtifactPath), publicKey, readFileSync(signaturePath));
    if (!valid) add(findings, "signature", "detached Ed25519 signature verification failed");
  } catch (error) {
    add(findings, "signature", `detached Ed25519 signature could not be verified: ${error.message}`);
  }
}

/**
 * Recomputes digests for all referenced gate and artifact files.
 *
 * Call [`validateReleaseEvidence`] first so malformed paths and hashes are
 * reported as schema findings rather than being used for filesystem access.
 *
 * @param {unknown} evidence
 * @param {string} root
 * @returns {string[]}
 */
export function verifyReleaseEvidenceFiles(evidence, root) {
  const findings = [];
  if (!isRecord(evidence) || !Array.isArray(evidence.gates) || !Array.isArray(evidence.artifacts)) {
    return ["manifest: file verification requires a structurally valid manifest"];
  }
  for (const [index, gate] of evidence.gates.entries()) {
    if (!isRecord(gate)) continue;
    verifyFileDigest(findings, root, `gates[${index}]`, gate.evidencePath, gate.sha256);
  }
  for (const [index, artifact] of evidence.artifacts.entries()) {
    if (!isRecord(artifact)) continue;
    verifyFileDigest(findings, root, `artifacts[${index}]`, artifact.path, artifact.sha256);
  }
  verifyDetachedSignature(findings, evidence, root);
  return findings;
}

function currentCommit(root) {
  try {
    const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    return COMMIT.test(commit) ? commit : undefined;
  } catch {
    return undefined;
  }
}

function currentPackageVersion(root) {
  try {
    const packageJson = JSON.parse(readFileSync(path.join(root, "packages/contracts/package.json"), "utf8"));
    return typeof packageJson.version === "string" ? packageJson.version : undefined;
  } catch {
    return undefined;
  }
}

function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath) {
    console.error("usage: node scripts/check-release-evidence.mjs path/to/release-evidence.json");
    process.exitCode = 64;
    return;
  }

  let evidence;
  try {
    evidence = JSON.parse(readFileSync(path.resolve(process.cwd(), manifestPath), "utf8"));
  } catch (error) {
    console.error(`release evidence could not be read: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const expectedCommit = currentCommit(process.cwd());
  const expectedPackageVersion = currentPackageVersion(process.cwd());
  const contextFindings = [];
  if (!expectedCommit) add(contextFindings, "commit", "current checkout commit could not be determined");
  if (!expectedPackageVersion) add(contextFindings, "packageVersion", "current release version could not be determined");
  const findings = [
    ...contextFindings,
    ...validateReleaseEvidence(evidence, { expectedCommit, expectedPackageVersion }),
  ];
  if (findings.length > 0) {
    console.error(findings.map((finding) => `- ${finding}`).join("\n"));
    process.exitCode = 1;
    return;
  }
  const fileFindings = verifyReleaseEvidenceFiles(evidence, process.cwd());
  if (fileFindings.length > 0) {
    console.error(fileFindings.map((finding) => `- ${finding}`).join("\n"));
    process.exitCode = 1;
    return;
  }
  console.log("release evidence schema valid");
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
