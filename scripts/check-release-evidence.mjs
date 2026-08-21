import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateDeviceEvidence, verifyDeviceEvidenceFiles } from "./check-device-evidence.mjs";

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SECRET_KEY = /password|passphrase|secret|sentinel|plaintext|credential(?:Value|Bytes)|rawInput|input(?:Value|Text|Bytes)|^value$/i;

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

export const DEVICE_RELEASE_GATE_POLICIES = Object.freeze({
  "ios-device-matrix": Object.freeze({ platform: "ios", requirePhysicalDevice: true }),
  "android-device-matrix": Object.freeze({ platform: "android", requirePhysicalDevice: true }),
  "web-browser-matrix": Object.freeze({ platform: "web", requirePhysicalDevice: false }),
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
 * signatures are verified separately by [`verifyReleaseEvidenceFiles`]. CI
 * provenance, trusted-key identity, and reviewer identity remain external
 * release-process responsibilities.
 *
 * @param {unknown} evidence
 * @param {{expectedCommit?: string, expectedPackageVersion?: string, expectedReleasePublicKeySha256?: string, expectedReviewerPublicKeySha256?: string}} [context]
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
      if (typeof gate.commit !== "string" || !COMMIT.test(gate.commit)) {
        add(findings, `${field}.commit`, "must be the exact 40-character gate commit SHA");
      } else if (COMMIT.test(evidence.commit) && gate.commit !== evidence.commit) {
        add(findings, `${field}.commit`, "must match the manifest commit");
      } else if (context.expectedCommit && gate.commit !== context.expectedCommit) {
        add(findings, `${field}.commit`, "must match the current checkout commit");
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
    "independent-review-report",
    "independent-review-public-key",
    "independent-review-signature",
  ]) {
    if (!artifactKinds.has(requiredArtifact)) {
      add(findings, "artifacts", `missing required artifact ${requiredArtifact}`);
    }
  }

  validateSignatureDescriptor(
    findings,
    "signature",
    evidence.signature,
    artifactsByPath,
    {
      signedArtifactKind: "release-bundle",
      publicKeyKind: "release-public-key",
      signatureKind: "release-signature",
    },
    context.expectedReleasePublicKeySha256,
  );
  validateSignatureDescriptor(
    findings,
    "independentReview",
    evidence.independentReview,
    artifactsByPath,
    {
      signedArtifactKind: "independent-review-report",
      publicKeyKind: "independent-review-public-key",
      signatureKind: "independent-review-signature",
    },
    context.expectedReviewerPublicKeySha256,
    {
      expectedCommit: context.expectedCommit,
      expectedPackageVersion: context.expectedPackageVersion,
      requireReviewedRelease: true,
    },
  );

  return findings;
}

function validateSignatureDescriptor(
  findings,
  fieldName,
  descriptor,
  artifactsByPath,
  expectedKinds,
  trustedPublicKeySha256,
  binding = {},
) {
  if (!isRecord(descriptor)) {
    add(findings, fieldName, "must contain an Ed25519 detached-signature descriptor");
    return;
  }
  if (descriptor.algorithm !== "ed25519") {
    add(findings, `${fieldName}.algorithm`, "must equal ed25519");
  }
  for (const field of ["publicKeyPath", "signedArtifactPath", "signaturePath"]) {
    checkEvidencePath(findings, `${fieldName}.${field}`, descriptor[field]);
  }
  checkHash(findings, `${fieldName}.publicKeySha256`, descriptor.publicKeySha256);
  if (trustedPublicKeySha256 !== undefined && descriptor.publicKeySha256 !== trustedPublicKeySha256) {
    add(findings, `${fieldName}.publicKeySha256`, "must match the trusted public-key fingerprint");
  }
  if (binding.requireReviewedRelease) {
    if (typeof descriptor.reviewedCommit !== "string" || !COMMIT.test(descriptor.reviewedCommit)) {
      add(findings, `${fieldName}.reviewedCommit`, "must be the exact 40-character reviewed commit SHA");
    } else if (binding.expectedCommit && descriptor.reviewedCommit !== binding.expectedCommit) {
      add(findings, `${fieldName}.reviewedCommit`, "must match the manifest commit");
    }
    if (typeof descriptor.reviewedPackageVersion !== "string" || !VERSION.test(descriptor.reviewedPackageVersion)) {
      add(findings, `${fieldName}.reviewedPackageVersion`, "must be the reviewed semantic package version");
    } else if (
      binding.expectedPackageVersion &&
      descriptor.reviewedPackageVersion !== binding.expectedPackageVersion
    ) {
      add(findings, `${fieldName}.reviewedPackageVersion`, "must match the manifest package version");
    }
  }
  const signedArtifact = artifactsByPath.get(descriptor.signedArtifactPath);
  if (signedArtifact?.kind !== expectedKinds.signedArtifactKind) {
    add(
      findings,
      `${fieldName}.signedArtifactPath`,
      `must reference the ${expectedKinds.signedArtifactKind} artifact`,
    );
  }
  const publicKeyArtifact = artifactsByPath.get(descriptor.publicKeyPath);
  if (publicKeyArtifact?.kind !== expectedKinds.publicKeyKind) {
    add(findings, `${fieldName}.publicKeyPath`, `must reference the ${expectedKinds.publicKeyKind} artifact`);
  }
  const signatureArtifact = artifactsByPath.get(descriptor.signaturePath);
  if (signatureArtifact?.kind !== expectedKinds.signatureKind) {
    add(findings, `${fieldName}.signaturePath`, `must reference the ${expectedKinds.signatureKind} artifact`);
  }
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

function verifyGateEvidenceRecord(findings, root, field, gate) {
  if (!isSafeRelativePath(gate.evidencePath) || !COMMIT.test(String(gate.commit))) return;
  const absolutePath = containedFilePath(findings, root, field, gate.evidencePath);
  if (!absolutePath) return;

  let record;
  try {
    record = JSON.parse(readFileSync(absolutePath, "utf8"));
  } catch (error) {
    add(findings, `${field}.evidencePath`, `gate evidence must be a JSON record: ${error.message}`);
    return;
  }
  if (!isRecord(record)) {
    add(findings, `${field}.evidencePath`, "gate evidence must be a JSON object");
    return;
  }
  checkSecretKeys(findings, record, `${field}.evidence`);
  if (record.schemaVersion !== 1) {
    add(findings, `${field}.evidence.schemaVersion`, "gate evidence schemaVersion must equal 1");
  }
  if (record.status !== "pass") {
    add(findings, `${field}.evidence.status`, "gate evidence status must equal pass");
  }
  if (typeof record.commit !== "string" || !COMMIT.test(record.commit)) {
    add(findings, `${field}.evidence.commit`, "gate evidence commit must be a 40-character lowercase commit SHA");
  } else if (record.commit !== gate.commit) {
    add(findings, `${field}.evidence.commit`, "gate evidence commit must match the gate commit");
  }
  if (record.gate !== gate.name) {
    add(findings, `${field}.evidence.gate`, "gate evidence gate must match the release gate");
  }

  const devicePolicy = DEVICE_RELEASE_GATE_POLICIES[gate.name];
  if (devicePolicy === undefined) return;
  if (record.platform !== devicePolicy.platform) {
    add(
      findings,
      `${field}.device.platform`,
      `must equal ${devicePolicy.platform} for the ${gate.name} gate`,
    );
  }
  for (const finding of validateDeviceEvidence(record, {
    expectedCommit: gate.commit,
    expectedGate: gate.name,
    requirePhysicalDevice: devicePolicy.requirePhysicalDevice,
  })) {
    add(findings, `${field}.device`, finding);
  }
  for (const finding of verifyDeviceEvidenceFiles(record, root)) {
    add(findings, `${field}.device.files`, finding);
  }
}

function verifyDetachedSignature(findings, evidence, root, fieldName) {
  if (!isRecord(evidence?.[fieldName])) return;
  const descriptor = evidence[fieldName];
  const publicKeyPath = containedFilePath(findings, root, `${fieldName}.publicKeyPath`, descriptor.publicKeyPath);
  const signedArtifactPath = containedFilePath(
    findings,
    root,
    `${fieldName}.signedArtifactPath`,
    descriptor.signedArtifactPath,
  );
  const signaturePath = containedFilePath(findings, root, `${fieldName}.signaturePath`, descriptor.signaturePath);
  if (!publicKeyPath || !signedArtifactPath || !signaturePath || !SHA256.test(String(descriptor.publicKeySha256))) {
    return;
  }
  try {
    const publicKeyBytes = readFileSync(publicKeyPath);
    const publicKeyHash = createHash("sha256").update(publicKeyBytes).digest("hex");
    if (publicKeyHash !== descriptor.publicKeySha256) {
      add(findings, `${fieldName}.publicKeySha256`, "does not match the referenced public key");
      return;
    }
    const publicKey = createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
    const valid = verify(null, readFileSync(signedArtifactPath), publicKey, readFileSync(signaturePath));
    if (!valid) add(findings, fieldName, "detached Ed25519 signature verification failed");
  } catch (error) {
    add(findings, fieldName, `detached Ed25519 signature could not be verified: ${error.message}`);
  }
}

/**
 * Recomputes digests for all referenced gate and artifact files and verifies
 * both the maintainer release signature and the independent-review signature.
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
    verifyGateEvidenceRecord(findings, root, `gates[${index}]`, gate);
  }
  for (const [index, artifact] of evidence.artifacts.entries()) {
    if (!isRecord(artifact)) continue;
    verifyFileDigest(findings, root, `artifacts[${index}]`, artifact.path, artifact.sha256);
  }
  verifyDetachedSignature(findings, evidence, root, "signature");
  verifyDetachedSignature(findings, evidence, root, "independentReview");
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

function readTrustedFingerprint(findings, environmentName, required) {
  const value = process.env[environmentName];
  if (required && !value) {
    add(findings, environmentName, "must be provided in trusted-key mode");
  }
  if (value !== undefined) checkHash(findings, environmentName, value);
  return value;
}

function main() {
  const requireTrustedKeys = process.argv.includes("--require-trusted-keys");
  const manifestPath = process.argv.slice(2).find((argument) => argument !== "--require-trusted-keys");
  if (!manifestPath) {
    console.error(
      "usage: node scripts/check-release-evidence.mjs [--require-trusted-keys] path/to/release-evidence.json",
    );
    process.exitCode = 64;
    return;
  }

  const absoluteManifestPath = path.resolve(process.cwd(), manifestPath);
  let evidence;
  try {
    evidence = JSON.parse(readFileSync(absoluteManifestPath, "utf8"));
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
  const expectedReleasePublicKeySha256 = readTrustedFingerprint(
    contextFindings,
    "SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256",
    requireTrustedKeys,
  );
  const expectedReviewerPublicKeySha256 = readTrustedFingerprint(
    contextFindings,
    "SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256",
    requireTrustedKeys,
  );
  const findings = [
    ...contextFindings,
    ...validateReleaseEvidence(evidence, {
      expectedCommit,
      expectedPackageVersion,
      expectedReleasePublicKeySha256,
      expectedReviewerPublicKeySha256,
    }),
  ];
  if (findings.length > 0) {
    console.error(findings.map((finding) => `- ${finding}`).join("\n"));
    process.exitCode = 1;
    return;
  }
  const evidenceRoot = path.dirname(absoluteManifestPath);
  const fileFindings = verifyReleaseEvidenceFiles(evidence, evidenceRoot);
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
