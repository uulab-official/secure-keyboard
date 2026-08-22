import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateDeviceEvidence, verifyDeviceEvidenceFiles } from "./check-device-evidence.mjs";

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SECRET_KEY = /password|passphrase|secret|sentinel|plaintext|credential(?:Value|Bytes)|rawInput|input(?:Value|Text|Bytes)|^value$/i;
const REVIEW_REPORT_TYPE = "independent-security-review";
const REVIEW_SCOPE = Object.freeze([
  "native-input-boundary",
  "opaque-authentication",
  "http-json-transport",
  "replay-rate-limit-backends",
  "framework-adapters",
  "device-runtime-evidence",
  "release-process",
]);
const REVIEW_DECISIONS = new Set(["approved", "approved-with-residual-risk", "not-approved"]);
const REVIEW_FINDING_SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);
const REVIEW_FINDING_STATUSES = new Set(["open", "accepted", "remediated"]);
const REVIEW_REPORT_MAX_BYTES = 1 * 1024 * 1024;
export const MAX_RELEASE_MANIFEST_BYTES = 1 * 1024 * 1024;
const MAX_GATE_EVIDENCE_BYTES = 1 * 1024 * 1024;
const MAX_RELEASE_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES = 1_024;
const ED25519_SIGNATURE_BYTES = 64;

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

/**
 * CI-only release gates must carry the checks emitted by their owning job.
 * This prevents a structurally valid but under-specified `pass` record from
 * satisfying a release gate without naming the required command group.
 */
export const CI_RELEASE_GATE_CHECKS = Object.freeze({
  "rust-workspace": Object.freeze([Object.freeze(["job-rust"])]),
  "javascript-contracts": Object.freeze([Object.freeze(["job-contracts"])]),
  "native-parity": Object.freeze([Object.freeze(["job-contracts"])]),
  "release-version-parity": Object.freeze([Object.freeze(["job-contracts"])]),
  "framework-host-builds": Object.freeze([
    Object.freeze([
      "job-flutter-host-build",
      "job-react-native-host-build",
      "job-ios-host-builds",
      "job-android-host-runtime-smoke",
    ]),
  ]),
  "fuzz-stability": Object.freeze([
    Object.freeze(["job-fuzz"]),
    Object.freeze(["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"]),
  ]),
  "linux-leak-sanitizer": Object.freeze([
    Object.freeze(["job-fuzz"]),
    Object.freeze(["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"]),
  ]),
  "durable-backends": Object.freeze([
    Object.freeze(["job-durable-backends"]),
    Object.freeze(["durable_storage", "durable_rate_limit", "durable_one_time_state"]),
  ]),
});

const CI_CHECK_LABEL = /^[a-z0-9][a-z0-9._-]{0,80}$/;

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

function maxArtifactBytes(kind) {
  if (kind === "release-public-key" || kind === "independent-review-public-key") {
    return MAX_PUBLIC_KEY_BYTES;
  }
  if (kind === "release-signature" || kind === "independent-review-signature") {
    return ED25519_SIGNATURE_BYTES;
  }
  if (kind === "independent-review-report") return REVIEW_REPORT_MAX_BYTES;
  return MAX_RELEASE_ARTIFACT_BYTES;
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
    const absoluteFile = path.resolve(realRoot, relativePath);
    let cursor = absoluteFile;
    while (cursor !== realRoot && cursor.startsWith(`${realRoot}${path.sep}`)) {
      if (lstatSync(cursor).isSymbolicLink()) {
        add(findings, `${field}.path`, "must not resolve through symbolic links");
        return undefined;
      }
      cursor = path.dirname(cursor);
    }
    const realFile = realpathSync(absoluteFile);
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

function verifyFileDigest(
  findings,
  root,
  field,
  relativePath,
  expectedHash,
  maximumBytes = MAX_RELEASE_ARTIFACT_BYTES,
) {
  if (!isSafeRelativePath(relativePath) || !SHA256.test(String(expectedHash))) {
    return;
  }
  const absolutePath = containedFilePath(findings, root, field, relativePath);
  if (!absolutePath) return;
  try {
    const fileStats = statSync(absolutePath);
    if (!fileStats.isFile()) {
      add(findings, `${field}.path`, "must reference a regular file");
      return;
    }
    if (fileStats.size === 0) {
      add(findings, `${field}.path`, "must not be empty");
      return;
    }
    if (fileStats.size > maximumBytes) {
      add(findings, `${field}.path`, `must not exceed ${maximumBytes} bytes`);
      return;
    }
    const actualHash = createHash("sha256").update(readFileSync(absolutePath)).digest("hex");
    if (actualHash !== expectedHash) {
      add(findings, `${field}.sha256`, `does not match ${relativePath}`);
    }
  } catch (error) {
    add(findings, `${field}.path`, `could not read ${relativePath}: ${error.message}`);
  }
}

function readBoundedFile(findings, absolutePath, field, maximumBytes) {
  try {
    const fileStats = statSync(absolutePath);
    if (!fileStats.isFile()) {
      add(findings, `${field}.path`, "must reference a regular file");
      return undefined;
    }
    if (fileStats.size === 0) {
      add(findings, `${field}.path`, "must be non-empty");
      return undefined;
    }
    if (fileStats.size > maximumBytes) {
      add(findings, `${field}.path`, `must not exceed ${maximumBytes} bytes`);
      return undefined;
    }
    return readFileSync(absolutePath);
  } catch (error) {
    add(findings, `${field}.path`, `could not read evidence file: ${error.message}`);
    return undefined;
  }
}

function readBoundedManifest(filePath) {
  const directoryEntry = lstatSync(filePath);
  if (directoryEntry.isSymbolicLink()) throw new Error("manifest must not be a symbolic link");
  const fileStats = statSync(filePath);
  if (!fileStats.isFile()) throw new Error("manifest must reference a regular file");
  if (fileStats.size === 0) throw new Error("manifest must not be empty");
  if (fileStats.size > MAX_RELEASE_MANIFEST_BYTES) {
    throw new Error(`manifest must not exceed ${MAX_RELEASE_MANIFEST_BYTES} bytes`);
  }
  return readFileSync(filePath);
}

function verifyGateEvidenceRecord(findings, root, field, gate) {
  if (!isSafeRelativePath(gate.evidencePath) || !COMMIT.test(String(gate.commit))) return;
  const absolutePath = containedFilePath(findings, root, field, gate.evidencePath);
  if (!absolutePath) return;

  const recordBytes = readBoundedFile(findings, absolutePath, field, MAX_GATE_EVIDENCE_BYTES);
  if (recordBytes === undefined) return;
  let record;
  try {
    record = JSON.parse(recordBytes.toString("utf8"));
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

  const requiredCiCheckSets = CI_RELEASE_GATE_CHECKS[gate.name];
  if (requiredCiCheckSets !== undefined) {
    if (record.evidenceKind !== "ci-command") {
      add(findings, `${field}.evidence.evidenceKind`, "CI gate evidenceKind must equal ci-command");
    }
    if (typeof record.runner !== "string" || !CI_CHECK_LABEL.test(record.runner)) {
      add(findings, `${field}.evidence.runner`, "CI gate runner must be a sanitized label");
    }
    if (
      typeof record.recordedAt !== "string" ||
      Number.isNaN(Date.parse(record.recordedAt)) ||
      new Date(record.recordedAt).toISOString() !== record.recordedAt
    ) {
      add(findings, `${field}.evidence.recordedAt`, "CI gate recordedAt must be an ISO-8601 UTC timestamp");
    }
    if (!Array.isArray(record.checks) || record.checks.length === 0) {
      add(findings, `${field}.evidence.checks`, "CI gate checks must contain the owning job checks");
    } else {
      for (const check of record.checks) {
        if (typeof check !== "string" || !CI_CHECK_LABEL.test(check)) {
          add(findings, `${field}.evidence.checks`, "CI gate checks must contain sanitized labels only");
          break;
        }
      }
      if (!requiredCiCheckSets.some((requiredChecks) => requiredChecks.every((check) => record.checks.includes(check)))) {
        add(
          findings,
          `${field}.evidence.checks`,
          "CI gate checks must include one complete owning job or command group",
        );
      }
    }
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
    requireNativeHostModes: true,
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
    const publicKeyBytes = readBoundedFile(
      findings,
      publicKeyPath,
      `${fieldName}.publicKeyPath`,
      MAX_PUBLIC_KEY_BYTES,
    );
    const signedArtifactBytes = readBoundedFile(
      findings,
      signedArtifactPath,
      fieldName === "independentReview" ? `${fieldName}.report` : `${fieldName}.signedArtifactPath`,
      fieldName === "independentReview" ? REVIEW_REPORT_MAX_BYTES : MAX_RELEASE_ARTIFACT_BYTES,
    );
    const signatureBytes = readBoundedFile(
      findings,
      signaturePath,
      `${fieldName}.signaturePath`,
      ED25519_SIGNATURE_BYTES,
    );
    if (publicKeyBytes === undefined || signedArtifactBytes === undefined || signatureBytes === undefined) return;
    if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) {
      add(findings, `${fieldName}.signaturePath`, `must contain exactly ${ED25519_SIGNATURE_BYTES} bytes`);
      return;
    }
    const publicKeyHash = createHash("sha256").update(publicKeyBytes).digest("hex");
    if (publicKeyHash !== descriptor.publicKeySha256) {
      add(findings, `${fieldName}.publicKeySha256`, "does not match the referenced public key");
      return;
    }
    const publicKey = createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
    const valid = verify(null, signedArtifactBytes, publicKey, signatureBytes);
    if (!valid) {
      add(findings, fieldName, "detached Ed25519 signature verification failed");
    } else if (fieldName === "independentReview") {
      verifyIndependentReviewReport(findings, signedArtifactBytes, descriptor, evidence);
    }
  } catch (error) {
    add(findings, fieldName, `detached Ed25519 signature could not be verified: ${error.message}`);
  }
}

function verifyIndependentReviewReport(findings, bytes, descriptor, evidence) {
  const field = "independentReview.report";
  let report;
  try {
    report = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch (error) {
    add(findings, field, `must be a structured JSON report: ${error.message}`);
    return;
  }
  if (!isRecord(report)) {
    add(findings, field, "must be a JSON object");
    return;
  }
  checkSecretKeys(findings, report, field);
  const allowedKeys = new Set([
    "schemaVersion",
    "reportType",
    "reviewedCommit",
    "reviewedPackageVersion",
    "reviewerPublicKeySha256",
    "scope",
    "findings",
    "decision",
  ]);
  for (const key of Object.keys(report)) {
    if (!allowedKeys.has(key)) add(findings, `${field}.${key}`, "unsupported review report field");
  }
  if (report.schemaVersion !== 1) add(findings, `${field}.schemaVersion`, "must equal 1");
  if (report.reportType !== REVIEW_REPORT_TYPE) {
    add(findings, `${field}.reportType`, `must equal ${REVIEW_REPORT_TYPE}`);
  }
  if (typeof report.reviewedCommit !== "string" || !COMMIT.test(report.reviewedCommit)) {
    add(findings, `${field}.reviewedCommit`, "must be the exact 40-character reviewed commit SHA");
  } else if (report.reviewedCommit !== evidence.commit) {
    add(findings, `${field}.reviewedCommit`, "must match the manifest commit");
  }
  if (typeof report.reviewedPackageVersion !== "string" || !VERSION.test(report.reviewedPackageVersion)) {
    add(findings, `${field}.reviewedPackageVersion`, "must be the reviewed semantic package version");
  } else if (report.reviewedPackageVersion !== evidence.packageVersion) {
    add(findings, `${field}.reviewedPackageVersion`, "must match the manifest package version");
  }
  if (!SHA256.test(String(report.reviewerPublicKeySha256))) {
    add(findings, `${field}.reviewerPublicKeySha256`, "must be a lowercase SHA-256 digest");
  } else if (report.reviewerPublicKeySha256 !== descriptor.publicKeySha256) {
    add(findings, `${field}.reviewerPublicKeySha256`, "must match the signed-report public-key fingerprint");
  }
  if (!Array.isArray(report.scope) || report.scope.length === 0 || report.scope.length > REVIEW_SCOPE.length) {
    add(findings, `${field}.scope`, "must contain the complete independent-review scope");
  } else {
    const scope = new Set(report.scope);
    if (scope.size !== report.scope.length || scope.size !== REVIEW_SCOPE.length) {
      add(findings, `${field}.scope`, "must contain each required scope exactly once");
    }
    for (const requiredScope of REVIEW_SCOPE) {
      if (!scope.has(requiredScope)) add(findings, `${field}.scope`, `must include ${requiredScope}`);
    }
  }
  if (!Array.isArray(report.findings) || report.findings.length > 256) {
    add(findings, `${field}.findings`, "must be an array with at most 256 entries");
  } else {
    report.findings.forEach((finding, index) => {
      const findingField = `${field}.findings[${index}]`;
      if (!isRecord(finding)) {
        add(findings, findingField, "must be an object");
        return;
      }
      for (const key of Object.keys(finding)) {
        if (!["id", "severity", "status", "summary", "affectedScope", "reproduction", "remediationOwner", "retestEvidence"].includes(key)) {
          add(findings, `${findingField}.${key}`, "unsupported finding field");
        }
      }
      if (typeof finding.id !== "string" || !/^[A-Z0-9][A-Z0-9._-]{0,31}$/.test(finding.id)) {
        add(findings, `${findingField}.id`, "must be a bounded finding identifier");
      }
      if (!REVIEW_FINDING_SEVERITIES.has(finding.severity)) {
        add(findings, `${findingField}.severity`, "must be a supported severity");
      }
      if (!REVIEW_FINDING_STATUSES.has(finding.status)) {
        add(findings, `${findingField}.status`, "must be a supported status");
      }
      if ((finding.severity === "critical" || finding.severity === "high") && finding.status === "open") {
        add(
          findings,
          `${findingField}.status`,
          `${finding.id} critical/high findings must be accepted or remediated before release`,
        );
      }
      if (
        typeof finding.summary !== "string" ||
        finding.summary.length === 0 ||
        finding.summary.length > 500 ||
        /[\r\n]/.test(finding.summary)
      ) {
        add(findings, `${findingField}.summary`, "must be a bounded single-line summary");
      }
      if (
        !Array.isArray(finding.affectedScope) ||
        finding.affectedScope.length === 0 ||
        finding.affectedScope.length > REVIEW_SCOPE.length
      ) {
        add(findings, `${findingField}.affectedScope`, "must contain one or more supported review scopes");
      } else {
        const affectedScope = new Set(finding.affectedScope);
        if (affectedScope.size !== finding.affectedScope.length) {
          add(findings, `${findingField}.affectedScope`, "must not contain duplicate review scopes");
        }
        for (const scope of finding.affectedScope) {
          if (!REVIEW_SCOPE.includes(scope)) {
            add(findings, `${findingField}.affectedScope`, "must contain supported review scopes only");
          }
        }
      }
      for (const [key, maximum] of [
        ["reproduction", 4_096],
        ["remediationOwner", 256],
        ["retestEvidence", 4_096],
      ]) {
        const value = finding[key];
        if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\r\n]/.test(value)) {
          add(findings, `${findingField}.${key}`, "must be bounded, non-empty, and single-line");
        }
      }
    });
  }
  if (!REVIEW_DECISIONS.has(report.decision)) {
    add(findings, `${field}.decision`, "must be an explicit release decision");
  } else if (report.decision === "not-approved") {
    add(findings, `${field}.decision`, "must approve the reviewed release");
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
    verifyFileDigest(
      findings,
      root,
      `gates[${index}]`,
      gate.evidencePath,
      gate.sha256,
      MAX_GATE_EVIDENCE_BYTES,
    );
    verifyGateEvidenceRecord(findings, root, `gates[${index}]`, gate);
  }
  for (const [index, artifact] of evidence.artifacts.entries()) {
    if (!isRecord(artifact)) continue;
    verifyFileDigest(
      findings,
      root,
      `artifacts[${index}]`,
      artifact.path,
      artifact.sha256,
      maxArtifactBytes(artifact.kind),
    );
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
    evidence = JSON.parse(readBoundedManifest(absoluteManifestPath).toString("utf8"));
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
