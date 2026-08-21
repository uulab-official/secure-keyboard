import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
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
 * This is a schema and policy check. It does not verify the referenced files,
 * cryptographic signatures, CI provenance, or the reviewer's identity; the
 * release process must verify those references independently.
 *
 * @param {unknown} evidence
 * @returns {string[]}
 */
export function validateReleaseEvidence(evidence) {
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
      checkHash(findings, `${field}.sha256`, gate.sha256);
    });
  }
  for (const requiredGate of REQUIRED_RELEASE_GATES) {
    if (!gatesByName.has(requiredGate)) {
      add(findings, "gates", `missing required gate ${requiredGate}`);
    }
  }

  const artifactKinds = new Set();
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
      } else {
        artifactKinds.add(artifact.kind);
      }
      checkEvidencePath(findings, `${field}.path`, artifact.path);
      checkHash(findings, `${field}.sha256`, artifact.sha256);
    });
  }
  for (const requiredArtifact of ["native-checksum", "sbom", "license-notices"]) {
    if (!artifactKinds.has(requiredArtifact)) {
      add(findings, "artifacts", `missing required artifact ${requiredArtifact}`);
    }
  }

  return findings;
}

function verifyFileDigest(findings, root, field, relativePath, expectedHash) {
  if (!isSafeRelativePath(relativePath) || !SHA256.test(String(expectedHash))) {
    return;
  }
  const absolutePath = path.resolve(root, relativePath);
  try {
    const actualHash = createHash("sha256").update(readFileSync(absolutePath)).digest("hex");
    if (actualHash !== expectedHash) {
      add(findings, `${field}.sha256`, `does not match ${relativePath}`);
    }
  } catch (error) {
    add(findings, `${field}.path`, `could not read ${relativePath}: ${error.message}`);
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
  return findings;
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

  const findings = validateReleaseEvidence(evidence);
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
