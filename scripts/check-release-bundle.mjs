import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";

const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NPM_PACKAGES = Object.freeze([
  "secure-keypad-contracts",
  "secure-keypad-react-native",
  "secure-keypad-web",
  "secure-keypad-server-node",
]);
const RUST_CRATES = Object.freeze([
  "secure-auth",
  "secure-auth-axum",
  "secure-auth-actix",
  "secure-auth-http",
  "secure-auth-server",
  "secure-core",
  "secure-ffi",
  "secure-webauthn-example",
]);
const REQUIRED_SOURCE_FILES = Object.freeze([
  "source/Cargo.lock",
  "source/pnpm-lock.yaml",
  "source/CHANGELOG.md",
  "source/README.md",
  "source/SECURITY.md",
  "source/LICENSE-MIT",
  "source/THIRD-PARTY-NOTICES.md",
  "source/secure-keypad.sbom.spdx.json",
  "source/release-candidate-metadata.json",
  "source/packages/flutter/pubspec.yaml",
  "source/docs/SECURITY-SPEC.md",
  "source/docs/PLATFORM-SECURITY-POLICY.md",
  "source/docs/RELEASE-GATES.md",
  "source/docs/ROADMAP.md",
]);
const SECRET_KEY = /password|passphrase|secret|private|plaintext|rawInput|input(?:Value|Text|Bytes)|credential(?:Value|Bytes)/i;

function regularFile(root, relativePath, findings) {
  const absolutePath = path.join(root, relativePath);
  try {
    const stat = lstatSync(absolutePath);
    if (stat.isSymbolicLink()) {
      findings.push(`${relativePath}: symlinks are not allowed in release staging`);
      return undefined;
    }
    if (!stat.isFile()) {
      findings.push(`${relativePath}: must be a regular file`);
      return undefined;
    }
    return absolutePath;
  } catch {
    findings.push(`${relativePath}: required release file is missing`);
    return undefined;
  }
}

function listFiles(root, relativePath = "") {
  const absolutePath = path.join(root, relativePath);
  let entries;
  try {
    entries = readdirSync(absolutePath, { withFileTypes: true });
  } catch {
    return [];
  }
  const files = [];
  for (const entry of entries) {
    const child = path.posix.join(relativePath.replaceAll(path.sep, "/"), entry.name);
    if (entry.isSymbolicLink()) {
      files.push({ relativePath: child, symlink: true });
    } else if (entry.isDirectory()) {
      files.push(...listFiles(root, child));
    } else if (entry.isFile()) {
      files.push({ relativePath: child, symlink: false });
    }
  }
  return files;
}

function rejectSecretMetadata(value, field, findings) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => rejectSecretMetadata(child, `${field}[${index}]`, findings));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const childField = `${field}.${key}`;
    if (SECRET_KEY.test(key)) findings.push(`${childField}: private signing material or secret fields are forbidden`);
    rejectSecretMetadata(child, childField, findings);
  }
}

function readJson(root, relativePath, findings) {
  const absolutePath = regularFile(root, relativePath, findings);
  if (!absolutePath) return undefined;
  try {
    return JSON.parse(readFileSync(absolutePath, "utf8"));
  } catch (error) {
    findings.push(`${relativePath}: invalid JSON (${error.message})`);
    return undefined;
  }
}

function validateCandidateMetadata(metadata, findings) {
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    findings.push("source/release-candidate-metadata.json: metadata must be an object");
    return undefined;
  }
  rejectSecretMetadata(metadata, "metadata", findings);
  if (metadata.schemaVersion !== 1) findings.push("candidate metadata schemaVersion must equal 1");
  if (metadata.kind !== "secure-keypad-release-candidate") findings.push("candidate metadata kind is invalid");
  if (metadata.claim !== "candidate-only") findings.push("candidate metadata must remain candidate-only");
  if (typeof metadata.commit !== "string" || !COMMIT.test(metadata.commit)) {
    findings.push("candidate metadata commit must be an immutable 40-character SHA");
  }
  if (typeof metadata.packageVersion !== "string" || !VERSION.test(metadata.packageVersion)) {
    findings.push("candidate metadata packageVersion must be semantic version");
  }
  if (!Array.isArray(metadata.requiredFinalGates)) {
    findings.push("candidate metadata must enumerate required final gates");
  } else if (
    metadata.requiredFinalGates.length !== REQUIRED_RELEASE_GATES.length ||
    metadata.requiredFinalGates.some((gate, index) => gate !== REQUIRED_RELEASE_GATES[index])
  ) {
    findings.push("candidate metadata requiredFinalGates must match the release contract");
  }
  return metadata;
}

function validateSpdx(root, findings) {
  const sbom = readJson(root, "source/secure-keypad.sbom.spdx.json", findings);
  if (sbom === undefined) return;
  if (typeof sbom.spdxVersion !== "string" || !sbom.spdxVersion.startsWith("SPDX-")) {
    findings.push("source/secure-keypad.sbom.spdx.json: SPDX version is missing");
  }
  if (!Array.isArray(sbom.packages) || sbom.packages.length === 0) {
    findings.push("source/secure-keypad.sbom.spdx.json: SPDX packages must be non-empty");
  }
}

function validateChangelog(root, findings) {
  const absolutePath = regularFile(root, "source/CHANGELOG.md", findings);
  if (!absolutePath) return;
  let contents;
  try {
    contents = readFileSync(absolutePath, "utf8");
  } catch (error) {
    findings.push(`source/CHANGELOG.md: cannot be read (${error.message})`);
    return;
  }
  if (!/^# Changelog(?:\r?\n|$)/m.test(contents)) {
    findings.push("source/CHANGELOG.md: must contain a top-level # Changelog heading");
  }
  if (!/^## Unreleased(?:\r?\n|$)/m.test(contents)) {
    findings.push("source/CHANGELOG.md: must contain a ## Unreleased release heading");
  }
}

function validatePublicDocuments(root, findings) {
  const documents = [
    [
      "source/README.md",
      [[/Secure Native Mode/, "must describe Secure Native Mode"]],
    ],
    [
      "source/SECURITY.md",
      [
        [/## Reporting a vulnerability/, "must contain a vulnerability reporting section"],
        [/private GitHub Security Advisory/, "must document the private GitHub Security Advisory channel"],
        [/security\/advisories\/new/, "must contain the private Security Advisory URL"],
      ],
    ],
  ];
  for (const [relativePath, checks] of documents) {
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    let contents;
    try {
      contents = readFileSync(absolutePath, "utf8");
    } catch (error) {
      findings.push(`${relativePath}: cannot be read (${error.message})`);
      continue;
    }
    for (const [pattern, detail] of checks) {
      if (!pattern.test(contents)) findings.push(`${relativePath}: ${detail}`);
    }
  }
}

function archiveEntries(absolutePath, findings) {
  try {
    return execFileSync("tar", ["-tzf", absolutePath], { encoding: "utf8" })
      .split("\n")
      .map((entry) => entry.replace(/^\.\//, "").trim())
      .filter(Boolean);
  } catch (error) {
    findings.push(`${path.basename(absolutePath)}: archive cannot be inspected (${error.message})`);
    return [];
  }
}

function validateNpmArchives(root, version, findings) {
  for (const packageName of NPM_PACKAGES) {
    const relativePath = `packages/${packageName}-${version}.tgz`;
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    const entries = archiveEntries(absolutePath, findings);
    for (const requiredEntry of ["package/package.json", "package/LICENSE", "package/README.md"]) {
      if (!entries.includes(requiredEntry)) {
        findings.push(`${relativePath}: archive must contain ${requiredEntry}`);
      }
    }
  }
}

function validateRustArchives(root, version, findings) {
  for (const crateName of RUST_CRATES) {
    const relativePath = `packages/${crateName}-${version}.crate`;
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    const entries = archiveEntries(absolutePath, findings);
    for (const requiredEntry of [`${crateName}-${version}/Cargo.toml`, `${crateName}-${version}/README.md`]) {
      if (!entries.includes(requiredEntry)) {
        findings.push(`${relativePath}: crate archive must contain ${requiredEntry}`);
      }
    }
  }
}

/**
 * Checks the directory assembled immediately before deterministic release
 * archiving. The check is intentionally independent of the release signer:
 * it proves that the signed input contains its policy, dependency, and
 * publishable-package records and that no private signing key was staged.
 *
 * @param {string} root
 * @returns {string[]}
 */
export function checkReleaseStaging(root) {
  const findings = [];
  if (typeof root !== "string" || root.length === 0 || !existsSync(root)) {
    return ["release staging root is missing"];
  }
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    return ["release staging root cannot be inspected"];
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return ["release staging root must be a real directory"];

  for (const relativePath of REQUIRED_SOURCE_FILES) regularFile(root, relativePath, findings);
  validateChangelog(root, findings);
  validatePublicDocuments(root, findings);
  const metadata = readJson(root, "source/release-candidate-metadata.json", findings);
  const validatedMetadata = validateCandidateMetadata(metadata, findings);
  validateSpdx(root, findings);
  if (validatedMetadata?.packageVersion) {
    validateNpmArchives(root, validatedMetadata.packageVersion, findings);
    validateRustArchives(root, validatedMetadata.packageVersion, findings);
  }

  for (const file of listFiles(root)) {
    if (file.symlink) {
      findings.push(`${file.relativePath}: symlinks are not allowed in release staging`);
    }
    if (/(?:private|signing[-_]?key)|\.pem$/i.test(file.relativePath)) {
      findings.push(`${file.relativePath}: private signing material must never enter release staging`);
    }
  }
  return [...new Set(findings)];
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const [root] = process.argv.slice(2);
  if (!root) {
    console.error("usage: node scripts/check-release-bundle.mjs <release-staging-root>");
    process.exitCode = 64;
  } else {
    const findings = checkReleaseStaging(path.resolve(process.cwd(), root));
    for (const finding of findings) console.error(`release-bundle: ${finding}`);
    if (findings.length === 0) console.log("release staging contract passed");
    process.exitCode = findings.length === 0 ? 0 : 1;
  }
}
