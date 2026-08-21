import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SECRET_KEY = /password|passphrase|secret|plaintext|credentialValue|inputValue|inputText/i;
const TOOLCHAIN_NAMES = new Set(["rust", "node", "flutter", "reactNative", "ndk"]);

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

function rejectSecretKeys(value, field = "evidence") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => rejectSecretKeys(child, `${field}[${index}]`));
    return [];
  }
  if (!isRecord(value)) return [];
  const findings = [];
  for (const [key, child] of Object.entries(value)) {
    const childField = `${field}.${key}`;
    if (SECRET_KEY.test(key)) findings.push(`${childField}: secret-bearing evidence fields are forbidden`);
    findings.push(...rejectSecretKeys(child, childField));
  }
  return findings;
}

function validateEvidenceRecord(record, commit) {
  if (!isRecord(record)) return ["gate evidence must be a JSON object"];
  const findings = rejectSecretKeys(record);
  if (record.schemaVersion !== 1) findings.push("gate evidence schemaVersion must equal 1");
  if (record.status !== "pass") findings.push("gate evidence status must equal pass");
  if (typeof record.commit !== "string" || !COMMIT.test(record.commit)) {
    findings.push("gate evidence commit must be a 40-character lowercase commit SHA");
  } else if (record.commit !== commit) {
    findings.push("gate evidence commit must match the gate commit");
  }
  return findings;
}

function validateToolchains(toolchains) {
  if (toolchains === undefined) return undefined;
  if (!isRecord(toolchains)) throw new Error("toolchains must be an object");
  const normalized = {};
  for (const [name, version] of Object.entries(toolchains)) {
    if (!TOOLCHAIN_NAMES.has(name)) throw new Error(`unsupported toolchain ${name}`);
    if (typeof version !== "string" || version.length === 0 || /[\r\n]/.test(version)) {
      throw new Error(`toolchain ${name} must be a non-empty single-line version`);
    }
    normalized[name] = version;
  }
  return Object.keys(normalized).length === 0 ? undefined : normalized;
}

/**
 * Builds one release evidence fragment from an already-produced JSON gate
 * record. The record bytes are hashed exactly as supplied; the caller must
 * keep those bytes at `evidencePath` inside the eventual evidence root.
 *
 * @param {{commit: string, packageVersion: string, gateName: string, evidencePath: string, evidenceBytes: Uint8Array|string, toolchains?: Record<string, string>}} input
 * @returns {Record<string, unknown>}
 */
export function buildReleaseGateFragment(input) {
  if (!isRecord(input)) throw new Error("fragment input must be an object");
  const { commit, packageVersion, gateName, evidencePath, evidenceBytes } = input;
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
  if (typeof gateName !== "string" || !REQUIRED_RELEASE_GATES.includes(gateName)) {
    throw new Error(`unsupported release gate ${gateName}`);
  }
  if (!isSafeRelativePath(evidencePath)) {
    throw new Error("evidencePath must be a safe relative path");
  }
  if (!(typeof evidenceBytes === "string" || evidenceBytes instanceof Uint8Array)) {
    throw new Error("evidenceBytes must be a string or byte array");
  }

  let record;
  try {
    record = JSON.parse(Buffer.from(evidenceBytes).toString("utf8"));
  } catch (error) {
    throw new Error(`gate evidence must be valid JSON: ${error.message}`);
  }
  const findings = validateEvidenceRecord(record, commit);
  if (findings.length > 0) throw new Error(findings.join("\n"));

  const toolchains = validateToolchains(input.toolchains);
  return {
    schemaVersion: 1,
    commit,
    packageVersion,
    ...(toolchains === undefined ? {} : { toolchains }),
    gates: [
      {
        name: gateName,
        commit,
        status: "pass",
        evidencePath,
        sha256: createHash("sha256").update(evidenceBytes).digest("hex"),
      },
    ],
  };
}

function containedFile(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) throw new Error("evidencePath must be a safe relative path");
  const realRoot = realpathSync(root);
  const realFile = realpathSync(path.resolve(realRoot, relativePath));
  const relative = path.relative(realRoot, realFile);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("evidencePath must resolve inside the evidence root");
  }
  return realFile;
}

function writeFragment(root, outputPath, fragment) {
  if (!isSafeRelativePath(outputPath)) throw new Error("output path must be a safe relative path");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, outputPath);
  const parent = path.dirname(absolutePath);
  mkdirSync(parent, { recursive: true });
  const realParent = realpathSync(parent);
  const parentRelative = path.relative(realRoot, realParent);
  if (parentRelative.startsWith(`..${path.sep}`) || path.isAbsolute(parentRelative)) {
    throw new Error("output path must resolve inside the evidence root");
  }
  try {
    lstatSync(absolutePath);
    throw new Error("output path must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, `${JSON.stringify(fragment, null, 2)}\n`, { mode: 0o600 });
  return absolutePath;
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting release evidence");
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

function parseToolchains(argumentsList) {
  const toolchains = {};
  for (let index = 0; index < argumentsList.length; index += 1) {
    if (argumentsList[index] !== "--toolchain" || typeof argumentsList[index + 1] !== "string") {
      throw new Error("toolchain options must use --toolchain name=version");
    }
    const separator = argumentsList[index + 1].indexOf("=");
    if (separator <= 0) throw new Error("toolchain options must use --toolchain name=version");
    const name = argumentsList[index + 1].slice(0, separator);
    const version = argumentsList[index + 1].slice(separator + 1);
    toolchains[name] = version;
    index += 1;
  }
  return toolchains;
}

function main() {
  const [rootArgument, outputPath, gateName, evidencePath, ...options] = process.argv.slice(2);
  if (!rootArgument || !outputPath || !gateName || !evidencePath) {
    console.error(
      "usage: node scripts/emit-release-gate-evidence.mjs <evidence-root> <fragment-json> <gate-name> <evidence-json> [--toolchain name=version]...",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const evidenceFile = containedFile(root, evidencePath);
    const evidenceBytes = readFileSync(evidenceFile);
    const fragment = buildReleaseGateFragment({
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      gateName,
      evidencePath,
      evidenceBytes,
      toolchains: parseToolchains(options),
    });
    if (outputPath === evidencePath) throw new Error("fragment output must not overwrite the evidence record");
    const output = writeFragment(root, outputPath, fragment);
    console.log(`release gate fragment emitted: ${path.relative(process.cwd(), output)}`);
  } catch (error) {
    console.error(`release gate fragment failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
