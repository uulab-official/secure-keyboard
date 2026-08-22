import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,80}$/;

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

function validateTimestamp(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    throw new Error("recordedAt must be an ISO-8601 UTC timestamp");
  }
}

function validateLabel(value, field) {
  if (typeof value !== "string" || !LABEL.test(value)) {
    throw new Error(`${field} must be a sanitized check label`);
  }
}

/**
 * Builds a sanitized CI gate record. It intentionally accepts check labels,
 * never command output, so logs cannot become release evidence payloads.
 *
 * @param {{commit: string, gateName: string, runner: string, checks: string[], recordedAt: string}} input
 * @returns {Record<string, unknown>}
 */
export function buildCiGateEvidence(input) {
  if (!isRecord(input)) throw new Error("CI gate evidence input must be an object");
  const { commit, gateName, runner, checks, recordedAt } = input;
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (typeof gateName !== "string" || !REQUIRED_RELEASE_GATES.includes(gateName)) {
    throw new Error("unsupported release gate");
  }
  validateLabel(runner, "runner");
  if (!Array.isArray(checks) || checks.length === 0 || checks.length > 64) {
    throw new Error("checks must contain one to 64 sanitized check labels");
  }
  checks.forEach((check) => validateLabel(check, "check"));
  validateTimestamp(recordedAt);

  return {
    schemaVersion: 1,
    status: "pass",
    commit,
    gate: gateName,
    evidenceKind: "ci-command",
    runner,
    recordedAt,
    checks: [...checks],
  };
}

function writeJson(root, relativePath, bytes) {
  if (!isSafeRelativePath(relativePath)) throw new Error("output path must be a safe relative path");
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
  writeFileSync(absolutePath, bytes, { mode: 0o600, flag: "wx" });
  return absolutePath;
}

/**
 * Writes one sanitized record and its commit-bound release-gate fragment.
 *
 * @param {{root: string, commit: string, packageVersion: string, gateName: string, evidencePath: string, fragmentPath: string, runner: string, checks: string[], recordedAt: string, toolchains?: Record<string, string>}} input
 * @returns {{record: Record<string, unknown>, fragment: Record<string, unknown>}}
 */
export function writeCiGateEvidence(input) {
  if (!isRecord(input)) throw new Error("CI gate evidence input must be an object");
  const { root, packageVersion, evidencePath, fragmentPath } = input;
  if (typeof root !== "string" || root.length === 0) throw new Error("evidence root is required");
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
  if (!isSafeRelativePath(evidencePath) || !isSafeRelativePath(fragmentPath)) {
    throw new Error("output path must be a safe relative path");
  }
  if (evidencePath === fragmentPath) throw new Error("fragment output must not overwrite the evidence record");

  const record = buildCiGateEvidence(input);
  const evidenceBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  const fragment = buildReleaseGateFragment({
    commit: input.commit,
    packageVersion,
    gateName: input.gateName,
    evidencePath,
    evidenceBytes,
    toolchains: input.toolchains,
  });
  const fragmentBytes = Buffer.from(`${JSON.stringify(fragment, null, 2)}\n`, "utf8");
  writeJson(root, evidencePath, evidenceBytes);
  writeJson(root, fragmentPath, fragmentBytes);
  return { record, fragment };
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting CI evidence");
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
  let runner;
  const checks = [];
  const toolchains = {};
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if ((option === "--runner" || option === "--check") && typeof value === "string") {
      if (option === "--runner") runner = value;
      else checks.push(value);
      index += 1;
      continue;
    }
    if (option === "--toolchain" && typeof value === "string") {
      const separator = value.indexOf("=");
      if (separator <= 0 || separator === value.length - 1) {
        throw new Error("toolchain option must use --toolchain name=version");
      }
      const name = value.slice(0, separator);
      if (Object.hasOwn(toolchains, name)) throw new Error(`toolchain ${name} must be specified once`);
      toolchains[name] = value.slice(separator + 1);
      index += 1;
      continue;
    }
    throw new Error("options must use --runner value, --check value, and --toolchain name=version");
  }
  return { runner, checks, toolchains };
}

function main() {
  const [rootArgument, gateName, evidencePath, fragmentPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !gateName || !evidencePath || !fragmentPath) {
    console.error(
      "usage: node scripts/emit-ci-gate-evidence.mjs <evidence-root> <gate-name> <evidence-json> <fragment-json> --runner <label> --check <label>... [--toolchain name=version]...",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = path.resolve(process.cwd(), rootArgument);
    mkdirSync(root, { recursive: true });
    const { runner, checks, toolchains } = parseOptions(options);
    writeCiGateEvidence({
      root,
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      gateName,
      evidencePath,
      fragmentPath,
      runner,
      checks,
      toolchains,
      recordedAt: new Date().toISOString(),
    });
    console.log(`CI release gate evidence emitted: ${path.relative(process.cwd(), root)}`);
  } catch (error) {
    console.error(`CI release gate evidence failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
