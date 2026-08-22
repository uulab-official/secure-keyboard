import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";
import { buildLsanGateEvidence, LSAN_LOG_PATH_PREFIX } from "./verify-lsan-evidence.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
}

function writeJson(root, relativePath, bytes) {
  if (!isSafeRelativePath(relativePath)) throw new Error("output path must be a safe relative path");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(realRoot, parent)) throw new Error("output path must not resolve through symbolic links");
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(realRoot, parent)) throw new Error("output path must not resolve through symbolic links");
  try {
    lstatSync(absolutePath);
    throw new Error("output path must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, bytes, { mode: 0o600, flag: "wx" });
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting LSAN evidence");
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

/**
 * Emits a sanitized LSAN record and its commit-bound release fragment. Raw
 * logs remain in `logRoot` and are uploaded separately into the exact retained
 * path referenced by the record.
 */
export function writeLsanGateEvidence({
  logRoot,
  outputRoot,
  commit,
  packageVersion,
  evidencePath,
  fragmentPath,
  runner,
  recordedAt,
  pathPrefix = LSAN_LOG_PATH_PREFIX,
}) {
  if (typeof outputRoot !== "string" || outputRoot.length === 0) throw new Error("outputRoot is required");
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) throw new Error("packageVersion is invalid");
  if (!isSafeRelativePath(evidencePath) || !isSafeRelativePath(fragmentPath)) {
    throw new Error("output paths must be safe relative paths");
  }
  if (evidencePath === fragmentPath) throw new Error("fragment output must not overwrite the evidence record");
  mkdirSync(outputRoot, { recursive: true });
  const record = buildLsanGateEvidence({ logRoot, commit, runner, recordedAt, pathPrefix });
  const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  const fragment = buildReleaseGateFragment({
    commit,
    packageVersion,
    gateName: "linux-leak-sanitizer",
    evidencePath,
    evidenceBytes: recordBytes,
  });
  writeJson(outputRoot, evidencePath, recordBytes);
  writeJson(outputRoot, fragmentPath, Buffer.from(`${JSON.stringify(fragment, null, 2)}\n`, "utf8"));
  return { record, fragment };
}

function main() {
  const [logRoot, outputRoot, evidencePath, fragmentPath, runnerFlag, runner] = process.argv.slice(2);
  if (!logRoot || !outputRoot || !evidencePath || !fragmentPath || runnerFlag !== "--runner" || !runner) {
    console.error(
      "usage: node scripts/emit-lsan-gate-evidence.mjs <log-root> <output-root> <evidence-json> <fragment-json> --runner <label>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    writeLsanGateEvidence({
      logRoot: path.resolve(process.cwd(), logRoot),
      outputRoot: path.resolve(process.cwd(), outputRoot),
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      evidencePath,
      fragmentPath,
      runner,
      recordedAt: new Date().toISOString(),
    });
    console.log("Linux LeakSanitizer release evidence emitted");
  } catch (error) {
    console.error(`Linux LeakSanitizer evidence failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
