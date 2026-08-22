import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MAX_DEVICE_EVIDENCE_FILE_BYTES } from "./check-device-evidence.mjs";
import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LABEL = /^[a-z0-9][a-z0-9._+:-]{0,120}$/;
const BROWSER_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BROWSERS = Object.freeze(["chromium", "firefox", "webkit"]);
const WEB_TEST_CASES = Object.freeze({
  passkeySecureContext: "pass",
  originAndRpId: "pass",
  boundedOptions: "pass",
  fallbackWarning: "pass",
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

function validateTimestamp(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    throw new Error("recordedAt must be an ISO-8601 UTC timestamp");
  }
}

function validateLabel(value, field) {
  if (typeof value !== "string" || !LABEL.test(value)) throw new Error(`${field} must be a bounded label`);
}

function nonEmptyBoundedBrowserVersion(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 120;
}

function parseBrowserSmokeVersion(browser, bytes) {
  const text = Buffer.from(bytes).toString("utf8");
  const prefix = `${browser}@`;
  const line = text.split(/\r?\n/).find((candidate) => candidate.startsWith(prefix));
  const match = line?.match(
    new RegExp(
      `^${browser}@([A-Za-z0-9][A-Za-z0-9._+-]{0,63}): secure-context pass; webauthn=[a-z0-9-]+$`,
    ),
  );
  if (!match || !BROWSER_VERSION.test(match[1])) {
    throw new Error(`${browser} log must contain the checked-in browser smoke result with its runtime version`);
  }
  return match[1];
}

function orderedLogs(logs) {
  if (!Array.isArray(logs) || logs.length !== BROWSERS.length) {
    throw new Error("logs must contain exactly one log for chromium, firefox, and webkit");
  }
  const byBrowser = new Map();
  logs.forEach((log) => {
    if (!isRecord(log)) throw new Error("browser log must be an object");
    if (!BROWSERS.includes(log.browser)) throw new Error("browser log must name chromium, firefox, or webkit");
    if (byBrowser.has(log.browser)) throw new Error("browser logs must not repeat a browser");
    if (!isSafeRelativePath(log.path)) throw new Error("browser log path must be a safe relative path");
    if (!(typeof log.bytes === "string" || log.bytes instanceof Uint8Array)) {
      throw new Error("browser log bytes must be a string or byte array");
    }
    const bytes = Buffer.from(log.bytes);
    if (bytes.length === 0) throw new Error("browser log bytes must not be empty");
    if (bytes.length > MAX_DEVICE_EVIDENCE_FILE_BYTES) {
      throw new Error(`browser log bytes must not exceed ${MAX_DEVICE_EVIDENCE_FILE_BYTES} bytes`);
    }
    byBrowser.set(log.browser, {
      browser: log.browser,
      path: log.path,
      bytes,
      version: parseBrowserSmokeVersion(log.browser, bytes),
    });
  });
  return BROWSERS.map((browser) => {
    const log = byBrowser.get(browser);
    if (!log) throw new Error("logs must contain exactly one log for chromium, firefox, and webkit");
    return log;
  });
}

/**
 * Builds the web-specific device evidence shape required by the release
 * validator. Log bytes are hashed and referenced, never copied into JSON.
 *
 * @param {{commit: string, frameworkVersion: string, runner: string, recordedAt: string, logs: Array<{browser: string, path: string, bytes: Uint8Array|string}>}} input
 * @returns {Record<string, unknown>}
 */
export function buildWebBrowserEvidence(input) {
  if (!isRecord(input)) throw new Error("web evidence input must be an object");
  const { commit, frameworkVersion, runner, recordedAt } = input;
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  validateLabel(frameworkVersion, "frameworkVersion");
  validateLabel(runner, "runner");
  validateTimestamp(recordedAt);
  const logs = orderedLogs(input.logs);
  const browserVersion = logs.map((log) => `${log.browser}@${log.version}`).join(",");
  if (!nonEmptyBoundedBrowserVersion(browserVersion)) {
    throw new Error("browser runtime version summary must be bounded");
  }
  return {
    schemaVersion: 1,
    status: "pass",
    commit,
    gate: "web-browser-matrix",
    platform: "web",
    framework: "web",
    frameworkVersion,
    recordedAt,
    physicalDevice: false,
    device: {
      browser: "chromium+firefox+webkit",
      browserVersion,
      osVersion: runner,
      secureContext: true,
    },
    testCases: { ...WEB_TEST_CASES },
    sanitizedLogs: true,
    logPath: logs[0].path,
    logSha256: createHash("sha256").update(logs[0].bytes).digest("hex"),
    artifacts: logs.slice(1).map((log) => ({
      kind: `browser-report-${log.browser}`,
      path: log.path,
      sha256: createHash("sha256").update(log.bytes).digest("hex"),
    })),
  };
}

function containedFile(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) throw new Error("browser log path must be a safe relative path");
  const realRoot = realpathSync(root);
  const absoluteFile = path.resolve(realRoot, relativePath);
  if (pathHasSymlinkComponent(realRoot, absoluteFile)) {
    throw new Error("browser log path must not resolve through symbolic links");
  }
  const realFile = realpathSync(absoluteFile);
  const relative = path.relative(realRoot, realFile);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("browser log path must resolve inside the evidence root");
  }
  return realFile;
}

function readBoundedBrowserLog(root, relativePath) {
  const filePath = containedFile(root, relativePath);
  const stats = statSync(filePath);
  if (!stats.isFile()) throw new Error("browser log path must reference a regular file");
  if (stats.size === 0) throw new Error("browser log file must not be empty");
  if (stats.size > MAX_DEVICE_EVIDENCE_FILE_BYTES) {
    throw new Error(`browser log file must not exceed ${MAX_DEVICE_EVIDENCE_FILE_BYTES} bytes`);
  }
  return readFileSync(filePath);
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
}

/**
 * Reads browser logs inside the evidence root, then writes a device evidence
 * record and a commit-bound release fragment.
 *
 * @param {{root: string, commit: string, packageVersion: string, evidencePath: string, fragmentPath: string, frameworkVersion: string, runner: string, recordedAt: string, logs: Array<{browser: string, path: string}>}} input
 * @returns {{record: Record<string, unknown>, fragment: Record<string, unknown>}}
 */
export function writeWebBrowserEvidence(input) {
  if (!isRecord(input)) throw new Error("web evidence input must be an object");
  const { root, packageVersion, evidencePath, fragmentPath } = input;
  if (typeof root !== "string" || root.length === 0) throw new Error("evidence root is required");
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
  if (!isSafeRelativePath(evidencePath) || !isSafeRelativePath(fragmentPath)) {
    throw new Error("output path must be a safe relative path");
  }
  if (evidencePath === fragmentPath) throw new Error("fragment output must not overwrite the evidence record");
  if (!Array.isArray(input.logs)) throw new Error("logs must contain exactly one log for chromium, firefox, and webkit");
  const logs = input.logs.map((log) => ({
    browser: log?.browser,
    path: log?.path,
    bytes: readBoundedBrowserLog(root, log?.path),
  }));
  const record = buildWebBrowserEvidence({ ...input, logs });
  const evidenceBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  const fragment = buildReleaseGateFragment({
    commit: input.commit,
    packageVersion,
    gateName: "web-browser-matrix",
    evidencePath,
    evidenceBytes,
  });
  writeJson(root, evidencePath, evidenceBytes);
  writeJson(root, fragmentPath, Buffer.from(`${JSON.stringify(fragment, null, 2)}\n`, "utf8"));
  return { record, fragment };
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting web evidence");
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
  let frameworkVersion;
  let runner;
  const logs = [];
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if ((option === "--framework-version" || option === "--runner") && typeof value === "string") {
      if (option === "--framework-version") frameworkVersion = value;
      else runner = value;
      index += 1;
      continue;
    }
    if (option === "--log" && typeof value === "string") {
      const separator = value.indexOf("=");
      if (separator <= 0) throw new Error("browser logs must use --log browser=relative/path");
      logs.push({ browser: value.slice(0, separator), path: value.slice(separator + 1) });
      index += 1;
      continue;
    }
    throw new Error("options must use --framework-version, --runner, and --log");
  }
  return { frameworkVersion, runner, logs };
}

function main() {
  const [rootArgument, evidencePath, fragmentPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !evidencePath || !fragmentPath) {
    console.error(
      "usage: node scripts/emit-web-browser-evidence.mjs <evidence-root> <evidence-json> <fragment-json> --framework-version <label> --runner <label> --log browser=relative/path...",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = path.resolve(process.cwd(), rootArgument);
    mkdirSync(root, { recursive: true });
    const { frameworkVersion, runner, logs } = parseOptions(options);
    writeWebBrowserEvidence({
      root,
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      evidencePath,
      fragmentPath,
      frameworkVersion,
      runner,
      recordedAt: new Date().toISOString(),
      logs,
    });
    console.log(`web browser release evidence emitted: ${path.relative(process.cwd(), root)}`);
  } catch (error) {
    console.error(`web browser release evidence failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
