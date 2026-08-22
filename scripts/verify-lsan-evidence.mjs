import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

export const LSAN_TARGETS = Object.freeze([
  "auth_envelope",
  "core_sequence",
  "ffi_sequence",
  "webauthn_state",
]);
export const LSAN_RUNS = 10_000;
export const LSAN_TOOLCHAIN = "nightly-2026-08-19";
export const LSAN_LOG_PATH_PREFIX = "retained/fuzz-logs";
export const MAX_LSAN_LOG_BYTES = 32 * 1024 * 1024;

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,80}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

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

function successMarker(target) {
  return `SECURE_KEYPAD_LSAN_RESULT target=${target} toolchain=${LSAN_TOOLCHAIN} sanitizer=leak runs=${LSAN_RUNS} status=pass`;
}

function hasSuccessMarker(bytes, target) {
  const lines = bytes.toString("utf8").split(/\r?\n/);
  return lines.includes(successMarker(target));
}

function add(findings, field, message) {
  findings.push(`${field}: ${message}`);
}

function expectedLogPath(target) {
  return `${LSAN_LOG_PATH_PREFIX}/${target}-lsan.log`;
}

function validateTimestamp(value) {
  return typeof value === "string" && ISO_TIMESTAMP.test(value) && new Date(value).toISOString() === value;
}

/**
 * Validates the sanitized metadata record that accompanies the four raw LSAN
 * logs. The record deliberately contains digests and bounded metadata only;
 * raw campaign output stays in the retained evidence tree.
 *
 * @param {unknown} record
 * @param {{expectedCommit?: string, expectedGate?: string}} [context]
 * @returns {string[]}
 */
export function validateLsanEvidenceRecord(record, context = {}) {
  const findings = [];
  if (!isRecord(record)) return ["record: must be a JSON object"];
  if (record.schemaVersion !== 1) add(findings, "schemaVersion", "must equal 1");
  if (record.status !== "pass") add(findings, "status", "must equal pass");
  if (typeof record.commit !== "string" || !COMMIT.test(record.commit)) {
    add(findings, "commit", "must be a 40-character lowercase commit SHA");
  } else if (context.expectedCommit !== undefined && record.commit !== context.expectedCommit) {
    add(findings, "commit", "must match the expected commit");
  }
  if (record.gate !== "linux-leak-sanitizer") add(findings, "gate", "must equal linux-leak-sanitizer");
  if (context.expectedGate !== undefined && record.gate !== context.expectedGate) {
    add(findings, "gate", "must match the expected gate");
  }
  if (record.evidenceKind !== "ci-command") add(findings, "evidenceKind", "must equal ci-command");
  if (record.logEvidenceKind !== "linux-leak-sanitizer") {
    add(findings, "logEvidenceKind", "must equal linux-leak-sanitizer");
  }
  if (typeof record.runner !== "string" || !LABEL.test(record.runner)) {
    add(findings, "runner", "must be a sanitized check label");
  }
  if (!validateTimestamp(record.recordedAt)) {
    add(findings, "recordedAt", "must be an ISO-8601 UTC timestamp");
  }
  if (record.toolchain !== LSAN_TOOLCHAIN) add(findings, "toolchain", `must equal ${LSAN_TOOLCHAIN}`);
  if (record.sanitizer !== "leak") add(findings, "sanitizer", "must equal leak");
  if (record.runs !== LSAN_RUNS) add(findings, "runs", `must equal ${LSAN_RUNS}`);

  if (!Array.isArray(record.targets) || record.targets.length !== LSAN_TARGETS.length) {
    add(findings, "targets", "must contain exactly one entry for every required target");
    return findings;
  }
  const seen = new Set();
  for (const [index, entry] of record.targets.entries()) {
    const field = `targets[${index}]`;
    if (!isRecord(entry)) {
      add(findings, field, "must be an object");
      continue;
    }
    if (!LSAN_TARGETS.includes(entry.target) || seen.has(entry.target)) {
      add(findings, `${field}.target`, "must be a unique required target");
    } else {
      seen.add(entry.target);
    }
    if (typeof entry.target === "string" && LSAN_TARGETS.includes(entry.target)) {
      const expectedPath = expectedLogPath(entry.target);
      if (entry.path !== expectedPath) add(findings, `${field}.path`, `must equal ${expectedPath}`);
    } else if (!isSafeRelativePath(entry.path)) {
      add(findings, `${field}.path`, "must be a safe relative path");
    }
    if (typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)) {
      add(findings, `${field}.sha256`, "must be a lowercase SHA-256 digest");
    }
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || entry.bytes > MAX_LSAN_LOG_BYTES) {
      add(findings, `${field}.bytes`, `must be between 1 and ${MAX_LSAN_LOG_BYTES}`);
    }
    if (entry.status !== "pass") add(findings, `${field}.status`, "must equal pass");
  }
  if (seen.size !== LSAN_TARGETS.length) add(findings, "targets", "must include every required target exactly once");
  return findings;
}

function realContainedFile(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) throw new Error("path must be a safe relative path");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  const relative = path.relative(realRoot, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("path must resolve inside the evidence root");
  }
  let cursor = absolutePath;
  while (cursor !== realRoot && cursor.startsWith(`${realRoot}${path.sep}`)) {
    if (lstatSync(cursor).isSymbolicLink()) throw new Error("path must not resolve through a symbolic link");
    cursor = path.dirname(cursor);
  }
  const realFile = realpathSync(absolutePath);
  const realRelative = path.relative(realRoot, realFile);
  if (realRelative === "" || realRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realRelative)) {
    throw new Error("path must resolve inside the evidence root");
  }
  return realFile;
}

/**
 * Verifies each referenced raw log against its recorded size, digest, and
 * success marker. `pathPrefix` is used only by the fuzz job, where logs live
 * in a separate directory before the aggregate evidence tree is assembled.
 * The final verifier leaves it empty and checks the manifest-relative paths.
 *
 * @param {unknown} record
 * @param {string} root
 * @param {{pathPrefix?: string}} [options]
 * @returns {string[]}
 */
export function verifyLsanEvidenceFiles(record, root, { pathPrefix = "" } = {}) {
  const findings = [...validateLsanEvidenceRecord(record)];
  if (!isRecord(record) || !Array.isArray(record.targets)) return findings;
  if (typeof root !== "string" || root.length === 0) return [...findings, "root: must be provided"];
  for (const [index, entry] of record.targets.entries()) {
    if (!isRecord(entry) || typeof entry.target !== "string" || !LSAN_TARGETS.includes(entry.target)) continue;
    const field = `targets[${index}]`;
    if (typeof entry.path !== "string") continue;
    const sourceRelativePath = pathPrefix.length > 0
      ? entry.path.startsWith(`${pathPrefix}/`)
        ? entry.path.slice(pathPrefix.length + 1)
        : undefined
      : entry.path;
    if (sourceRelativePath === undefined) {
      add(findings, `${field}.path`, "does not match the configured source prefix");
      continue;
    }
    let absolutePath;
    try {
      absolutePath = realContainedFile(root, sourceRelativePath);
      const stats = statSync(absolutePath);
      if (!stats.isFile()) throw new Error("must reference a regular file");
      if (stats.size === 0) throw new Error("must not be empty");
      if (stats.size > MAX_LSAN_LOG_BYTES) throw new Error(`must not exceed ${MAX_LSAN_LOG_BYTES} bytes`);
      const bytes = readFileSync(absolutePath);
      if (bytes.length !== entry.bytes) add(findings, `${field}.bytes`, "does not match the raw log");
      const digest = createHash("sha256").update(bytes).digest("hex");
      if (digest !== entry.sha256) add(findings, `${field}.sha256`, "does not match the raw log");
      if (!hasSuccessMarker(bytes, entry.target)) {
        add(findings, `${field}.path`, "must contain the exact LSAN success marker");
      }
    } catch (error) {
      add(findings, `${field}.path`, error.message);
    }
  }
  return findings;
}

function readLog(logRoot, target) {
  const absolutePath = path.resolve(realpathSync(logRoot), `${target}-lsan.log`);
  const root = realpathSync(logRoot);
  const relative = path.relative(root, absolutePath);
  if (relative !== `${target}-lsan.log` || lstatSync(absolutePath).isSymbolicLink()) {
    throw new Error(`${target}: LSAN log must be a regular file directly under the log root`);
  }
  const stats = statSync(absolutePath);
  if (!stats.isFile() || stats.size === 0) throw new Error(`${target}: LSAN log must be non-empty`);
  if (stats.size > MAX_LSAN_LOG_BYTES) throw new Error(`${target}: LSAN log exceeds ${MAX_LSAN_LOG_BYTES} bytes`);
  const bytes = readFileSync(absolutePath);
  if (!hasSuccessMarker(bytes, target)) throw new Error(`${target}: LSAN log is missing the exact success marker`);
  return bytes;
}

/**
 * Reads the four successful campaign logs and creates sanitized, hash-bound
 * metadata for the release evidence tree.
 */
export function buildLsanGateEvidence({ logRoot, commit, runner, recordedAt, pathPrefix = LSAN_LOG_PATH_PREFIX }) {
  if (pathPrefix !== LSAN_LOG_PATH_PREFIX) throw new Error(`pathPrefix must equal ${LSAN_LOG_PATH_PREFIX}`);
  const targets = LSAN_TARGETS.map((target) => {
    const bytes = readLog(logRoot, target);
    return {
      target,
      path: expectedLogPath(target),
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
      status: "pass",
    };
  });
  const record = {
    schemaVersion: 1,
    status: "pass",
    commit,
    gate: "linux-leak-sanitizer",
    evidenceKind: "ci-command",
    logEvidenceKind: "linux-leak-sanitizer",
    runner,
    recordedAt,
    toolchain: LSAN_TOOLCHAIN,
    sanitizer: "leak",
    runs: LSAN_RUNS,
    checks: [...LSAN_TARGETS],
    targets,
  };
  const findings = validateLsanEvidenceRecord(record);
  if (findings.length > 0) throw new Error(`invalid LSAN evidence: ${findings.join("; ")}`);
  return record;
}
