import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import {
  LSAN_RUNS,
  LSAN_TARGETS,
  buildLsanGateEvidence,
  validateLsanEvidenceRecord,
  verifyLsanEvidenceFiles,
} from "./verify-lsan-evidence.mjs";
import { writeLsanGateEvidence } from "./emit-lsan-gate-evidence.mjs";

const COMMIT = "c".repeat(40);
const LOG_PREFIX = "retained/fuzz-logs";
const CI_WORKFLOW = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const MARKER = (target) =>
  `SECURE_KEYPAD_LSAN_RESULT target=${target} toolchain=nightly-2026-08-19 sanitizer=leak runs=${LSAN_RUNS} status=pass`;

function createLogs() {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-lsan-"));
  for (const target of LSAN_TARGETS) {
    writeFileSync(
      join(root, `${target}-lsan.log`),
      `cargo fuzz run ${target} --sanitizer=leak\n${MARKER(target)}\n`,
      { mode: 0o600 },
    );
  }
  return root;
}

test("builds a commit-bound LSAN record with every target log digest", () => {
  const logRoot = createLogs();
  const record = buildLsanGateEvidence({
    logRoot,
    commit: COMMIT,
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    pathPrefix: LOG_PREFIX,
  });

  assert.equal(record.evidenceKind, "ci-command");
  assert.equal(record.logEvidenceKind, "linux-leak-sanitizer");
  assert.equal(record.toolchain, "nightly-2026-08-19");
  assert.equal(record.sanitizer, "leak");
  assert.equal(record.runs, LSAN_RUNS);
  assert.deepEqual(
    record.targets.map((entry) => entry.target),
    [...LSAN_TARGETS],
  );
  for (const entry of record.targets) {
    const bytes = readFileSync(join(logRoot, `${entry.target}-lsan.log`));
    assert.equal(entry.path, `${LOG_PREFIX}/${entry.target}-lsan.log`);
    assert.equal(entry.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.equal(entry.bytes, bytes.length);
    assert.equal(entry.status, "pass");
  }
  assert.deepEqual(validateLsanEvidenceRecord(record), []);
  assert.deepEqual(verifyLsanEvidenceFiles(record, logRoot, { pathPrefix: LOG_PREFIX }), []);
});

test("writes the LSAN record and release fragment without embedding log contents", () => {
  const logRoot = createLogs();
  const outputRoot = mkdtempSync(join(tmpdir(), "secure-keypad-lsan-output-"));
  mkdirSync(join(outputRoot, "evidence"), { recursive: true });

  const result = writeLsanGateEvidence({
    logRoot,
    outputRoot,
    commit: COMMIT,
    packageVersion: "0.1.0",
    evidencePath: "evidence/linux-leak-sanitizer.json",
    fragmentPath: "fragments/linux-leak-sanitizer.json",
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    pathPrefix: LOG_PREFIX,
  });

  const recordBytes = readFileSync(join(outputRoot, "evidence/linux-leak-sanitizer.json"));
  const fragment = JSON.parse(readFileSync(join(outputRoot, "fragments/linux-leak-sanitizer.json"), "utf8"));
  assert.deepEqual(JSON.parse(recordBytes), result.record);
  assert.equal(fragment.gates[0].sha256, createHash("sha256").update(recordBytes).digest("hex"));
  assert.equal(recordBytes.includes(Buffer.from("cargo fuzz run")), false);
  assert.deepEqual(validateLsanEvidenceRecord(result.record), []);
});

test("rejects a missing target, a missing success marker, and a path outside the retained log prefix", () => {
  const logRoot = createLogs();
  const record = buildLsanGateEvidence({
    logRoot,
    commit: COMMIT,
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    pathPrefix: LOG_PREFIX,
  });

  const missingTarget = { ...record, targets: record.targets.slice(0, -1) };
  assert.match(validateLsanEvidenceRecord(missingTarget).join("\n"), /exactly one entry for every required target/);

  const missingMarker = {
    ...record,
    targets: record.targets.map((entry, index) => (index === 0 ? { ...entry, status: "pass" } : entry)),
  };
  writeFileSync(join(logRoot, "auth_envelope-lsan.log"), "cargo fuzz run auth_envelope --sanitizer=leak\n");
  assert.match(
    verifyLsanEvidenceFiles(missingMarker, logRoot, { pathPrefix: LOG_PREFIX }).join("\n"),
    /success marker/,
  );

  const unsafePath = {
    ...record,
    targets: record.targets.map((entry, index) => (index === 0 ? { ...entry, path: "retained/other.log" } : entry)),
  };
  assert.match(validateLsanEvidenceRecord(unsafePath).join("\n"), /must equal retained\/fuzz-logs\/auth_envelope-lsan\.log/);

  const missingPath = {
    ...record,
    targets: record.targets.map((entry, index) => (index === 0 ? { ...entry, path: undefined } : entry)),
  };
  assert.doesNotThrow(() => verifyLsanEvidenceFiles(missingPath, logRoot, { pathPrefix: LOG_PREFIX }));
});

test("rejects a success marker that is not the final meaningful log line", () => {
  const logRoot = createLogs();
  writeFileSync(
    join(logRoot, "auth_envelope-lsan.log"),
    `${MARKER("auth_envelope")}\nlate sanitizer output\n`,
  );
  assert.throws(
    () =>
      buildLsanGateEvidence({
        logRoot,
        commit: COMMIT,
        runner: "ubuntu-24.04",
        recordedAt: "2026-08-22T00:00:00.000Z",
        pathPrefix: LOG_PREFIX,
      }),
    /missing the exact success marker/,
  );
});

test("CI records the success marker only after each LSAN command and preserves the bound record", () => {
  for (const target of LSAN_TARGETS) {
    assert.match(
      CI_WORKFLOW,
      new RegExp(
        `fuzz run ${target}[^\\n]*--sanitizer=leak[\\s\\S]*?tee "\\$RUNNER_TEMP/secure-keypad-fuzz-logs/${target}-lsan\\.log"[\\s\\S]*?SECURE_KEYPAD_LSAN_RESULT target=${target}`,
      ),
    );
  }
  assert.match(CI_WORKFLOW, /node scripts\/emit-lsan-gate-evidence\.mjs/);
  assert.match(CI_WORKFLOW, /name: secure-keypad-ci-gate-fuzz/);
  assert.match(CI_WORKFLOW, /name: Retain commit-bound fuzz gate records/);
  assert.doesNotMatch(CI_WORKFLOW, /linux-leak-sanitizer-aggregate\.json/);
});
