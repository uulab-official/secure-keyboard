import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildCiGateEvidence, writeCiGateEvidence } from "./emit-ci-gate-evidence.mjs";

const COMMIT = "c".repeat(40);
const CI_WORKFLOW = readFileSync(fileURLToPath(new URL("../.github/workflows/ci.yml", import.meta.url)), "utf8");

test("builds a sanitized pass record for an allowed CI release gate", () => {
  const record = buildCiGateEvidence({
    commit: COMMIT,
    gateName: "linux-leak-sanitizer",
    runner: "ubuntu-24.04",
    checks: ["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"],
    recordedAt: "2026-08-22T00:00:00.000Z",
  });

  assert.deepEqual(record, {
    schemaVersion: 1,
    status: "pass",
    commit: COMMIT,
    gate: "linux-leak-sanitizer",
    evidenceKind: "ci-command",
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    checks: ["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"],
  });
});

test("writes a commit-bound evidence record and matching fragment without raw logs", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-ci-evidence-"));
  mkdirSync(join(root, "evidence"), { recursive: true });

  const result = writeCiGateEvidence({
    root,
    commit: COMMIT,
    packageVersion: "0.1.0",
    gateName: "durable-backends",
    evidencePath: "evidence/durable-backends.json",
    fragmentPath: "fragments/durable-backends.json",
    runner: "ubuntu-24.04",
    checks: ["durable_storage", "durable_rate_limit", "durable_one_time_state"],
    recordedAt: "2026-08-22T00:00:00.000Z",
  });

  const evidenceBytes = readFileSync(join(root, "evidence/durable-backends.json"));
  const fragment = JSON.parse(readFileSync(join(root, "fragments/durable-backends.json"), "utf8"));
  assert.deepEqual(JSON.parse(evidenceBytes), result.record);
  assert.equal(fragment.gates[0].evidencePath, "evidence/durable-backends.json");
  assert.equal(fragment.gates[0].sha256, createHash("sha256").update(evidenceBytes).digest("hex"));
  assert.equal(Object.hasOwn(result.record, "log"), false);
});

test("rejects unsafe paths, unknown gates, and non-sanitized check labels", () => {
  assert.throws(
    () =>
      buildCiGateEvidence({
        commit: COMMIT,
        gateName: "not-a-release-gate",
        runner: "ubuntu-24.04",
        checks: ["ok"],
        recordedAt: "2026-08-22T00:00:00.000Z",
      }),
    /unsupported release gate/,
  );
  assert.throws(
    () =>
      buildCiGateEvidence({
        commit: COMMIT,
        gateName: "durable-backends",
        runner: "ubuntu-24.04",
        checks: ["password=raw"],
        recordedAt: "2026-08-22T00:00:00.000Z",
      }),
    /sanitized check label/,
  );
  assert.throws(
    () =>
      writeCiGateEvidence({
        root: mkdtempSync(join(tmpdir(), "secure-keypad-ci-evidence-")),
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "durable-backends",
        evidencePath: "../evidence.json",
        fragmentPath: "fragments/durable-backends.json",
        runner: "ubuntu-24.04",
        checks: ["durable_storage"],
        recordedAt: "2026-08-22T00:00:00.000Z",
      }),
    /safe relative path/,
  );
});

test("CI emits durable and fuzz gate fragments only after their command groups", () => {
  assert.match(CI_WORKFLOW, /name: Emit durable backend CI release evidence[\s\S]*?emit-ci-gate-evidence\.mjs/);
  assert.match(CI_WORKFLOW, /durable-backends[\s\S]*?--check durable_storage[\s\S]*?--check durable_rate_limit[\s\S]*?--check durable_one_time_state/);
  assert.match(CI_WORKFLOW, /name: Emit fuzz CI release evidence[\s\S]*?emit-ci-gate-evidence\.mjs/);
  assert.match(CI_WORKFLOW, /fuzz-stability[\s\S]*?linux-leak-sanitizer/);
  assert.match(CI_WORKFLOW, /name: secure-keypad-ci-gate-fuzz/);
});
