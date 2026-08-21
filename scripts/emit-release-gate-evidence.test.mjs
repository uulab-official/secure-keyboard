import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildReleaseGateFragment } from "./emit-release-gate-evidence.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const EMIT_SCRIPT = fileURLToPath(new URL("./emit-release-gate-evidence.mjs", import.meta.url));
const COMMIT = "a".repeat(40);

function evidenceRecord(commit = COMMIT, gate = "rust-workspace") {
  return { schemaVersion: 1, commit, gate, status: "pass", result: "sanitized" };
}

test("builds a commit-bound gate fragment with the exact evidence digest", () => {
  const bytes = Buffer.from(`${JSON.stringify(evidenceRecord())}\n`, "utf8");
  const fragment = buildReleaseGateFragment({
    commit: COMMIT,
    packageVersion: "0.1.0",
    gateName: "rust-workspace",
    evidencePath: "evidence/rust-workspace.json",
    evidenceBytes: bytes,
    toolchains: { rust: "1.97.1" },
  });

  assert.deepEqual(fragment, {
    schemaVersion: 1,
    commit: COMMIT,
    packageVersion: "0.1.0",
    toolchains: { rust: "1.97.1" },
    gates: [
      {
        name: "rust-workspace",
        commit: COMMIT,
        status: "pass",
        evidencePath: "evidence/rust-workspace.json",
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
    ],
  });
});

test("rejects unsupported gates, stale records, unsafe paths, and secret fields", () => {
  const bytes = Buffer.from(`${JSON.stringify(evidenceRecord())}\n`, "utf8");
  assert.throws(
    () =>
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "made-up-gate",
        evidencePath: "evidence/gate.json",
        evidenceBytes: bytes,
      }),
    /unsupported release gate/,
  );
  assert.throws(
    () =>
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "rust-workspace",
        evidencePath: "../gate.json",
        evidenceBytes: bytes,
      }),
    /safe relative path/,
  );
  assert.throws(
    () =>
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "rust-workspace",
        evidencePath: "evidence/gate.json",
        evidenceBytes: Buffer.from(JSON.stringify({ ...evidenceRecord(), password: "never" }), "utf8"),
      }),
    /secret-bearing evidence fields/,
  );
  for (const key of ["sentinel", "inputBytes", "credentialBytes", "rawInput"]) {
    assert.throws(
      () =>
        buildReleaseGateFragment({
          commit: COMMIT,
          packageVersion: "0.1.0",
          gateName: "rust-workspace",
          evidencePath: "evidence/gate.json",
          evidenceBytes: Buffer.from(JSON.stringify({ ...evidenceRecord(), [key]: "never" }), "utf8"),
        }),
      /secret-bearing evidence fields/,
      `must reject ${key}`,
    );
  }
  assert.throws(
    () =>
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "rust-workspace",
        evidencePath: "evidence/gate.json",
        evidenceBytes: Buffer.from(JSON.stringify(evidenceRecord("b".repeat(40)), "utf8"), "utf8"),
      }),
    /must match the gate commit/,
  );
  assert.throws(
    () =>
      buildReleaseGateFragment({
        commit: COMMIT,
        packageVersion: "0.1.0",
        gateName: "rust-workspace",
        evidencePath: "evidence/gate.json",
        evidenceBytes: Buffer.from(JSON.stringify(evidenceRecord(COMMIT, "javascript-contracts")), "utf8"),
      }),
    /must match the fragment gate/,
  );
});

test("CLI emits a fragment from the current checkout and package version", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-release-gate-"));
  mkdirSync(join(root, "evidence"), { recursive: true });
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  const evidencePath = "evidence/rust-workspace.json";
  writeFileSync(join(root, evidencePath), `${JSON.stringify(evidenceRecord(commit))}\n`);

  execFileSync(
    process.execPath,
    [
      EMIT_SCRIPT,
      root,
      "fragments/rust-workspace.json",
      "rust-workspace",
      evidencePath,
      "--toolchain",
      "rust=1.97.1",
    ],
    { cwd: ROOT, encoding: "utf8" },
  );

  const fragment = JSON.parse(readFileSync(join(root, "fragments/rust-workspace.json"), "utf8"));
  assert.equal(fragment.commit, commit);
  assert.equal(fragment.packageVersion, "0.1.0");
  assert.equal(fragment.gates[0].commit, commit);
  assert.equal(fragment.gates[0].status, "pass");
});
