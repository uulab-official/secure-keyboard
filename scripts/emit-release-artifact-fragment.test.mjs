import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import { buildReleaseArtifactFragment } from "./emit-release-artifact-fragment.mjs";

const COMMIT = "a".repeat(40);
const REPOSITORY_ROOT = fileURLToPath(new URL("..", import.meta.url));
const EMIT_SCRIPT = fileURLToPath(new URL("./emit-release-artifact-fragment.mjs", import.meta.url));

test("builds a commit-bound fragment for hashed public release artifacts", () => {
  const fragment = buildReleaseArtifactFragment({
    commit: COMMIT,
    packageVersion: "0.1.0",
    artifacts: [
      { kind: "native-checksum", path: "source/secure-keypad-ios-ffi.sha256", bytes: "native\n" },
      { kind: "sbom", path: "secure-keypad.sbom.spdx.json", bytes: "sbom\n" },
      { kind: "license-notices", path: "source/THIRD-PARTY-NOTICES.md", bytes: "notices\n" },
    ],
  });

  assert.equal(fragment.schemaVersion, 1);
  assert.equal(fragment.commit, COMMIT);
  assert.equal(fragment.packageVersion, "0.1.0");
  assert.deepEqual(
    fragment.artifacts.map(({ kind, path: artifactPath }) => ({ kind, path: artifactPath })),
    [
      { kind: "native-checksum", path: "source/secure-keypad-ios-ffi.sha256" },
      { kind: "sbom", path: "secure-keypad.sbom.spdx.json" },
      { kind: "license-notices", path: "source/THIRD-PARTY-NOTICES.md" },
    ],
  );
  assert.match(fragment.artifacts[0].sha256, /^[a-f0-9]{64}$/);
});

test("rejects duplicate, unsafe, secret-bearing, and oversized artifact inputs", () => {
  const base = { commit: COMMIT, packageVersion: "0.1.0" };
  assert.throws(
    () => buildReleaseArtifactFragment({ ...base, artifacts: [
      { kind: "sbom", path: "a", bytes: "a" },
      { kind: "sbom", path: "b", bytes: "b" },
    ] }),
    /duplicate artifact kind/,
  );
  assert.throws(
    () => buildReleaseArtifactFragment({ ...base, artifacts: [{ kind: "sbom", path: "../sbom", bytes: "a" }] }),
    /safe and relative/,
  );
  assert.throws(
    () => buildReleaseArtifactFragment({ ...base, artifacts: [{ kind: "sbom", path: "secret.pem", bytes: "a" }] }),
    /private signing material or secret/,
  );
  assert.throws(
    () => buildReleaseArtifactFragment({ ...base, artifacts: [{ kind: "sbom", path: "sbom", bytes: { byteLength: 1_048_577 } }] }),
    /string or byte array/,
  );
});

test("release workflows publish and consume the candidate artifact fragment", () => {
  const candidateWorkflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  const finalWorkflow = readFileSync(
    new URL("../.github/workflows/release-finalize.yml", import.meta.url),
    "utf8",
  );
  assert.match(candidateWorkflow, /secure-keypad-ios-ffi\.sha256/);
  assert.match(candidateWorkflow, /secure-keypad-android-ffi\.sha256/);
  assert.match(candidateWorkflow, /secure-keypad-release-android-ffi/);
  assert.match(candidateWorkflow, /emit-release-artifact-fragment\.mjs/);
  assert.match(candidateWorkflow, /native-checksum/);
  assert.match(candidateWorkflow, /native-checksum-android/);
  assert.match(candidateWorkflow, /license-notices/);
  assert.match(finalWorkflow, /secure-keypad-release-candidate/);
  assert.match(finalWorkflow, /fragments/);
  assert.equal(REQUIRED_RELEASE_GATES.includes("signed-release"), true);
});

test("artifact fragment CLI reads bounded files and writes an exclusive JSON output", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-artifact-fragment-"));
  try {
    mkdirSync(path.join(root, "source"), { recursive: true });
    writeFileSync(path.join(root, "source/native.sha256"), "native\n");
    const result = spawnSync(
      process.execPath,
      [
        EMIT_SCRIPT,
        root,
        "fragments/candidate-artifacts.json",
        "--commit",
        "a".repeat(40),
        "--package-version",
        "0.1.0",
        "--artifact",
        "native-checksum=source/native.sha256",
      ],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const fragment = JSON.parse(readFileSync(path.join(root, "fragments/candidate-artifacts.json"), "utf8"));
    assert.equal(fragment.artifacts[0].kind, "native-checksum");
    assert.equal(fragment.artifacts[0].path, "source/native.sha256");
    assert.match(fragment.artifacts[0].sha256, /^[a-f0-9]{64}$/);
    assert.equal(
      spawnSync(
        process.execPath,
        [
          EMIT_SCRIPT,
          root,
          "fragments/candidate-artifacts.json",
          "--commit",
          "a".repeat(40),
          "--package-version",
          "0.1.0",
          "--artifact",
          "native-checksum=source/native.sha256",
        ],
        { cwd: REPOSITORY_ROOT, encoding: "utf8" },
      ).status,
      1,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact fragment CLI accepts an explicit candidate identity from a trusted verifier checkout", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-explicit-artifact-identity-"));
  try {
    mkdirSync(path.join(root, "source"), { recursive: true });
    writeFileSync(path.join(root, "source/native.sha256"), "native\n");
    const result = spawnSync(
      process.execPath,
      [
        EMIT_SCRIPT,
        root,
        "fragments/candidate-artifacts.json",
        "--commit",
        "b".repeat(40),
        "--package-version",
        "9.9.9-rc.1",
        "--artifact",
        "native-checksum=source/native.sha256",
      ],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const fragment = JSON.parse(readFileSync(path.join(root, "fragments/candidate-artifacts.json"), "utf8"));
    assert.equal(fragment.commit, "b".repeat(40));
    assert.equal(fragment.packageVersion, "9.9.9-rc.1");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
