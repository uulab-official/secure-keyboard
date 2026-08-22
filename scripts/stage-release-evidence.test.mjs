import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { stageReleaseEvidence } from "./stage-release-evidence.mjs";

function writeFile(root, relativePath, contents) {
  const absolutePath = path.join(root, relativePath);
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, contents);
}

function fixtureRoots() {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-stage-evidence-"));
  const candidate = path.join(root, "candidate");
  const ci = path.join(root, "ci");
  const external = path.join(root, "external");
  const output = path.join(root, "output");
  mkdirSync(candidate);
  mkdirSync(ci);
  mkdirSync(external);
  return { root, candidate, ci, external, output };
}

test("stages candidate, CI, and external evidence without overwriting files", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    writeFile(candidate, "secure-keypad-release.tar.gz", "bundle");
    writeFile(candidate, "evidence/signed-release.json", '{"gate":"signed-release"}\n');
    writeFile(candidate, "fragments/candidate-artifacts.json", '{"artifacts":[]}\n');
    writeFile(ci, "fragments/rust-workspace.json", '{"gates":[]}\n');
    writeFile(external, "fragments/ios-device-matrix.json", '{"gates":[]}\n');

    const staged = stageReleaseEvidence(output, [candidate, ci, external]);

    assert.equal(staged.fragmentPaths.includes("fragments/signed-release.json"), false);
    assert.equal(readFileSync(path.join(output, "secure-keypad-release.tar.gz"), "utf8"), "bundle");
    assert.equal(readFileSync(path.join(output, "evidence/signed-release.json"), "utf8"), '{"gate":"signed-release"}\n');
    assert.equal(readFileSync(path.join(output, "fragments/rust-workspace.json"), "utf8"), '{"gates":[]}\n');
    assert.equal(readFileSync(path.join(output, "fragments/ios-device-matrix.json"), "utf8"), '{"gates":[]}\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("staging rejects duplicate files and symlinked inputs", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    writeFile(candidate, "fragments/duplicate.json", "candidate\n");
    writeFile(ci, "fragments/duplicate.json", "ci\n");
    assert.throws(
      () => stageReleaseEvidence(output, [candidate, ci, external]),
      /duplicate release evidence path fragments\/duplicate\.json/,
    );

    rmSync(path.join(candidate, "fragments/duplicate.json"));
    rmSync(path.join(ci, "fragments/duplicate.json"));
    const symlinked = path.join(external, "secret.txt");
    writeFile(candidate, "evidence/signed-release.json", "signed\n");
    symlinkSync(path.join(candidate, "secure-keypad-release.tar.gz"), symlinked);
    assert.throws(
      () => stageReleaseEvidence(path.join(root, "symlink-output"), [candidate, ci, external]),
      /symlinks are not allowed in release evidence inputs/,
    );

    rmSync(symlinked);
    writeFile(external, "reviewer-private.pem", "private\n");
    assert.throws(
      () => stageReleaseEvidence(path.join(root, "private-output"), [candidate, ci, external]),
      /private signing material or secret files are not allowed/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("staging requires the candidate signed-release evidence record", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    assert.throws(
      () => stageReleaseEvidence(output, [candidate, ci, external]),
      /candidate signed-release evidence is missing/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("staging rejects an oversized untrusted evidence file before copying it", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    const oversized = path.join(external, "retained", "oversized.log");
    mkdirSync(path.dirname(oversized), { recursive: true });
    writeFileSync(oversized, "");
    truncateSync(oversized, 512 * 1024 * 1024 + 1);

    assert.throws(
      () => stageReleaseEvidence(output, [candidate, ci, external]),
      /must not exceed 536870912 bytes/,
    );
    assert.equal(existsSync(path.join(output, "retained", "oversized.log")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("staging rejects evidence directories deeper than the traversal bound", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    let nested = external;
    for (let index = 0; index < 65; index += 1) {
      nested = path.join(nested, `nested-${index}`);
      mkdirSync(nested);
    }

    assert.throws(
      () => stageReleaseEvidence(output, [candidate, ci, external]),
      /directory depth must not exceed 64 components/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("staging rejects evidence with too many directories before copying it", () => {
  const { root, candidate, ci, external, output } = fixtureRoots();
  try {
    for (let index = 0; index < 16_385; index += 1) {
      mkdirSync(path.join(external, `empty-${index}`));
    }

    assert.throws(
      () => stageReleaseEvidence(output, [candidate, ci, external]),
      /must not contain more than 16384 directories/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release finalization workflow downloads immutable evidence inputs and runs the trusted verifier", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-finalize.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /candidate-run-id:/);
  assert.match(workflow, /ci-run-id:/);
  assert.match(workflow, /external-evidence-run-id:/);
  assert.match(workflow, /external-evidence-artifact:/);
  assert.match(workflow, /actions:\s*read/);
  assert.match(workflow, /contents:\s*read/);
  assert.match(workflow, /actions\/download-artifact@[0-9a-f]{40}/);
  assert.match(workflow, /run-id:\s*\$\{\{ inputs\.candidate-run-id \}\}/);
  assert.match(workflow, /run-id:\s*\$\{\{ inputs\.ci-run-id \}\}/);
  assert.match(workflow, /run-id:\s*\$\{\{ inputs\.external-evidence-run-id \}\}/);
  assert.match(workflow, /scripts\/check-release-bundle\.mjs/);
  assert.match(workflow, /scripts\/check-release-archive\.mjs/);
  assert.match(workflow, /sha256sum -c secure-keypad-release\.sha256/);
  assert.match(workflow, /tar --extract --to-stdout/);
  assert.match(workflow, /secure-keypad-ios-ffi\.sha256/);
  assert.match(workflow, /secure-keypad-android-ffi\.sha256/);
  assert.match(workflow, /scripts\/stage-release-evidence\.mjs/);
  assert.match(workflow, /scripts\/emit-signed-release-fragment\.mjs[\s\S]*signed-release/);
  assert.match(workflow, /scripts\/merge-release-evidence\.mjs/);
  assert.match(workflow, /scripts\/check-release-evidence\.mjs --require-trusted-keys/);
  assert.match(workflow, /SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256/);
  assert.match(workflow, /SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256/);
  assert.match(workflow, /name: secure-keypad-production-release-evidence/);
  assert.doesNotMatch(workflow, /contents:\s*write/);
});
