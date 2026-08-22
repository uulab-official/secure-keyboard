import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import { checkReleaseFragmentSet } from "./check-release-fragment-set.mjs";

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-fragment-set-"));
  mkdirSync(path.join(root, "fragments"), { recursive: true });
  return root;
}

function writeFragment(root, name, gateName) {
  writeFileSync(
    path.join(root, "fragments", name),
    `${JSON.stringify(gateName === undefined ? { artifacts: [] } : { gates: [{ name: gateName }] })}\n`,
    { mode: 0o600 },
  );
}

function completeFragmentSet(root) {
  const paths = ["fragments/candidate-artifacts.json"];
  writeFragment(root, "candidate-artifacts.json");
  for (const [index, gateName] of REQUIRED_RELEASE_GATES.entries()) {
    const relativePath = `fragments/gate-${index}.json`;
    writeFragment(root, `gate-${index}.json`, gateName);
    paths.push(relativePath);
  }
  return paths;
}

test("accepts every required release gate exactly once and allows artifact-only fragments", () => {
  const root = fixture();
  try {
    const result = checkReleaseFragmentSet(root, completeFragmentSet(root));
    assert.deepEqual(result.gateNames, [...REQUIRED_RELEASE_GATES].sort());
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects missing, duplicate, and unsupported release gates", () => {
  const root = fixture();
  try {
    const paths = completeFragmentSet(root);
    assert.throws(
      () => checkReleaseFragmentSet(root, paths.slice(0, -1)),
      /missing required release gate fragments/,
    );

    const duplicatePath = "fragments/duplicate.json";
    writeFragment(root, "duplicate.json", REQUIRED_RELEASE_GATES[0]);
    assert.throws(
      () => checkReleaseFragmentSet(root, [...paths, duplicatePath]),
      /duplicate release gate fragment/,
    );

    writeFragment(root, "unsupported.json", "future-gate");
    assert.throws(
      () => checkReleaseFragmentSet(root, [...paths, "fragments/unsupported.json"]),
      /unsupported release gate/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects duplicate paths and symbolic-link fragments before parsing", () => {
  const root = fixture();
  try {
    writeFragment(root, "gate.json", REQUIRED_RELEASE_GATES[0]);
    assert.throws(
      () => checkReleaseFragmentSet(root, ["fragments/gate.json", "fragments/gate.json"]),
      /duplicate release fragment path/,
    );
    symlinkSync("gate.json", path.join(root, "fragments", "link.json"));
    assert.throws(
      () => checkReleaseFragmentSet(root, ["fragments/link.json"]),
      /symbolic links/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
