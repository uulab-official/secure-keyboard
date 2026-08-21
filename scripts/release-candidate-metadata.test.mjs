import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import {
  buildReleaseCandidateMetadata,
  validateReleaseCandidateCheckoutStatus,
} from "./release-candidate-metadata.mjs";

const WORKFLOW = readFileSync(
  fileURLToPath(new URL("../.github/workflows/release-candidate.yml", import.meta.url)),
  "utf8",
);

test("candidate metadata binds the exact checkout and final evidence contract", () => {
  const metadata = buildReleaseCandidateMetadata({
    commit: "b".repeat(40),
    packageVersion: "0.1.0",
    createdAt: "2026-08-21T00:00:00.000Z",
  });

  assert.equal(metadata.schemaVersion, 1);
  assert.equal(metadata.kind, "secure-keypad-release-candidate");
  assert.equal(metadata.commit, "b".repeat(40));
  assert.equal(metadata.packageVersion, "0.1.0");
  assert.deepEqual(metadata.requiredFinalGates, REQUIRED_RELEASE_GATES);
  assert.equal(metadata.claim, "candidate-only");
  assert.equal(metadata.finalVerifier.command, "node scripts/check-release-evidence.mjs --require-trusted-keys release-evidence/release-evidence.json");
});

test("candidate metadata rejects mutable or invalid release identity", () => {
  assert.throws(
    () =>
      buildReleaseCandidateMetadata({
        commit: "main",
        packageVersion: "0.1.0",
        createdAt: "2026-08-21T00:00:00.000Z",
      }),
    /commit must be a 40-character lowercase commit SHA/,
  );
  assert.throws(
    () =>
      buildReleaseCandidateMetadata({
        commit: "b".repeat(40),
        packageVersion: "0.1",
        createdAt: "2026-08-21T00:00:00.000Z",
      }),
    /packageVersion must be a semantic version/,
  );
});

test("candidate metadata requires a clean checkout before bundling", () => {
  assert.doesNotThrow(() => validateReleaseCandidateCheckoutStatus(""));
  assert.throws(
    () => validateReleaseCandidateCheckoutStatus(" M packages/react-native/dist/index.js\n"),
    /current checkout must be clean before emitting candidate metadata/,
  );
});

test("release candidate workflow embeds the metadata inside the signed bundle", () => {
  assert.match(WORKFLOW, /scripts\/release-candidate-metadata\.mjs\s+\"\$RELEASE_DIR\/source\/release-candidate-metadata\.json\"/);
  assert.match(WORKFLOW, /release-candidate-metadata\.json/);
});
