import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import test from "node:test";

import {
  fetchGitHubRunProvenance,
  validateGitHubRunProvenance,
  verifyGitHubRunProvenance,
} from "./verify-github-run-provenance.mjs";

const COMMIT = "a".repeat(40);
const REPOSITORY = "uulab-official/secure-keyboard";

function successfulRun(overrides = {}) {
  return {
    id: 123456,
    head_sha: COMMIT,
    status: "completed",
    conclusion: "success",
    path: ".github/workflows/ci.yml",
    repository: { full_name: REPOSITORY },
    ...overrides,
  };
}

test("accepts a successful run bound to the requested commit and workflow", () => {
  assert.doesNotThrow(() =>
    validateGitHubRunProvenance(successfulRun(), {
      runId: 123456,
      repository: REPOSITORY,
      expectedCommit: COMMIT,
      expectedWorkflow: ".github/workflows/ci.yml",
    }),
  );
});

test("accepts GitHub workflow paths that include the API ref suffix", () => {
  assert.doesNotThrow(() =>
    validateGitHubRunProvenance(successfulRun({ path: ".github/workflows/ci.yml@main" }), {
      runId: 123456,
      repository: REPOSITORY,
      expectedCommit: COMMIT,
      expectedWorkflow: ".github/workflows/ci.yml",
    }),
  );
});

test("rejects a run that is not completed successfully", () => {
  assert.throws(
    () =>
      validateGitHubRunProvenance(successfulRun({ status: "in_progress", conclusion: null }), {
        runId: 123456,
        repository: REPOSITORY,
        expectedCommit: COMMIT,
        expectedWorkflow: ".github/workflows/ci.yml",
      }),
    /must be completed with a success conclusion/,
  );
});

test("rejects a run from another commit or workflow", () => {
  assert.throws(
    () =>
      validateGitHubRunProvenance(
        successfulRun({ head_sha: "b".repeat(40), path: ".github/workflows/release-candidate.yml" }),
        {
          runId: 123456,
          repository: REPOSITORY,
          expectedCommit: COMMIT,
          expectedWorkflow: ".github/workflows/ci.yml",
        },
      ),
    /head_sha must match the requested release commit|workflow path must match the expected workflow/,
  );
});

test("fetches the requested run from the GitHub API and validates its response", async () => {
  let request;
  const server = createServer((incoming, response) => {
    request = incoming;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(successfulRun()));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  try {
    const run = await fetchGitHubRunProvenance({
      runId: 123456,
      repository: REPOSITORY,
      expectedCommit: COMMIT,
      expectedWorkflow: ".github/workflows/ci.yml",
      token: "test-token",
      apiBaseUrl: `http://127.0.0.1:${address.port}/api/v3`,
    });

    assert.equal(run.id, 123456);
    assert.equal(request.url, "/api/v3/repos/uulab-official/secure-keyboard/actions/runs/123456");
    assert.equal(request.headers.authorization, "Bearer test-token");
    assert.equal(request.headers.accept, "application/vnd.github+json");
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("does not let one run descriptor override shared repository or commit expectations", async () => {
  await assert.rejects(
    () =>
      verifyGitHubRunProvenance({
        repository: REPOSITORY,
        expectedCommit: COMMIT,
        token: "test-token",
        fetchImpl: async () => ({
          ok: true,
          json: async () =>
            successfulRun({
              head_sha: "b".repeat(40),
              repository: { full_name: "attacker/other-repository" },
            }),
        }),
        runs: [
          {
            runId: 123456,
            expectedWorkflow: ".github/workflows/ci.yml",
            expectedCommit: "b".repeat(40),
            repository: "attacker/other-repository",
          },
        ],
      }),
    /repository must match the requested repository|head_sha must match the requested release commit/,
  );
});
