import path from "node:path";
import { fileURLToPath, URL } from "node:url";

const COMMIT = /^[0-9a-f]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKFLOW_PATH = /^\.github\/workflows\/[A-Za-z0-9_.-]+\.(?:yml|yaml)$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeRunId(value, field = "run ID") {
  const normalized = typeof value === "number" ? String(value) : value;
  if (typeof normalized !== "string" || !RUN_ID.test(normalized)) {
    throw new Error(`${field} must be a positive decimal integer`);
  }
  const numeric = Number(normalized);
  if (!Number.isSafeInteger(numeric)) throw new Error(`${field} must be a safe integer`);
  return numeric;
}

function validateRepository(repository) {
  if (typeof repository !== "string" || !REPOSITORY.test(repository)) {
    throw new Error("repository must use the owner/name format");
  }
}

function validateExpectedWorkflow(expectedWorkflow) {
  if (
    typeof expectedWorkflow !== "string" ||
    !WORKFLOW_PATH.test(expectedWorkflow) ||
    expectedWorkflow.split("/").includes("..")
  ) {
    throw new Error("expected workflow must be a safe .github/workflows YAML path");
  }
}

function workflowPathMatches(actualWorkflow, expectedWorkflow) {
  return (
    actualWorkflow === expectedWorkflow ||
    (typeof actualWorkflow === "string" &&
      actualWorkflow.startsWith(`${expectedWorkflow}@`) &&
      actualWorkflow.length > expectedWorkflow.length + 1 &&
      !/[\r\n]/.test(actualWorkflow))
  );
}

/**
 * Verifies the immutable GitHub-side identity of one artifact-producing run.
 * The artifact contents are still validated separately; this prevents a
 * caller from selecting a failed, stale, or unrelated workflow run by ID.
 *
 * @param {unknown} run GitHub Actions workflow-run JSON
 * @param {{runId: number|string, repository: string, expectedCommit: string, expectedWorkflow: string}} options
 */
export function validateGitHubRunProvenance(run, options) {
  if (!isRecord(run)) throw new Error("GitHub workflow run response must be an object");
  if (!isRecord(options)) throw new Error("GitHub workflow run expectations are required");

  const expectedRunId = normalizeRunId(options.runId);
  validateRepository(options.repository);
  if (typeof options.expectedCommit !== "string" || !COMMIT.test(options.expectedCommit)) {
    throw new Error("expected release commit must be a 40-character lowercase commit SHA");
  }
  validateExpectedWorkflow(options.expectedWorkflow);

  if (normalizeRunId(run.id, "GitHub workflow run id") !== expectedRunId) {
    throw new Error("GitHub workflow run id must match the requested run ID");
  }
  if (run.repository?.full_name !== options.repository) {
    throw new Error("GitHub workflow run repository must match the requested repository");
  }
  if (run.head_sha !== options.expectedCommit) {
    throw new Error("GitHub workflow run head_sha must match the requested release commit");
  }
  if (!workflowPathMatches(run.path, options.expectedWorkflow)) {
    throw new Error("GitHub workflow run workflow path must match the expected workflow");
  }
  if (run.status !== "completed" || run.conclusion !== "success") {
    throw new Error("GitHub workflow run must be completed with a success conclusion");
  }
  return run;
}

function buildRunUrl(apiBaseUrl, repository, runId) {
  validateRepository(repository);
  const normalizedRunId = normalizeRunId(runId);
  if (typeof apiBaseUrl !== "string" || apiBaseUrl.length === 0) {
    throw new Error("GitHub API base URL is required");
  }
  let base;
  try {
    base = new URL(apiBaseUrl.endsWith("/") ? apiBaseUrl : `${apiBaseUrl}/`);
  } catch (error) {
    throw new Error(`GitHub API base URL is invalid: ${error.message}`);
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") {
    throw new Error("GitHub API base URL must use HTTP(S)");
  }
  const [owner, name] = repository.split("/");
  return new URL(
    `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/actions/runs/${normalizedRunId}`,
    base,
  );
}

/**
 * Retrieves and verifies one run through the GitHub Actions API.
 *
 * @param {{runId: number|string, repository: string, expectedCommit: string, expectedWorkflow: string, token: string, apiBaseUrl?: string, fetchImpl?: typeof fetch}} options
 */
export async function fetchGitHubRunProvenance(options) {
  if (!isRecord(options)) throw new Error("GitHub workflow run options are required");
  if (typeof options.token !== "string" || options.token.length === 0) {
    throw new Error("GitHub API token is required");
  }
  const url = buildRunUrl(
    options.apiBaseUrl ?? "https://api.github.com",
    options.repository,
    options.runId,
  );
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("fetch is not available");
  const response = await fetchImpl(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${options.token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response || typeof response.ok !== "boolean") {
    throw new Error("GitHub API returned an invalid response");
  }
  if (!response.ok) {
    throw new Error(`GitHub workflow run lookup failed with HTTP ${response.status}`);
  }
  let run;
  try {
    run = await response.json();
  } catch (error) {
    throw new Error(`GitHub workflow run response was not valid JSON: ${error.message}`);
  }
  return validateGitHubRunProvenance(run, options);
}

/**
 * Verifies the candidate, CI, and external evidence-producing runs.
 *
 * @param {{repository: string, expectedCommit: string, token: string, apiBaseUrl?: string, runs: Array<{runId: number|string, expectedWorkflow: string}>, fetchImpl?: typeof fetch}} options
 */
export async function verifyGitHubRunProvenance(options) {
  if (!isRecord(options) || !Array.isArray(options.runs) || options.runs.length === 0) {
    throw new Error("at least one GitHub workflow run is required");
  }
  const verified = [];
  for (const run of options.runs) {
    if (!isRecord(run)) throw new Error("GitHub workflow run input must be an object");
    verified.push(
      await fetchGitHubRunProvenance({
        runId: run.runId,
        expectedWorkflow: run.expectedWorkflow,
        repository: options.repository,
        expectedCommit: options.expectedCommit,
        token: options.token,
        apiBaseUrl: options.apiBaseUrl,
        fetchImpl: options.fetchImpl,
      }),
    );
  }
  return verified;
}

function main() {
  const [repository, expectedCommit, ...runArguments] = process.argv.slice(2);
  if (!repository || !expectedCommit || runArguments.length === 0 || runArguments.length % 2 !== 0) {
    console.error(
      "usage: node scripts/verify-github-run-provenance.mjs <owner/repository> <commit-sha> <run-id> <workflow-path>...",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const runs = [];
    for (let index = 0; index < runArguments.length; index += 2) {
      runs.push({ runId: runArguments[index], expectedWorkflow: runArguments[index + 1] });
    }
    verifyGitHubRunProvenance({
      repository,
      expectedCommit,
      token: process.env.GITHUB_TOKEN,
      apiBaseUrl: process.env.GITHUB_API_URL,
      runs,
    })
      .then((verified) => {
        console.log(`verified GitHub workflow provenance for ${verified.length} run(s)`);
      })
      .catch((error) => {
        console.error(`GitHub workflow provenance verification failed: ${error.message}`);
        process.exitCode = 1;
      });
  } catch (error) {
    console.error(`GitHub workflow provenance verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
