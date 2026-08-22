import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isValidTimestamp(value) {
  return typeof value === "string" && ISO_TIMESTAMP.test(value) && new Date(value).toISOString() === value;
}

/**
 * Describes a signed release candidate without claiming that external gates
 * have passed. The metadata is intentionally free of credentials and secret
 * input values, and is included in the signed source bundle.
 *
 * @param {{commit: string, packageVersion: string, createdAt: string}} input
 * @returns {Record<string, unknown>}
 */
export function buildReleaseCandidateMetadata(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("metadata input must be an object");
  }
  const { commit, packageVersion, createdAt } = input;
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
  if (!isValidTimestamp(createdAt)) {
    throw new Error("createdAt must be an ISO-8601 UTC timestamp");
  }

  return {
    schemaVersion: 1,
    kind: "secure-keypad-release-candidate",
    claim: "candidate-only",
    commit,
    packageVersion,
    createdAt,
    requiredFinalGates: [...REQUIRED_RELEASE_GATES],
    candidateArtifacts: [
      { kind: "release-bundle", path: "secure-keypad-release.tar.gz" },
      { kind: "release-signature", path: "secure-keypad-release.sig" },
      { kind: "release-public-key", path: "secure-keypad-release.pub.der" },
      { kind: "sbom", path: "secure-keypad.sbom.spdx.json" },
      { kind: "native-checksum", path: "source/secure-keypad-ios-ffi.sha256" },
      { kind: "license-notices", path: "source/THIRD-PARTY-NOTICES.md" },
      { kind: "checksums", path: "secure-keypad-release.sha256" },
    ],
    finalVerifier: {
      command:
        "node scripts/check-release-evidence.mjs --require-trusted-keys release-evidence/release-evidence.json",
      workflow: ".github/workflows/release-finalize.yml",
      requiredProtectedInputs: [
        "SECURE_KEYPAD_RELEASE_PUBLIC_KEY_SHA256",
        "SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256",
      ],
      evidenceMergeCommand:
        "pnpm merge:release-evidence release-evidence release-evidence/release-evidence.json <fragment.json>...",
    },
  };
}

export function validateReleaseCandidateCheckoutStatus(status) {
  if (typeof status !== "string" || status.trim().length > 0) {
    throw new Error("current checkout must be clean before emitting candidate metadata");
  }
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  validateReleaseCandidateCheckoutStatus(status);
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  if (!COMMIT.test(commit)) throw new Error("current checkout commit is not an immutable SHA");
  return commit;
}

function currentPackageVersion() {
  const packageJson = JSON.parse(readFileSync(path.join(ROOT, "packages/contracts/package.json"), "utf8"));
  if (typeof packageJson.version !== "string" || !VERSION.test(packageJson.version)) {
    throw new Error("current contracts package version is invalid");
  }
  return packageJson.version;
}

function currentCommitTimestamp() {
  const commitTimestamp = execFileSync("git", ["show", "-s", "--format=%cI", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8",
  }).trim();
  const timestamp = new Date(commitTimestamp).toISOString();
  if (!isValidTimestamp(timestamp)) throw new Error("current commit timestamp is invalid");
  return timestamp;
}

function main() {
  const [outputPath] = process.argv.slice(2);
  if (!outputPath) {
    console.error("usage: node scripts/release-candidate-metadata.mjs <output-json>");
    process.exitCode = 64;
    return;
  }
  try {
    const absolutePath = path.resolve(process.cwd(), outputPath);
    mkdirSync(path.dirname(absolutePath), { recursive: true });
    const metadata = buildReleaseCandidateMetadata({
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      createdAt: currentCommitTimestamp(),
    });
    writeFileSync(absolutePath, `${JSON.stringify(metadata, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    console.log(`release candidate metadata emitted: ${absolutePath}`);
  } catch (error) {
    console.error(`release candidate metadata failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
