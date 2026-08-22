import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MAX_RELEASE_ARTIFACT_BYTES } from "./sign-release.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256 = /^[a-f0-9]{64}$/;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,80}$/;
const PRIVATE_MATERIAL_PATH = /(?:private|signing[-_]?key|password|secret|\.pem$|\.key$)/i;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
}

function normalizeBytes(bytes, field) {
  if (!(typeof bytes === "string" || bytes instanceof Uint8Array)) {
    throw new Error(`${field} must be a string or byte array`);
  }
  const normalized = Buffer.from(bytes);
  if (normalized.length === 0) throw new Error(`${field} must not be empty`);
  if (normalized.length > MAX_RELEASE_ARTIFACT_BYTES) {
    throw new Error(`${field} must not exceed ${MAX_RELEASE_ARTIFACT_BYTES} bytes`);
  }
  return normalized;
}

function validateIdentity(commit, packageVersion) {
  if (typeof commit !== "string" || !COMMIT.test(commit)) {
    throw new Error("commit must be a 40-character lowercase commit SHA");
  }
  if (typeof packageVersion !== "string" || !VERSION.test(packageVersion)) {
    throw new Error("packageVersion must be a semantic version");
  }
}

/**
 * Builds a fragment for public release files that are not themselves signed
 * payload descriptors. Hashes are computed from bytes supplied by the caller;
 * the CLI reads those bytes only from the bounded, symlink-free evidence root.
 *
 * @param {{commit: string, packageVersion: string, artifacts: Array<{kind: string, path: string, bytes: Uint8Array|string}>}} input
 * @returns {Record<string, unknown>}
 */
export function buildReleaseArtifactFragment(input) {
  if (!isRecord(input)) throw new Error("artifact fragment input must be an object");
  const { commit, packageVersion, artifacts } = input;
  validateIdentity(commit, packageVersion);
  if (!Array.isArray(artifacts) || artifacts.length === 0 || artifacts.length > 64) {
    throw new Error("artifacts must contain one to 64 entries");
  }
  const kinds = new Set();
  const paths = new Set();
  const normalized = artifacts.map((artifact) => {
    if (!isRecord(artifact)) throw new Error("artifact must be an object");
    if (typeof artifact.kind !== "string" || !LABEL.test(artifact.kind)) {
      throw new Error("artifact kind must be a sanitized label");
    }
    if (!isSafeRelativePath(artifact.path)) {
      throw new Error("artifact path must be safe and relative");
    }
    if (PRIVATE_MATERIAL_PATH.test(artifact.path)) {
      throw new Error("private signing material or secret artifact paths are forbidden");
    }
    if (kinds.has(artifact.kind)) throw new Error(`duplicate artifact kind ${artifact.kind}`);
    if (paths.has(artifact.path)) throw new Error(`duplicate artifact path ${artifact.path}`);
    const bytes = normalizeBytes(artifact.bytes, `artifact ${artifact.kind} bytes`);
    kinds.add(artifact.kind);
    paths.add(artifact.path);
    return {
      kind: artifact.kind,
      path: artifact.path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  });
  return {
    schemaVersion: 1,
    commit,
    packageVersion,
    artifacts: normalized,
  };
}

function containedFile(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) throw new Error("artifact path must be safe and relative");
  if (PRIVATE_MATERIAL_PATH.test(relativePath)) {
    throw new Error("private signing material or secret artifact paths are forbidden");
  }
  const absolutePath = path.resolve(root, relativePath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("artifact path must resolve inside the evidence root");
  }
  if (pathHasSymlinkComponent(root, absolutePath)) {
    throw new Error("artifact path must not resolve through symbolic links");
  }
  const entry = lstatSync(absolutePath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error("artifact path must reference a regular file");
  const size = statSync(absolutePath).size;
  if (size === 0) throw new Error("artifact file must not be empty");
  if (size > MAX_RELEASE_ARTIFACT_BYTES) {
    throw new Error(`artifact file must not exceed ${MAX_RELEASE_ARTIFACT_BYTES} bytes`);
  }
  return absolutePath;
}

function currentCommit() {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (status.trim().length > 0) throw new Error("current checkout must be clean before emitting artifact evidence");
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

function writeFragment(root, outputPath, fragment) {
  if (!isSafeRelativePath(outputPath)) throw new Error("output path must be safe and relative");
  const absolutePath = path.resolve(root, outputPath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("output path must resolve inside the evidence root");
  }
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(root, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(root, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  try {
    lstatSync(absolutePath);
    throw new Error("output path must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, `${JSON.stringify(fragment, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
}

function parseOptions(argumentsList) {
  const artifacts = [];
  for (let index = 0; index < argumentsList.length; index += 1) {
    if (argumentsList[index] !== "--artifact" || typeof argumentsList[index + 1] !== "string") {
      throw new Error("options must use --artifact kind=relative-path");
    }
    const specification = argumentsList[index + 1];
    const separator = specification.indexOf("=");
    if (separator <= 0 || separator === specification.length - 1) {
      throw new Error("artifact option must use --artifact kind=relative-path");
    }
    artifacts.push({ kind: specification.slice(0, separator), path: specification.slice(separator + 1) });
    index += 1;
  }
  return artifacts;
}

function main() {
  const [rootArgument, outputPath, ...options] = process.argv.slice(2);
  if (!rootArgument || !outputPath || options.length === 0) {
    console.error(
      "usage: node scripts/emit-release-artifact-fragment.mjs <evidence-root> <fragment-json> --artifact kind=relative-path...",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const artifactInputs = parseOptions(options).map((artifact) => ({
      ...artifact,
      bytes: readFileSync(containedFile(root, artifact.path)),
    }));
    const fragment = buildReleaseArtifactFragment({
      commit: currentCommit(),
      packageVersion: currentPackageVersion(),
      artifacts: artifactInputs,
    });
    writeFragment(root, outputPath, fragment);
    console.log(`release artifact fragment emitted: ${path.relative(process.cwd(), path.join(root, outputPath))}`);
  } catch (error) {
    console.error(`release artifact fragment failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
