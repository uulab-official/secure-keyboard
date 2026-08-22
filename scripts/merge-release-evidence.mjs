import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateReleaseEvidence, verifyReleaseEvidenceFiles } from "./check-release-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
export const MAX_RELEASE_FRAGMENT_BYTES = 1 * 1024 * 1024;

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

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, canonicalize(child)]));
}

function sameValue(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function containedPath(root, relativePath, label) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${label} must be a safe relative path`);
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  if (pathHasSymlinkComponent(realRoot, absolutePath)) {
    throw new Error(`${label} must not resolve through symbolic links`);
  }
  const realPath = realpathSync(absolutePath);
  const relative = path.relative(realRoot, realPath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${label} must resolve inside the evidence root`);
  }
  return realPath;
}

function readFragment(root, relativePath) {
  try {
    const filePath = containedPath(root, relativePath, "fragment path");
    const stats = statSync(filePath);
    if (!stats.isFile()) throw new Error("fragment path must reference a regular file");
    if (stats.size === 0) throw new Error("fragment file must not be empty");
    if (stats.size > MAX_RELEASE_FRAGMENT_BYTES) {
      throw new Error(`fragment file must not exceed ${MAX_RELEASE_FRAGMENT_BYTES} bytes`);
    }
    return JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`could not read evidence fragment ${relativePath}: ${error.message}`);
  }
}

function addContext(context, fragment, field, fragmentIndex) {
  if (!Object.hasOwn(fragment, field)) return;
  if (context[field] === undefined) {
    context[field] = fragment[field];
    return;
  }
  if (!sameValue(context[field], fragment[field])) {
    throw new Error(`fragment ${fragmentIndex} conflicts on ${field}`);
  }
}

/**
 * Merges independently produced release evidence fragments without ever
 * upgrading a gate or artifact status. The final policy validator remains the
 * authority: an incomplete merge is rejected rather than emitted as a release
 * claim.
 *
 * @param {unknown[]} fragments
 * @param {{createdAt?: string}} [options]
 * @returns {Record<string, unknown>}
 */
export function mergeReleaseEvidence(fragments, options = {}) {
  if (!Array.isArray(fragments) || fragments.length === 0) {
    throw new Error("at least one release evidence fragment is required");
  }

  const context = {};
  const gates = new Map();
  const artifacts = new Map();
  const referencedPaths = new Set();
  let signature;
  let independentReview;

  fragments.forEach((fragment, fragmentIndex) => {
    if (!isRecord(fragment)) throw new Error(`fragment ${fragmentIndex} must be a JSON object`);
    if (fragment.schemaVersion !== undefined && fragment.schemaVersion !== 1) {
      throw new Error(`fragment ${fragmentIndex} has unsupported schemaVersion`);
    }
    for (const field of ["commit", "packageVersion", "toolchains"]) {
      addContext(context, fragment, field, fragmentIndex);
    }
    if (
      !Array.isArray(fragment.gates) &&
      !Array.isArray(fragment.artifacts) &&
      fragment.signature === undefined &&
      fragment.independentReview === undefined
    ) {
      throw new Error(`fragment ${fragmentIndex} contains no mergeable evidence`);
    }
    for (const gate of fragment.gates ?? []) {
      if (!isRecord(gate) || typeof gate.name !== "string" || gate.name.length === 0) {
        throw new Error(`fragment ${fragmentIndex} contains an invalid gate`);
      }
      if (gates.has(gate.name)) throw new Error(`duplicate release gate ${gate.name}`);
      if (isSafeRelativePath(gate.evidencePath)) {
        if (referencedPaths.has(gate.evidencePath)) throw new Error(`duplicate release evidence path ${gate.evidencePath}`);
        referencedPaths.add(gate.evidencePath);
      }
      gates.set(gate.name, gate);
    }
    for (const artifact of fragment.artifacts ?? []) {
      if (!isRecord(artifact) || typeof artifact.kind !== "string" || artifact.kind.length === 0) {
        throw new Error(`fragment ${fragmentIndex} contains an invalid artifact`);
      }
      if (artifacts.has(artifact.kind)) throw new Error(`duplicate release artifact kind ${artifact.kind}`);
      if (isSafeRelativePath(artifact.path)) {
        if (referencedPaths.has(artifact.path)) throw new Error(`duplicate release evidence path ${artifact.path}`);
        referencedPaths.add(artifact.path);
      }
      artifacts.set(artifact.kind, artifact);
    }
    if (fragment.signature !== undefined) {
      if (signature !== undefined) throw new Error("duplicate release signature descriptor");
      signature = fragment.signature;
    }
    if (fragment.independentReview !== undefined) {
      if (independentReview !== undefined) throw new Error("duplicate independent review descriptor");
      independentReview = fragment.independentReview;
    }
  });

  const merged = {
    schemaVersion: 1,
    commit: context.commit,
    createdAt: options.createdAt ?? new Date().toISOString(),
    packageVersion: context.packageVersion,
    toolchains: context.toolchains,
    gates: [...gates.values()].sort((left, right) => left.name.localeCompare(right.name)),
    artifacts: [...artifacts.values()].sort((left, right) => left.kind.localeCompare(right.kind)),
    ...(signature === undefined ? {} : { signature }),
    ...(independentReview === undefined ? {} : { independentReview }),
  };
  const findings = validateReleaseEvidence(merged);
  if (findings.length > 0) {
    throw new Error(`merged release evidence is incomplete:\n${findings.join("\n")}`);
  }
  return merged;
}

function currentCommit() {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  } catch {
    return undefined;
  }
}

export function writeMergedEvidence(root, outputPath, manifest) {
  if (!isSafeRelativePath(outputPath)) throw new Error("output path must be a safe relative path");
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, outputPath);
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(realRoot, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(realRoot, parent)) {
    throw new Error("output path must not resolve through symbolic links");
  }
  const realParent = realpathSync(parent);
  const parentRelative = path.relative(realRoot, realParent);
  if (parentRelative.startsWith(`..${path.sep}`) || path.isAbsolute(parentRelative)) {
    throw new Error("output path must resolve inside the evidence root");
  }
  try {
    lstatSync(absolutePath);
    throw new Error("output path must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return absolutePath;
}

function main() {
  const [rootArgument, outputPath, ...fragmentPaths] = process.argv.slice(2);
  if (!rootArgument || !outputPath || fragmentPaths.length === 0) {
    console.error("usage: node scripts/merge-release-evidence.mjs <evidence-root> <output-json> <fragment-json>...");
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const fragments = fragmentPaths.map((fragmentPath) => readFragment(root, fragmentPath));
    const manifest = mergeReleaseEvidence(fragments, { createdAt: new Date().toISOString() });
    if ([...manifest.gates.map((gate) => gate.evidencePath), ...manifest.artifacts.map((artifact) => artifact.path)].includes(outputPath)) {
      throw new Error("output path must not overwrite a referenced evidence file");
    }
    const output = writeMergedEvidence(root, outputPath, manifest);
    const fileFindings = verifyReleaseEvidenceFiles(manifest, root);
    if (fileFindings.length > 0) throw new Error(fileFindings.join("\n"));
    const expectedCommit = currentCommit();
    if (expectedCommit && manifest.commit !== expectedCommit) {
      throw new Error("merged release evidence commit does not match the current checkout");
    }
    console.log(`release evidence merged and verified: ${path.relative(process.cwd(), output)}`);
  } catch (error) {
    console.error(`release evidence merge failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
