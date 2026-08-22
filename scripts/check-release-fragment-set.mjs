import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import { MAX_RELEASE_FRAGMENT_BYTES } from "./merge-release-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const REQUIRED_GATE_SET = new Set(REQUIRED_RELEASE_GATES);

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

function containedFragmentPath(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) {
    throw new Error(`fragment path must be a safe relative path: ${relativePath}`);
  }
  const realRoot = realpathSync(root);
  const absolutePath = path.resolve(realRoot, relativePath);
  if (pathHasSymlinkComponent(realRoot, absolutePath)) {
    throw new Error(`fragment path must not resolve through symbolic links: ${relativePath}`);
  }
  const realPath = realpathSync(absolutePath);
  const relative = path.relative(realRoot, realPath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`fragment path must resolve inside the evidence root: ${relativePath}`);
  }
  return realPath;
}

function readFragment(root, relativePath) {
  const fragmentPath = containedFragmentPath(root, relativePath);
  const entry = lstatSync(fragmentPath);
  if (entry.isSymbolicLink() || !entry.isFile()) {
    throw new Error(`fragment path must reference a regular file: ${relativePath}`);
  }
  const size = statSync(fragmentPath).size;
  if (size === 0) throw new Error(`fragment file must not be empty: ${relativePath}`);
  if (size > MAX_RELEASE_FRAGMENT_BYTES) {
    throw new Error(`fragment file must not exceed ${MAX_RELEASE_FRAGMENT_BYTES} bytes: ${relativePath}`);
  }
  try {
    return JSON.parse(readFileSync(fragmentPath, "utf8"));
  } catch (error) {
    throw new Error(`fragment file must contain valid JSON: ${relativePath}: ${error.message}`);
  }
}

/**
 * Verifies that a finalization input set contains each canonical release gate
 * exactly once before the merger reads the same fragments. Non-gate fragments
 * such as candidate artifacts remain allowed; the merger and final verifier
 * retain authority over their schemas, hashes, and signatures.
 *
 * @param {string} root
 * @param {string[]} fragmentPaths
 * @returns {{fragmentPaths: string[], gateNames: string[]}}
 */
export function checkReleaseFragmentSet(root, fragmentPaths) {
  if (typeof root !== "string" || root.length === 0) {
    throw new Error("evidence root is required");
  }
  if (!Array.isArray(fragmentPaths) || fragmentPaths.length === 0) {
    throw new Error("at least one release fragment path is required");
  }
  const seenPaths = new Set();
  const gates = new Map();
  for (const relativePath of fragmentPaths) {
    if (seenPaths.has(relativePath)) {
      throw new Error(`duplicate release fragment path: ${relativePath}`);
    }
    seenPaths.add(relativePath);
    const fragment = readFragment(root, relativePath);
    if (!isRecord(fragment)) throw new Error(`fragment must be a JSON object: ${relativePath}`);
    if (!Array.isArray(fragment.gates)) continue;
    for (const gate of fragment.gates) {
      if (!isRecord(gate) || typeof gate.name !== "string" || gate.name.length === 0) {
        throw new Error(`fragment contains an invalid gate: ${relativePath}`);
      }
      if (!REQUIRED_GATE_SET.has(gate.name)) {
        throw new Error(`fragment contains an unsupported release gate: ${gate.name}`);
      }
      if (gates.has(gate.name)) {
        throw new Error(`duplicate release gate fragment: ${gate.name}`);
      }
      gates.set(gate.name, relativePath);
    }
  }
  const missing = REQUIRED_RELEASE_GATES.filter((gateName) => !gates.has(gateName));
  if (missing.length > 0) {
    throw new Error(`missing required release gate fragments: ${missing.join(", ")}`);
  }
  return {
    fragmentPaths: [...seenPaths],
    gateNames: [...gates.keys()].sort(),
  };
}

function main() {
  const [rootArgument, ...fragmentPaths] = process.argv.slice(2);
  if (!rootArgument || fragmentPaths.length === 0) {
    console.error("usage: node scripts/check-release-fragment-set.mjs <evidence-root> <fragment-json>...");
    process.exitCode = 64;
    return;
  }
  try {
    const result = checkReleaseFragmentSet(path.resolve(process.cwd(), rootArgument), fragmentPaths);
    console.log(`release fragment set verified: ${result.gateNames.join(" ")}`);
  } catch (error) {
    console.error(`release fragment set failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
