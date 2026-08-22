import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MAX_GATE_EVIDENCE_BYTES } from "./emit-release-gate-evidence.mjs";
import {
  buildSignedReleaseFragment,
} from "./emit-signed-release-evidence.mjs";
import { pathHasSymlinkComponent } from "./evidence-path.mjs";

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
}

function containedPath(root, relativePath, field) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${field} must be a safe relative path`);
  const absolutePath = path.resolve(root, relativePath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve inside the evidence root`);
  }
  if (pathHasSymlinkComponent(root, absolutePath)) {
    throw new Error(`${field} must not resolve through symbolic links`);
  }
  const entry = lstatSync(absolutePath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${field} must reference a regular file`);
  return absolutePath;
}

function readEvidence(root, relativePath) {
  const absolutePath = containedPath(root, relativePath, "signed-release evidence path");
  const size = statSync(absolutePath).size;
  if (size === 0) throw new Error("signed-release evidence must not be empty");
  if (size > MAX_GATE_EVIDENCE_BYTES) {
    throw new Error(`signed-release evidence must not exceed ${MAX_GATE_EVIDENCE_BYTES} bytes`);
  }
  const bytes = readFileSync(absolutePath);
  let record;
  try {
    record = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`signed-release evidence must be valid JSON: ${error.message}`);
  }
  return { record, bytes };
}

function writeFragment(root, outputPath, fragment) {
  if (!isSafeRelativePath(outputPath)) throw new Error("signed-release fragment output must be safe and relative");
  const absolutePath = path.resolve(root, outputPath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("signed-release fragment output must resolve inside the evidence root");
  }
  const parent = path.dirname(absolutePath);
  if (pathHasSymlinkComponent(root, parent)) {
    throw new Error("signed-release fragment output must not resolve through symbolic links");
  }
  mkdirSync(parent, { recursive: true });
  if (pathHasSymlinkComponent(root, parent)) {
    throw new Error("signed-release fragment output must not resolve through symbolic links");
  }
  try {
    lstatSync(absolutePath);
    throw new Error("signed-release fragment output must not already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writeFileSync(absolutePath, `${JSON.stringify(fragment, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

function main() {
  const [rootArgument, outputPath, evidencePath] = process.argv.slice(2);
  if (!rootArgument || !outputPath || !evidencePath) {
    console.error(
      "usage: node scripts/emit-signed-release-fragment.mjs <evidence-root> <fragment-json> <signed-release-evidence-json>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const root = realpathSync(path.resolve(process.cwd(), rootArgument));
    const { record, bytes } = readEvidence(root, evidencePath);
    const fragment = buildSignedReleaseFragment({ record, evidencePath, evidenceBytes: bytes });
    writeFragment(root, outputPath, fragment);
    console.log(`signed-release fragment emitted: ${path.relative(process.cwd(), path.join(root, outputPath))}`);
  } catch (error) {
    console.error(`signed-release fragment failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
