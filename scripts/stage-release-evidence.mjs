import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const COPYFILE_EXCL = 1;
const CANDIDATE_SIGNED_EVIDENCE = "evidence/signed-release.json";
const PRIVATE_MATERIAL_PATH = /(?:private|signing[-_]?key|password|secret|\.pem$|\.key$)/i;

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.includes("\\") &&
    !value.split("/").includes("..")
  );
}

function requireDirectory(directory, label) {
  let entry;
  try {
    entry = lstatSync(directory);
  } catch (error) {
    throw new Error(`${label} could not be read: ${error.message}`);
  }
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error(`${label} must be a real directory`);
  }
  return realpathSync(directory);
}

function ensureContained(root, relativePath, label) {
  if (!isSafeRelativePath(relativePath)) throw new Error(`${label} must be a safe relative path`);
  const absolutePath = path.resolve(root, relativePath);
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${label} must resolve inside the staging root`);
  }
  return absolutePath;
}

function copyFileToOutput(sourcePath, outputRoot, relativePath, seen) {
  if (PRIVATE_MATERIAL_PATH.test(relativePath)) {
    throw new Error(`${relativePath}: private signing material or secret files are not allowed in release evidence inputs`);
  }
  const sourceEntry = lstatSync(sourcePath);
  if (sourceEntry.isSymbolicLink()) {
    throw new Error(`${relativePath}: symlinks are not allowed in release evidence inputs`);
  }
  if (!sourceEntry.isFile()) {
    throw new Error(`${relativePath}: only regular files are allowed in release evidence inputs`);
  }
  if (seen.has(relativePath)) {
    throw new Error(`duplicate release evidence path ${relativePath}`);
  }
  seen.add(relativePath);

  const outputPath = ensureContained(outputRoot, relativePath, "release evidence output path");
  const outputParent = path.dirname(outputPath);
  if (pathHasSymlinkComponent(outputRoot, outputParent)) {
    throw new Error(`${relativePath}: output path must not resolve through symbolic links`);
  }
  mkdirSync(outputParent, { recursive: true });
  if (pathHasSymlinkComponent(outputRoot, outputParent)) {
    throw new Error(`${relativePath}: output path must not resolve through symbolic links`);
  }
  try {
    copyFileSync(sourcePath, outputPath, COPYFILE_EXCL);
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`duplicate release evidence path ${relativePath}`);
    throw error;
  }
  chmodSync(outputPath, 0o600);
}

function copyRegularFile(sourceRoot, outputRoot, relativePath, seen) {
  const sourcePath = ensureContained(sourceRoot, relativePath, "release evidence input path");
  copyFileToOutput(sourcePath, outputRoot, relativePath, seen);
}

function walkFiles(sourceRoot, relativePath = "") {
  const directory = relativePath
    ? ensureContained(sourceRoot, relativePath, "release evidence input directory")
    : sourceRoot;
  const entries = readdirSync(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const childPath = relativePath ? path.posix.join(relativePath, entry.name) : entry.name;
    if (entry.isSymbolicLink()) {
      throw new Error(`${childPath}: symlinks are not allowed in release evidence inputs`);
    }
    if (entry.isDirectory()) {
      files.push(...walkFiles(sourceRoot, childPath));
    } else if (entry.isFile()) {
      files.push(childPath);
    } else {
      throw new Error(`${childPath}: only regular files are allowed in release evidence inputs`);
    }
  }
  return files.sort();
}

/**
 * Copies three independently downloaded artifact roots into one evidence
 * root. The roots are intentionally copied as untrusted input: symlinks,
 * special files, duplicate paths, and missing candidate signing evidence all
 * fail before the release evidence merger sees them.
 *
 * @param {string} outputDirectory
 * @param {string[]} inputDirectories [candidate, ci, external]
 * @returns {{fragmentPaths: string[]}}
 */
export function stageReleaseEvidence(outputDirectory, inputDirectories) {
  if (typeof outputDirectory !== "string" || outputDirectory.length === 0) {
    throw new Error("release evidence output directory is required");
  }
  if (!Array.isArray(inputDirectories) || inputDirectories.length !== 3) {
    throw new Error("release evidence requires candidate, CI, and external input directories");
  }
  const sourceDirectories = inputDirectories.map((directory, index) =>
    requireDirectory(directory, `release evidence input ${index + 1}`),
  );
  mkdirSync(outputDirectory, { recursive: true });
  const outputRoot = requireDirectory(outputDirectory, "release evidence output");
  const seen = new Set();

  for (const sourceRoot of sourceDirectories) {
    for (const relativePath of walkFiles(sourceRoot)) {
      copyRegularFile(sourceRoot, outputRoot, relativePath, seen);
    }
  }

  if (!seen.has(CANDIDATE_SIGNED_EVIDENCE)) {
    throw new Error("candidate signed-release evidence is missing");
  }

  const fragmentPaths = [...seen]
    .filter((relativePath) => relativePath.startsWith("fragments/") && relativePath.endsWith(".json"))
    .sort();
  return { fragmentPaths };
}

function main() {
  const [outputDirectory, candidateDirectory, ciDirectory, externalDirectory] = process.argv.slice(2);
  if (!outputDirectory || !candidateDirectory || !ciDirectory || !externalDirectory) {
    console.error(
      "usage: node scripts/stage-release-evidence.mjs <output-dir> <candidate-dir> <ci-dir> <external-dir>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const staged = stageReleaseEvidence(
      path.resolve(process.cwd(), outputDirectory),
      [candidateDirectory, ciDirectory, externalDirectory].map((directory) => path.resolve(process.cwd(), directory)),
    );
    console.log(`release evidence staged: ${staged.fragmentPaths.join(" ")}`);
  } catch (error) {
    console.error(`release evidence staging failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
