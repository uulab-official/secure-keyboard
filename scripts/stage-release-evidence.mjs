import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  opendirSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { pathHasSymlinkComponent } from "./evidence-path.mjs";

const COPYFILE_EXCL = 1;
const CANDIDATE_SIGNED_EVIDENCE = "evidence/signed-release.json";
const PRIVATE_MATERIAL_PATH = /(?:private|signing[-_]?key|password|secret|\.pem$|\.key$)/i;
/** Maximum size of one untrusted evidence input before staging. */
export const MAX_STAGED_FILE_BYTES = 512 * 1024 * 1024;
/** Maximum combined size of candidate, CI, and external evidence inputs. */
export const MAX_STAGED_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
/** Maximum number of regular files accepted across all evidence roots. */
export const MAX_STAGED_FILE_COUNT = 16_384;
/** Maximum number of directories traversed across all evidence roots. */
export const MAX_STAGED_DIRECTORY_COUNT = 16_384;
/** Maximum relative directory depth accepted in one evidence root. */
export const MAX_STAGED_PATH_DEPTH = 64;

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

function copyFileToOutput(sourcePath, outputRoot, relativePath, state) {
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
  if (state.paths.has(relativePath)) {
    throw new Error(`duplicate release evidence path ${relativePath}`);
  }
  const size = statSync(sourcePath).size;
  if (size > MAX_STAGED_FILE_BYTES) {
    throw new Error(`${relativePath}: file must not exceed ${MAX_STAGED_FILE_BYTES} bytes before staging`);
  }
  if (state.totalBytes > MAX_STAGED_TOTAL_BYTES - size) {
    throw new Error(`staged evidence must not exceed ${MAX_STAGED_TOTAL_BYTES} bytes`);
  }

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
  state.paths.add(relativePath);
  state.totalBytes += size;
}

function copyRegularFile(sourceRoot, outputRoot, relativePath, state) {
  const sourcePath = ensureContained(sourceRoot, relativePath, "release evidence input path");
  copyFileToOutput(sourcePath, outputRoot, relativePath, state);
}

function walkFiles(
  sourceRoot,
  relativePath = "",
  fileBudget = { count: 0 },
  directoryBudget = { count: 0 },
) {
  const depth = relativePath ? relativePath.split("/").length : 0;
  if (depth > MAX_STAGED_PATH_DEPTH) {
    throw new Error(
      `release evidence input directory depth must not exceed ${MAX_STAGED_PATH_DEPTH} components`,
    );
  }
  directoryBudget.count += 1;
  if (directoryBudget.count > MAX_STAGED_DIRECTORY_COUNT) {
    throw new Error(
      `staged evidence must not contain more than ${MAX_STAGED_DIRECTORY_COUNT} directories`,
    );
  }
  const directory = relativePath
    ? ensureContained(sourceRoot, relativePath, "release evidence input directory")
    : sourceRoot;
  const files = [];
  const directoryHandle = opendirSync(directory);
  try {
    let entry;
    while ((entry = directoryHandle.readSync()) !== null) {
      const childPath = relativePath ? path.posix.join(relativePath, entry.name) : entry.name;
      if (entry.isSymbolicLink()) {
        throw new Error(`${childPath}: symlinks are not allowed in release evidence inputs`);
      }
      if (entry.isDirectory()) {
        files.push(...walkFiles(sourceRoot, childPath, fileBudget, directoryBudget));
      } else if (entry.isFile()) {
        fileBudget.count += 1;
        if (fileBudget.count > MAX_STAGED_FILE_COUNT) {
          throw new Error(`staged evidence must not contain more than ${MAX_STAGED_FILE_COUNT} regular files`);
        }
        files.push(childPath);
      } else {
        throw new Error(`${childPath}: only regular files are allowed in release evidence inputs`);
      }
    }
  } finally {
    directoryHandle.closeSync();
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
  const state = { paths: new Set(), totalBytes: 0 };
  const fileBudget = { count: 0 };
  const directoryBudget = { count: 0 };

  for (const sourceRoot of sourceDirectories) {
    for (const relativePath of walkFiles(sourceRoot, "", fileBudget, directoryBudget)) {
      copyRegularFile(sourceRoot, outputRoot, relativePath, state);
    }
  }

  if (!state.paths.has(CANDIDATE_SIGNED_EVIDENCE)) {
    throw new Error("candidate signed-release evidence is missing");
  }

  const fragmentPaths = [...state.paths]
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
