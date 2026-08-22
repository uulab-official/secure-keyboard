import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";

const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NPM_PACKAGES = Object.freeze([
  "secure-keypad-contracts",
  "secure-keypad-react-native",
  "secure-keypad-web",
  "secure-keypad-server-node",
]);
const RUST_CRATES = Object.freeze([
  "secure-auth",
  "secure-auth-axum",
  "secure-auth-actix",
  "secure-auth-http",
  "secure-auth-server",
  "secure-core",
  "secure-ffi",
  "secure-webauthn-example",
]);
const REQUIRED_SOURCE_FILES = Object.freeze([
  "source/Cargo.lock",
  "source/pnpm-lock.yaml",
  "source/CHANGELOG.md",
  "source/README.md",
  "source/SECURITY.md",
  "source/LICENSE-MIT",
  "source/THIRD-PARTY-NOTICES.md",
  "source/secure-keypad.sbom.spdx.json",
  "source/secure-keypad-ios-ffi.sha256",
  "source/secure-keypad-android-ffi.sha256",
  "source/native-artifacts/android/arm64-v8a/libsecure_ffi.a",
  "source/native-artifacts/android/x86_64/libsecure_ffi.a",
  "source/release-candidate-metadata.json",
  "source/packages/flutter/pubspec.yaml",
  "source/packages/flutter/ios/secure_ffi.xcframework/Info.plist",
  "source/packages/flutter/ios/libsecure_ffi.a",
  "source/packages/flutter/android/secure_ffi/arm64-v8a/libsecure_ffi.a",
  "source/packages/flutter/android/secure_ffi/x86_64/libsecure_ffi.a",
  "source/docs/SECURITY-SPEC.md",
  "source/docs/PLATFORM-SECURITY-POLICY.md",
  "source/docs/RELEASE-GATES.md",
  "source/docs/ROADMAP.md",
]);
const SECRET_KEY = /password|passphrase|secret|private|plaintext|rawInput|input(?:Value|Text|Bytes)|credential(?:Value|Bytes)/i;
const ANDROID_FFI_CHECKSUM_ENTRIES = Object.freeze([
  "native-artifacts/android/arm64-v8a/libsecure_ffi.a",
  "native-artifacts/android/x86_64/libsecure_ffi.a",
]);
const ANDROID_PACKAGE_FFI_ENTRIES = Object.freeze([
  {
    abi: "arm64-v8a",
    flutterPath: "source/packages/flutter/android/secure_ffi/arm64-v8a/libsecure_ffi.a",
    reactNativeArchivePath: "package/android/secure_ffi/arm64-v8a/libsecure_ffi.a",
    sourcePath: "source/native-artifacts/android/arm64-v8a/libsecure_ffi.a",
  },
  {
    abi: "x86_64",
    flutterPath: "source/packages/flutter/android/secure_ffi/x86_64/libsecure_ffi.a",
    reactNativeArchivePath: "package/android/secure_ffi/x86_64/libsecure_ffi.a",
    sourcePath: "source/native-artifacts/android/x86_64/libsecure_ffi.a",
  },
]);
const MAX_PACKAGED_FFI_BYTES = 64 * 1024 * 1024;
const IOS_PACKAGE_XCFRAMEWORK_SOURCE = "source/packages/flutter/ios/secure_ffi.xcframework";
const IOS_PACKAGE_XCFRAMEWORK_ARCHIVE_PREFIX = "package/secure_ffi.xcframework";
const IOS_PACKAGE_LIBRARY_SOURCE = "source/packages/flutter/ios/libsecure_ffi.a";
const IOS_PACKAGE_LIBRARY_ARCHIVE = "package/libsecure_ffi.a";
const IOS_FFI_CHECKSUM_MANIFEST = "source/secure-keypad-ios-ffi.sha256";
const MAX_NATIVE_CHECKSUM_MANIFEST_BYTES = 1 * 1024 * 1024;

function regularFile(root, relativePath, findings) {
  const absolutePath = path.join(root, relativePath);
  try {
    const stat = lstatSync(absolutePath);
    if (stat.isSymbolicLink()) {
      findings.push(`${relativePath}: symlinks are not allowed in release staging`);
      return undefined;
    }
    if (!stat.isFile()) {
      findings.push(`${relativePath}: must be a regular file`);
      return undefined;
    }
    return absolutePath;
  } catch {
    findings.push(`${relativePath}: required release file is missing`);
    return undefined;
  }
}

function readBoundedChecksumManifest(absolutePath, relativePath, findings) {
  try {
    const stat = lstatSync(absolutePath);
    if (stat.size > MAX_NATIVE_CHECKSUM_MANIFEST_BYTES) {
      findings.push(`${relativePath}: must not exceed ${MAX_NATIVE_CHECKSUM_MANIFEST_BYTES} bytes`);
      return undefined;
    }
    return readFileSync(absolutePath, "utf8");
  } catch (error) {
    findings.push(`${relativePath}: cannot be read (${error.message})`);
    return undefined;
  }
}

function validateAndroidFfiChecksum(root, findings) {
  const relativeManifest = "source/secure-keypad-android-ffi.sha256";
  const manifestPath = regularFile(root, relativeManifest, findings);
  if (!manifestPath) return;

  const contents = readBoundedChecksumManifest(manifestPath, relativeManifest, findings);
  if (contents === undefined) return;

  const seen = new Set();
  const lines = contents.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length !== ANDROID_FFI_CHECKSUM_ENTRIES.length) {
    findings.push(`${relativeManifest}: must contain exactly one checksum for each supported Android FFI library`);
  }
  for (const line of lines) {
    const match = line.match(/^([a-f0-9]{64})  ([^\r\n]+)$/);
    if (!match) {
      findings.push(`${relativeManifest}: contains a malformed checksum line`);
      continue;
    }
    const [, expectedHash, relativePath] = match;
    if (path.posix.isAbsolute(relativePath) || relativePath.includes("\\") || relativePath.split("/").includes("..")) {
      findings.push(`${relativeManifest}: checksum path must be relative and non-parent`);
      continue;
    }
    if (!ANDROID_FFI_CHECKSUM_ENTRIES.includes(relativePath)) {
      findings.push(`${relativeManifest}: unexpected Android FFI checksum path ${relativePath}`);
      continue;
    }
    if (seen.has(relativePath)) {
      findings.push(`${relativeManifest}: duplicate Android FFI checksum path ${relativePath}`);
      continue;
    }
    seen.add(relativePath);
    const sourceRelativePath = path.posix.join("source", relativePath);
    const absolutePath = regularFile(root, sourceRelativePath, findings);
    if (!absolutePath) continue;
    const actualHash = createHash("sha256").update(readFileSync(absolutePath)).digest("hex");
    if (actualHash !== expectedHash) {
      findings.push(`${relativeManifest}: checksum does not match ${sourceRelativePath}`);
    }
  }
  for (const requiredPath of ANDROID_FFI_CHECKSUM_ENTRIES) {
    if (!seen.has(requiredPath)) findings.push(`${relativeManifest}: missing checksum for ${requiredPath}`);
  }
}

function listFiles(root, relativePath = "") {
  const absolutePath = path.join(root, relativePath);
  let entries;
  try {
    entries = readdirSync(absolutePath, { withFileTypes: true });
  } catch {
    return [];
  }
  const files = [];
  for (const entry of entries) {
    const child = path.posix.join(relativePath.replaceAll(path.sep, "/"), entry.name);
    if (entry.isSymbolicLink()) {
      files.push({ relativePath: child, symlink: true });
    } else if (entry.isDirectory()) {
      files.push(...listFiles(root, child));
    } else if (entry.isFile()) {
      files.push({ relativePath: child, regular: true, symlink: false });
    } else {
      files.push({ relativePath: child, regular: false, symlink: false });
    }
  }
  return files;
}

function rejectSecretMetadata(value, field, findings) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => rejectSecretMetadata(child, `${field}[${index}]`, findings));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const childField = `${field}.${key}`;
    if (SECRET_KEY.test(key)) findings.push(`${childField}: private signing material or secret fields are forbidden`);
    rejectSecretMetadata(child, childField, findings);
  }
}

function readJson(root, relativePath, findings) {
  const absolutePath = regularFile(root, relativePath, findings);
  if (!absolutePath) return undefined;
  try {
    return JSON.parse(readFileSync(absolutePath, "utf8"));
  } catch (error) {
    findings.push(`${relativePath}: invalid JSON (${error.message})`);
    return undefined;
  }
}

function validateCandidateMetadata(metadata, findings) {
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    findings.push("source/release-candidate-metadata.json: metadata must be an object");
    return undefined;
  }
  rejectSecretMetadata(metadata, "metadata", findings);
  if (metadata.schemaVersion !== 1) findings.push("candidate metadata schemaVersion must equal 1");
  if (metadata.kind !== "secure-keypad-release-candidate") findings.push("candidate metadata kind is invalid");
  if (metadata.claim !== "candidate-only") findings.push("candidate metadata must remain candidate-only");
  if (typeof metadata.commit !== "string" || !COMMIT.test(metadata.commit)) {
    findings.push("candidate metadata commit must be an immutable 40-character SHA");
  }
  if (typeof metadata.packageVersion !== "string" || !VERSION.test(metadata.packageVersion)) {
    findings.push("candidate metadata packageVersion must be semantic version");
  }
  if (!Array.isArray(metadata.requiredFinalGates)) {
    findings.push("candidate metadata must enumerate required final gates");
  } else if (
    metadata.requiredFinalGates.length !== REQUIRED_RELEASE_GATES.length ||
    metadata.requiredFinalGates.some((gate, index) => gate !== REQUIRED_RELEASE_GATES[index])
  ) {
    findings.push("candidate metadata requiredFinalGates must match the release contract");
  }
  return metadata;
}

function validateSpdx(root, findings) {
  const sbom = readJson(root, "source/secure-keypad.sbom.spdx.json", findings);
  if (sbom === undefined) return;
  if (typeof sbom.spdxVersion !== "string" || !sbom.spdxVersion.startsWith("SPDX-")) {
    findings.push("source/secure-keypad.sbom.spdx.json: SPDX version is missing");
  }
  if (!Array.isArray(sbom.packages) || sbom.packages.length === 0) {
    findings.push("source/secure-keypad.sbom.spdx.json: SPDX packages must be non-empty");
  }
}

function validateChangelog(root, findings) {
  const absolutePath = regularFile(root, "source/CHANGELOG.md", findings);
  if (!absolutePath) return;
  let contents;
  try {
    contents = readFileSync(absolutePath, "utf8");
  } catch (error) {
    findings.push(`source/CHANGELOG.md: cannot be read (${error.message})`);
    return;
  }
  if (!/^# Changelog(?:\r?\n|$)/m.test(contents)) {
    findings.push("source/CHANGELOG.md: must contain a top-level # Changelog heading");
  }
  if (!/^## Unreleased(?:\r?\n|$)/m.test(contents)) {
    findings.push("source/CHANGELOG.md: must contain a ## Unreleased release heading");
  }
}

function validatePublicDocuments(root, findings) {
  const documents = [
    [
      "source/README.md",
      [[/Secure Native Mode/, "must describe Secure Native Mode"]],
    ],
    [
      "source/SECURITY.md",
      [
        [/## Reporting a vulnerability/, "must contain a vulnerability reporting section"],
        [/private GitHub Security Advisory/, "must document the private GitHub Security Advisory channel"],
        [/security\/advisories\/new/, "must contain the private Security Advisory URL"],
      ],
    ],
  ];
  for (const [relativePath, checks] of documents) {
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    let contents;
    try {
      contents = readFileSync(absolutePath, "utf8");
    } catch (error) {
      findings.push(`${relativePath}: cannot be read (${error.message})`);
      continue;
    }
    for (const [pattern, detail] of checks) {
      if (!pattern.test(contents)) findings.push(`${relativePath}: ${detail}`);
    }
  }
}

function archiveEntries(absolutePath, findings) {
  try {
    return execFileSync("tar", ["-tzf", absolutePath], { encoding: "utf8" })
      .split("\n")
      .map((entry) => entry.replace(/^\.\//, "").trim())
      .filter(Boolean);
  } catch (error) {
    findings.push(`${path.basename(absolutePath)}: archive cannot be inspected (${error.message})`);
    return [];
  }
}

function archiveEntryBytes(absolutePath, entry, findings) {
  try {
    return execFileSync("tar", ["-xOzf", absolutePath, "--", entry], {
      encoding: null,
      maxBuffer: MAX_PACKAGED_FFI_BYTES,
    });
  } catch (error) {
    findings.push(`${path.basename(absolutePath)}: cannot read ${entry} (${error.message})`);
    return undefined;
  }
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeChecksumPath(value) {
  const normalized = value.replace(/^\.\//, "");
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    normalized.includes("\\") ||
    normalized.includes("//") ||
    normalized.split("/").includes("..")
  ) {
    return undefined;
  }
  return normalized;
}

function validateIosFfiChecksum(root, version, findings, archiveEntryMap, metadata) {
  const manifestPath = regularFile(root, IOS_FFI_CHECKSUM_MANIFEST, findings);
  if (!manifestPath) return;

  const manifestContents = readBoundedChecksumManifest(manifestPath, IOS_FFI_CHECKSUM_MANIFEST, findings);
  if (manifestContents === undefined) return;

  const manifestEntries = new Map();
  for (const [index, line] of manifestContents.split(/\r?\n/).entries()) {
    if (line.length === 0) continue;
    const match = line.match(/^([a-f0-9]{64})  (.+)$/);
    if (!match) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: malformed checksum line ${index + 1}`);
      continue;
    }
    const relativePath = normalizeChecksumPath(match[2]);
    if (!relativePath) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: unsafe checksum path on line ${index + 1}`);
      continue;
    }
    if (manifestEntries.has(relativePath)) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: duplicate checksum path ${relativePath}`);
      continue;
    }
    manifestEntries.set(relativePath, match[1]);
  }

  const expectedEntries = new Map();
  const sourceFiles = listFiles(root, IOS_PACKAGE_XCFRAMEWORK_SOURCE);
  for (const sourceFile of sourceFiles) {
    const relativePath = sourceFile.relativePath.slice(`${IOS_PACKAGE_XCFRAMEWORK_SOURCE}/`.length);
    if (!sourceFile.regular) {
      findings.push(`${sourceFile.relativePath}: iOS XCFramework checksum inputs must be regular files`);
      continue;
    }
    expectedEntries.set(`flutter/ios/secure_ffi.xcframework/${relativePath}`, {
      sourcePath: sourceFile.relativePath,
    });
    expectedEntries.set(`react-native/secure_ffi.xcframework/${relativePath}`, {
      archivePath: `package/secure_ffi.xcframework/${relativePath}`,
    });
  }

  const sourceLibrary = regularFile(root, IOS_PACKAGE_LIBRARY_SOURCE, findings);
  if (sourceLibrary) {
    expectedEntries.set("flutter/ios/libsecure_ffi.a", { sourcePath: IOS_PACKAGE_LIBRARY_SOURCE });
  }
  expectedEntries.set("react-native/libsecure_ffi.a", { archivePath: IOS_PACKAGE_LIBRARY_ARCHIVE });
  expectedEntries.set("secure-keypad-ios-ffi.commit", {
    bytes: Buffer.from(`${metadata.commit}\n`, "utf8"),
  });

  const reactNativeArchiveRelativePath = `packages/secure-keypad-react-native-${version}.tgz`;
  const reactNativeArchivePath = regularFile(root, reactNativeArchiveRelativePath, findings);
  const archiveEntriesForPackage = archiveEntryMap.get(reactNativeArchiveRelativePath) ?? [];
  for (const relativePath of manifestEntries.keys()) {
    if (!expectedEntries.has(relativePath)) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: unexpected checksum path ${relativePath}`);
    }
  }
  for (const relativePath of expectedEntries.keys()) {
    if (!manifestEntries.has(relativePath)) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: missing checksum for ${relativePath}`);
    }
  }

  for (const [relativePath, expected] of expectedEntries) {
    const expectedHash = manifestEntries.get(relativePath);
    if (!expectedHash) continue;
    let actualHash;
    if (expected.bytes) {
      actualHash = sha256Bytes(expected.bytes);
    } else if (expected.sourcePath) {
      actualHash = sha256Bytes(readFileSync(path.join(root, expected.sourcePath)));
    } else if (reactNativeArchivePath && archiveEntriesForPackage.includes(expected.archivePath)) {
      const archiveBytes = archiveEntryBytes(reactNativeArchivePath, expected.archivePath, findings);
      if (!archiveBytes) continue;
      actualHash = sha256Bytes(archiveBytes);
    } else {
      continue;
    }
    if (actualHash !== expectedHash) {
      findings.push(`${IOS_FFI_CHECKSUM_MANIFEST}: checksum does not match ${relativePath}`);
    }
  }
}

function validatePackagedIosFfi(root, version, findings, archiveEntryMap) {
  const reactNativeArchiveRelativePath = `packages/secure-keypad-react-native-${version}.tgz`;
  const reactNativeArchivePath = regularFile(root, reactNativeArchiveRelativePath, findings);
  if (!reactNativeArchivePath) return;
  const archiveEntriesForPackage = archiveEntryMap.get(reactNativeArchiveRelativePath) ?? [];

  const sourceFiles = listFiles(root, IOS_PACKAGE_XCFRAMEWORK_SOURCE);
  const expectedXcframeworkEntries = new Set();
  for (const sourceFile of sourceFiles) {
    const relativePath = sourceFile.relativePath.slice(`${IOS_PACKAGE_XCFRAMEWORK_SOURCE}/`.length);
    const archiveEntry = `${IOS_PACKAGE_XCFRAMEWORK_ARCHIVE_PREFIX}/${relativePath}`;
    if (!sourceFile.regular) {
      findings.push(`${sourceFile.relativePath}: iOS XCFramework source entries must be regular files`);
      continue;
    }
    expectedXcframeworkEntries.add(archiveEntry);
    if (!archiveEntriesForPackage.includes(archiveEntry)) {
      findings.push(`${reactNativeArchiveRelativePath}: archive must contain ${archiveEntry}`);
      continue;
    }
    const archiveBytes = archiveEntryBytes(reactNativeArchivePath, archiveEntry, findings);
    if (archiveBytes && sha256Bytes(archiveBytes) !== sha256Bytes(readFileSync(path.join(root, sourceFile.relativePath)))) {
      findings.push(`React Native iOS FFI ${relativePath}: packaged bytes do not match signed source`);
    }
  }

  const actualXcframeworkEntries = new Set(
    archiveEntriesForPackage.filter(
      (entry) => entry.startsWith(`${IOS_PACKAGE_XCFRAMEWORK_ARCHIVE_PREFIX}/`) && !entry.endsWith("/"),
    ),
  );
  for (const extraEntry of actualXcframeworkEntries) {
    if (!expectedXcframeworkEntries.has(extraEntry)) {
      findings.push(`${reactNativeArchiveRelativePath}: unexpected iOS XCFramework entry ${extraEntry}`);
    }
  }

  const sourceLibrary = regularFile(root, IOS_PACKAGE_LIBRARY_SOURCE, findings);
  if (!sourceLibrary || !archiveEntriesForPackage.includes(IOS_PACKAGE_LIBRARY_ARCHIVE)) return;
  const archiveBytes = archiveEntryBytes(reactNativeArchivePath, IOS_PACKAGE_LIBRARY_ARCHIVE, findings);
  if (archiveBytes && sha256Bytes(archiveBytes) !== sha256Bytes(readFileSync(sourceLibrary))) {
    findings.push("React Native iOS FFI libsecure_ffi.a: packaged bytes do not match signed source");
  }
}

function validatePackagedAndroidFfi(root, version, findings, archiveEntryMap) {
  const reactNativeArchiveRelativePath = `packages/secure-keypad-react-native-${version}.tgz`;
  const reactNativeArchivePath = regularFile(root, reactNativeArchiveRelativePath, findings);
  for (const entry of ANDROID_PACKAGE_FFI_ENTRIES) {
    const sourcePath = regularFile(root, entry.sourcePath, findings);
    if (!sourcePath) continue;
    const expectedHash = sha256Bytes(readFileSync(sourcePath));

    const flutterPath = regularFile(root, entry.flutterPath, findings);
    if (flutterPath && sha256Bytes(readFileSync(flutterPath)) !== expectedHash) {
      findings.push(`Flutter Android FFI ${entry.abi}: packaged bytes do not match signed source ${entry.sourcePath}`);
    }

    if (!reactNativeArchivePath) continue;
    const archiveEntriesForPackage = archiveEntryMap.get(reactNativeArchiveRelativePath) ?? [];
    if (!archiveEntriesForPackage.includes(entry.reactNativeArchivePath)) continue;
    const archiveBytes = archiveEntryBytes(reactNativeArchivePath, entry.reactNativeArchivePath, findings);
    if (archiveBytes && sha256Bytes(archiveBytes) !== expectedHash) {
      findings.push(`React Native Android FFI ${entry.abi}: packaged bytes do not match signed source ${entry.sourcePath}`);
    }
  }
}

function validateNpmArchives(root, version, findings) {
  const archiveEntryMap = new Map();
  for (const packageName of NPM_PACKAGES) {
    const relativePath = `packages/${packageName}-${version}.tgz`;
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    const entries = archiveEntries(absolutePath, findings);
    archiveEntryMap.set(relativePath, entries);
    const requiredEntries = ["package/package.json", "package/LICENSE", "package/README.md"];
    if (packageName === "secure-keypad-react-native") {
      requiredEntries.push(
        "package/secure_ffi.xcframework/Info.plist",
        "package/libsecure_ffi.a",
        "package/android/secure_ffi/arm64-v8a/libsecure_ffi.a",
        "package/android/secure_ffi/x86_64/libsecure_ffi.a",
      );
    }
    for (const requiredEntry of requiredEntries) {
      if (!entries.includes(requiredEntry)) {
        findings.push(`${relativePath}: archive must contain ${requiredEntry}`);
      }
    }
  }
  return archiveEntryMap;
}

function validateRustArchives(root, version, findings) {
  for (const crateName of RUST_CRATES) {
    const relativePath = `packages/${crateName}-${version}.crate`;
    const absolutePath = regularFile(root, relativePath, findings);
    if (!absolutePath) continue;
    const entries = archiveEntries(absolutePath, findings);
    for (const requiredEntry of [`${crateName}-${version}/Cargo.toml`, `${crateName}-${version}/README.md`]) {
      if (!entries.includes(requiredEntry)) {
        findings.push(`${relativePath}: crate archive must contain ${requiredEntry}`);
      }
    }
  }
}

/**
 * Checks the directory assembled immediately before deterministic release
 * archiving. The check is intentionally independent of the release signer:
 * it proves that the signed input contains its policy, dependency, and
 * publishable-package records and that no private signing key was staged.
 *
 * @param {string} root
 * @returns {string[]}
 */
export function checkReleaseStaging(root) {
  const findings = [];
  if (typeof root !== "string" || root.length === 0 || !existsSync(root)) {
    return ["release staging root is missing"];
  }
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    return ["release staging root cannot be inspected"];
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return ["release staging root must be a real directory"];

  for (const relativePath of REQUIRED_SOURCE_FILES) regularFile(root, relativePath, findings);
  validateChangelog(root, findings);
  validatePublicDocuments(root, findings);
  const metadata = readJson(root, "source/release-candidate-metadata.json", findings);
  const validatedMetadata = validateCandidateMetadata(metadata, findings);
  validateSpdx(root, findings);
  validateAndroidFfiChecksum(root, findings);
  if (validatedMetadata?.packageVersion) {
    const archiveEntryMap = validateNpmArchives(root, validatedMetadata.packageVersion, findings);
    validateIosFfiChecksum(root, validatedMetadata.packageVersion, findings, archiveEntryMap, validatedMetadata);
    validatePackagedIosFfi(root, validatedMetadata.packageVersion, findings, archiveEntryMap);
    validatePackagedAndroidFfi(root, validatedMetadata.packageVersion, findings, archiveEntryMap);
    validateRustArchives(root, validatedMetadata.packageVersion, findings);
  }

  for (const file of listFiles(root)) {
    if (file.symlink) {
      findings.push(`${file.relativePath}: symlinks are not allowed in release staging`);
    }
    if (!file.regular && !file.symlink) {
      findings.push(`${file.relativePath}: only regular files are allowed in release staging`);
    }
    if (/(?:private|signing[-_]?key)|\.pem$/i.test(file.relativePath)) {
      findings.push(`${file.relativePath}: private signing material must never enter release staging`);
    }
  }
  return [...new Set(findings)];
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const [root] = process.argv.slice(2);
  if (!root) {
    console.error("usage: node scripts/check-release-bundle.mjs <release-staging-root>");
    process.exitCode = 64;
  } else {
    const findings = checkReleaseStaging(path.resolve(process.cwd(), root));
    for (const finding of findings) console.error(`release-bundle: ${finding}`);
    if (findings.length === 0) console.log("release staging contract passed");
    process.exitCode = findings.length === 0 ? 0 : 1;
  }
}
