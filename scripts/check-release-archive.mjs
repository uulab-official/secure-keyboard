import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const REQUIRED_SOURCE_ENTRIES = Object.freeze([
  "source/release-candidate-metadata.json",
  "source/secure-keypad.sbom.spdx.json",
  "source/secure-keypad-android-ffi.sha256",
  "source/native-artifacts/android/arm64-v8a/libsecure_ffi.a",
  "source/native-artifacts/android/x86_64/libsecure_ffi.a",
  "source/packages/flutter/pubspec.yaml",
  "source/packages/flutter/ios/secure_ffi.xcframework/Info.plist",
  "source/packages/flutter/ios/libsecure_ffi.a",
  "source/packages/flutter/android/secure_ffi/arm64-v8a/libsecure_ffi.a",
  "source/packages/flutter/android/secure_ffi/x86_64/libsecure_ffi.a",
]);

function requiredPackageEntries(version) {
  return [
    ...NPM_PACKAGES.map((name) => `packages/${name}-${version}.tgz`),
    ...RUST_CRATES.map((name) => `packages/${name}-${version}.crate`),
  ];
}

function normalizeEntry(value) {
  return typeof value === "string" ? value.replace(/^\.\//, "").replace(/\/$/, "") : "";
}

/**
 * Verifies that the archive signed by the release workflow contains the
 * complete staged source tree and every publishable npm/crate archive.
 *
 * @param {readonly string[]} entries output from `tar -tzf`
 * @returns {string[]}
 */
export function validateReleaseArchiveEntries(entries) {
  const findings = [];
  if (!Array.isArray(entries) || entries.length === 0) {
    return ["release archive must contain entries"];
  }

  const normalized = new Set();
  for (const rawEntry of entries) {
    const entry = normalizeEntry(rawEntry);
    if (entry.length === 0) continue;
    if (normalized.has(entry)) {
      findings.push(`${entry}: archive entry must be unique`);
    }
    normalized.add(entry);
    if (entry.startsWith("/") || entry.split("/").includes("..")) {
      findings.push(`${entry}: archive path must be relative and non-parent`);
      continue;
    }
    const topLevel = entry.split("/", 1)[0];
    if (topLevel !== "source" && topLevel !== "packages") {
      findings.push(`${entry}: archive entry is outside source/ or packages/`);
    }
  }

  for (const requiredEntry of REQUIRED_SOURCE_ENTRIES) {
    if (!normalized.has(requiredEntry)) findings.push(`${requiredEntry}: signed release archive entry is missing`);
  }

  const packageEntries = [...normalized].filter((entry) => entry.startsWith("packages/"));
  const versions = new Set();
  for (const entry of packageEntries) {
    const match = entry.match(/^packages\/.+-([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.(?:tgz|crate)$/);
    if (match && VERSION.test(match[1])) versions.add(match[1]);
  }
  if (versions.size !== 1) {
    findings.push("signed release archives must use the same package version");
  }
  const version = [...versions][0];
  if (version !== undefined) {
    for (const requiredEntry of requiredPackageEntries(version)) {
      if (!normalized.has(requiredEntry)) findings.push(`${requiredEntry}: signed release archive entry is missing`);
    }
  } else {
    findings.push("signed release archive package version could not be determined");
  }

  return [...new Set(findings)];
}

export function checkReleaseArchive(archivePath) {
  if (typeof archivePath !== "string" || archivePath.length === 0) {
    return ["release archive path is required"];
  }
  try {
    const verboseListing = execFileSync("tar", ["-tvzf", archivePath], { encoding: "utf8" });
    const entries = execFileSync("tar", ["-tzf", archivePath], { encoding: "utf8" })
      .split("\n")
      .map(normalizeEntry)
      .filter(Boolean);
    const findings = [];
    const listingTypes = verboseListing
      .split("\n")
      .filter(Boolean)
      .map((line) => line[0]);
    if (listingTypes.includes("l")) {
      findings.push("signed release archive must not contain symbolic links");
    }
    if (listingTypes.some((type) => type !== "-" && type !== "d")) {
      findings.push("signed release archive must contain only regular files and directories");
    }
    return [...new Set([...findings, ...validateReleaseArchiveEntries(entries)])];
  } catch (error) {
    return [`release archive cannot be inspected: ${error.message}`];
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const [archivePath] = process.argv.slice(2);
  const findings = checkReleaseArchive(archivePath);
  for (const finding of findings) console.error(`release-archive: ${finding}`);
  if (findings.length === 0) console.log(`release archive contract passed: ${archivePath}`);
  process.exitCode = findings.length === 0 ? 0 : 1;
}
