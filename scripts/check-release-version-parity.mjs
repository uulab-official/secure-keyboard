import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Every public artifact in one release must carry the same UI/SDK package
 * version. The authentication protocol and C ABI versions remain separate
 * contracts and are checked by their own gates.
 */
export const RELEASE_ARTIFACTS = Object.freeze([
  Object.freeze({ path: "packages/contracts/package.json", format: "json" }),
  Object.freeze({ path: "packages/react-native/package.json", format: "json" }),
  Object.freeze({ path: "packages/web/package.json", format: "json" }),
  Object.freeze({ path: "packages/server-node/package.json", format: "json" }),
  Object.freeze({ path: "packages/flutter/pubspec.yaml", format: "pubspec" }),
  Object.freeze({ path: "packages/react-native/SecureKeypadReactNative.podspec", format: "podspec" }),
  Object.freeze({ path: "packages/flutter/ios/secure_keypad_flutter.podspec", format: "podspec" }),
  Object.freeze({ path: "crates/secure-core/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-auth/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-auth-server/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-auth-http/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-auth-axum/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-auth-actix/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-ffi/Cargo.toml", format: "cargo" }),
  Object.freeze({ path: "crates/secure-webauthn-example/Cargo.toml", format: "cargo" }),
]);

function parseVersion(contents, format) {
  if (format === "json") return JSON.parse(contents).version;
  if (format === "cargo") return contents.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (format === "pubspec") return contents.match(/^version:\s*([^\s#]+)/m)?.[1];
  if (format === "podspec") return contents.match(/spec\.version\s*=\s*['"]([^'"]+)['"]/)?.[1];
  return undefined;
}

function readArtifactVersion(root, artifact) {
  const absolutePath = path.join(root, artifact.path);
  if (!existsSync(absolutePath)) return undefined;
  return parseVersion(readFileSync(absolutePath, "utf8"), artifact.format);
}

/**
 * Returns public artifacts whose release version differs from the canonical
 * Contracts package or cannot be parsed.
 *
 * @param {string} root repository root used by release tooling and tests
 * @returns {Array<{path: string, expected: string, actual: string}>}
 */
export function findReleaseVersionMismatches(root = ROOT) {
  const canonical = RELEASE_ARTIFACTS[0];
  const expected = readArtifactVersion(root, canonical);
  if (!expected) {
    return [{ path: canonical.path, expected: "defined", actual: "missing-or-invalid" }];
  }

  return RELEASE_ARTIFACTS.flatMap((artifact) => {
    const actual = readArtifactVersion(root, artifact);
    return actual === expected
      ? []
      : [{ path: artifact.path, expected, actual: actual ?? "missing-or-invalid" }];
  });
}

export function checkReleaseVersionParity(root = ROOT) {
  const mismatches = findReleaseVersionMismatches(root);
  for (const mismatch of mismatches) {
    process.stderr.write(
      `release version mismatch: ${mismatch.path}: expected ${mismatch.expected}, found ${mismatch.actual}\n`,
    );
  }
  return mismatches.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkReleaseVersionParity();
}
