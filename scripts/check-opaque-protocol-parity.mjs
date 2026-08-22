import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Sources that declare the pinned OPAQUE metadata used by the Rust reference
 * engine and the Node transport bridge. The Node package remains a transport
 * adapter; these declarations describe the Rust/native delegate it is allowed
 * to call and do not implement cryptography in JavaScript.
 */
export const OPAQUE_PROTOCOL_SOURCES = Object.freeze([
  Object.freeze({
    kind: "protocol-version",
    path: "crates/secure-auth/src/lib.rs",
    pattern: /pub const PROTOCOL_VERSION:\s*u16\s*=\s*(\d+)\s*;/,
  }),
  Object.freeze({
    kind: "protocol-version",
    path: "packages/server-node/src/index.ts",
    pattern: /export const OPAQUE_PROTOCOL_VERSION\s*=\s*(\d+)\s+as const;/,
  }),
  Object.freeze({
    kind: "cipher-suite",
    path: "crates/secure-auth/src/lib.rs",
    pattern: /pub const CIPHER_SUITE_ID:\s*&str\s*=\s*"([^"]+)"\s*;/,
  }),
  Object.freeze({
    kind: "cipher-suite",
    path: "packages/server-node/src/index.ts",
    pattern: /export const OPAQUE_CIPHER_SUITE_ID\s*=\s*"([^"]+)"\s+as const;/,
  }),
]);

function readValue(root, source) {
  const file = path.join(root, source.path);
  if (!existsSync(file)) return undefined;
  return readFileSync(file, "utf8").match(source.pattern)?.[1];
}

/**
 * Returns OPAQUE metadata declarations that are missing or differ from the
 * canonical Rust reference declaration.
 *
 * @param {string} root repository root used by release tooling and tests
 * @returns {Array<{kind: string, path: string, expected: string, actual: string}>}
 */
export function findOpaqueProtocolMismatches(root = ROOT) {
  return ["protocol-version", "cipher-suite"].flatMap((kind) => {
    const sources = OPAQUE_PROTOCOL_SOURCES.filter((source) => source.kind === kind);
    const expected = readValue(root, sources[0]);
    if (expected === undefined) {
      return sources.map((source) => ({
        kind,
        path: source.path,
        expected: "defined",
        actual: readValue(root, source) ?? "missing-or-invalid",
      }));
    }
    return sources.flatMap((source) => {
      const actual = readValue(root, source);
      return actual === expected
        ? []
        : [{ kind, path: source.path, expected, actual: actual ?? "missing-or-invalid" }];
    });
  });
}

export function checkOpaqueProtocolParity(root = ROOT) {
  const mismatches = findOpaqueProtocolMismatches(root);
  for (const mismatch of mismatches) {
    process.stderr.write(
      `OPAQUE ${mismatch.kind} mismatch: ${mismatch.path}: expected ${mismatch.expected}, found ${mismatch.actual}\n`,
    );
  }
  return mismatches.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkOpaqueProtocolParity();
}
