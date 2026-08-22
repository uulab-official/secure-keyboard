import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Sources that implement the versioned framework-neutral HTTP transport.
 * Axum and Actix consume the Rust source contract directly; the Node bridge
 * has an independent declaration that must remain equal to the Rust value.
 */
export const HTTP_CONTRACT_VERSION_SOURCES = Object.freeze([
  Object.freeze({
    path: "crates/secure-auth-http/src/lib.rs",
    pattern: /pub const HTTP_CONTRACT_VERSION:\s*u16\s*=\s*(\d+)\s*;/,
  }),
  Object.freeze({
    path: "packages/server-node/src/index.ts",
    pattern: /export const NODE_SERVER_CONTRACT_VERSION\s*=\s*(\d+)\s+as const;/,
  }),
]);

function readVersion(root, source) {
  const file = path.join(root, source.path);
  if (!existsSync(file)) return undefined;
  return readFileSync(file, "utf8").match(source.pattern)?.[1];
}

/**
 * Returns HTTP transport implementations whose declared contract version is
 * missing or differs from the canonical Rust route contract.
 *
 * @param {string} root repository root used by release tooling and tests
 * @returns {Array<{path: string, expected: string, actual: string}>}
 */
export function findHttpContractVersionMismatches(root = ROOT) {
  const expected = readVersion(root, HTTP_CONTRACT_VERSION_SOURCES[0]);
  if (expected === undefined) {
    return HTTP_CONTRACT_VERSION_SOURCES.map((source) => ({
      path: source.path,
      expected: "defined",
      actual: readVersion(root, source) ?? "missing-or-invalid",
    }));
  }

  return HTTP_CONTRACT_VERSION_SOURCES.flatMap((source) => {
    const actual = readVersion(root, source);
    return actual === expected
      ? []
      : [{ path: source.path, expected, actual: actual ?? "missing-or-invalid" }];
  });
}

export function checkHttpContractVersionParity(root = ROOT) {
  const mismatches = findHttpContractVersionMismatches(root);
  for (const mismatch of mismatches) {
    process.stderr.write(
      `HTTP contract version mismatch: ${mismatch.path}: expected ${mismatch.expected}, found ${mismatch.actual}\n`,
    );
  }
  return mismatches.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkHttpContractVersionParity();
}
