import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const RUST_AUTH = readFileSync(path.join(ROOT, "crates/secure-auth/src/lib.rs"), "utf8");
const NODE_SERVER = readFileSync(path.join(ROOT, "packages/server-node/src/index.ts"), "utf8");

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("Node server bridge declares the exact pinned OPAQUE protocol metadata", () => {
  const protocolVersion = RUST_AUTH.match(/pub const PROTOCOL_VERSION:\s*u16\s*=\s*(\d+)\s*;/)?.[1];
  const suiteId = RUST_AUTH.match(/pub const CIPHER_SUITE_ID:\s*&str\s*=\s*"([^"]+)"\s*;/)?.[1];

  assert.ok(protocolVersion, "Rust OPAQUE protocol version must be declared");
  assert.ok(suiteId, "Rust OPAQUE suite ID must be declared");
  assert.match(
    NODE_SERVER,
    new RegExp(`export const OPAQUE_PROTOCOL_VERSION\\s*=\\s*${protocolVersion}\\s+as const;`),
  );
  assert.match(
    NODE_SERVER,
    new RegExp(`export const OPAQUE_CIPHER_SUITE_ID\\s*=\\s*"${escapeRegExp(suiteId)}"\\s+as const;`),
  );
});
