import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  HTTP_CONTRACT_VERSION_SOURCES,
  findHttpContractVersionMismatches,
} from "./check-http-contract-version-parity.mjs";

test("Rust HTTP and Node transport contracts share one version", () => {
  assert.deepEqual(findHttpContractVersionMismatches(), []);
});

test("version parity reports missing and mismatched contract declarations", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-http-version-"));
  for (const source of HTTP_CONTRACT_VERSION_SOURCES) {
    const file = path.join(root, source.path);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(
      file,
      source.path.includes("server-node")
        ? "export const NODE_SERVER_CONTRACT_VERSION = 2 as const;\n"
        : "pub const HTTP_CONTRACT_VERSION: u16 = 1;\n",
    );
  }

  assert.deepEqual(findHttpContractVersionMismatches(root), [
    {
      path: "packages/server-node/src/index.ts",
      expected: "1",
      actual: "2",
    },
  ]);
});
