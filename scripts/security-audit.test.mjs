import test from "node:test";
import assert from "node:assert/strict";

import { findMutableCiActionLines, runSecurityAudit } from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});

test("CI action audit rejects mutable refs and accepts immutable revisions", () => {
  assert.deepEqual(
    findMutableCiActionLines([
      "      - uses: actions/checkout@v4",
      "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
    ].join("\n")),
    ["      - uses: actions/checkout@v4"],
  );
});
