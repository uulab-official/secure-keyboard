import test from "node:test";
import assert from "node:assert/strict";

import { runSecurityAudit } from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});
