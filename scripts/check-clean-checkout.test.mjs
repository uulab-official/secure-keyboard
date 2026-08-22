import assert from "node:assert/strict";
import test from "node:test";

import { validateCheckoutStatus } from "./check-clean-checkout.mjs";

test("accepts empty porcelain output", () => {
  assert.doesNotThrow(() => validateCheckoutStatus(""));
  assert.doesNotThrow(() => validateCheckoutStatus("\n"));
});

test("rejects modified or untracked porcelain output", () => {
  assert.throws(
    () => validateCheckoutStatus(" M packages/contracts/src/index.ts\n"),
    /current checkout must be clean/,
  );
  assert.throws(
    () => validateCheckoutStatus("?? evidence/private.json\n"),
    /current checkout must be clean/,
  );
});
