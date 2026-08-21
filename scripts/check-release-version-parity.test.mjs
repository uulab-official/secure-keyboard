import test from "node:test";
import assert from "node:assert/strict";

import {
  RELEASE_ARTIFACTS,
  findReleaseVersionMismatches,
} from "./check-release-version-parity.mjs";

test("all public release artifacts share the canonical version", () => {
  assert.ok(RELEASE_ARTIFACTS.length >= 10);
  assert.deepEqual(findReleaseVersionMismatches(), []);
});
