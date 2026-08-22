import assert from "node:assert/strict";
import test from "node:test";

import {
  PLATFORM_SUPPORT_POLICY,
  validatePlatformSupportDevice,
  validatePlatformSupportPolicy,
} from "./platform-support.mjs";

test("checked-in platform support policy is internally valid", () => {
  assert.deepEqual(validatePlatformSupportPolicy(), []);
  assert.equal(PLATFORM_SUPPORT_POLICY.platforms.ios.minimumOsVersion, "15.1");
  assert.equal(PLATFORM_SUPPORT_POLICY.platforms.android.minimumApiLevel, 24);
});

test("accepts native device evidence at the policy floors", () => {
  assert.deepEqual(
    validatePlatformSupportDevice("ios", {
      osVersion: "15.1",
      securityPatchLevel: "15.1",
    }),
    [],
  );
  assert.deepEqual(
    validatePlatformSupportDevice("android", {
      apiLevel: 24,
      securityPatchLevel: "2026-01-01",
    }),
    [],
  );
});

test("rejects a malformed checked-in policy instead of broadening support", () => {
  const malformed = structuredClone(PLATFORM_SUPPORT_POLICY);
  malformed.platforms.android.minimumApiLevel = 1;
  assert.ok(validatePlatformSupportPolicy(malformed).some((finding) => finding.includes("minimumApiLevel")));
});
