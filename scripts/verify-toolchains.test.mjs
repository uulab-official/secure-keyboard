import test from "node:test";
import assert from "node:assert/strict";

import {
  parseFlutterMachineVersion,
  validatePinnedToolchains,
} from "./verify-toolchains.mjs";

const validFlutterOutput = JSON.stringify({
  frameworkVersion: "3.47.0",
  flutterVersion: "3.47.0",
  dartSdkVersion: "3.13.0",
});

test("accepts the exact pinned host toolchain versions", () => {
  assert.deepEqual(
    validatePinnedToolchains({
      nodeVersion: "v22.13.0",
      pnpmVersion: "11.19.0\n",
      flutterMachineOutput: validFlutterOutput,
    }),
    { node: "22.13.0", pnpm: "11.19.0", flutter: "3.47.0", dart: "3.13.0" },
  );
});

test("rejects contradictory Flutter framework version fields", () => {
  assert.throws(
    () => parseFlutterMachineVersion(JSON.stringify({
      frameworkVersion: "3.47.0",
      flutterVersion: "3.46.0",
      dartSdkVersion: "3.13.0",
    })),
    /frameworkVersion and flutterVersion must match/,
  );
});
