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
      rustcVersionOutput: "rustc 1.97.1 (stable)",
      cargoVersionOutput: "cargo 1.97.1 (stable)",
      dartVersionOutput: "Dart SDK version: 3.13.0 (stable)",
      flutterMachineOutput: validFlutterOutput,
    }),
    {
      node: "22.13.0",
      pnpm: "11.19.0",
      rust: "1.97.1",
      cargo: "1.97.1",
      flutter: "3.47.0",
      dart: "3.13.0",
    },
  );
});

test("rejects a standalone executable that is not the pinned SDK", () => {
  assert.throws(
    () => validatePinnedToolchains({
      nodeVersion: "22.13.0",
      pnpmVersion: "11.19.0",
      rustcVersionOutput: "rustc 1.97.0 (stable)",
      cargoVersionOutput: "cargo 1.97.1 (stable)",
      dartVersionOutput: "Dart SDK version: 3.12.0 (stable)",
      flutterMachineOutput: validFlutterOutput,
    }),
    /Rust must be 1\.97\.1, found 1\.97\.0/,
  );
  assert.throws(
    () => validatePinnedToolchains({
      nodeVersion: "22.13.0",
      pnpmVersion: "11.19.0",
      rustcVersionOutput: "rustc 1.97.1 (stable)",
      cargoVersionOutput: "cargo 1.97.1 (stable)",
      dartVersionOutput: "Dart SDK version: 3.12.0 (stable)",
      flutterMachineOutput: validFlutterOutput,
    }),
    /Dart executable must be 3\.13\.0, found 3\.12\.0/,
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
