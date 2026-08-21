import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const BUILD_GRADLE = readFileSync(`${ROOT}/packages/flutter/android/build.gradle`, "utf8");

test("Flutter Android plugin aligns Java and Kotlin JVM targets for pinned host builds", () => {
  assert.match(BUILD_GRADLE, /sourceCompatibility\s+JavaVersion\.VERSION_17/);
  assert.match(BUILD_GRADLE, /targetCompatibility\s+JavaVersion\.VERSION_17/);
  assert.match(BUILD_GRADLE, /jvmTarget\s*=\s*JavaVersion\.VERSION_17\.toString\(\)/);
});

test("Flutter Android plugin configures only ABIs with a supplied native FFI library", () => {
  assert.match(BUILD_GRADLE, /secureKeypadAbiFilters/);
  assert.match(BUILD_GRADLE, /abiFilters\(\*secureKeypadAbiFilters\)/);
  assert.match(BUILD_GRADLE, /arm64-v8a,x86_64/);
});
