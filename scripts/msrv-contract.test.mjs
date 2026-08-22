import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const cargoManifest = readFileSync(`${ROOT}/Cargo.toml`, "utf8");
const compatibility = readFileSync(`${ROOT}/docs/COMPATIBILITY.md`, "utf8");
const ciWorkflow = readFileSync(`${ROOT}/.github/workflows/ci.yml`, "utf8");
const releaseWorkflow = readFileSync(`${ROOT}/.github/workflows/release-candidate.yml`, "utf8");

test("the declared workspace MSRV is documented and compiled in CI", () => {
  assert.match(cargoManifest, /rust-version\s*=\s*"1\.88"/);
  assert.match(compatibility, /workspace MSRV `1\.88`/);
  assert.match(ciWorkflow, /toolchain:\s*1\.88\.0/);
  assert.match(ciWorkflow, /cargo \+1\.88\.0 test --locked --workspace --all-features/);
  assert.match(releaseWorkflow, /toolchain:\s*1\.88\.0/);
  assert.match(releaseWorkflow, /cargo \+1\.88\.0 test --locked --workspace --all-features/);
});
