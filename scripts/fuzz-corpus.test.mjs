import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FUZZ_CORPUS_ROOT = path.join(ROOT, "fuzz", "corpus");
const FUZZ_TARGETS = ["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"];
const MAX_SEED_BYTES = 4096;

for (const target of FUZZ_TARGETS) {
  test(`tracks a non-empty bounded seed corpus for ${target}`, () => {
    const directory = path.join(FUZZ_CORPUS_ROOT, target);
    const seeds = readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => path.join(directory, entry.name));

    assert.ok(seeds.length > 0, `${target} must have at least one checked-in seed`);
    for (const seed of seeds) {
      const size = statSync(seed).size;
      assert.ok(size > 0, `${seed} must not be empty`);
      assert.ok(size <= MAX_SEED_BYTES, `${seed} must stay within the fuzz input bound`);
    }
  });
}
