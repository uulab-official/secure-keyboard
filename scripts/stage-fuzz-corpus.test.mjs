import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const SCRIPT = path.join(ROOT, "scripts/stage-fuzz-corpus.sh");

test("stages every fuzz corpus outside the checkout", () => {
  const destination = mkdtempSync(path.join(tmpdir(), "secure-keypad-fuzz-corpus-"));
  try {
    execFileSync("bash", [SCRIPT, destination], { cwd: ROOT, stdio: "pipe" });

    for (const target of ["auth_envelope", "core_sequence", "ffi_sequence", "webauthn_state"]) {
      assert.ok(readdirSync(path.join(destination, target)).length > 0, `${target} corpus is empty`);
    }
    assert.equal(readdirSync(path.join(ROOT, "fuzz/corpus/auth_envelope")).length > 0, true);
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
});

test("rejects a corpus destination inside the checkout", () => {
  const destination = path.join(ROOT, ".tmp-secure-keypad-fuzz-corpus");
  rmSync(destination, { recursive: true, force: true });
  try {
    assert.throws(() => execFileSync("bash", [SCRIPT, destination], { cwd: ROOT, stdio: "pipe" }), /outside the checkout/);
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
});
