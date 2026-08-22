import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
  buildProductionCandidateCommands,
  parseProductionCandidateArguments,
} from "./verify-production-candidate.mjs";

test("dry-run plan contains every deterministic production-candidate gate", () => {
  const commands = buildProductionCandidateCommands();
  const rendered = commands.map(({ executable, args, display }) => display ?? [executable, ...args].join(" "));

  assert.equal(rendered[0], "node scripts/check-clean-checkout.mjs");
  assert.ok(rendered.includes("cargo fmt --all -- --check"));
  assert.ok(rendered.includes("cargo test --locked --workspace --all-features"));
  assert.ok(rendered.includes("cargo +1.88.0 test --locked --workspace --all-features"));
  assert.ok(rendered.includes("cargo clippy --locked --workspace --all-targets --all-features -- -D warnings"));
  assert.ok(rendered.includes("pnpm audit --audit-level high"));
  assert.ok(rendered.includes("pnpm check:native-parity"));
  assert.ok(rendered.includes("pnpm check:http-contract-version-parity"));
  assert.ok(rendered.includes("pnpm check:opaque-protocol-parity"));
  assert.ok(rendered.includes("pnpm security-audit"));
  assert.ok(rendered.includes("node --test scripts/*.test.mjs"));
  assert.ok(rendered.includes("pnpm test:web-browser"));
  assert.ok(rendered.includes("pnpm -r test"));
  assert.ok(rendered.includes("pnpm -r typecheck"));
  assert.ok(rendered.includes("pnpm -r build"));
  assert.ok(rendered.includes("node scripts/verify-toolchains.mjs"));
});

test("production-candidate arguments expose evidence verification without weakening local gates", () => {
  assert.deepEqual(parseProductionCandidateArguments(["--dry-run"]), { dryRun: true, evidencePath: undefined });
  const parsed = parseProductionCandidateArguments(["--evidence", "evidence/release-evidence.json"]);
  assert.equal(parsed.dryRun, false);
  assert.equal(path.isAbsolute(parsed.evidencePath), true);
  assert.match(parsed.evidencePath, /evidence[\\/]release-evidence\.json$/);
  assert.throws(
    () => parseProductionCandidateArguments(["--skip-security-audit"]),
    /unknown option/,
  );
});
