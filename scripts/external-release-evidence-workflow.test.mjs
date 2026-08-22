import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKFLOW = readFileSync(path.join(ROOT, ".github/workflows/external-release-evidence.yml"), "utf8");

test("external evidence workflow requires a self-hosted device lab and immutable ref", () => {
  assert.match(WORKFLOW, /workflow_dispatch:/);
  assert.match(WORKFLOW, /ref:/);
  assert.match(WORKFLOW, /runs-on:\s*\n\s*- self-hosted\n\s*- secure-keypad-device-lab/);
  assert.match(WORKFLOW, /ref:\s*\$\{\{ inputs\.ref \}\}/);
  assert.match(WORKFLOW, /test "\$\(git -C candidate rev-parse HEAD\)" = "\$RELEASE_REF"/);
  assert.match(WORKFLOW, /external evidence root must not be inside the checkout/);
});

test("external evidence workflow validates and uploads only checked external evidence", () => {
  assert.match(WORKFLOW, /SECURE_KEYPAD_EXTERNAL_EVIDENCE_ROOT/);
  assert.match(WORKFLOW, /validate-external-release-evidence\.mjs/);
  assert.match(WORKFLOW, /--reviewer-public-key-sha256/);
  assert.match(WORKFLOW, /secrets\.SECURE_KEYPAD_REVIEWER_PUBLIC_KEY_SHA256/);
  assert.doesNotMatch(WORKFLOW, /inputs\.reviewer-public-key-sha256/);
  assert.match(WORKFLOW, /secure-keypad-external-release-evidence/);
  assert.match(WORKFLOW, /actions\/upload-artifact@[0-9a-f]{40}/);
});

test("external evidence workflow does not synthesize a device pass", () => {
  assert.doesNotMatch(WORKFLOW, /physicalDevice:\s*true/);
  assert.doesNotMatch(WORKFLOW, /status:\s*pass/);
  assert.match(WORKFLOW, /validate-external-release-evidence\.mjs/);
});

test("protected reviewer material is used only by a separately pinned verifier checkout", () => {
  assert.match(WORKFLOW, /SECURE_KEYPAD_TRUSTED_VERIFIER_REF/);
  assert.match(WORKFLOW, /path:\s*verifier/);
  assert.match(WORKFLOW, /ref:\s*\$\{\{ vars\.SECURE_KEYPAD_TRUSTED_VERIFIER_REF \}\}/);
  assert.match(WORKFLOW, /verifier\/scripts\/validate-external-release-evidence\.mjs/);
  assert.doesNotMatch(WORKFLOW, /node scripts\/validate-external-release-evidence\.mjs/);
  assert.match(WORKFLOW, /git -C verifier rev-parse HEAD/);
});
