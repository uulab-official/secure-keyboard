import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { validateDeviceEvidence, verifyDeviceEvidenceFiles } from "./check-device-evidence.mjs";
import { buildWebBrowserEvidence, writeWebBrowserEvidence } from "./emit-web-browser-evidence.mjs";

const COMMIT = "d".repeat(40);
const BROWSERS = ["chromium", "firefox", "webkit"];
const CI_WORKFLOW = readFileSync(fileURLToPath(new URL("../.github/workflows/ci.yml", import.meta.url)), "utf8");
const LOGS = [
  { browser: "chromium", path: "browser/chromium.log", bytes: Buffer.from("chromium secure-context pass\n") },
  { browser: "firefox", path: "browser/firefox.log", bytes: Buffer.from("firefox secure-context pass\n") },
  { browser: "webkit", path: "browser/webkit.log", bytes: Buffer.from("webkit secure-context pass\n") },
];

test("builds a valid sanitized web browser matrix record from hashed log references", () => {
  const record = buildWebBrowserEvidence({
    commit: COMMIT,
    frameworkVersion: "playwright-1.62.1",
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    logs: LOGS,
  });

  assert.deepEqual(validateDeviceEvidence(record, { expectedCommit: COMMIT }), []);
  assert.equal(record.logPath, "browser/chromium.log");
  assert.equal(record.logSha256, createHash("sha256").update(LOGS[0].bytes).digest("hex"));
  assert.equal(record.artifacts.length, 2);
  assert.equal(Object.hasOwn(record, "rawLogs"), false);
});

test("writes web evidence and a commit-bound fragment whose files verify", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-web-evidence-"));
  for (const log of LOGS) {
    mkdirSync(join(root, log.path.split("/")[0]), { recursive: true });
    writeFileSync(join(root, log.path), log.bytes);
  }

  const result = writeWebBrowserEvidence({
    root,
    commit: COMMIT,
    packageVersion: "0.1.0",
    evidencePath: "ci/web-browser-matrix.json",
    fragmentPath: "fragments/web-browser-matrix.json",
    frameworkVersion: "playwright-1.62.1",
    runner: "ubuntu-24.04",
    recordedAt: "2026-08-22T00:00:00.000Z",
    logs: LOGS.map(({ browser, path }) => ({ browser, path })),
  });

  const evidence = JSON.parse(readFileSync(join(root, "ci/web-browser-matrix.json"), "utf8"));
  const fragment = JSON.parse(readFileSync(join(root, "fragments/web-browser-matrix.json"), "utf8"));
  assert.deepEqual(evidence, result.record);
  assert.equal(fragment.gates[0].evidencePath, "ci/web-browser-matrix.json");
  assert.deepEqual(verifyDeviceEvidenceFiles(evidence, root), []);
});

test("rejects incomplete browser matrices and unsafe log references", () => {
  assert.throws(
    () =>
      buildWebBrowserEvidence({
        commit: COMMIT,
        frameworkVersion: "playwright-1.62.1",
        runner: "ubuntu-24.04",
        recordedAt: "2026-08-22T00:00:00.000Z",
        logs: LOGS.slice(0, 2),
      }),
    /exactly one log for chromium, firefox, and webkit/,
  );
  assert.throws(
    () =>
      buildWebBrowserEvidence({
        commit: COMMIT,
        frameworkVersion: "playwright-1.62.1",
        runner: "ubuntu-24.04",
        recordedAt: "2026-08-22T00:00:00.000Z",
        logs: LOGS.map((log, index) => (index === 0 ? { ...log, path: "../raw.log" } : log)),
      }),
    /safe relative path/,
  );
});

test("rejects oversized browser logs before hashing evidence", () => {
  const logs = BROWSERS.map((browser, index) => ({
    browser,
    path: `browser/${browser}.log`,
    bytes: index === 0 ? Buffer.alloc(32 * 1024 * 1024 + 1, 0x20) : Buffer.from(`${browser}\n`, "utf8"),
  }));

  assert.throws(
    () =>
      buildWebBrowserEvidence({
        commit: COMMIT,
        frameworkVersion: "playwright-1.62.1",
        runner: "ubuntu-24.04",
        recordedAt: "2026-08-22T00:00:00.000Z",
        logs,
      }),
    /must not exceed 33554432 bytes/,
  );
});

test("rejects empty browser logs before hashing evidence", () => {
  const emptyLogs = LOGS.map((log, index) => (index === 1 ? { ...log, bytes: Buffer.alloc(0) } : log));

  assert.throws(
    () =>
      buildWebBrowserEvidence({
        commit: COMMIT,
        frameworkVersion: "playwright-1.62.1",
        runner: "ubuntu-24.04",
        recordedAt: "2026-08-22T00:00:00.000Z",
        logs: emptyLogs,
      }),
    /browser log bytes must not be empty/,
  );
});

test("CI downloads the browser matrix logs before emitting web release evidence", () => {
  assert.match(CI_WORKFLOW, /actions\/download-artifact@[0-9a-f]{40}[\s\S]*?secure-keypad-browser-smoke-/);
  assert.match(CI_WORKFLOW, /name: Emit web browser CI release evidence[\s\S]*?emit-web-browser-evidence\.mjs/);
  assert.match(CI_WORKFLOW, /web-browser-matrix[\s\S]*?web-browser-matrix\.json[\s\S]*?fragments\/web-browser-matrix\.json/);
});
