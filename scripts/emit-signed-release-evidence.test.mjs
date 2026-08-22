import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const REPOSITORY_ROOT = fileURLToPath(new URL("..", import.meta.url));
const EMIT_SCRIPT = fileURLToPath(new URL("./emit-signed-release-evidence.mjs", import.meta.url));

function writeSignedArtifacts(root) {
  const bundle = Buffer.from("deterministic release bundle bytes\n", "utf8");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signature = sign(null, bundle, privateKey);
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, "artifacts/release.tar.gz"), bundle);
  writeFileSync(join(root, "artifacts/release.sig"), signature);
  writeFileSync(join(root, "artifacts/release.pub.der"), publicKeyDer);
  return { bundle, signature, publicKeyDer };
}

function runEmitter(root) {
  return spawnSync(
    process.execPath,
    [
      EMIT_SCRIPT,
      root,
      "evidence/signed-release.json",
      "--bundle",
      "artifacts/release.tar.gz",
      "--signature",
      "artifacts/release.sig",
      "--public-key",
      "artifacts/release.pub.der",
    ],
    { cwd: REPOSITORY_ROOT, encoding: "utf8" },
  );
}

test("emits a commit-bound signed-release evidence record with verified artifact hashes", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-signed-release-"));
  const { bundle, signature, publicKeyDer } = writeSignedArtifacts(root);

  const result = runEmitter(root);

  assert.equal(result.status, 0, result.stderr);
  const record = JSON.parse(readFileSync(join(root, "evidence/signed-release.json"), "utf8"));
  assert.equal(record.schemaVersion, 1);
  assert.equal(record.gate, "signed-release");
  assert.equal(record.status, "pass");
  assert.equal(record.algorithm, "ed25519");
  assert.match(record.commit, /^[0-9a-f]{40}$/);
  assert.equal(record.packageVersion, "0.1.0");
  assert.equal(record.bundlePath, "artifacts/release.tar.gz");
  assert.equal(record.bundleSha256, createHash("sha256").update(bundle).digest("hex"));
  assert.equal(record.signatureSha256, createHash("sha256").update(signature).digest("hex"));
  assert.equal(record.publicKeySha256, createHash("sha256").update(publicKeyDer).digest("hex"));
});

test("rejects a signed-release evidence record when the detached signature is tampered", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-tampered-release-"));
  writeSignedArtifacts(root);
  const signaturePath = join(root, "artifacts/release.sig");
  const signature = readFileSync(signaturePath);
  signature[0] ^= 0xff;
  writeFileSync(signaturePath, signature);

  const result = runEmitter(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /signature/i);
});

test("rejects signed-release evidence paths that escape the evidence root", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-unsafe-release-"));
  writeSignedArtifacts(root);

  const result = spawnSync(
    process.execPath,
    [
      EMIT_SCRIPT,
      root,
      "evidence/signed-release.json",
      "--bundle",
      "../outside.tar.gz",
      "--signature",
      "artifacts/release.sig",
      "--public-key",
      "artifacts/release.pub.der",
    ],
    { cwd: REPOSITORY_ROOT, encoding: "utf8" },
  );

  assert.equal(result.status, 1);
  assert.match(result.stderr, /relative|inside|path/i);
});

test("rejects an oversized detached signature before reading an unbounded buffer", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-oversized-release-signature-"));
  writeSignedArtifacts(root);
  writeFileSync(join(root, "artifacts/release.sig"), Buffer.alloc(65, 0));

  const result = runEmitter(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /signaturePath must not exceed 64 bytes/);
});

test("rejects an evidence output directory that resolves outside the root", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-symlinked-release-output-"));
  const outside = mkdtempSync(join(tmpdir(), "secure-keypad-release-output-target-"));
  writeSignedArtifacts(root);
  symlinkSync(outside, join(root, "evidence"), "dir");

  const result = runEmitter(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /outputPath must resolve inside the evidence root/);
});

test("rejects signed-release inputs reached through a symlinked parent directory", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-symlinked-release-input-"));
  writeSignedArtifacts(root);
  renameSync(join(root, "artifacts"), join(root, "real-artifacts"));
  symlinkSync("real-artifacts", join(root, "artifacts"), "dir");

  const result = runEmitter(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /symbolic link/);
});
