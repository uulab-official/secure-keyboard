import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { signReleaseArtifact } from "./sign-release.mjs";

test("signs a release artifact with an Ed25519 key and emits only public material", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-sign-release-"));
  const artifactPath = join(root, "release.tar.gz");
  const privateKeyPath = join(root, "signing-key.pem");
  const signaturePath = join(root, "release.sig");
  const publicKeyPath = join(root, "release.pub.der");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeFileSync(artifactPath, Buffer.from("release artifact", "utf8"));
  writeFileSync(privateKeyPath, privateKey.export({ format: "pem", type: "pkcs8" }));

  const result = signReleaseArtifact(artifactPath, privateKeyPath, signaturePath, publicKeyPath);

  assert.equal(result.algorithm, "ed25519");
  assert.equal(result.signatureBytes, 64);
  assert.equal(result.publicKeySha256.length, 64);
  assert.equal(readFileSync(signaturePath).length, 64);
  assert.deepEqual(readFileSync(publicKeyPath), publicKey.export({ format: "der", type: "spki" }));
  assert.equal(
    verify(null, readFileSync(artifactPath), publicKey, readFileSync(signaturePath)),
    true,
  );
});

test("rejects a non-Ed25519 signing key", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-sign-release-invalid-"));
  const artifactPath = join(root, "release.tar.gz");
  const privateKeyPath = join(root, "signing-key.pem");
  const signaturePath = join(root, "release.sig");
  const publicKeyPath = join(root, "release.pub.der");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(artifactPath, Buffer.from("release artifact", "utf8"));
  writeFileSync(privateKeyPath, privateKey.export({ format: "pem", type: "pkcs8" }));

  assert.throws(
    () => signReleaseArtifact(artifactPath, privateKeyPath, signaturePath, publicKeyPath),
    /Ed25519/,
  );
});

test("rejects an empty release artifact before signing", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-sign-release-empty-artifact-"));
  const artifactPath = join(root, "release.tar.gz");
  const privateKeyPath = join(root, "signing-key.pem");
  const signaturePath = join(root, "release.sig");
  const publicKeyPath = join(root, "release.pub.der");
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(artifactPath, Buffer.alloc(0));
  writeFileSync(privateKeyPath, privateKey.export({ format: "pem", type: "pkcs8" }));

  assert.throws(
    () => signReleaseArtifact(artifactPath, privateKeyPath, signaturePath, publicKeyPath),
    /artifact must be non-empty/,
  );
});
