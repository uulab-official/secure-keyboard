import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MAX_RELEASE_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;

function readBoundedFile(filePath, label, maximumBytes) {
  const stats = statSync(filePath);
  if (!stats.isFile()) throw new Error(`${label} must reference a regular file`);
  if (stats.size === 0) throw new Error(`${label} must be non-empty`);
  if (stats.size > maximumBytes) throw new Error(`${label} must not exceed ${maximumBytes} bytes`);
  return readFileSync(filePath);
}

/**
 * Creates the detached Ed25519 material required by the release evidence
 * manifest. The private key is read only; it is never copied to an output
 * file, logged, or included in the manifest.
 *
 * @param {string} artifactPath
 * @param {string} privateKeyPath
 * @param {string} signaturePath
 * @param {string} publicKeyPath
 * @returns {{algorithm: "ed25519", signatureBytes: number, publicKeySha256: string}}
 */
export function signReleaseArtifact(artifactPath, privateKeyPath, signaturePath, publicKeyPath) {
  const privateKeyBytes = readBoundedFile(privateKeyPath, "private key", MAX_PRIVATE_KEY_BYTES);
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyBytes);
  } finally {
    privateKeyBytes.fill(0);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("release signing key must be Ed25519");
  }
  const artifact = readBoundedFile(artifactPath, "release artifact", MAX_RELEASE_ARTIFACT_BYTES);
  const signature = sign(null, artifact, privateKey);
  const publicKeyDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  writeFileSync(signaturePath, signature, { mode: 0o644, flag: "wx" });
  writeFileSync(publicKeyPath, publicKeyDer, { mode: 0o644, flag: "wx" });

  return {
    algorithm: "ed25519",
    signatureBytes: signature.length,
    publicKeySha256: createHash("sha256").update(publicKeyDer).digest("hex"),
  };
}

function main() {
  const [, , artifactPath, privateKeyPath, signaturePath, publicKeyPath] = process.argv;
  if (!artifactPath || !privateKeyPath || !signaturePath || !publicKeyPath) {
    console.error(
      "usage: node scripts/sign-release.mjs <artifact> <ed25519-private-key-pem> <signature> <public-key-der>",
    );
    process.exitCode = 64;
    return;
  }
  try {
    const result = signReleaseArtifact(artifactPath, privateKeyPath, signaturePath, publicKeyPath);
    console.log(JSON.stringify({
      ...result,
      artifactPath: path.relative(process.cwd(), path.resolve(artifactPath)),
      signaturePath: path.relative(process.cwd(), path.resolve(signaturePath)),
      publicKeyPath: path.relative(process.cwd(), path.resolve(publicKeyPath)),
    }));
  } catch (error) {
    console.error(`release signing failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
