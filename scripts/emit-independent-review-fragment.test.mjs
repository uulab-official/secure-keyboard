import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildIndependentReviewFragment } from "./emit-independent-review-fragment.mjs";

const COMMIT = "a".repeat(40);
const PACKAGE_VERSION = "0.1.0";

function reviewReport(publicKeySha256) {
  return {
    schemaVersion: 1,
    reportType: "independent-security-review",
    reviewedCommit: COMMIT,
    reviewedPackageVersion: PACKAGE_VERSION,
    reviewerPublicKeySha256: publicKeySha256,
    scope: [
      "native-input-boundary",
      "opaque-authentication",
      "http-json-transport",
      "replay-rate-limit-backends",
      "framework-adapters",
      "device-runtime-evidence",
      "release-process",
    ],
    findings: [],
    decision: "approved",
  };
}

function completeInput() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = createHash("sha256").update(publicKeyBytes).digest("hex");
  const reportBytes = Buffer.from(`${JSON.stringify(reviewReport(publicKeySha256))}\n`, "utf8");
  const signatureBytes = sign(null, reportBytes, privateKey);
  return {
    commit: COMMIT,
    packageVersion: PACKAGE_VERSION,
    reportPath: "artifacts/review.json",
    reportBytes,
    signaturePath: "artifacts/review.sig",
    signatureBytes,
    publicKeyPath: "artifacts/review.pub.der",
    publicKeyBytes,
    evidencePath: "evidence/independent-security-review.json",
  };
}

test("builds a verified independent-review gate and artifact fragment", () => {
  const input = completeInput();
  const result = buildIndependentReviewFragment(input);

  assert.equal(result.gates[0].name, "independent-security-review");
  assert.equal(result.gates[0].evidencePath, input.evidencePath);
  assert.deepEqual(
    result.artifacts.map(({ kind }) => kind),
    ["independent-review-report", "independent-review-public-key", "independent-review-signature"],
  );
  assert.equal(result.independentReview.algorithm, "ed25519");
  assert.equal(
    result.independentReview.publicKeySha256,
    createHash("sha256").update(input.publicKeyBytes).digest("hex"),
  );
});

test("rejects a tampered independent-review signature and a report for another commit", () => {
  const input = completeInput();
  input.signatureBytes[0] ^= 0xff;
  assert.throws(() => buildIndependentReviewFragment(input), /signature does not verify/);

  const other = completeInput();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  const report = reviewReport(createHash("sha256").update(publicKeyBytes).digest("hex"));
  report.reviewedCommit = "b".repeat(40);
  other.reportBytes = Buffer.from(`${JSON.stringify(report)}\n`, "utf8");
  other.publicKeyBytes = publicKeyBytes;
  other.signatureBytes = sign(null, other.reportBytes, privateKey);
  assert.throws(() => buildIndependentReviewFragment(other), /reviewedCommit/);
});

test("CLI emits the reviewer evidence and fragment from a clean checkout", () => {
  const root = mkdtempSync(join(tmpdir(), "secure-keypad-independent-review-"));
  const input = completeInput();
  for (const [relativePath, bytes] of [
    [input.reportPath, input.reportBytes],
    [input.signaturePath, input.signatureBytes],
    [input.publicKeyPath, input.publicKeyBytes],
  ]) {
    const absolutePath = join(root, relativePath);
    const directory = absolutePath.slice(0, absolutePath.lastIndexOf("/"));
    mkdirSync(directory, { recursive: true });
    writeFileSync(absolutePath, bytes);
  }

  const script = fileURLToPath(new URL("./emit-independent-review-fragment.mjs", import.meta.url));
  const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
  const report = JSON.parse(input.reportBytes.toString("utf8"));
  report.reviewedCommit = commit;
  const reportBytes = Buffer.from(`${JSON.stringify(report)}\n`, "utf8");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  report.reviewerPublicKeySha256 = createHash("sha256").update(publicKeyBytes).digest("hex");
  const finalReportBytes = Buffer.from(`${JSON.stringify(report)}\n`, "utf8");
  writeFileSync(join(root, input.reportPath), finalReportBytes);
  writeFileSync(join(root, input.signaturePath), sign(null, finalReportBytes, privateKey));
  writeFileSync(join(root, input.publicKeyPath), publicKeyBytes);

  const result = execFileSync(
    process.execPath,
    [
      script,
      root,
      input.evidencePath,
      "fragments/independent-review.json",
      "--report",
      input.reportPath,
      "--signature",
      input.signaturePath,
      "--public-key",
      input.publicKeyPath,
    ],
    { cwd: repositoryRoot, encoding: "utf8" },
  );

  assert.match(result, /independent-review fragment emitted/);
  const fragment = JSON.parse(readFileSync(join(root, "fragments/independent-review.json"), "utf8"));
  assert.equal(fragment.commit, commit);
  assert.equal(fragment.independentReview.reviewedCommit, commit);
});
