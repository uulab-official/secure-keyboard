import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { REQUIRED_RELEASE_GATES } from "./check-release-evidence.mjs";
import { checkReleaseStaging } from "./check-release-bundle.mjs";

const NPM_PACKAGES = [
  "secure-keypad-contracts",
  "secure-keypad-react-native",
  "secure-keypad-web",
];
const RUST_CRATES = [
  "secure-auth",
  "secure-auth-axum",
  "secure-auth-http",
  "secure-auth-server",
  "secure-core",
  "secure-ffi",
  "secure-webauthn-example",
];

function writeFile(root, relativePath, contents) {
  const absolutePath = path.join(root, relativePath);
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, contents);
}

function createTarball(root, relativePath, directoryName, contents) {
  const stage = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-tar-stage-"));
  const packageRoot = path.join(stage, directoryName);
  mkdirSync(packageRoot, { recursive: true });
  for (const [relativePath, value] of Object.entries(contents)) {
    writeFile(packageRoot, relativePath, value);
  }
  mkdirSync(path.dirname(path.join(root, relativePath)), { recursive: true });
  execFileSync("tar", ["-czf", path.join(root, relativePath), "-C", stage, directoryName]);
  rmSync(stage, { recursive: true, force: true });
}

function createValidStaging() {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-release-staging-"));
  const commit = "a".repeat(40);
  writeFile(
    root,
    "source/release-candidate-metadata.json",
    `${JSON.stringify(
      {
        schemaVersion: 1,
        kind: "secure-keypad-release-candidate",
        claim: "candidate-only",
        commit,
        packageVersion: "0.1.0",
        requiredFinalGates: REQUIRED_RELEASE_GATES,
        candidateArtifacts: [
          { kind: "sbom", path: "secure-keypad.sbom.spdx.json" },
          { kind: "checksums", path: "secure-keypad-release.sha256" },
        ],
      },
      null,
      2,
    )}\n`,
  );
  writeFile(root, "source/Cargo.lock", "# cargo lock fixture\n");
  writeFile(root, "source/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
  writeFile(root, "source/CHANGELOG.md", "# Changelog\n\n## Unreleased\n");
  writeFile(root, "source/README.md", "# Secure Keypad SDK\n\nSecure Native Mode\n");
  writeFile(root, "source/SECURITY.md", "# Security Policy\n\n## Reporting a vulnerability\n\nDo not open a public issue. Use the private GitHub Security Advisory form.\n\nhttps://github.com/uulab-official/secure-keyboard/security/advisories/new\n");
  writeFile(root, "source/LICENSE-MIT", "MIT License\n");
  writeFile(root, "source/THIRD-PARTY-NOTICES.md", "# Third-party notices\n");
  writeFile(root, "source/secure-keypad.sbom.spdx.json", JSON.stringify({
    spdxVersion: "SPDX-2.3",
    packages: [{ name: "secure-core", SPDXID: "SPDXRef-secure-core" }],
  }));
  writeFile(root, "source/packages/flutter/pubspec.yaml", "name: secure_keypad_flutter\nversion: 0.1.0\n");
  for (const document of ["SECURITY-SPEC.md", "PLATFORM-SECURITY-POLICY.md", "RELEASE-GATES.md", "ROADMAP.md"]) {
    writeFile(root, `source/docs/${document}`, `# ${document}\n`);
  }

  for (const packageName of NPM_PACKAGES) {
    createTarball(root, `packages/${packageName}-0.1.0.tgz`, "package", {
      "package.json": JSON.stringify({ name: packageName, version: "0.1.0" }),
      LICENSE: "MIT License\n",
      "README.md": "# Package\n",
    });
  }
  for (const crateName of RUST_CRATES) {
    createTarball(root, `packages/${crateName}-0.1.0.crate`, `${crateName}-0.1.0`, {
      "Cargo.toml": `[package]\nname = "${crateName}"\nversion = "0.1.0"\n`,
      "README.md": "# Crate\n",
    });
  }
  return root;
}

test("release staging requires the complete signed-bundle input contract", () => {
  const root = createValidStaging();
  try {
    assert.deepEqual(checkReleaseStaging(root), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release staging requires the security changelog", () => {
  const root = createValidStaging();
  try {
    rmSync(path.join(root, "source/CHANGELOG.md"));
    const findings = checkReleaseStaging(root);
    assert.ok(findings.some((finding) => finding.includes("CHANGELOG.md")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release staging rejects a changelog without release headings", () => {
  const root = createValidStaging();
  try {
    writeFile(root, "source/CHANGELOG.md", "# Changelog\n\nplaceholder\n");
    const findings = checkReleaseStaging(root);
    assert.ok(findings.some((finding) => finding.includes("## Unreleased")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release staging requires the public README and vulnerability policy", () => {
  const root = createValidStaging();
  try {
    rmSync(path.join(root, "source/README.md"));
    rmSync(path.join(root, "source/SECURITY.md"));
    const findings = checkReleaseStaging(root);
    assert.ok(findings.some((finding) => finding.includes("source/README.md")));
    assert.ok(findings.some((finding) => finding.includes("source/SECURITY.md")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release staging rejects placeholder public security documents", () => {
  const root = createValidStaging();
  try {
    writeFile(root, "source/README.md", "# Secure Keypad SDK\n");
    writeFile(root, "source/SECURITY.md", "# Security Policy\n");
    const findings = checkReleaseStaging(root);
    assert.ok(findings.some((finding) => finding.includes("Secure Native Mode")));
    assert.ok(findings.some((finding) => finding.includes("private GitHub Security Advisory")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release staging rejects missing notices, malformed SBOM, package license loss, and private keys", () => {
  const root = createValidStaging();
  try {
    rmSync(path.join(root, "source/THIRD-PARTY-NOTICES.md"));
    writeFile(root, "source/secure-keypad.sbom.spdx.json", "{}\n");
    createTarball(root, "packages/secure-keypad-web-0.1.0.tgz", "package", {
      "package.json": JSON.stringify({ name: "secure-keypad-web", version: "0.1.0" }),
    });
    createTarball(root, "packages/secure-core-0.1.0.crate", "secure-core-0.1.0", {
      "Cargo.toml": "[package]\nname = \"secure-core\"\nversion = \"0.1.0\"\n",
    });
    writeFile(root, "secure-keypad-signing-key.pem", "private material\n");

    const findings = checkReleaseStaging(root);
    assert.ok(findings.some((finding) => finding.includes("THIRD-PARTY-NOTICES.md")));
    assert.ok(findings.some((finding) => finding.includes("SPDX")));
    assert.ok(findings.some((finding) => finding.includes("secure-keypad-web-0.1.0.tgz")));
    assert.ok(findings.some((finding) => finding.includes("secure-keypad-web-0.1.0.tgz: archive must contain package/README.md")));
    assert.ok(findings.some((finding) => finding.includes("secure-core-0.1.0.crate: crate archive must contain secure-core-0.1.0/README.md")));
    assert.ok(findings.some((finding) => finding.includes("private signing material")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release candidate workflow runs the staging inspector before archiving", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /scripts\/check-release-bundle\.mjs\s+"\$RELEASE_DIR"/);
});

test("release candidate workflow includes the security changelog in the signed source bundle", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /cp\s+CHANGELOG\.md\s+"\$RELEASE_DIR\/source\/CHANGELOG\.md"/);
});

test("release candidate workflow includes public security documents in the signed source bundle", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release-candidate.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /cp\s+README\.md\s+"\$RELEASE_DIR\/source\/README\.md"/);
  assert.match(workflow, /cp\s+SECURITY\.md\s+"\$RELEASE_DIR\/source\/SECURITY\.md"/);
});
