import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  checkReleaseArchive,
  validateReleaseArchiveEntries,
} from "./check-release-archive.mjs";

const REQUIRED_ENTRIES = [
  "source/release-candidate-metadata.json",
  "source/secure-keypad.sbom.spdx.json",
  "source/packages/flutter/pubspec.yaml",
  "source/packages/flutter/ios/secure_ffi.xcframework/Info.plist",
  "source/packages/flutter/ios/libsecure_ffi.a",
  "packages/secure-keypad-contracts-0.1.0.tgz",
  "packages/secure-keypad-react-native-0.1.0.tgz",
  "packages/secure-keypad-web-0.1.0.tgz",
  "packages/secure-keypad-server-node-0.1.0.tgz",
  "packages/secure-auth-0.1.0.crate",
  "packages/secure-auth-axum-0.1.0.crate",
  "packages/secure-auth-actix-0.1.0.crate",
  "packages/secure-auth-http-0.1.0.crate",
  "packages/secure-auth-server-0.1.0.crate",
  "packages/secure-core-0.1.0.crate",
  "packages/secure-ffi-0.1.0.crate",
  "packages/secure-webauthn-example-0.1.0.crate",
];

test("signed release archive must include every staged package and source contract", () => {
  assert.deepEqual(validateReleaseArchiveEntries(REQUIRED_ENTRIES), []);
});

test("signed release archive checker reads the actual tarball entry list", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-release-archive-"));
  const stage = path.join(root, "stage");
  const archive = path.join(root, "secure-keypad-release.tar.gz");
  try {
    for (const entry of REQUIRED_ENTRIES) {
      const absolutePath = path.join(stage, entry);
      mkdirSync(path.dirname(absolutePath), { recursive: true });
      writeFileSync(absolutePath, "fixture\n");
    }
    execFileSync("tar", ["-czf", archive, "-C", stage, "source", "packages"]);
    assert.deepEqual(checkReleaseArchive(archive), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("signed release archive rejects symbolic links even when required paths are present", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-release-archive-symlink-"));
  const stage = path.join(root, "stage");
  const archive = path.join(root, "secure-keypad-release.tar.gz");
  try {
    for (const entry of REQUIRED_ENTRIES) {
      const absolutePath = path.join(stage, entry);
      mkdirSync(path.dirname(absolutePath), { recursive: true });
      writeFileSync(absolutePath, "fixture\n");
    }
    const symlinkPath = path.join(stage, "source/release-candidate-metadata.json");
    rmSync(symlinkPath);
    symlinkSync("outside-release-metadata.json", symlinkPath);
    execFileSync("tar", ["-czf", archive, "-C", stage, "source", "packages"]);

    const findings = checkReleaseArchive(archive);

    assert.ok(findings.some((finding) => finding.includes("symbolic link")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("signed release archive rejects non-regular filesystem entries", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "secure-keypad-release-archive-special-"));
  const stage = path.join(root, "stage");
  const archive = path.join(root, "secure-keypad-release.tar.gz");
  try {
    for (const entry of REQUIRED_ENTRIES) {
      const absolutePath = path.join(stage, entry);
      mkdirSync(path.dirname(absolutePath), { recursive: true });
      writeFileSync(absolutePath, "fixture\n");
    }
    const fifoPath = path.join(stage, "source/unexpected.pipe");
    execFileSync("mkfifo", [fifoPath]);
    execFileSync("tar", ["-czf", archive, "-C", stage, "source", "packages"]);

    const findings = checkReleaseArchive(archive);

    assert.ok(findings.some((finding) => finding.includes("regular files and directories")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("signed release archive rejects a source-only archive", () => {
  const findings = validateReleaseArchiveEntries([
    "source/release-candidate-metadata.json",
    "source/secure-keypad.sbom.spdx.json",
    "source/packages/flutter/pubspec.yaml",
  ]);
  assert.ok(findings.some((finding) => finding.includes("package version could not be determined")));
});

test("signed release archive rejects mixed versions and unexpected top-level paths", () => {
  const findings = validateReleaseArchiveEntries([
    ...REQUIRED_ENTRIES.filter((entry) => !entry.includes("secure-keypad-web-0.1.0.tgz")),
    "packages/secure-keypad-web-0.2.0.tgz",
    "private-signing-key.pem",
  ]);
  assert.ok(findings.some((finding) => finding.includes("same package version")));
  assert.ok(findings.some((finding) => finding.includes("outside source/ or packages/")));
});

test("signed release archive rejects duplicate paths", () => {
  const findings = validateReleaseArchiveEntries([
    ...REQUIRED_ENTRIES,
    REQUIRED_ENTRIES[0],
  ]);

  assert.ok(findings.some((finding) => finding.includes("archive entry must be unique")));
});
