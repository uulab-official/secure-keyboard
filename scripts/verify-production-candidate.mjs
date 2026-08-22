import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readdirSync } from "node:fs";
import path from "node:path";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY_ROOT = path.resolve(path.dirname(SCRIPT_PATH), "..");
const SCRIPT_ROOT = path.join(REPOSITORY_ROOT, "scripts");

function command(label, executable, args, options = {}) {
  return {
    label,
    executable,
    args,
    cwd: options.cwd ?? REPOSITORY_ROOT,
    env: options.env ?? {},
    display: options.display ?? [executable, ...args].join(" "),
  };
}

function nodeScriptTestFiles() {
  return readdirSync(SCRIPT_ROOT)
    .filter((entry) => entry.endsWith(".test.mjs"))
    .sort()
    .map((entry) => path.join("scripts", entry));
}

/**
 * Returns the deterministic gates that can run against the current checkout.
 * This intentionally does not synthesize device, service, CI, or review
 * evidence; those remain separate release inputs.
 */
export function buildProductionCandidateCommands({ evidencePath } = {}) {
  const commands = [
    command("Pinned host toolchains", process.execPath, ["scripts/verify-toolchains.mjs"], {
      display: "node scripts/verify-toolchains.mjs",
    }),
    command("Rust formatting", "cargo", ["fmt", "--all", "--", "--check"]),
    command("Rust workspace tests", "cargo", ["test", "--locked", "--workspace", "--all-features"]),
    command("Rust MSRV tests", "cargo", ["+1.88.0", "test", "--locked", "--workspace", "--all-features"]),
    command("Rust clippy", "cargo", [
      "clippy",
      "--locked",
      "--workspace",
      "--all-targets",
      "--all-features",
      "--",
      "-D",
      "warnings",
    ]),
    command(
      "Rust documentation",
      "cargo",
      ["doc", "--locked", "--workspace", "--all-features", "--no-deps"],
      { env: { RUSTDOCFLAGS: "-D warnings" } },
    ),
    command("Cargo dependency audit", "cargo", ["audit"]),
    command("Node dependency audit", "pnpm", ["audit", "--audit-level", "high"]),
    command("Native package parity", "pnpm", ["check:native-parity"]),
    command("HTTP contract version parity", "pnpm", ["check:http-contract-version-parity"]),
    command("OPAQUE protocol parity", "pnpm", ["check:opaque-protocol-parity"]),
    command("JavaScript package tests", "pnpm", ["-r", "test"]),
    command("JavaScript package typecheck", "pnpm", ["-r", "typecheck"]),
    command("JavaScript package builds", "pnpm", ["-r", "build"]),
    command("Repository script tests", process.execPath, ["--test", ...nodeScriptTestFiles()], {
      display: "node --test scripts/*.test.mjs",
    }),
    command("Static security audit", "pnpm", ["security-audit"]),
    command("Browser runtime matrix", "pnpm", ["test:web-browser"]),
    command("Flutter dependencies", "flutter", ["pub", "get"], { cwd: path.join(REPOSITORY_ROOT, "packages/flutter") }),
    command(
      "Flutter formatting",
      "dart",
      ["format", "--output=none", "--set-exit-if-changed", "lib", "test"],
      { cwd: path.join(REPOSITORY_ROOT, "packages/flutter") },
    ),
    command("Flutter analysis", "flutter", ["analyze"], { cwd: path.join(REPOSITORY_ROOT, "packages/flutter") }),
    command("Flutter tests", "flutter", ["test"], { cwd: path.join(REPOSITORY_ROOT, "packages/flutter") }),
    command("Flutter publish dry-run", "dart", ["pub", "publish", "--dry-run"], {
      cwd: path.join(REPOSITORY_ROOT, "packages/flutter"),
    }),
  ];

  if (evidencePath !== undefined) {
    commands.push(
      command(
        "Trusted release evidence verification",
        process.execPath,
        ["scripts/check-release-evidence.mjs", "--require-trusted-keys", evidencePath],
      ),
    );
  }

  return commands;
}

export function parseProductionCandidateArguments(argv) {
  let dryRun = false;
  let evidencePath;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--dry-run") {
      if (dryRun) throw new Error("--dry-run must be specified once");
      dryRun = true;
      continue;
    }
    if (argument === "--evidence") {
      if (evidencePath !== undefined) throw new Error("--evidence must be specified once");
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--evidence requires a manifest path");
      }
      evidencePath = path.resolve(REPOSITORY_ROOT, value);
      index += 1;
      continue;
    }
    throw new Error(`unknown option: ${argument}`);
  }

  return { dryRun, evidencePath };
}

export function runProductionCandidate(commands) {
  for (const step of commands) {
    console.log(`\n== ${step.label} ==`);
    console.log(step.display);
    const result = spawnSync(step.executable, step.args, {
      cwd: step.cwd,
      env: { ...process.env, ...step.env },
      stdio: "inherit",
    });
    if (result.error) throw new Error(`${step.label} could not start: ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(`${step.label} failed with exit code ${result.status ?? "unknown"}`);
    }
  }
}

function main() {
  try {
    const options = parseProductionCandidateArguments(process.argv.slice(2));
    const commands = buildProductionCandidateCommands(options);
    if (options.dryRun) {
      console.log("deterministic production-candidate gates:");
      for (const step of commands) console.log(`- ${step.label}: ${step.display}`);
      console.log("external device, service, CI-provenance, and independent-review evidence is not synthesized");
      return;
    }

    runProductionCandidate(commands);
    console.log("\ndeterministic production-candidate gates passed");
    if (options.evidencePath === undefined) {
      console.log("release evidence was not supplied; this is not a production-release approval");
    } else {
      console.log("trusted release evidence verification passed");
    }
  } catch (error) {
    console.error(`production-candidate verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SCRIPT_PATH)) main();
