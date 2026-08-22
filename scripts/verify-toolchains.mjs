import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

/** Exact host toolchain versions used by the reproducible release workflows. */
export const PINNED_TOOLCHAINS = Object.freeze({
  node: "22.13.0",
  pnpm: "11.19.0",
  rust: "1.97.1",
  cargo: "1.97.1",
  flutter: "3.47.0",
  dart: "3.13.0",
});

const MAX_VERSION_OUTPUT_BYTES = 64 * 1024;

function versionString(value) {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : undefined;
}

/** Parses Flutter's bounded machine-readable version output. */
export function parseFlutterMachineVersion(output) {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > MAX_VERSION_OUTPUT_BYTES) {
    throw new Error("flutter --version output is missing or oversized");
  }
  let parsed;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error("flutter --version --machine output is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("flutter --version --machine output must be an object");
  }
  const frameworkVersion = versionString(parsed.frameworkVersion);
  const flutterVersion = versionString(parsed.flutterVersion);
  const dartSdkVersion = versionString(parsed.dartSdkVersion);
  if (frameworkVersion === undefined || flutterVersion === undefined || dartSdkVersion === undefined) {
    throw new Error("flutter version output must include frameworkVersion, flutterVersion, and dartSdkVersion");
  }
  if (frameworkVersion !== flutterVersion) {
    throw new Error("frameworkVersion and flutterVersion must match");
  }
  return { frameworkVersion, flutterVersion, dartSdkVersion };
}

const VERSION_PATTERNS = Object.freeze({
  rustc: /\brustc\s+v?(\d+\.\d+\.\d+)/,
  cargo: /\bcargo\s+v?(\d+\.\d+\.\d+)/,
  dart: /\bDart SDK version:\s*v?(\d+\.\d+\.\d+)/,
});

/** Parses a bounded standalone executable version string. */
export function parseToolchainVersion(output, executable) {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > MAX_VERSION_OUTPUT_BYTES) {
    throw new Error(`${executable} version output is missing or oversized`);
  }
  const pattern = VERSION_PATTERNS[executable];
  if (pattern === undefined) throw new Error(`unsupported toolchain executable: ${executable}`);
  const match = output.match(pattern);
  if (match === null) throw new Error(`${executable} version output is not recognized`);
  return match[1];
}

/** Validates exact executable and SDK versions used by production-candidate gates. */
export function validatePinnedToolchains({
  nodeVersion,
  pnpmVersion,
  rustcVersionOutput,
  cargoVersionOutput,
  dartVersionOutput,
  flutterMachineOutput,
}) {
  const actualNode = versionString(nodeVersion);
  const actualPnpm = versionString(pnpmVersion);
  if (actualNode !== PINNED_TOOLCHAINS.node) {
    throw new Error(`Node must be ${PINNED_TOOLCHAINS.node}, found ${actualNode ?? "unknown"}`);
  }
  if (actualPnpm !== PINNED_TOOLCHAINS.pnpm) {
    throw new Error(`pnpm must be ${PINNED_TOOLCHAINS.pnpm}, found ${actualPnpm ?? "unknown"}`);
  }
  const actualRust = parseToolchainVersion(rustcVersionOutput, "rustc");
  const actualCargo = parseToolchainVersion(cargoVersionOutput, "cargo");
  const actualDartExecutable = parseToolchainVersion(dartVersionOutput, "dart");
  if (actualRust !== PINNED_TOOLCHAINS.rust) {
    throw new Error(`Rust must be ${PINNED_TOOLCHAINS.rust}, found ${actualRust}`);
  }
  if (actualCargo !== PINNED_TOOLCHAINS.cargo) {
    throw new Error(`Cargo must be ${PINNED_TOOLCHAINS.cargo}, found ${actualCargo}`);
  }
  if (actualDartExecutable !== PINNED_TOOLCHAINS.dart) {
    throw new Error(`Dart executable must be ${PINNED_TOOLCHAINS.dart}, found ${actualDartExecutable}`);
  }
  const flutter = parseFlutterMachineVersion(flutterMachineOutput);
  if (flutter.frameworkVersion !== PINNED_TOOLCHAINS.flutter) {
    throw new Error(`Flutter must be ${PINNED_TOOLCHAINS.flutter}, found ${flutter.frameworkVersion}`);
  }
  if (flutter.dartSdkVersion !== PINNED_TOOLCHAINS.dart) {
    throw new Error(`Dart must be ${PINNED_TOOLCHAINS.dart}, found ${flutter.dartSdkVersion}`);
  }
  return {
    node: actualNode,
    pnpm: actualPnpm,
    rust: actualRust,
    cargo: actualCargo,
    flutter: flutter.frameworkVersion,
    dart: flutter.dartSdkVersion,
  };
}

function commandOutput(executable, args, { includeStderr = false } = {}) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    maxBuffer: MAX_VERSION_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw new Error(`${executable} could not start: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`${executable} ${args.join(" ")} failed with exit code ${result.status ?? "unknown"}`);
  }
  return includeStderr ? `${result.stdout}${result.stderr}` : result.stdout;
}

function main() {
  try {
    const versions = validatePinnedToolchains({
      nodeVersion: process.versions.node,
      pnpmVersion: commandOutput("pnpm", ["--version"]),
      rustcVersionOutput: commandOutput("rustc", ["--version"]),
      cargoVersionOutput: commandOutput("cargo", ["--version"]),
      dartVersionOutput: commandOutput("dart", ["--version"], { includeStderr: true }),
      flutterMachineOutput: commandOutput("flutter", ["--version", "--machine"]),
    });
    console.log(
      `pinned toolchains verified: node=${versions.node} pnpm=${versions.pnpm} rust=${versions.rust} cargo=${versions.cargo} flutter=${versions.flutter} dart=${versions.dart}`,
    );
  } catch (error) {
    console.error(`pinned toolchain verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) main();
