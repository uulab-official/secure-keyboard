import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Validates the porcelain output used by the production-candidate gate.
 *
 * @param {unknown} status
 */
export function validateCheckoutStatus(status) {
  if (typeof status !== "string" || status.trim().length > 0) {
    throw new Error("current checkout must be clean before production-candidate verification");
  }
}

export function checkCleanCheckout(root = ROOT) {
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  validateCheckoutStatus(status);
  return true;
}

function main() {
  try {
    checkCleanCheckout();
    console.log("clean checkout verified");
  } catch (error) {
    console.error(`clean checkout verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) main();
