import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  findMutableCiActionLines,
  findNativeAbiVersionMismatches,
  runSecurityAudit,
} from "./security-audit.mjs";

test("independent static security audit has no findings", () => {
  assert.deepEqual(runSecurityAudit(), []);
});

test("CI action audit rejects mutable refs and accepts immutable revisions", () => {
  assert.deepEqual(
    findMutableCiActionLines([
      "      - uses: actions/checkout@v4",
      "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
    ].join("\n")),
    ["      - uses: actions/checkout@v4"],
  );
});

test("Android secure native view fails closed without a secure Activity window", () => {
  const source = readFileSync(
    new URL("../native/android/src/main/kotlin/com/uulab/securekeypad/SecureKeypadView.kt", import.meta.url),
    "utf8",
  );

  assert.match(source, /findActivity\(\)\s*\?:\s*error/);
  assert.match(source, /onAttachedToWindow\(\)[\s\S]*addFlags\(WindowManager\.LayoutParams\.FLAG_SECURE\)/);
});

test("native host ABI expectations stay synchronized with the FFI header", () => {
  assert.deepEqual(findNativeAbiVersionMismatches(), []);
});
