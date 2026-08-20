import { describe, expect, it } from "vitest";
import { validateLayout, validateTheme } from "../src/index.js";

const exampleLayout = {
  schemaVersion: 1,
  rows: [[{ id: "digit-1", label: "1", role: "input" }]],
};

const exampleTheme = {
  schemaVersion: 1,
  colors: {
    background: "#111111",
    keyBackground: "#222222",
    keyForeground: "#ffffff",
    keyPressedBackground: "#333333",
    keyDisabledBackground: "#444444",
    error: "#ff0000",
  },
  metrics: { keyHeight: 56, keyGap: 8, keyRadius: 12, contentPadding: 16 },
  typography: { keyFontSize: 24, keyFontWeight: "600" },
};

describe("public customization contract", () => {
  it("accepts branded layout and theme data", () => {
    expect(validateLayout(exampleLayout).valid).toBe(true);
    expect(validateTheme(exampleTheme).valid).toBe(true);
  });

  it("rejects secret-bearing fields", () => {
    expect(validateLayout({ ...exampleLayout, password: "secret" }).valid).toBe(false);
    expect(validateLayout({ ...exampleLayout, value: "secret" }).valid).toBe(false);
    expect(validateLayout({ ...exampleLayout, rows: [[{ id: "digit-1", role: "input", value: "1" }]] }).valid).toBe(false);
  });

  it("rejects unsafe or unbounded presentation data", () => {
    expect(validateLayout({ ...exampleLayout, rows: [[{ id: "../../secret", role: "input" }]] }).valid).toBe(false);
    expect(validateTheme({ ...exampleTheme, metrics: { ...exampleTheme.metrics, keyHeight: 1000 } }).valid).toBe(false);
  });

  it("does not echo supplied field values in validation errors", () => {
    const result = validateLayout({ ...exampleLayout, password: "fixture-only-secret" });
    expect(result.errors.join(" ")).not.toContain("fixture-only-secret");
  });
});
