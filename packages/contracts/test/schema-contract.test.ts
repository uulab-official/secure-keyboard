import { describe, expect, it } from "vitest";
import { validateLayout, validateMaskedState, validateResultEvent, validateTheme } from "../src/index.js";

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

  it("bounds public labels by UTF-8 bytes across native renderers", () => {
    expect(
      validateLayout({
        ...exampleLayout,
        rows: [[{ id: "korean", label: "가가가가가가", role: "input" }]],
      }).valid,
    ).toBe(false);
    expect(
      validateLayout({
        ...exampleLayout,
        rows: [[{ id: "accented", label: "éééééééé", role: "input" }]],
      }).valid,
    ).toBe(true);
    expect(
      validateLayout({
        ...exampleLayout,
        rows: [[{ id: "accessible", accessibilityLabel: "가".repeat(27), role: "input" }]],
      }).valid,
    ).toBe(false);
  });

  it("rejects duplicate key IDs across layout rows", () => {
    expect(
      validateLayout({
        schemaVersion: 1,
        rows: [
          [{ id: "digit-1", role: "input" }],
          [{ id: "digit-1", role: "input" }],
        ],
      }),
    ).toMatchObject({ valid: false });
  });

  it("accepts an explicit cancel action without adding a secret channel", () => {
    expect(
      validateLayout({
        schemaVersion: 1,
        rows: [[{ id: "cancel", label: "Cancel", role: "cancel" }]],
      }),
    ).toEqual({ valid: true, errors: [] });
  });

  it("does not echo supplied field values in validation errors", () => {
    const result = validateLayout({ ...exampleLayout, password: "fixture-only-secret" });
    expect(result.errors.join(" ")).not.toContain("fixture-only-secret");
  });

  it("bounds masked state metadata before it reaches a host callback", () => {
    expect(validateMaskedState({ length: 0, displayState: "empty" })).toEqual({ valid: true, errors: [] });
    expect(validateMaskedState({ length: 4096, displayState: "masked" })).toEqual({ valid: true, errors: [] });
    expect(validateMaskedState({ length: -1, displayState: "masked" }).valid).toBe(false);
    expect(validateMaskedState({ length: 4097, displayState: "masked" }).valid).toBe(false);
    expect(validateMaskedState({ length: 1.5, displayState: "masked" }).valid).toBe(false);
    expect(validateMaskedState({ length: 1, displayState: "masked", value: "fixture-only-secret" }).errors.join(" "))
      .not.toContain("fixture-only-secret");
  });

  it("bounds result events to stable non-secret codes", () => {
    expect(validateResultEvent({ type: "result", code: "success" })).toEqual({ valid: true, errors: [] });
    expect(validateResultEvent({ type: "result", code: "unknown" }).valid).toBe(false);
    expect(validateResultEvent({ type: "result", code: "error", password: "fixture-only-secret" }).errors.join(" "))
      .not.toContain("fixture-only-secret");
  });
});
