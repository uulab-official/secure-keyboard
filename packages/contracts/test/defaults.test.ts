import { describe, expect, it } from "vitest";
import {
  DEFAULT_HANGUL_LAYOUT,
  DEFAULT_NUMERIC_LAYOUT,
  DEFAULT_THEME,
  validateLayout,
  validateTheme,
} from "../src/index.js";

describe("safe default presentation contracts", () => {
  it("ships a valid numeric keypad without secret-bearing fields", () => {
    expect(validateLayout(DEFAULT_NUMERIC_LAYOUT).valid).toBe(true);
    expect(JSON.stringify(DEFAULT_NUMERIC_LAYOUT)).not.toContain("password");
    expect(JSON.stringify(DEFAULT_NUMERIC_LAYOUT)).not.toContain("value");
  });

  it("ships a valid Hangul composition example and theme", () => {
    expect(validateLayout(DEFAULT_HANGUL_LAYOUT).valid).toBe(true);
    expect(validateTheme(DEFAULT_THEME).valid).toBe(true);
  });
});
