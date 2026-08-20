import { describe, expect, it } from "vitest";
import { DEFAULT_NUMERIC_LAYOUT, DEFAULT_THEME } from "@secure-keypad/contracts";
import { assertSecureKeypadProps, validateSecureKeypadProps } from "../src/index.js";

describe("React Native public prop boundary", () => {
  it("accepts only serializable layout/theme/policy props", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "numeric",
      maxTokens: 8,
      timeoutMs: 60_000,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects secret-bearing host props without echoing values", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      password: "fixture-only-secret",
    });
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).not.toContain("fixture-only-secret");
  });

  it("rejects invalid policy bounds without accepting a value-like prop", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "numeric",
      maxTokens: 0,
      timeoutMs: 86_400_001,
      value: "never-crosses-the-boundary",
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("props.maxTokens is invalid");
    expect(result.errors).toContain("props.timeoutMs is invalid");
    expect(result.errors.join(" ")).not.toContain("never-crosses-the-boundary");
  });

  it("asserts invalid props using only generic, non-secret-bearing diagnostics", () => {
    expect(() =>
      assertSecureKeypadProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        secret: "fixture-only-secret",
      }),
    ).toThrow("props contains an unsupported field");
    expect(() =>
      assertSecureKeypadProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        secret: "fixture-only-secret",
      }),
    ).toThrowError(/^(?!.*fixture-only-secret)/);
  });
});
