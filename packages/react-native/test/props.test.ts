import { describe, expect, it } from "vitest";
import { DEFAULT_NUMERIC_LAYOUT, DEFAULT_THEME } from "@secure-keypad/contracts";
import {
  assertSecureKeypadProps,
  createSecureKeypadEventHandlers,
  getSecureKeypadNativeProps,
  validateMaskedStateEvent,
  validateResultEvent,
  validateSecureKeypadProps,
} from "../src/index.js";


describe("React Native public prop boundary", () => {
  it("accepts only serializable layout/theme/policy props", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "numeric",
      maxTokens: 8,
      timeoutMs: 60_000,
      cancelRequest: 0,
    });
    expect(result.valid).toBe(true);
  });

  it("accepts presentation-only React Native styles without creating a secret channel", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      style: { flex: 1, minHeight: 240 },
    });

    expect(result.valid).toBe(true);
  });

  it("accepts the native printable-ASCII policy without creating a value prop", () => {
    const result = validateSecureKeypadProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "ascii",
      maxTokens: 32,
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

  it("accepts a monotonic cancel command without adding a secret channel", () => {
    expect(
      validateSecureKeypadProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        cancelRequest: 1,
      }),
    ).toMatchObject({ valid: true });
    expect(
      validateSecureKeypadProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        cancelRequest: 1.5,
      }),
    ).toMatchObject({ valid: false });
    expect(
      validateSecureKeypadProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        cancelRequest: -1,
      }),
    ).toMatchObject({ valid: false });
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

  it("strips callbacks and rejects unknown props before native serialization", () => {
    const nativeProps = getSecureKeypadNativeProps({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "numeric",
      cancelRequest: 0,
    });
    expect(nativeProps).toEqual({
      layout: DEFAULT_NUMERIC_LAYOUT,
      theme: DEFAULT_THEME,
      inputPolicy: "numeric",
      cancelRequest: 0,
    });
    expect(nativeProps).not.toHaveProperty("onResult");

    expect(() =>
      getSecureKeypadNativeProps({
        layout: DEFAULT_NUMERIC_LAYOUT,
        theme: DEFAULT_THEME,
        password: "fixture-only-secret",
      } as never),
    ).toThrow("props contains an unsupported field");
  });

  it("rejects malformed native masked-state events before host callbacks", () => {
    expect(validateMaskedStateEvent({ nativeEvent: { length: 0, displayState: "empty" } })).toMatchObject({ valid: true });
    expect(validateMaskedStateEvent({ nativeEvent: { length: 0, displayState: "empty" }, secret: "fixture-only-secret" })).toMatchObject({ valid: false });
    expect(validateMaskedStateEvent({ nativeEvent: { length: 4_096, displayState: "masked" } })).toMatchObject({ valid: true });
    expect(validateMaskedStateEvent({ nativeEvent: { length: 4_097, displayState: "masked" } })).toMatchObject({ valid: false });
    expect(validateMaskedStateEvent({ nativeEvent: { length: -1, displayState: "masked" } })).toMatchObject({ valid: false });
    expect(validateMaskedStateEvent({ nativeEvent: { length: 1, displayState: "masked", secret: "fixture-only-secret" } }).errors.join(" "))
      .not.toContain("fixture-only-secret");
  });

  it("accepts only the bounded result event shape", () => {
    expect(validateResultEvent({ nativeEvent: { type: "result", code: "success" } })).toMatchObject({ valid: true });
    expect(validateResultEvent({ nativeEvent: { type: "result", code: "success" }, rawInput: "fixture-only-secret" })).toMatchObject({ valid: false });
    expect(validateResultEvent({ nativeEvent: { type: "result", code: "error", secret: "fixture-only-secret" } }).valid)
      .toBe(false);
    expect(validateResultEvent({ nativeEvent: { type: "result", code: "fixture-only-secret" } }).errors.join(" "))
      .not.toContain("fixture-only-secret");
  });

  it("uses fail-closed handlers for native bridge events", () => {
    const maskedStates: unknown[] = [];
    const results: unknown[] = [];
    const handlers = createSecureKeypadEventHandlers(
      (event) => maskedStates.push(event),
      (event) => results.push(event),
    );
    handlers.onMaskedStateChange?.({
      nativeEvent: { length: 4_097, displayState: "masked" },
    });
    handlers.onMaskedStateChange?.({
      nativeEvent: { length: 2, displayState: "masked" },
      rawInput: "fixture-only-secret",
    } as never);
    handlers.onMaskedStateChange?.({
      nativeEvent: { length: 2, displayState: "masked" },
    });
    handlers.onResult?.({
      nativeEvent: { type: "result", code: "success" },
      rawInput: "fixture-only-secret",
    } as never);
    handlers.onResult?.({
      nativeEvent: { type: "result", code: "success", secret: "fixture-only-secret" },
    } as never);

    expect(maskedStates).toHaveLength(1);
    expect(results).toEqual([
      { nativeEvent: { type: "result", code: "error" } },
      { nativeEvent: { type: "result", code: "error" } },
      { nativeEvent: { type: "result", code: "error" } },
      { nativeEvent: { type: "result", code: "error" } },
    ]);
  });
});
