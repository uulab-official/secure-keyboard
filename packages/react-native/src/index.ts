import type { HostComponent } from "react-native";
import {
  validateLayout,
  validateTheme,
  type KeypadLayout,
  type InputPolicy as ContractInputPolicy,
  type MaskedState,
  type SecureKeypadEvent,
  type ThemeTokens,
  type ValidationResult,
} from "@secure-keypad/contracts";

/** The native view-manager name registered by the platform adapters. */
export const SECURE_KEYPAD_NATIVE_VIEW_NAME = "SecureKeypadView" as const;

export type InputPolicy = ContractInputPolicy;

export interface SecureKeypadProps {
  /** Versioned, serializable layout data. It never contains the entered secret. */
  readonly layout: KeypadLayout;
  /** Versioned, serializable visual tokens. */
  readonly theme: ThemeTokens;
  /** Selects the native/core input policy. Defaults to numeric. */
  readonly inputPolicy?: InputPolicy;
  /** Upper bound for the number of accepted tokens. */
  readonly maxTokens?: number;
  /** Inactivity timeout in milliseconds. */
  readonly timeoutMs?: number;
  /** Monotonic, non-secret command token; changing it cancels the native session. */
  readonly cancelRequest?: number;
  /** Receives masked length/state only. */
  readonly onMaskedStateChange?: (event: MaskedStateEvent) => void;
  /** Receives a result code only; no submitted value is surfaced to JavaScript. */
  readonly onResult?: (event: ResultEvent) => void;
}

export interface MaskedStateEvent {
  readonly nativeEvent: MaskedState;
}

export interface ResultEvent {
  readonly nativeEvent: Extract<SecureKeypadEvent, { readonly type: "result" }>;
}

export type SecureKeypadNativeComponent = HostComponent<SecureKeypadProps>;

const ALLOWED_PROP_NAMES = [
  "layout",
  "theme",
  "inputPolicy",
  "maxTokens",
  "timeoutMs",
  "cancelRequest",
  "onMaskedStateChange",
  "onResult",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyAllowedProps(value: Record<string, unknown>): boolean {
  return Object.keys(value).every((key) =>
    (ALLOWED_PROP_NAMES as readonly string[]).includes(key),
  );
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isInteger(value) && typeof value === "number" && value >= minimum && value <= maximum;
}

/**
 * Validates the JavaScript-facing boundary without echoing arbitrary prop values.
 * In particular, secret-bearing props such as `value`, `password`, or `secret` are
 * rejected as unsupported and are never copied into an error message.
 */
export function validateSecureKeypadProps(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, errors: ["props must be an object"] };
  }

  if (!hasOnlyAllowedProps(value)) {
    errors.push("props contains an unsupported field");
  }

  const layoutResult = validateLayout(value.layout);
  if (!layoutResult.valid) errors.push(...layoutResult.errors);

  const themeResult = validateTheme(value.theme);
  if (!themeResult.valid) errors.push(...themeResult.errors);

  if (
    value.inputPolicy !== undefined &&
    value.inputPolicy !== "numeric" &&
    value.inputPolicy !== "ascii" &&
    value.inputPolicy !== "hangul"
  ) {
    errors.push("props.inputPolicy is invalid");
  }
  if (value.maxTokens !== undefined && !isBoundedInteger(value.maxTokens, 1, 4096)) {
    errors.push("props.maxTokens is invalid");
  }
  if (value.timeoutMs !== undefined && !isBoundedInteger(value.timeoutMs, 1, 86_400_000)) {
    errors.push("props.timeoutMs is invalid");
  }
  if (
    value.cancelRequest !== undefined &&
    (typeof value.cancelRequest !== "number" ||
      !Number.isSafeInteger(value.cancelRequest) ||
      value.cancelRequest < 0)
  ) {
    errors.push("props.cancelRequest is invalid");
  }
  if (value.onMaskedStateChange !== undefined && typeof value.onMaskedStateChange !== "function") {
    errors.push("props.onMaskedStateChange is invalid");
  }
  if (value.onResult !== undefined && typeof value.onResult !== "function") {
    errors.push("props.onResult is invalid");
  }

  return { valid: errors.length === 0, errors };
}

/** Throws a generic validation error suitable for a host-side configuration boundary. */
export function assertSecureKeypadProps(value: unknown): asserts value is SecureKeypadProps {
  const result = validateSecureKeypadProps(value);
  if (!result.valid) throw new TypeError(result.errors.join("; "));
}

/**
 * Lazily resolves the native component so importing this package remains safe in
 * Node-based tooling and web bundles. The native view must be registered by the
 * iOS/Android adapter; Expo Go and a browser are not supported runtimes.
 */
export function getSecureKeypadView(): SecureKeypadNativeComponent {
  const reactNative = require("react-native") as typeof import("react-native");
  return reactNative.requireNativeComponent<SecureKeypadProps>(SECURE_KEYPAD_NATIVE_VIEW_NAME);
}
