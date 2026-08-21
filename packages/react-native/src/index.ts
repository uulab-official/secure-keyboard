import type { HostComponent, StyleProp, ViewStyle } from "react-native";
import {
  KEY_ID_PATTERN,
  MAX_RENDERED_LENGTH,
  validateLayout,
  validateMaskedState,
  validateResultEvent as validateContractResultEvent,
  validateTheme,
  type KeypadLayout,
  type KeypadMode,
  type InputPolicy as ContractInputPolicy,
  type MaskedState,
  type SecureKeypadEvent,
  type ThemeTokens,
  type ValidationResult,
} from "@secure-keypad/contracts";

/** The native view-manager name registered by the platform adapters. */
export const SECURE_KEYPAD_NATIVE_VIEW_NAME = "SecureKeypadView" as const;

export type InputPolicy = ContractInputPolicy;
export type SecureKeypadMode = KeypadMode;

/** A public host command; it never contains or derives an input character. */
export interface HeadlessKeyPress {
  readonly token: number;
  readonly keyId: string;
}

export interface SecureKeypadProps {
  /** React Native presentation style; it never crosses into the secret/session contract. */
  readonly style?: StyleProp<ViewStyle>;
  /** Versioned, serializable layout data. It never contains the entered secret. */
  readonly layout: KeypadLayout;
  /** Versioned, serializable visual tokens. */
  readonly theme: ThemeTokens;
  /** Selects the native/core input policy. Defaults to numeric. */
  readonly inputPolicy?: InputPolicy;
  /** Selects the renderer. Secure Native is the default; headless-host is lower assurance. */
  readonly mode?: SecureKeypadMode;
  /** Required true acknowledgement before the lower-assurance host renderer can run. */
  readonly acknowledgeLowerAssurance?: boolean;
  /** Upper bound for the number of accepted tokens. */
  readonly maxTokens?: number;
  /** Inactivity timeout in milliseconds. */
  readonly timeoutMs?: number;
  /** Monotonic, non-secret command token; changing it cancels the native session. */
  readonly cancelRequest?: number;
  /** Monotonic public host command. Only accepted in acknowledged headless-host mode. */
  readonly headlessKeyPress?: HeadlessKeyPress;
  /** Receives masked length/state only. */
  readonly onMaskedStateChange?: (event: MaskedStateEvent) => void;
  /** Receives a result code only; no submitted value is surfaced to JavaScript. */
  readonly onResult?: (event: ResultEvent) => void;
}

/** Native-facing props after validation and removal of framework callbacks. */
export type SecureKeypadNativeProps = Omit<SecureKeypadProps, "onMaskedStateChange" | "onResult">;

export interface MaskedStateEvent {
  readonly nativeEvent: MaskedState;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

/** Validates the native event payload before an application invokes its callback. */
export function validateMaskedStateEvent(value: unknown): ValidationResult {
  if (!isRecord(value)) return { valid: false, errors: ["masked state event must be an object"] };
  if (!hasExactKeys(value, ["nativeEvent"])) {
    return { valid: false, errors: ["masked state event contains an unsupported field"] };
  }
  return validateMaskedState(value.nativeEvent);
}

/** Validates the native result event before an application invokes its callback. */
export function validateResultEvent(value: unknown): ValidationResult {
  if (!isRecord(value)) return { valid: false, errors: ["result event must be an object"] };
  if (!hasExactKeys(value, ["nativeEvent"])) {
    return { valid: false, errors: ["result event contains an unsupported field"] };
  }
  return validateContractResultEvent(value.nativeEvent);
}

export interface ResultEvent {
  readonly nativeEvent: Extract<SecureKeypadEvent, { readonly type: "result" }>;
}

export type SecureKeypadNativeComponent = HostComponent<SecureKeypadProps>;

/** Creates fail-closed callbacks for native bridge events. */
export function createSecureKeypadEventHandlers(
  onMaskedStateChange: SecureKeypadProps["onMaskedStateChange"],
  onResult: SecureKeypadProps["onResult"],
): Pick<SecureKeypadProps, "onMaskedStateChange" | "onResult"> {
  const emitGenericError = () => {
    onResult?.({ nativeEvent: { type: "result", code: "error" } });
  };
  return {
    onMaskedStateChange: (event: MaskedStateEvent) => {
      if (!validateMaskedStateEvent(event).valid) {
        emitGenericError();
        return;
      }
      onMaskedStateChange?.(event);
    },
    onResult: (event: ResultEvent) => {
      if (!validateResultEvent(event).valid) {
        emitGenericError();
        return;
      }
      onResult?.(event);
    },
  };
}

const ALLOWED_PROP_NAMES = [
  "style",
  "layout",
  "theme",
  "inputPolicy",
  "mode",
  "acknowledgeLowerAssurance",
  "maxTokens",
  "timeoutMs",
  "cancelRequest",
  "headlessKeyPress",
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

function validateHeadlessKeyPress(value: unknown): value is HeadlessKeyPress {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return (
    keys.length === 2 &&
    keys.every((key) => key === "token" || key === "keyId") &&
    isBoundedInteger(value.token, 0, Number.MAX_SAFE_INTEGER) &&
    typeof value.keyId === "string" &&
    KEY_ID_PATTERN.test(value.keyId)
  );
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
  const mode = value.mode ?? "secure-native";
  if (mode !== "secure-native" && mode !== "headless-host") {
    errors.push("props.mode is invalid");
  }
  if (value.acknowledgeLowerAssurance !== undefined && typeof value.acknowledgeLowerAssurance !== "boolean") {
    errors.push("props.acknowledgeLowerAssurance is invalid");
  }
  if (mode === "headless-host" && value.acknowledgeLowerAssurance !== true) {
    errors.push("headless-host mode requires explicit lower-assurance acknowledgement");
  }
  if (mode === "secure-native" && value.acknowledgeLowerAssurance === true) {
    errors.push("lower-assurance acknowledgement requires headless-host mode");
  }
  if (value.headlessKeyPress !== undefined && !validateHeadlessKeyPress(value.headlessKeyPress)) {
    errors.push("props.headlessKeyPress is invalid");
  }
  if (value.headlessKeyPress !== undefined && mode !== "headless-host") {
    errors.push("headlessKeyPress requires headless-host mode");
  }
  if (value.maxTokens !== undefined && !isBoundedInteger(value.maxTokens, 1, MAX_RENDERED_LENGTH)) {
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
 * Validates and allowlists the props that may cross into the native view.
 * Framework callbacks and arbitrary host props never enter the native map.
 */
export function getSecureKeypadNativeProps(props: SecureKeypadProps): SecureKeypadNativeProps {
  assertSecureKeypadProps(props);
  return {
    layout: props.layout,
    theme: props.theme,
    ...(props.style === undefined ? {} : { style: props.style }),
    ...(props.inputPolicy === undefined ? {} : { inputPolicy: props.inputPolicy }),
    ...(props.mode === undefined ? {} : { mode: props.mode }),
    ...(props.acknowledgeLowerAssurance === undefined
      ? {}
      : { acknowledgeLowerAssurance: props.acknowledgeLowerAssurance }),
    ...(props.maxTokens === undefined ? {} : { maxTokens: props.maxTokens }),
    ...(props.timeoutMs === undefined ? {} : { timeoutMs: props.timeoutMs }),
    ...(props.cancelRequest === undefined ? {} : { cancelRequest: props.cancelRequest }),
    ...(props.headlessKeyPress === undefined ? {} : { headlessKeyPress: props.headlessKeyPress }),
  };
}

/** Lazily resolves the unwrapped native component for low-level host integration. */
export function getSecureKeypadNativeView(): SecureKeypadNativeComponent {
  const reactNative = require("react-native") as typeof import("react-native");
  return reactNative.requireNativeComponent<SecureKeypadProps>(SECURE_KEYPAD_NATIVE_VIEW_NAME);
}

let secureKeypadComponent: SecureKeypadNativeComponent | undefined;

/**
 * Lazily resolves the native component behind a fail-closed event boundary.
 * Malformed masked state or result payloads never reach the application callback;
 * they produce only a canonical `error` result.
 */
export function getSecureKeypadView(): SecureKeypadNativeComponent {
  if (secureKeypadComponent !== undefined) return secureKeypadComponent;
  const NativeView = getSecureKeypadNativeView();
  const react = require("react") as {
    createElement: (type: SecureKeypadNativeComponent, props: Record<string, unknown>) => unknown;
    forwardRef: (render: (props: SecureKeypadProps, ref: unknown) => unknown) => SecureKeypadNativeComponent;
  };
  secureKeypadComponent = react.forwardRef((props, ref) => {
    const { onMaskedStateChange, onResult } = props;
    let nativeProps: SecureKeypadNativeProps;
    try {
      nativeProps = getSecureKeypadNativeProps(props);
    } catch {
      if (typeof onResult === "function") {
        onResult({ nativeEvent: { type: "result", code: "error" } });
      }
      return null;
    }
    const eventHandlers = createSecureKeypadEventHandlers(onMaskedStateChange, onResult);
    return react.createElement(NativeView, {
      ...nativeProps,
      ref,
      ...eventHandlers,
    });
  });
  return secureKeypadComponent;
}
