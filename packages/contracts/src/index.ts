export const CONTRACT_VERSION = 1 as const;
/** Maximum masked length that any framework adapter may render or forward. */
export const MAX_RENDERED_LENGTH = 4_096 as const;
/** Maximum UTF-8 byte length of one public key label. */
export const MAX_KEY_LABEL_BYTES = 16 as const;
/** Maximum UTF-8 byte length of one public accessibility label. */
export const MAX_ACCESSIBILITY_LABEL_BYTES = 80 as const;

export const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const LOCALE_PATTERN = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/;
export const COLOR_PATTERN = /^#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?$/;

export type KeyRole = "input" | "backspace" | "submit" | "clear" | "cancel" | "spacer";
/** Native-only input policy. Browser custom keypads are intentionally excluded. */
export type InputPolicy = "numeric" | "ascii" | "hangul";
/** Mobile renderer mode. Secure Native remains the default and highest-assurance mode. */
export type KeypadMode = "secure-native" | "headless-host";
export type LayoutDirection = "ltr" | "rtl";

export interface KeySpec {
  readonly id: string;
  readonly label?: string;
  readonly icon?: string;
  readonly role: KeyRole;
  readonly accessibilityLabel?: string;
  readonly testId?: string;
}

export interface KeypadLayout {
  readonly schemaVersion: 1;
  readonly id?: string;
  readonly locale?: string;
  readonly direction?: LayoutDirection;
  readonly rows: readonly (readonly KeySpec[])[];
  readonly slots?: {
    readonly header?: boolean;
    readonly display?: boolean;
    readonly footer?: boolean;
    readonly error?: boolean;
  };
}

export interface ThemeTokens {
  readonly schemaVersion: 1;
  readonly colors: {
    readonly background: string;
    readonly keyBackground: string;
    readonly keyForeground: string;
    readonly keyPressedBackground: string;
    readonly keyDisabledBackground: string;
    readonly error: string;
  };
  readonly metrics: {
    readonly keyHeight: number;
    readonly keyGap: number;
    readonly keyRadius: number;
    readonly contentPadding: number;
  };
  readonly typography: {
    readonly keyFontSize: number;
    readonly keyFontWeight: "400" | "500" | "600" | "700";
  };
  readonly animation?: {
    readonly pressDurationMs?: number;
    readonly maskRevealDurationMs?: number;
  };
  readonly feedback?: {
    readonly haptic?: "none" | "light" | "medium" | "heavy";
    readonly sound?: "none" | "click";
  };
}

export type DisplayState = "empty" | "masked" | "submitted" | "cancelled";

const DISPLAY_STATES: readonly DisplayState[] = ["empty", "masked", "submitted", "cancelled"];

export interface MaskedState {
  readonly length: number;
  readonly displayState: DisplayState;
}

/** Validates native masked metadata without echoing untrusted event values. */
export function validateMaskedState(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, errors: ["masked state must be an object"] };
  }
  if (!hasOnlyKeys(value, ["length", "displayState"])) {
    errors.push("masked state contains an unsupported field");
  }
  if (!isBoundedInteger(value.length, 0, MAX_RENDERED_LENGTH)) {
    errors.push("masked state.length is invalid");
  }
  if (typeof value.displayState !== "string" || !DISPLAY_STATES.includes(value.displayState as DisplayState)) {
    errors.push("masked state.displayState is invalid");
  }
  return { valid: errors.length === 0, errors };
}

export type SecureKeypadEvent =
  | { readonly type: "state"; readonly state: MaskedState }
  | { readonly type: "result"; readonly code: "success" | "cancelled" | "invalid" | "locked" | "error" };

/** Validates a framework result event without accepting arbitrary payload fields. */
export function validateResultEvent(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, errors: ["result event must be an object"] };
  }
  if (!hasOnlyKeys(value, ["type", "code"])) {
    errors.push("result event contains an unsupported field");
  }
  if (value.type !== "result") errors.push("result event.type is invalid");
  if (
    value.code !== "success" &&
    value.code !== "cancelled" &&
    value.code !== "invalid" &&
    value.code !== "locked" &&
    value.code !== "error"
  ) {
    errors.push("result event.code is invalid");
  }
  return { valid: errors.length === 0, errors };
}

/** Safe starting layout for a numeric PIN keypad. */
export const DEFAULT_NUMERIC_LAYOUT = {
  schemaVersion: 1,
  id: "default-numeric",
  locale: "en",
  direction: "ltr",
  rows: [
    [
      { id: "digit-1", label: "1", role: "input" },
      { id: "digit-2", label: "2", role: "input" },
      { id: "digit-3", label: "3", role: "input" },
    ],
    [
      { id: "digit-4", label: "4", role: "input" },
      { id: "digit-5", label: "5", role: "input" },
      { id: "digit-6", label: "6", role: "input" },
    ],
    [
      { id: "digit-7", label: "7", role: "input" },
      { id: "digit-8", label: "8", role: "input" },
      { id: "digit-9", label: "9", role: "input" },
    ],
    [
      { id: "clear", label: "Clear", role: "clear" },
      { id: "digit-0", label: "0", role: "input" },
      { id: "backspace", label: "Delete", role: "backspace" },
    ],
    [
      { id: "cancel", label: "Cancel", role: "cancel" },
      { id: "submit", label: "Continue", role: "submit" },
    ],
  ],
  slots: { header: true, display: true, footer: true, error: true },
} as const satisfies KeypadLayout;

/** Safe starting layout demonstrating structured Hangul composition. */
export const DEFAULT_HANGUL_LAYOUT = {
  schemaVersion: 1,
  id: "default-hangul-example",
  locale: "ko",
  direction: "ltr",
  rows: [
    [
      { id: "jamo-giyeok", label: "ㄱ", role: "input" },
      { id: "jamo-nieun", label: "ㄴ", role: "input" },
      { id: "jamo-digeut", label: "ㄷ", role: "input" },
    ],
    [
      { id: "vowel-a", label: "ㅏ", role: "input" },
      { id: "vowel-eo", label: "ㅓ", role: "input" },
      { id: "vowel-o", label: "ㅗ", role: "input" },
    ],
    [
      { id: "tail-giyeok", label: "받침 ㄱ", role: "input" },
      { id: "tail-nieun", label: "받침 ㄴ", role: "input" },
      { id: "tail-mieum", label: "받침 ㅁ", role: "input" },
    ],
    [
      { id: "clear", label: "초기화", role: "clear" },
      { id: "backspace", label: "삭제", role: "backspace" },
      { id: "cancel", label: "취소", role: "cancel" },
      { id: "submit", label: "확인", role: "submit" },
    ],
  ],
  slots: { header: true, display: true, footer: true, error: true },
} as const satisfies KeypadLayout;

/** Neutral, accessible baseline theme for native renderers. */
export const DEFAULT_THEME = {
  schemaVersion: 1,
  colors: {
    background: "#101114",
    keyBackground: "#23262D",
    keyForeground: "#FFFFFF",
    keyPressedBackground: "#3B82F6",
    keyDisabledBackground: "#4B5563",
    error: "#F87171",
  },
  metrics: {
    keyHeight: 56,
    keyGap: 8,
    keyRadius: 12,
    contentPadding: 16,
  },
  typography: {
    keyFontSize: 24,
    keyFontWeight: "600",
  },
  animation: { pressDurationMs: 80, maskRevealDurationMs: 0 },
  feedback: { haptic: "light", sound: "none" },
} as const satisfies ThemeTokens;

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

const KEY_ROLES: readonly KeyRole[] = ["input", "backspace", "submit", "clear", "cancel", "spacer"];
const FONT_WEIGHTS: readonly ThemeTokens["typography"]["keyFontWeight"][] = ["400", "500", "600", "700"];
const HANGUL_INPUT_KEY_IDS: ReadonlySet<string> = new Set([
  "jamo-giyeok",
  "jamo-ssang-giyeok",
  "jamo-nieun",
  "jamo-digeut",
  "jamo-ssang-digeut",
  "jamo-rieul",
  "jamo-mieum",
  "jamo-bieub",
  "jamo-ssang-bieub",
  "jamo-siot",
  "jamo-ssang-siot",
  "jamo-ieung",
  "jamo-jieut",
  "jamo-ssang-jieut",
  "jamo-chieut",
  "jamo-kieuk",
  "jamo-tieut",
  "jamo-pieup",
  "jamo-hieuh",
  "vowel-a",
  "vowel-ae",
  "vowel-ya",
  "vowel-yae",
  "vowel-eo",
  "vowel-e",
  "vowel-yeo",
  "vowel-ye",
  "vowel-o",
  "vowel-wa",
  "vowel-wae",
  "vowel-oe",
  "vowel-yo",
  "vowel-u",
  "vowel-wo",
  "vowel-we",
  "vowel-wi",
  "vowel-yu",
  "vowel-eu",
  "vowel-ui",
  "vowel-i",
  "tail-giyeok",
  "tail-ssang-giyeok",
  "tail-giyeok-siot",
  "tail-nieun",
  "tail-nieun-jieut",
  "tail-nieun-hieuh",
  "tail-digeut",
  "tail-rieul",
  "tail-rieul-giyeok",
  "tail-rieul-mieum",
  "tail-rieul-bieub",
  "tail-rieul-siot",
  "tail-rieul-tieut",
  "tail-rieul-pieup",
  "tail-rieul-hieuh",
  "tail-mieum",
  "tail-bieub",
  "tail-bieub-siot",
  "tail-siot",
  "tail-ssang-siot",
  "tail-ieung",
  "tail-jieut",
  "tail-chieut",
  "tail-kieuk",
  "tail-tieut",
  "tail-pieup",
  "tail-hieuh",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isBoundedNumber(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= minimum && value <= maximum;
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isInteger(value) && isBoundedNumber(value, minimum, maximum);
}

function utf8ByteLength(value: string): number {
  let length = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0) as number;
    length += codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
  }
  return length;
}

function validateKey(value: unknown, errors: string[], path: string): value is KeySpec {
  if (!isRecord(value)) {
    errors.push(`${path} must be an object`);
    return false;
  }
  if (!hasOnlyKeys(value, ["id", "label", "icon", "role", "accessibilityLabel", "testId"])) {
    errors.push(`${path} contains an unsupported field`);
  }
  if (typeof value.id !== "string" || !KEY_ID_PATTERN.test(value.id)) {
    errors.push(`${path}.id is invalid`);
  }
  if (
    value.label !== undefined &&
    (typeof value.label !== "string" || utf8ByteLength(value.label) > MAX_KEY_LABEL_BYTES)
  ) {
    errors.push(`${path}.label is invalid`);
  }
  if (value.icon !== undefined && (typeof value.icon !== "string" || !KEY_ID_PATTERN.test(value.icon))) {
    errors.push(`${path}.icon is invalid`);
  }
  if (typeof value.role !== "string" || !KEY_ROLES.includes(value.role as KeyRole)) {
    errors.push(`${path}.role is invalid`);
  }
  if (
    value.accessibilityLabel !== undefined &&
    (typeof value.accessibilityLabel !== "string" ||
      utf8ByteLength(value.accessibilityLabel) > MAX_ACCESSIBILITY_LABEL_BYTES)
  ) {
    errors.push(`${path}.accessibilityLabel is invalid`);
  }
  if (value.testId !== undefined && (typeof value.testId !== "string" || !KEY_ID_PATTERN.test(value.testId))) {
    errors.push(`${path}.testId is invalid`);
  }
  return errors.length === 0;
}

/** Validates public layout data without echoing field values in errors. */
export function validateLayout(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, errors: ["layout must be an object"] };
  }
  if (!hasOnlyKeys(value, ["schemaVersion", "id", "locale", "direction", "rows", "slots"])) {
    errors.push("layout contains an unsupported field");
  }
  if (value.schemaVersion !== 1) errors.push("layout.schemaVersion is unsupported");
  if (value.id !== undefined && (typeof value.id !== "string" || !KEY_ID_PATTERN.test(value.id))) {
    errors.push("layout.id is invalid");
  }
  if (value.locale !== undefined && (typeof value.locale !== "string" || !LOCALE_PATTERN.test(value.locale))) {
    errors.push("layout.locale is invalid");
  }
  if (value.direction !== undefined && value.direction !== "ltr" && value.direction !== "rtl") {
    errors.push("layout.direction is invalid");
  }
  if (!Array.isArray(value.rows) || value.rows.length < 1 || value.rows.length > 16) {
    errors.push("layout.rows is invalid");
  } else {
    const keyIds = new Set<string>();
    value.rows.forEach((row, rowIndex) => {
      if (!Array.isArray(row) || row.length < 1 || row.length > 32) {
        errors.push(`layout.rows[${rowIndex}] is invalid`);
        return;
      }
      row.forEach((key, keyIndex) => {
        const path = `layout.rows[${rowIndex}][${keyIndex}]`;
        validateKey(key, errors, path);
        if (isRecord(key) && typeof key.id === "string") {
          if (keyIds.has(key.id)) errors.push(`${path}.id is duplicated`);
          keyIds.add(key.id);
        }
      });
    });
  }
  if (value.slots !== undefined) {
    if (!isRecord(value.slots) || !hasOnlyKeys(value.slots, ["header", "display", "footer", "error"])) {
      errors.push("layout.slots is invalid");
    } else if (Object.values(value.slots).some((slot) => typeof slot !== "boolean")) {
      errors.push("layout.slots values are invalid");
    }
  }
  return { valid: errors.length === 0, errors };
}

/** Returns whether an input-role key ID is canonical for a native policy. */
export function isCanonicalInputKeyId(keyId: string, policy: InputPolicy): boolean {
  if (policy === "numeric") return /^digit-[0-9]$/.test(keyId);
  if (policy === "ascii") {
    if (!/^ascii-[0-9a-f]{2}$/.test(keyId)) return false;
    const codePoint = Number.parseInt(keyId.slice("ascii-".length), 16);
    return codePoint >= 0x20 && codePoint <= 0x7e;
  }
  return HANGUL_INPUT_KEY_IDS.has(keyId);
}

/** Validates a layout and its input-role IDs against the selected native policy. */
export function validateLayoutForPolicy(value: unknown, policy: InputPolicy): ValidationResult {
  const result = validateLayout(value);
  const errors = [...result.errors];
  if (isRecord(value) && Array.isArray(value.rows)) {
    value.rows.forEach((row, rowIndex) => {
      if (!Array.isArray(row)) return;
      row.forEach((key, keyIndex) => {
        if (
          isRecord(key) &&
          key.role === "input" &&
          typeof key.id === "string" &&
          !isCanonicalInputKeyId(key.id, policy)
        ) {
          errors.push(`layout.rows[${rowIndex}][${keyIndex}].id is invalid for input policy`);
        }
      });
    });
  }
  return { valid: errors.length === 0, errors };
}

/** Validates public theme data without echoing field values in errors. */
export function validateTheme(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, errors: ["theme must be an object"] };
  }
  if (!hasOnlyKeys(value, ["schemaVersion", "colors", "metrics", "typography", "animation", "feedback"])) {
    errors.push("theme contains an unsupported field");
  }
  if (value.schemaVersion !== 1) errors.push("theme.schemaVersion is unsupported");

  const colorKeys = ["background", "keyBackground", "keyForeground", "keyPressedBackground", "keyDisabledBackground", "error"] as const;
  if (!isRecord(value.colors) || !hasOnlyKeys(value.colors, colorKeys)) {
    errors.push("theme.colors is invalid");
  } else {
    const colors = value.colors;
    colorKeys.forEach((key) => {
      if (typeof colors[key] !== "string" || !COLOR_PATTERN.test(colors[key] as string)) {
        errors.push(`theme.colors.${key} is invalid`);
      }
    });
  }

  const metricKeys = ["keyHeight", "keyGap", "keyRadius", "contentPadding"] as const;
  if (!isRecord(value.metrics) || !hasOnlyKeys(value.metrics, metricKeys)) {
    errors.push("theme.metrics is invalid");
  } else {
    if (!isBoundedNumber(value.metrics.keyHeight, 32, 160)) errors.push("theme.metrics.keyHeight is invalid");
    if (!isBoundedNumber(value.metrics.keyGap, 0, 48)) errors.push("theme.metrics.keyGap is invalid");
    if (!isBoundedNumber(value.metrics.keyRadius, 0, 80)) errors.push("theme.metrics.keyRadius is invalid");
    if (!isBoundedNumber(value.metrics.contentPadding, 0, 80)) errors.push("theme.metrics.contentPadding is invalid");
  }

  if (!isRecord(value.typography) || !hasOnlyKeys(value.typography, ["keyFontSize", "keyFontWeight"])) {
    errors.push("theme.typography is invalid");
  } else {
    if (!isBoundedNumber(value.typography.keyFontSize, 10, 72)) errors.push("theme.typography.keyFontSize is invalid");
    if (!FONT_WEIGHTS.includes(value.typography.keyFontWeight as ThemeTokens["typography"]["keyFontWeight"])) {
      errors.push("theme.typography.keyFontWeight is invalid");
    }
  }

  if (value.animation !== undefined) {
    if (!isRecord(value.animation) || !hasOnlyKeys(value.animation, ["pressDurationMs", "maskRevealDurationMs"])) {
      errors.push("theme.animation is invalid");
    } else {
      if (value.animation.pressDurationMs !== undefined && !isBoundedInteger(value.animation.pressDurationMs, 0, 500)) {
        errors.push("theme.animation.pressDurationMs is invalid");
      }
      if (value.animation.maskRevealDurationMs !== undefined && !isBoundedInteger(value.animation.maskRevealDurationMs, 0, 2000)) {
        errors.push("theme.animation.maskRevealDurationMs is invalid");
      }
    }
  }

  if (value.feedback !== undefined) {
    if (!isRecord(value.feedback) || !hasOnlyKeys(value.feedback, ["haptic", "sound"])) {
      errors.push("theme.feedback is invalid");
    } else {
      if (value.feedback.haptic !== undefined && !["none", "light", "medium", "heavy"].includes(String(value.feedback.haptic))) {
        errors.push("theme.feedback.haptic is invalid");
      }
      if (value.feedback.sound !== undefined && !["none", "click"].includes(String(value.feedback.sound))) {
        errors.push("theme.feedback.sound is invalid");
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
