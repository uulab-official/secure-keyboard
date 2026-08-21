# Customization examples

All examples below send only public layout/theme/policy data into the native
view. No example stores or reads the entered value.

## Numeric PIN with a branded layout (React Native)

```tsx
import { useMemo } from "react";
import { getSecureKeypadView } from "@secure-keypad/react-native";
import { DEFAULT_THEME, type KeypadLayout } from "@secure-keypad/contracts";

const SecureKeypadView = getSecureKeypadView();

const brandedNumericLayout: KeypadLayout = {
  schemaVersion: 1,
  id: "acme-pin",
  locale: "en",
  rows: [
    [
      { id: "digit-1", label: "1", role: "input", accessibilityLabel: "One" },
      { id: "digit-2", label: "2", role: "input", accessibilityLabel: "Two" },
      { id: "digit-3", label: "3", role: "input", accessibilityLabel: "Three" },
    ],
    [
      { id: "clear", label: "Reset", role: "clear" },
      { id: "digit-0", label: "0", role: "input", accessibilityLabel: "Zero" },
      { id: "backspace", label: "Delete", role: "backspace" },
    ],
    [{ id: "submit", label: "Continue", role: "submit" }],
  ],
  slots: { header: true, display: true, footer: true, error: true },
};

export function BrandedPin() {
  const theme = useMemo(() => ({
    ...DEFAULT_THEME,
    colors: {
      ...DEFAULT_THEME.colors,
      background: "#071A2B",
      keyBackground: "#0E7490",
      keyPressedBackground: "#22D3EE",
    },
  }), []);
  return <SecureKeypadView layout={brandedNumericLayout} theme={theme} maxTokens={6} />;
}
```

## Structured Hangul password (Flutter)

```dart
final hangul = KeypadLayout(
  schemaVersion: 1,
  id: 'hangul-login',
  locale: 'ko',
  rows: <List<KeySpec>>[
    <KeySpec>[
      KeySpec(id: 'jamo-giyeok', label: 'ㄱ', role: KeyRole.input),
      KeySpec(id: 'jamo-nieun', label: 'ㄴ', role: KeyRole.input),
      KeySpec(id: 'jamo-digeut', label: 'ㄷ', role: KeyRole.input),
    ],
    <KeySpec>[
      KeySpec(id: 'vowel-a', label: 'ㅏ', role: KeyRole.input),
      KeySpec(id: 'vowel-eo', label: 'ㅓ', role: KeyRole.input),
      KeySpec(id: 'vowel-o', label: 'ㅗ', role: KeyRole.input),
    ],
    <KeySpec>[
      KeySpec(id: 'clear', label: '초기화', role: KeyRole.clear),
      KeySpec(id: 'backspace', label: '삭제', role: KeyRole.backspace),
      KeySpec(id: 'submit', label: '확인', role: KeyRole.submit),
    ],
  ],
);

SecureKeypad(
  configuration: SecureKeypadConfiguration(
    layout: hangul,
    theme: SecureKeypadTheme.defaultTheme(),
    inputPolicy: InputPolicy.hangul,
    maxTokens: 32,
    timeoutMs: 120000,
    onMaskedStateChanged: (state) {
      // length/displayState only; never a submitted string.
    },
  ),
);
```

The native parser rejects unknown fields, duplicate IDs, oversized labels, and
unsupported policy values before the session is created. Theme values can be
changed freely within the bounded schema; the input buffer and native
submission ownership do not change with the theme.
