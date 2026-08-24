import { useMemo, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import { getSecureKeypadView, type SecureKeypadProps } from "@secure-keypad/react-native";
import { DEFAULT_THEME, type KeypadLayout } from "@secure-keypad/contracts";

const SecureKeypadView = getSecureKeypadView();

const brandedNumericLayout: KeypadLayout = {
  schemaVersion: 1,
  id: "example-numeric",
  locale: "en",
  randomizeInputKeys: true,
  rows: [
    [
      { id: "digit-1", label: "1", role: "input", accessibilityLabel: "One" },
      { id: "digit-2", label: "2", role: "input", accessibilityLabel: "Two" },
      { id: "digit-3", label: "3", role: "input", accessibilityLabel: "Three" },
    ],
    [
      { id: "digit-4", label: "4", role: "input", accessibilityLabel: "Four" },
      { id: "digit-5", label: "5", role: "input", accessibilityLabel: "Five" },
      { id: "digit-6", label: "6", role: "input", accessibilityLabel: "Six" },
    ],
    [
      { id: "digit-7", label: "7", role: "input", accessibilityLabel: "Seven" },
      { id: "digit-8", label: "8", role: "input", accessibilityLabel: "Eight" },
      { id: "digit-9", label: "9", role: "input", accessibilityLabel: "Nine" },
    ],
    [
      { id: "clear", label: "Clear", role: "clear" },
      { id: "digit-0", label: "0", role: "input", accessibilityLabel: "Zero" },
      { id: "backspace", label: "Delete", role: "backspace" },
    ],
    [
      { id: "cancel", label: "Cancel", role: "cancel" },
      { id: "submit", label: "Continue", role: "submit" },
    ],
  ],
  slots: { header: true, display: true, footer: true, error: true },
};

const brandedTheme = {
  ...DEFAULT_THEME,
  colors: {
    ...DEFAULT_THEME.colors,
    background: "#071A2B",
    keyBackground: "#0E7490",
    keyPressedBackground: "#22D3EE",
  },
};

export default function App() {
  const [length, setLength] = useState(0);
  const [result, setResult] = useState("idle");
  const props = useMemo<SecureKeypadProps>(() => ({
    layout: brandedNumericLayout,
    theme: brandedTheme,
    inputPolicy: "numeric",
    maxTokens: 8,
    timeoutMs: 60_000,
    onMaskedStateChange: ({ nativeEvent }) => {
      setLength(nativeEvent.length);
    },
    onResult: ({ nativeEvent }) => {
      setResult(nativeEvent.code);
    },
  }), []);

  return (
    <View style={styles.screen}>
      <Text style={styles.title}>Secure Native example</Text>
      <Text accessibilityRole="text" style={styles.status}>
        {result} · {length} masked characters
      </Text>
      <SecureKeypadView style={styles.keypad} {...props} />
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#071A2B", padding: 24 },
  title: { color: "#FFFFFF", fontSize: 22, fontWeight: "700", marginBottom: 8 },
  status: { color: "#BAE6FD", fontSize: 14, marginBottom: 16 },
  keypad: { minHeight: 360 },
});
