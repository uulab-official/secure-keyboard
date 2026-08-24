# Secure Keypad host examples

These are copyable host-app entrypoints for the supported public integration
surfaces. They deliberately render only public lifecycle metadata; native/core
code owns key handling, composition, and authentication handoff.

| Example | Boundary | Policy | Notes |
| --- | --- | --- | --- |
| [`react-native/App.tsx`](./react-native/App.tsx) | Secure Native view | Numeric | Custom branded layout and masked-state/result callbacks |
| [`flutter/lib/main.dart`](./flutter/lib/main.dart) | Secure Native PlatformView | Hangul | Branded native layout and public status text |
| [`web/src/passkey.ts`](./web/src/passkey.ts) | WebAuthn | Passkey | Controller lifecycle UI and server ceremony handoff |

## Run in a host application

Copy the relevant entrypoint into an existing host project and install the
matching package versions from the same SDK commit. React Native requires a
Development Build or a native build; Expo Go cannot load the native security
boundary. Flutter requires a supported iOS/Android host and the verified native
FFI artifacts. The web example requires HTTPS (or localhost) and a server that
returns the bounded WebAuthn JSON options described by the WebAuthn route
contract.

The examples do not include a fake authentication server and do not place
credentials in logs, browser storage, framework state, or callback payloads.
Install a real server integration using the Rust WebAuthn/OPAQUE reference
contracts before connecting a production account flow.

For printable-ASCII layouts, RTL direction, key randomization, accessibility,
and additional branded theme variants, see
[`docs/CUSTOMIZATION-EXAMPLES.md`](../docs/CUSTOMIZATION-EXAMPLES.md).

## Production integration rules

- Keep Secure Native mode as the default on mobile.
- Consume native opaque submissions in host-native authentication code; never
  route them through JavaScript, Dart, a text field, or a mutable global account
  context.
- Treat only masked length/display state and stable result codes as UI state.
- Prefer WebAuthn/passkeys on the web. A browser keypad is a lower-assurance
  fallback because page JavaScript and extensions can observe browser memory.
- Run the release candidate and physical-device evidence gates before making a
  production security claim.
