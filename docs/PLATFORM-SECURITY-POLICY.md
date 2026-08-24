# Platform security policy

This policy defines the v1 boundary for controls that the SDK cannot own
across every host application, network stack, and operating-system security
model.

## TLS and certificate pinning

The SDK does not implement an HTTP client. The native OPAQUE FFI boundary
passes opaque protocol messages to host-native authentication code, while the
Rust route crates receive requests after the host or trusted proxy has
terminated TLS. Consequently, the SDK does not claim to provide certificate
or public-key pinning.

Every deployment must still enforce HTTPS or a validated trusted-proxy TLS
assertion, body and connection limits, origin/CSRF validation, and private
upstream access as specified in `docs/HTTP-DEPLOYMENT.md`. A product that
selects pinning must implement it in its host-native transport, prefer an
SPKI/public-key pin with an explicit rotation overlap, fail closed on a pin
mismatch, and attach a platform-specific test to the release evidence
manifest. Pinning policy must not be implemented in JavaScript or Dart.

## Root, jailbreak, tamper, and injected-process policy

Secure Native Mode is designed for a non-compromised application process. The
SDK v1 does not claim to detect or defeat rooted/jailbroken devices, injected
code, malicious accessibility services, debugger attachment, arbitrary hostile
overlays, or a malicious host application. Android Secure Native does reject
the platform's fully and partially obscured touch flags before key activation,
but that bounded tapjacking control is not a general overlay or device-
integrity guarantee. These environments can observe input or native memory
despite the keypad boundary.

A product requiring a higher assurance decision must apply its own platform
attestation, device-integrity, debugger/tamper, and account-risk policy before
starting authentication. The product must choose whether to deny, step up, or
limit authentication on a failed integrity signal; the SDK does not silently
make that product decision. Any selected response must be tested on the
supported OS/device matrix and recorded as residual risk when unavailable.

This policy is a documented limitation, not an OWASP certification or a claim
that secret theft is impossible.
