# `@secure-keypad/server-node`

This package is the Node/TypeScript transport adapter for the versioned
Secure Keypad OPAQUE HTTP contract. It accepts a Web Fetch `Request`, validates
TLS/deployment facts, CSRF/origin policy, route/method/media type, and the
128 KiB body bound before calling a host-supplied delegate.

The delegate is the cryptographic boundary. This package does not implement
OPAQUE in JavaScript and must be connected to the pinned Rust reference
service/native bridge. It receives only the bounded protocol body and must
return generic JSON response bytes. Do not log or persist the request body,
identifiers, protocol errors, or delegate response details.

The adapter clears the bounded request `Uint8Array` immediately after the
delegate returns (and clears already-read chunks on size/read failure). It also
copies the delegate's response `Uint8Array` into the Fetch response and clears
the delegate-owned response buffer before returning. These controls reduce
residual exposure but cannot erase copies made by the Fetch runtime or
delegate. A delegate must finish consuming the request view before returning;
the request buffer is not valid for asynchronous use after that point.
JavaScript remains outside the strongest native secret boundary.

`transport: "trusted-proxy-tls"` is valid only after the host has independently
validated the proxy source and forwarded scheme. The adapter never trusts or
parses `X-Forwarded-*` headers. JavaScript memory is not a secure-memory
boundary; applications requiring the strongest secret handling should keep the
OPAQUE engine in the Rust/native process.

The public release version follows the Contracts package. Authentication
protocol and C ABI versions remain independent.
