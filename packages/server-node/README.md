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

`transport: "trusted-proxy-tls"` is valid only after the host has independently
validated the proxy source and forwarded scheme. The adapter never trusts or
parses `X-Forwarded-*` headers. JavaScript memory is not a secure-memory
boundary; applications requiring the strongest secret handling should keep the
OPAQUE engine in the Rust/native process.

The public release version follows the Contracts package. Authentication
protocol and C ABI versions remain independent.
