# `@secure-keypad/server-node`

This package is the Node/TypeScript transport adapter for the versioned
Secure Keypad OPAQUE HTTP contract. It accepts a Web Fetch `Request`, validates
TLS/deployment facts, CSRF/origin policy, route/method/media type, and the
128 KiB body bound before calling a host-supplied delegate.

`NODE_SERVER_CONTRACT_VERSION = 1` must match
`secure_auth_http::HTTP_CONTRACT_VERSION`. Run
`pnpm test:http-contract-version-parity` and
`pnpm check:http-contract-version-parity` when changing either transport
implementation; the same checks are mandatory release gates.

`OPAQUE_PROTOCOL_VERSION` and `OPAQUE_CIPHER_SUITE_ID` are metadata bindings
to the pinned Rust/native delegate. Run
`pnpm test:opaque-protocol-parity` and
`pnpm check:opaque-protocol-parity` when changing the authentication protocol
or suite. This package still does not implement OPAQUE in JavaScript.

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
the request buffer is not valid for asynchronous use after that point. A
malformed non-byte stream chunk is rejected before delegation and any supported
typed-array backing bytes are cleared.
JavaScript remains outside the strongest native secret boundary.

The handler rejects malformed, non-decimal, overflowing, signed, comma-joined,
and oversized `Content-Length` values before reading the body. It also rejects
duplicate declarations; a missing header remains valid only because the
streaming reader enforces the same 128 KiB bound.

`transport: "trusted-proxy-tls"` is valid only after the host has independently
validated the proxy source and forwarded scheme. The adapter never trusts or
parses `X-Forwarded-*` headers. The `rateLimitDecision` callback is also a
required production admission boundary: it must apply account/IP/deployment
limits from request metadata without reading the body. It returns
`"allowed"`, `"rate-limited"`, or `"unavailable"`; a rate-limited request gets
the generic 429 response, and an unavailable or omitted callback fails closed
with 503 before the body is read. JavaScript memory is not a secure-memory
boundary; applications requiring the strongest secret handling should keep the
OPAQUE engine in the Rust/native process.

For financial authentication, set `securityProfile: "financial"` and provide
`deviceIntegrityDecision`. The callback must verify the Android Play Integrity,
iOS App Attest/DeviceCheck, or equivalent server-verifiable result bound to the
current account, authentication operation, nonce, and deployment. It runs after
CSRF/rate-limit admission but before the request body is read; `"rejected"`,
`"unavailable"`, a missing callback, or a callback failure returns a generic
failure and never reaches the OPAQUE delegate:

```ts
const handler = createOpaqueHandler({
  deploymentContext,
  securityProfile: "financial",
  csrfValidated: validateHostSession,
  rateLimitDecision: admitRateLimit,
  deviceIntegrityDecision: verifyPlatformIntegrity,
  delegate: pinnedRustOpaqueDelegate,
});
```

`verifyPlatformIntegrity` is intentionally host-supplied: the SDK cannot hold
Google/Apple credentials or decide the product's account-risk policy. The Rust
Axum/Actix adapters expose the equivalent `financial_router` boundary.

The public release version follows the Contracts package. Authentication
protocol and C ABI versions remain independent.
