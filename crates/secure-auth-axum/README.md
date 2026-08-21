# secure-auth-axum

Compile-tested Axum adapters for the Secure Keypad OPAQUE and, behind the
optional `webauthn` feature, WebAuthn HTTP contracts. The WebAuthn adapter is
generic over the injected `WebAuthnService<C, S>` storage contracts.

```rust,no_run
let app = secure_auth_axum::router(
    secure_auth_http::HttpAuthRouter::new(service, credential_repository),
    secure_auth_http::HttpDeploymentContext::trusted_proxy_tls(),
);
```

Enable `webauthn` for the passkey routes. The principal resolver receives only
Axum request parts, never the request body, and must resolve the account from
the host's authenticated session:

```rust,no_run
let app = secure_auth_axum::webauthn_router(
    std::sync::Arc::new(webauthn_service),
    secure_webauthn_example::WebAuthnDeploymentContext::trusted_proxy_tls(),
    |parts| host_session_principal(parts),
);
```

Before constructing the trusted-proxy context, the host must validate the
proxy source and forwarded scheme. The adapter bounds body buffering at 128 KiB
with Axum's streaming body helper, copies the OPAQUE route's static security
headers, and never returns framework error details. The WebAuthn adapter uses
the same bounded body and response-header contract and rejects an unavailable
deployment context before dispatch. TLS termination, request authentication,
rate limits, account-enrollment policy, CSRF, session issuance, and
durable/distributed stores remain application responsibilities.

The crate is an adapter contract and is not a complete server binary.
