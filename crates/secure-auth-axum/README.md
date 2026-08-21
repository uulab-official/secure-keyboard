# secure-auth-axum

Compile-tested Axum adapter for the Secure Keypad OPAQUE HTTP contract.

```rust,no_run
let app = secure_auth_axum::router(
    secure_auth_http::HttpAuthRouter::new(service, credential_repository),
    secure_auth_http::HttpDeploymentContext::trusted_proxy_tls(),
);
```

Before constructing the trusted-proxy context, the host must validate the
proxy source and forwarded scheme. The adapter bounds body buffering at 128 KiB
with Axum's streaming body helper, copies the OPAQUE route's static security
headers, and never returns framework error details. TLS termination, request
authentication, rate limits, account-enrollment policy, session issuance, and
durable/distributed stores remain application responsibilities.

The crate is an adapter contract and is not a complete server binary.
