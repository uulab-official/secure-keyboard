# secure-auth-actix

Compile-tested Actix Web adapter for the Secure Keypad OPAQUE HTTP contract.

```rust,no_run
let app = actix_web::App::new().service(secure_auth_actix::router(
    secure_auth_http::HttpAuthRouter::new(service, credential_repository),
    secure_auth_http::HttpDeploymentContext::trusted_proxy_tls(),
    |request| host_csrf_is_valid(request),
));
```

The adapter calls the host CSRF/origin callback before buffering a request,
uses Actix's bounded payload collector, preserves the framework-neutral generic
errors and security headers, and never parses forwarded transport headers.
TLS termination, proxy source validation, connection/read limits, rate limits,
credential persistence, and session issuance remain host responsibilities.
The crate is an adapter contract rather than a complete server binary.
