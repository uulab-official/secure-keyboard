# secure-auth-actix

Compile-tested Actix Web adapter for the Secure Keypad OPAQUE HTTP contract.

```rust,no_run
let app = actix_web::App::new().service(secure_auth_actix::router(
    secure_auth_http::HttpAuthRouter::new(service, credential_repository),
    secure_auth_http::HttpDeploymentContext::trusted_proxy_tls(),
    |request| host_csrf_is_valid(request),
    |request| host_rate_limit_admission(request),
));
```

The adapter calls the host CSRF/origin callback before buffering a request,
rejects malformed or duplicate `Content-Length` values before buffering, uses
Actix's bounded payload collector, preserves the framework-neutral generic
errors and security headers, and never parses forwarded transport headers.
TLS termination, proxy source validation, connection/read limits, rate limits,
credential persistence, and session issuance remain host responsibilities.
The rate-limit callback runs from request metadata before Actix buffers the
body; return `RequestAdmission::Allowed` only after the host's
account/IP/deployment limiter allows the request. Denied and unavailable
decisions fail closed. The crate is an adapter contract rather than a complete
server binary.

Enable `webauthn` for the passkey routes. The principal resolver receives only
Actix request metadata and must resolve the account from the host session; it
must not trust a browser-supplied JSON principal:

```rust,no_run
let app = actix_web::App::new().service(secure_auth_actix::webauthn_router(
    std::sync::Arc::new(webauthn_service),
    secure_webauthn_example::WebAuthnDeploymentContext::trusted_proxy_tls(),
    |request| host_session_principal(request),
    |request| host_csrf_is_valid(request),
));
```
