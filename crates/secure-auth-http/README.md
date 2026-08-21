# secure-auth-http

Framework-neutral HTTP/JSON route contract for the Secure Keypad OPAQUE
server service.

The adapter accepts only `POST` requests with an `application/json` media type
and a body no larger than 128 KiB. It provides these routes:

- `/v1/opaque/registration/start`
- `/v1/opaque/registration/finish`
- `/v1/opaque/login/start`
- `/v1/opaque/login/finish`

All routes return generic public error classes. Login state handles are fixed
32-byte opaque values encoded as lowercase hex for transport and are consumed
atomically by the configured `BoundOneTimeLoginStateStore`. The HTTP response
buffer is zeroized when dropped. Credential files, OPAQUE payloads, and session
keys are never returned as JSON or included in diagnostics.

Every call must pass `HttpDeploymentContext::direct_tls()` or
`HttpDeploymentContext::trusted_proxy_tls()`. The latter is valid only after
the host validates the proxy source and forwarded scheme; the route never
trusts `X-Forwarded-Proto` itself. The context also requires a pre-buffering
body limit no larger than 128 KiB and enforced connection/read limits.

The embedding server still owns certificate policy, proxy source allowlisting,
request authentication, account creation authorization, rate limiting, and
application session tokens. Registration finish in particular must be
protected by the application's account-enrollment policy.

```rust,no_run
let response = router.handle(request, HttpDeploymentContext::trusted_proxy_tls());
```

Configure the reverse proxy to reject oversized bodies and slow connections
before forwarding to the application. Do not construct the trusted-proxy
context from an unvalidated client header.
