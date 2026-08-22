# secure-auth-http

Framework-neutral HTTP/JSON route contract for the Secure Keypad OPAQUE
server service.

This route contract is versioned independently from the OPAQUE protocol:
`HTTP_CONTRACT_VERSION = 1`. The Node/TypeScript bridge must expose the same
value, and the repository parity test/check run in CI and release-candidate
gates before the adapters are published.

The adapter accepts only `POST` requests with an `application/json` media type
and a body no larger than 128 KiB. It provides these routes:

- `/v1/opaque/registration/start`
- `/v1/opaque/registration/finish`
- `/v1/opaque/login/start`
- `/v1/opaque/login/finish`

Framework adapters must reject malformed, non-decimal, overflowing,
comma-joined, invalid-byte, or duplicate `Content-Length` values before body
buffering. A valid declaration above the configured limit is a generic 413;
an invalid declaration is a generic 400. Requests without `Content-Length`
remain subject to the bounded streaming collector.

All routes return generic public error classes. Login state handles are fixed
32-byte opaque values encoded as lowercase hex for transport and are consumed
atomically by the configured `BoundOneTimeLoginStateStore`. The HTTP response
buffer is zeroized when dropped. Credential files, OPAQUE payloads, and session
keys are never returned as JSON or included in diagnostics.

`CredentialRepository::load` must return a protected copy without deleting the
stored credential. Login credentials are reusable records; only the separate
server login state handle is consumed once.

Every response also carries static `no-store`, `nosniff`, `no-referrer`, and
API-safe CSP headers through `RESPONSE_SECURITY_HEADERS`; a framework adapter
must copy them to the actual HTTP response.

Every call must pass `HttpDeploymentContext::direct_tls()` or
`HttpDeploymentContext::trusted_proxy_tls()`. The latter is valid only after
the host validates the proxy source and forwarded scheme; the route never
trusts `X-Forwarded-Proto` itself. The context also requires a pre-buffering
body limit no larger than 128 KiB and enforced connection/read limits.

Every `HttpRequest` must set `csrf_validated` only after the host has checked
its same-origin/CSRF policy from request metadata. The route rejects `false`
with a generic 403 response before JSON dispatch; it never treats a body field
as a CSRF token.

The embedding server still owns certificate policy, proxy source allowlisting,
request authentication, account creation authorization, rate limiting, and
application session tokens. Registration finish in particular must be
protected by the application's account-enrollment policy. Its
`CredentialRepository::create` implementation must also be an atomic
create-only operation: an existing credential must return
`RepositoryError::AlreadyExists` and never be replaced. The route maps that
conflict to the generic invalid-request response.

```rust,no_run
let response = router.handle(request, HttpDeploymentContext::trusted_proxy_tls());
```

Configure the reverse proxy to reject oversized bodies and slow connections
before forwarding to the application. Do not construct the trusted-proxy
context from an unvalidated client header.
