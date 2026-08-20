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

The route layer does not provide TLS, certificate policy, proxy limits,
request authentication, account creation authorization, rate limiting, or
application session tokens. The embedding server must provide those controls;
registration finish in particular must be protected by the application's
account-enrollment policy.
