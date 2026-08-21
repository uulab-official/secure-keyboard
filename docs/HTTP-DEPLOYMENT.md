# HTTP deployment baseline

The Rust route crates are framework-neutral, but the deployment boundary is
not optional. The host must apply these controls before calling a route:

1. terminate TLS directly or validate a trusted reverse-proxy hop;
2. reject request bodies above 128 KiB before buffering them;
3. enforce header, request-line, connection, read, and idle time limits;
4. allowlist the reverse-proxy source and do not trust client-supplied
   `X-Forwarded-*` headers;
5. validate the request's same-origin/CSRF policy from headers, origin, and
   the host session before buffering or dispatching JSON;
6. bind registration and login routes to the application's authenticated
   session/account policy;
7. use a distributed atomic ceremony store and rate limiter when more than one
   application instance can receive a request.

After these checks, pass `HttpDeploymentContext::direct_tls()` or
`HttpDeploymentContext::trusted_proxy_tls()` to the OPAQUE router. Pass the
corresponding `WebAuthnDeploymentContext` to the passkey router. The trusted
proxy variant is an assertion made by the host after validation; it is not a
header parser or a TLS implementation. The framework-neutral request contract
also requires `csrf_validated: true` only after the host has completed its
same-origin/CSRF check. The Axum adapter requires a request-parts callback and
rejects an unvalidated request before body buffering.

## Reverse-proxy baseline

The following snippets are starting points, not a certification or a complete
site configuration. Set the connection limit for the expected deployment and
keep the upstream listener private.

Nginx location-level controls:

```nginx
client_max_body_size 128k;
client_body_timeout 10s;
proxy_connect_timeout 3s;
proxy_read_timeout 10s;
proxy_send_timeout 10s;

location /v1/opaque/ {
    proxy_pass http://secure_keypad_backend;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Caddy handler controls:

```caddyfile
example.com {
    request_body {
        max_size 128KB
    }

    reverse_proxy 127.0.0.1:8080 {
        transport http {
            dial_timeout 3s
            read_timeout 10s
            write_timeout 10s
        }
    }
}
```

The application must accept forwarded transport metadata only from the
configured proxy network. Keep rate-limit keys, ceremony handles, request
bodies, credential IDs, and protocol errors out of proxy/application logs and
traces. Replace the process-local reference stores before enabling multiple
instances or failover.
