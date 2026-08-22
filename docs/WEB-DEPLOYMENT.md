# Web deployment baseline

The web adapter is passkey-first. It converts server-generated WebAuthn
options and returns browser ceremony results; it never accepts a password, PIN,
or keypad secret as an API value. The SDK does not ship a browser DOM keypad; page JavaScript can observe page input and memory, so a custom browser UI remains lower assurance. For a custom passkey UI, use
`createPasskeyController()` and render its secret-free lifecycle state. If a
product builds a custom browser keypad around the explicit fallback
acknowledgement, that UI is lower assurance for the same reason.

Server-supplied WebAuthn extension objects and browser extension results are
defensively copied with bounded depth, node count, key count, and string size.
The adapter rejects malformed or oversized extension JSON before handing it to
the browser or serializing it back to the server.

## Browser policy

- Serve the app and WebAuthn endpoints over HTTPS with a valid origin and an
  RP ID that is a registrable suffix of that origin.
- Prefer a per-response CSP nonce for inline bootstrap code. Do not enable
  `unsafe-inline` or `unsafe-eval`.
- Restrict `connect-src` to the API origins required by the app; use
  `frame-ancestors 'none'`, `object-src 'none'`, and `base-uri 'none'` unless a
  reviewed product requirement needs a narrower exception.
- Do not put ceremony handles, credential IDs, WebAuthn responses, or error
  payloads in analytics, CSP reports, URLs, or client logs.
- Keep the browser adapter's explicit fallback acknowledgement in the product
  UI and operator documentation. Never silently switch to the custom keypad
  when WebAuthn is unavailable. Prefer the passkey controller for custom
  presentation and preserve its lifecycle-only state contract.

Example baseline header (replace the nonce and API origin per response):

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{per-response}'; connect-src 'self' https://auth.example.com; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'
```

## Supply chain

- Commit and review `pnpm-lock.yaml`; update dependencies through a dedicated
  change with `pnpm audit --audit-level high` and the package tests.
- Serve built JavaScript from the release artifact or a reviewed same-origin
  asset host. If a third-party asset is unavoidable, pin its exact URL and
  attach an `integrity="sha384-..."` hash plus `crossorigin="anonymous"`.
- Do not load remote scripts that can read the keypad page or intercept
  WebAuthn responses. Treat analytics, A/B testing, tag managers, and support
  widgets as code in the trust boundary.
- Generate an SBOM for the web artifact and retain the exact source commit,
  lockfile, Node/pnpm versions, bundle hashes, and CSP configuration with the
  release record.
- Use a separate CSP report endpoint with rate limits and redaction; reports
  are diagnostics, not an authentication audit log.

The web security boundary is still the browser and the host page. CSP, SRI,
HTTPS, and dependency review reduce attack surface but do not turn a custom
browser keypad into native secure input.
