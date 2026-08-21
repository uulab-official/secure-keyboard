# secure-auth

`secure-auth` provides the pinned OPAQUE 4.0.1 protocol boundary used by the
Secure Keypad server and native integrations. The suite is
`opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2`; transport envelopes,
server-login state, identifiers, and serialized records are bounded and
version-checked before protocol processing.

`CredentialFile` and `ServerSetupBytes` are password-equivalent sensitive
server material. Store them in an encrypted or access-controlled secret store,
and use a one-time atomic backend for serialized login state. The crate never
provides a password getter or a replayable client-side password hash. See the
repository authentication transport contract and release gates before
deployment.
