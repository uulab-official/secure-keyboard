# Third-party notices

The SDK is MIT-licensed. The following production dependency is redistributed
through the Rust workspace and its license must remain visible in release
artifacts and source distributions.

| Dependency | Version pin | License | Source |
|---|---:|---|---|
| `webauthn-rs` and its `webauthn-rs-*` support crates | `0.5.4` | MPL-2.0 | [webauthn-rs repository](https://github.com/kanidm/webauthn-rs) |
| OpenSSL used by `webauthn-rs-core` | locked `openssl`/`openssl-src` versions | Apache-2.0 / OpenSSL license | [OpenSSL license](https://www.openssl.org/source/license.html) |
| Axum adapter HTTP stack (`axum`, `tokio`, `tower`, `http-body`, `http-body-util`, `hyper`) | exact versions in `Cargo.lock` | MIT | The package source distributions and `cargo metadata` provide the authoritative notices. |
| Actix adapter HTTP stack (`actix-web` and its `actix-*` support crates) | exact versions in `Cargo.lock`; `actix-web = 4.11.0` | MIT / Apache-2.0 as applicable | The package source distributions and `cargo metadata` provide the authoritative notices. |
| Node/TypeScript server adapter | Node Web Fetch APIs; no runtime dependency | Node.js runtime and TypeScript development tooling are not bundled into the package. |
| Optional durable storage/rate-limit clients and state protection (`redis`, `postgres`, `r2d2`, `r2d2_postgres`, `sha2`, `aes-gcm`) | exact feature-gated versions in `Cargo.lock` | MIT / Apache-2.0 / BSD-3-Clause as applicable | Include the CI SBOM and the dependency source notices when shipping a durable-backend or distributed-rate-limit build. |

The exact transitive dependency versions and checksums are recorded in
`Cargo.lock` and the CI-generated SBOM. Release automation must preserve those
records and include the applicable license texts from the dependency source
distributions.

`playwright` `1.62.1` is a verification-only development dependency used by
the Chromium/Firefox/WebKit smoke gate. It is not included in the published
SDK packages; when the verification tool runs, its exact lockfile entry and
transitive notices remain part of the CI dependency metadata.
