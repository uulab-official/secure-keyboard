# Third-party notices

The SDK is MIT-licensed. The following production dependency is redistributed
through the Rust workspace and its license must remain visible in release
artifacts and source distributions.

| Dependency | Version pin | License | Source |
|---|---:|---|---|
| `webauthn-rs` and its `webauthn-rs-*` support crates | `0.5.4` | MPL-2.0 | [webauthn-rs repository](https://github.com/kanidm/webauthn-rs) |
| OpenSSL used by `webauthn-rs-core` | locked `openssl`/`openssl-src` versions | Apache-2.0 / OpenSSL license | [OpenSSL license](https://www.openssl.org/source/license.html) |
| Axum adapter HTTP stack (`axum`, `tokio`, `tower`, `http-body`, `http-body-util`, `hyper`) | exact versions in `Cargo.lock` | MIT | The package source distributions and `cargo metadata` provide the authoritative notices. |

The exact transitive dependency versions and checksums are recorded in
`Cargo.lock` and the CI-generated SBOM. Release automation must preserve those
records and include the applicable license texts from the dependency source
distributions.
