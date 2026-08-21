#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! A bounded, passkey-first `WebAuthn` reference service.
//!
//! The service delegates CBOR, COSE, challenge, origin, RP-ID, user
//! verification, and signature validation to the pinned `webauthn-rs` engine.
//! It adds the application boundary that the engine cannot provide: bounded
//! JSON bodies, one-time ceremony handles, generic public errors, credential
//! uniqueness, and counter/backup-state persistence.
//!
//! The default state and credential stores are process-local examples. The
//! [`WebAuthnService`] type accepts external [`CeremonyStateStore`] and
//! [`CredentialStore`] implementations so a production deployment can use an
//! encrypted durable credential repository and an atomic distributed ceremony
//! store. The server-only `webauthn-rs` state serialization feature is used
//! only for protected backend bytes; no ceremony state is accepted from the
//! browser.

use secure_auth_server::LoginStateHandle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};
use zeroize::{Zeroize, Zeroizing};

mod storage;

#[cfg(feature = "postgres-backend")]
mod storage_postgres;

#[cfg(feature = "redis-backend")]
mod storage_redis;

pub use storage::{
    CeremonyKind, CeremonyState, CeremonyStateStore, CeremonyStoreError, CredentialStore,
    CredentialStoreError, InMemoryCeremonyStateStore, InMemoryCredentialStore,
};

#[cfg(feature = "postgres-backend")]
pub use storage_postgres::{
    PostgresStorageConfigError, PostgresWebAuthnStore, POSTGRES_SCHEMA_SQL,
};

#[cfg(feature = "redis-backend")]
pub use storage_redis::{RedisStorageConfigError, RedisWebAuthnStore};

/// Maximum JSON response body accepted by the reference boundary.
pub const MAX_CLIENT_RESPONSE_BYTES: usize = 128 * 1024;
/// Maximum number of credentials associated with one example account.
pub const MAX_CREDENTIALS_PER_USER: usize = 64;
/// Maximum serialized credential record accepted by a durable backend.
pub const MAX_CREDENTIAL_RECORD_BYTES: usize = 256 * 1024;
/// Maximum number of pending ceremony states in one example process.
pub const MAX_PENDING_CEREMONIES: usize = 100_000;
/// Maximum serialized ceremony state accepted by a backend.
pub const MAX_CEREMONY_STATE_BYTES: usize = 128 * 1024;
/// Current server-side serialized ceremony state format version.
pub const WEBAUTHN_CEREMONY_STATE_VERSION: u16 = 1;
/// Maximum user name or display name accepted by the example boundary.
pub const MAX_USER_FIELD_BYTES: usize = 256;
const HANDLE_BYTES: usize = 32;

/// Generic public error for the server boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebAuthnExampleError {
    /// The relying-party configuration is invalid.
    InvalidConfiguration,
    /// The request body or public identifier is invalid.
    InvalidRequest,
    /// The one-time ceremony handle was already consumed or expired.
    Replay,
    /// The example store cannot safely complete an operation.
    StoreUnavailable,
    /// The configured process-local capacity has been reached.
    CapacityReached,
    /// A serialized ceremony state exceeded the configured bound.
    StateTooLarge,
    /// The credential cannot be added to this account.
    CredentialLimit,
}

impl core::fmt::Display for WebAuthnExampleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("webauthn request rejected")
    }
}

impl std::error::Error for WebAuthnExampleError {}

/// A public ceremony response. The handle must be kept confidential by the
/// embedding server and sent back only to the same authenticated browser flow.
/// Its [`core::fmt::Debug`] output redacts both the handle and browser options.
#[derive(Serialize)]
pub struct CeremonyStart {
    /// Fixed-size lowercase hexadecimal one-time handle.
    pub handle: String,
    /// Server-generated `WebAuthn` options for the browser adapter.
    pub options: Value,
}

impl core::fmt::Debug for CeremonyStart {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CeremonyStart")
            .field("handle_len", &self.handle.len())
            .field("options", &"<redacted>")
            .finish()
    }
}

/// Result of a successful passkey registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationOutcome {
    /// Account to which the credential was attached.
    pub user_id: Uuid,
}

/// Result of a successful passkey authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationOutcome {
    /// Account authenticated by the verified credential.
    pub user_id: Uuid,
    /// Whether authenticator counter or backup flags changed and should be
    /// persisted by a durable credential store.
    pub credential_updated: bool,
}

#[derive(Deserialize, Serialize)]
struct CeremonyStateEnvelope<T> {
    version: u16,
    state: T,
}

/// A passkey-first `WebAuthn` service parameterized by its persistence backends.
///
/// `C` stores public credential records and `S` stores serialized one-time
/// ceremony states. The default [`WebAuthnExampleService`] alias uses bounded
/// process-local stores for tests and development; production applications
/// should instantiate this type with shared encrypted/access-controlled
/// implementations of [`CredentialStore`] and [`CeremonyStateStore`].
pub struct WebAuthnService<C, S> {
    webauthn: Webauthn,
    registration_states: S,
    authentication_states: S,
    credentials: C,
    ceremony_ttl: Duration,
}

/// The default process-local reference service retained for compatibility.
pub type WebAuthnExampleService =
    WebAuthnService<InMemoryCredentialStore, InMemoryCeremonyStateStore>;

impl<C, S> WebAuthnService<C, S>
where
    C: CredentialStore,
    S: CeremonyStateStore,
{
    /// Builds a service with caller-supplied durable storage contracts.
    ///
    /// The ceremony stores may be separate namespace wrappers over one shared
    /// backend. Each must apply the supplied TTL and implement atomic
    /// consume-once semantics; the credential store must implement atomic
    /// uniqueness and post-authentication counter updates.
    ///
    /// # Errors
    ///
    /// Returns [`WebAuthnExampleError::InvalidConfiguration`] for invalid RP
    /// configuration or an unrepresentable/zero ceremony TTL.
    pub fn new_with_stores(
        rp_id: &str,
        origin: &str,
        rp_name: &str,
        ceremony_ttl: Duration,
        registration_states: S,
        authentication_states: S,
        credentials: C,
    ) -> Result<Self, WebAuthnExampleError> {
        validate_ceremony_ttl(ceremony_ttl)?;
        Ok(Self {
            webauthn: build_webauthn(rp_id, origin, rp_name)?,
            registration_states,
            authentication_states,
            credentials,
            ceremony_ttl,
        })
    }

    /// Starts passkey registration and returns browser options plus a one-time
    /// state handle. The account-enrollment policy belongs to the host server.
    ///
    /// # Errors
    ///
    /// Returns a generic error for invalid public fields, a full state store,
    /// or a protected-store failure.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> Result<CeremonyStart, WebAuthnExampleError> {
        validate_user_field(user_name)?;
        validate_user_field(display_name)?;
        let existing = self
            .credentials
            .load(user_id)
            .map_err(map_credential_error)?;
        if existing.len() > MAX_CREDENTIALS_PER_USER {
            return Err(WebAuthnExampleError::CredentialLimit);
        }
        let exclude_credentials = if existing.is_empty() {
            None
        } else {
            Some(
                existing
                    .iter()
                    .map(|credential| credential.cred_id().clone())
                    .collect(),
            )
        };
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_id, user_name, display_name, exclude_credentials)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let options =
            serde_json::to_value(options).map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let state = serialize_state(&state)?;
        let handle = self
            .registration_states
            .insert(
                CeremonyKind::Registration,
                user_id,
                &state,
                self.ceremony_ttl,
            )
            .map_err(map_ceremony_error)?;
        Ok(CeremonyStart {
            handle: encode_handle(&handle),
            options,
        })
    }

    /// Finishes registration after atomically consuming the pending state.
    /// The response is bounded before deserialization and never logged.
    ///
    /// # Errors
    ///
    /// Returns a generic request error for malformed or invalid credentials,
    /// a replay error for a consumed handle, or a store/capacity error.
    pub fn finish_registration(
        &self,
        handle: &str,
        response_body: &[u8],
    ) -> Result<RegistrationOutcome, WebAuthnExampleError> {
        self.finish_registration_bound(handle, None, response_body)
    }

    /// Finishes registration while binding the ceremony to the host session's
    /// authenticated principal before parsing or storing the credential.
    ///
    /// # Errors
    ///
    /// Returns the same generic errors as [`Self::finish_registration`]. A
    /// principal mismatch consumes the ceremony and returns
    /// [`WebAuthnExampleError::InvalidRequest`].
    pub fn finish_registration_for_principal(
        &self,
        handle: &str,
        principal: Uuid,
        response_body: &[u8],
    ) -> Result<RegistrationOutcome, WebAuthnExampleError> {
        self.finish_registration_bound(handle, Some(principal), response_body)
    }

    fn finish_registration_bound(
        &self,
        handle: &str,
        expected_principal: Option<Uuid>,
        response_body: &[u8],
    ) -> Result<RegistrationOutcome, WebAuthnExampleError> {
        let handle = decode_handle(handle)?;
        let pending = self
            .registration_states
            .take(CeremonyKind::Registration, &handle)
            .map_err(map_ceremony_error)?
            .ok_or(WebAuthnExampleError::Replay)?;
        let (_, user_id, state_bytes) = pending.into_parts();
        if expected_principal.is_some_and(|principal| principal != user_id) {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let state_bytes = Zeroizing::new(state_bytes);
        let state: PasskeyRegistration = deserialize_state(&state_bytes)?;
        let response: RegisterPublicKeyCredential = parse_response(response_body)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        self.credentials
            .insert(user_id, passkey)
            .map_err(map_credential_error)?;
        Ok(RegistrationOutcome { user_id })
    }

    /// Starts passkey authentication for a known account.
    ///
    /// Unknown accounts deliberately return the same public error as malformed
    /// requests so the endpoint cannot be used for account enumeration.
    ///
    /// # Errors
    ///
    /// Returns [`WebAuthnExampleError::InvalidRequest`] for unknown accounts or
    /// invalid protected credential state.
    pub fn start_authentication(
        &self,
        user_id: Uuid,
    ) -> Result<CeremonyStart, WebAuthnExampleError> {
        let credentials = self
            .credentials
            .load(user_id)
            .map_err(map_credential_error)?;
        if credentials.len() > MAX_CREDENTIALS_PER_USER {
            return Err(WebAuthnExampleError::CredentialLimit);
        }
        if credentials.is_empty() {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let options =
            serde_json::to_value(options).map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let state = serialize_state(&state)?;
        let handle = self
            .authentication_states
            .insert(
                CeremonyKind::Authentication,
                user_id,
                &state,
                self.ceremony_ttl,
            )
            .map_err(map_ceremony_error)?;
        Ok(CeremonyStart {
            handle: encode_handle(&handle),
            options,
        })
    }

    /// Finishes authentication after atomically consuming the pending state.
    /// The verified credential's counter and backup state are persisted in the
    /// in-memory reference store when the library reports an update.
    ///
    /// # Errors
    ///
    /// Returns a generic request error for malformed or invalid assertions, a
    /// replay error for a consumed handle, or a protected-store error.
    pub fn finish_authentication(
        &self,
        handle: &str,
        response_body: &[u8],
    ) -> Result<AuthenticationOutcome, WebAuthnExampleError> {
        self.finish_authentication_bound(handle, None, response_body)
    }

    /// Finishes authentication while binding the ceremony to the host
    /// session's authenticated principal before verifying the assertion.
    ///
    /// # Errors
    ///
    /// Returns the same generic errors as [`Self::finish_authentication`]. A
    /// principal mismatch consumes the ceremony and returns
    /// [`WebAuthnExampleError::InvalidRequest`].
    pub fn finish_authentication_for_principal(
        &self,
        handle: &str,
        principal: Uuid,
        response_body: &[u8],
    ) -> Result<AuthenticationOutcome, WebAuthnExampleError> {
        self.finish_authentication_bound(handle, Some(principal), response_body)
    }

    fn finish_authentication_bound(
        &self,
        handle: &str,
        expected_principal: Option<Uuid>,
        response_body: &[u8],
    ) -> Result<AuthenticationOutcome, WebAuthnExampleError> {
        let handle = decode_handle(handle)?;
        let pending = self
            .authentication_states
            .take(CeremonyKind::Authentication, &handle)
            .map_err(map_ceremony_error)?
            .ok_or(WebAuthnExampleError::Replay)?;
        let (_, user_id, state_bytes) = pending.into_parts();
        if expected_principal.is_some_and(|principal| principal != user_id) {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let state_bytes = Zeroizing::new(state_bytes);
        let state: PasskeyAuthentication = deserialize_state(&state_bytes)?;
        let response: PublicKeyCredential = parse_response(response_body)?;
        let result: AuthenticationResult = self
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let updated = self
            .credentials
            .update_after_auth(user_id, &result)
            .map_err(map_credential_error)?;
        Ok(AuthenticationOutcome {
            user_id,
            credential_updated: updated,
        })
    }
}

impl WebAuthnService<InMemoryCredentialStore, InMemoryCeremonyStateStore> {
    /// Builds the bounded process-local reference service.
    ///
    /// HTTPS is required. `http://localhost` and loopback origins are allowed
    /// only for local development and must never be used in production.
    ///
    /// # Errors
    ///
    /// Returns [`WebAuthnExampleError::InvalidConfiguration`] for an invalid
    /// origin, RP ID, display name, or ceremony TTL.
    pub fn new(
        rp_id: &str,
        origin: &str,
        rp_name: &str,
        ceremony_ttl: Duration,
    ) -> Result<Self, WebAuthnExampleError> {
        Self::new_with_stores(
            rp_id,
            origin,
            rp_name,
            ceremony_ttl,
            InMemoryCeremonyStateStore::new(MAX_PENDING_CEREMONIES)
                .map_err(|_| WebAuthnExampleError::InvalidConfiguration)?,
            InMemoryCeremonyStateStore::new(MAX_PENDING_CEREMONIES)
                .map_err(|_| WebAuthnExampleError::InvalidConfiguration)?,
            InMemoryCredentialStore::new(),
        )
    }

    /// Returns the number of credentials in the reference store for tests and
    /// operational health checks. It exposes no credential material.
    ///
    /// # Errors
    ///
    /// Returns [`WebAuthnExampleError::StoreUnavailable`] if the store lock is
    /// poisoned.
    pub fn credential_count(&self, user_id: Uuid) -> Result<usize, WebAuthnExampleError> {
        self.credentials
            .credential_count(user_id)
            .map_err(map_credential_error)
    }
}

fn build_webauthn(
    rp_id: &str,
    origin: &str,
    rp_name: &str,
) -> Result<Webauthn, WebAuthnExampleError> {
    if rp_id.is_empty() || rp_id.len() > 253 || rp_id.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WebAuthnExampleError::InvalidConfiguration);
    }
    validate_user_field(rp_name).map_err(|_| WebAuthnExampleError::InvalidConfiguration)?;
    let parsed_origin =
        Url::parse(origin).map_err(|_| WebAuthnExampleError::InvalidConfiguration)?;
    if !is_allowed_origin(&parsed_origin) {
        return Err(WebAuthnExampleError::InvalidConfiguration);
    }
    WebauthnBuilder::new(rp_id, &parsed_origin)
        .map_err(|_| WebAuthnExampleError::InvalidConfiguration)?
        .rp_name(rp_name)
        .build()
        .map_err(|_| WebAuthnExampleError::InvalidConfiguration)
}

fn validate_ceremony_ttl(ttl: Duration) -> Result<(), WebAuthnExampleError> {
    if ttl.is_zero() || std::time::Instant::now().checked_add(ttl).is_none() {
        return Err(WebAuthnExampleError::InvalidConfiguration);
    }
    Ok(())
}

fn serialize_state<T: Serialize>(state: &T) -> Result<Zeroizing<Vec<u8>>, WebAuthnExampleError> {
    let bytes = serde_json::to_vec(&CeremonyStateEnvelope {
        version: WEBAUTHN_CEREMONY_STATE_VERSION,
        state,
    })
    .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
    if bytes.len() > MAX_CEREMONY_STATE_BYTES {
        return Err(WebAuthnExampleError::StateTooLarge);
    }
    Ok(Zeroizing::new(bytes))
}

fn deserialize_state<T: serde::de::DeserializeOwned>(
    state: &[u8],
) -> Result<T, WebAuthnExampleError> {
    if state.is_empty() || state.len() > MAX_CEREMONY_STATE_BYTES {
        return Err(WebAuthnExampleError::StoreUnavailable);
    }
    let envelope: CeremonyStateEnvelope<T> =
        serde_json::from_slice(state).map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
    if envelope.version != WEBAUTHN_CEREMONY_STATE_VERSION {
        return Err(WebAuthnExampleError::StoreUnavailable);
    }
    Ok(envelope.state)
}

fn map_ceremony_error(error: CeremonyStoreError) -> WebAuthnExampleError {
    match error {
        CeremonyStoreError::CapacityReached | CeremonyStoreError::HandleCollision => {
            WebAuthnExampleError::CapacityReached
        }
        CeremonyStoreError::StateTooLarge => WebAuthnExampleError::StateTooLarge,
        CeremonyStoreError::InvalidCapacity
        | CeremonyStoreError::InvalidTtl
        | CeremonyStoreError::InvalidState
        | CeremonyStoreError::Unavailable => WebAuthnExampleError::StoreUnavailable,
    }
}

fn map_credential_error(error: CredentialStoreError) -> WebAuthnExampleError {
    match error {
        CredentialStoreError::Unavailable => WebAuthnExampleError::StoreUnavailable,
        CredentialStoreError::CapacityReached => WebAuthnExampleError::CredentialLimit,
        CredentialStoreError::Duplicate | CredentialStoreError::InvalidRecord => {
            WebAuthnExampleError::InvalidRequest
        }
    }
}

/// Exact API prefix used by the framework-neutral `WebAuthn` routes.
pub const WEBAUTHN_API_PREFIX: &str = "/v1/webauthn";
/// JSON media type emitted by the `WebAuthn` route contract.
pub const WEBAUTHN_JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// A static response header that a framework adapter can copy verbatim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebAuthnHttpHeader {
    /// Lowercase HTTP header name.
    pub name: &'static str,
    /// Header value.
    pub value: &'static str,
}

/// Security headers attached to every passkey route response.
pub const WEBAUTHN_RESPONSE_SECURITY_HEADERS: &[WebAuthnHttpHeader] = &[
    WebAuthnHttpHeader {
        name: "cache-control",
        value: "no-store",
    },
    WebAuthnHttpHeader {
        name: "pragma",
        value: "no-cache",
    },
    WebAuthnHttpHeader {
        name: "x-content-type-options",
        value: "nosniff",
    },
    WebAuthnHttpHeader {
        name: "referrer-policy",
        value: "no-referrer",
    },
    WebAuthnHttpHeader {
        name: "content-security-policy",
        value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    },
];

/// Transport state established by the embedding HTTP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebAuthnTransportSecurity {
    /// The request arrived over a TLS connection terminated by this service.
    DirectTls,
    /// A configured, trusted reverse proxy terminated TLS before forwarding.
    ///
    /// The host must validate the proxy source and forwarded scheme before it
    /// constructs this value. The route never parses `X-Forwarded-Proto`.
    TrustedProxyTls,
    /// Plain HTTP or an unvalidated forwarded scheme.
    Plaintext,
}

impl WebAuthnTransportSecurity {
    const fn is_encrypted(self) -> bool {
        !matches!(self, Self::Plaintext)
    }
}

/// Deployment controls that must be established before a route reads JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebAuthnDeploymentContext {
    transport: WebAuthnTransportSecurity,
    upstream_body_limit_bytes: usize,
    connection_limits_enforced: bool,
}

impl WebAuthnDeploymentContext {
    /// Creates a context from host-validated transport and proxy limits.
    ///
    /// `upstream_body_limit_bytes` must be no greater than
    /// [`MAX_CLIENT_RESPONSE_BYTES`]. The host must enforce this limit before
    /// buffering the request body, and must enforce connection/read timeouts
    /// before calling the route.
    #[must_use]
    pub const fn new(
        transport: WebAuthnTransportSecurity,
        upstream_body_limit_bytes: usize,
        connection_limits_enforced: bool,
    ) -> Self {
        Self {
            transport,
            upstream_body_limit_bytes,
            connection_limits_enforced,
        }
    }

    /// Returns the standard context for direct TLS termination.
    #[must_use]
    pub const fn direct_tls() -> Self {
        Self::new(
            WebAuthnTransportSecurity::DirectTls,
            MAX_CLIENT_RESPONSE_BYTES,
            true,
        )
    }

    /// Returns the standard context for a previously validated trusted proxy.
    #[must_use]
    pub const fn trusted_proxy_tls() -> Self {
        Self::new(
            WebAuthnTransportSecurity::TrustedProxyTls,
            MAX_CLIENT_RESPONSE_BYTES,
            true,
        )
    }

    /// Returns the maximum body size the embedding adapter must apply before
    /// buffering the request.
    #[must_use]
    pub const fn body_limit_bytes(self) -> usize {
        self.upstream_body_limit_bytes
    }

    /// Returns whether this context is safe for route dispatch.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.transport.is_encrypted() && self.has_valid_limits()
    }

    const fn has_valid_limits(self) -> bool {
        self.upstream_body_limit_bytes > 0
            && self.upstream_body_limit_bytes <= MAX_CLIENT_RESPONSE_BYTES
            && self.connection_limits_enforced
    }
}

/// A borrowed HTTP request view for Axum, Actix, Go, Java, or ASP.NET
/// adapters. `principal` is populated by the host's authenticated session and
/// never read from the JSON body.
#[derive(Clone, Copy)]
pub struct WebAuthnHttpRequest<'a> {
    /// HTTP method; every route requires `POST`.
    pub method: &'a str,
    /// Exact path without a query string.
    pub path: &'a str,
    /// Request media type from the transport layer.
    pub content_type: Option<&'a str>,
    /// Host-authenticated account principal, if one exists.
    pub principal: Option<Uuid>,
    /// Whether the embedding server validated its CSRF/origin policy for this
    /// request. The route never derives this value from the JSON body.
    pub csrf_validated: bool,
    /// Raw bounded JSON body.
    pub body: &'a [u8],
}

/// An owned bounded JSON response. Response bytes are cleared on drop.
pub struct WebAuthnHttpResponse {
    /// HTTP status selected by the route contract.
    pub status: u16,
    /// Always [`WEBAUTHN_JSON_CONTENT_TYPE`].
    pub content_type: &'static str,
    /// Static cache, MIME, referrer, and CSP headers for the adapter to emit.
    pub headers: &'static [WebAuthnHttpHeader],
    /// JSON body bytes, cleared when the response is dropped.
    pub body: Vec<u8>,
}

impl Drop for WebAuthnHttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl WebAuthnHttpResponse {
    /// Transfers the response body to a framework response writer.
    ///
    /// The returned body is now owned by the framework and the dropped
    /// response shell retains no duplicate bytes.
    #[must_use]
    pub fn into_parts(self) -> (u16, &'static str, &'static [WebAuthnHttpHeader], Vec<u8>) {
        let mut response = self;
        let body = core::mem::take(&mut response.body);
        (
            response.status,
            response.content_type,
            response.headers,
            body,
        )
    }
}

/// Framework-neutral bounded `WebAuthn` route handler.
pub struct WebAuthnHttpRouter<'a, C = InMemoryCredentialStore, S = InMemoryCeremonyStateStore>
where
    C: CredentialStore,
    S: CeremonyStateStore,
{
    service: &'a WebAuthnService<C, S>,
}

impl<'a, C, S> WebAuthnHttpRouter<'a, C, S>
where
    C: CredentialStore,
    S: CeremonyStateStore,
{
    /// Creates a router around a configured service and its storage contracts.
    #[must_use]
    pub const fn new(service: &'a WebAuthnService<C, S>) -> Self {
        Self { service }
    }

    /// Handles one request without logging body, handles, credentials, or
    /// verifier errors.
    ///
    /// The context is mandatory so a framework adapter cannot accidentally
    /// expose the route over plaintext HTTP or omit the reverse-proxy body and
    /// connection limits. CSRF, session issuance, and durable store
    /// implementation remain host-server responsibilities.
    #[must_use]
    pub fn handle(
        &self,
        request: WebAuthnHttpRequest<'_>,
        context: WebAuthnDeploymentContext,
    ) -> WebAuthnHttpResponse {
        if !context.transport.is_encrypted() {
            return webauthn_http_error(400, "invalid_request");
        }
        if !context.has_valid_limits() {
            return webauthn_http_error(503, "temporarily_unavailable");
        }
        if !request.csrf_validated {
            return webauthn_http_error(403, "invalid_request");
        }
        if request.body.len() > context.upstream_body_limit_bytes {
            return webauthn_http_error(413, "invalid_request");
        }
        if request.method != "POST" {
            return webauthn_http_error(405, "invalid_request");
        }
        if !is_json_content_type(request.content_type) {
            return webauthn_http_error(415, "invalid_request");
        }

        match request.path {
            "/v1/webauthn/registration/start" => {
                self.registration_start(request.principal, request.body)
            }
            "/v1/webauthn/registration/finish" => {
                self.registration_finish(request.principal, request.body)
            }
            "/v1/webauthn/authentication/start" => {
                self.authentication_start(request.principal, request.body)
            }
            "/v1/webauthn/authentication/finish" => {
                self.authentication_finish(request.principal, request.body)
            }
            _ => webauthn_http_error(404, "invalid_request"),
        }
    }

    fn registration_start(&self, principal: Option<Uuid>, body: &[u8]) -> WebAuthnHttpResponse {
        let Some(principal) = principal else {
            return webauthn_http_error(401, "unauthenticated");
        };
        let request: RegistrationStartBody = match parse_webauthn_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        match self
            .service
            .start_registration(principal, &request.user_name, &request.display_name)
        {
            Ok(start) => webauthn_json_response(200, &start),
            Err(error) => webauthn_service_error(error),
        }
    }

    fn registration_finish(&self, principal: Option<Uuid>, body: &[u8]) -> WebAuthnHttpResponse {
        let Some(principal) = principal else {
            return webauthn_http_error(401, "unauthenticated");
        };
        let request: CeremonyFinishBody = match parse_webauthn_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        let Ok(response_body) = serde_json::to_vec(&request.response) else {
            return webauthn_http_error(400, "invalid_request");
        };
        match self.service.finish_registration_for_principal(
            &request.handle,
            principal,
            &response_body,
        ) {
            Ok(_) => {
                webauthn_json_response(200, &serde_json::json!({"credentialRegistered": true}))
            }
            Err(error) => webauthn_service_error(error),
        }
    }

    fn authentication_start(&self, principal: Option<Uuid>, body: &[u8]) -> WebAuthnHttpResponse {
        let Some(principal) = principal else {
            return webauthn_http_error(401, "unauthenticated");
        };
        if parse_webauthn_json::<EmptyBody>(body).is_err() {
            return webauthn_http_error(400, "invalid_request");
        }
        match self.service.start_authentication(principal) {
            Ok(start) => webauthn_json_response(200, &start),
            Err(error) => webauthn_service_error(error),
        }
    }

    fn authentication_finish(&self, principal: Option<Uuid>, body: &[u8]) -> WebAuthnHttpResponse {
        let Some(principal) = principal else {
            return webauthn_http_error(401, "unauthenticated");
        };
        let request: CeremonyFinishBody = match parse_webauthn_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        let Ok(response_body) = serde_json::to_vec(&request.response) else {
            return webauthn_http_error(400, "invalid_request");
        };
        match self.service.finish_authentication_for_principal(
            &request.handle,
            principal,
            &response_body,
        ) {
            Ok(_) => webauthn_json_response(200, &serde_json::json!({"authenticated": true})),
            Err(error) => webauthn_service_error(error),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationStartBody {
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CeremonyFinishBody {
    handle: String,
    response: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

fn parse_webauthn_json<T>(body: &[u8]) -> Result<T, WebAuthnHttpResponse>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|_| webauthn_http_error(400, "invalid_request"))
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn webauthn_json_response<T>(status: u16, value: &T) -> WebAuthnHttpResponse
where
    T: Serialize,
{
    match serde_json::to_vec(value) {
        Ok(body) if body.len() <= MAX_CLIENT_RESPONSE_BYTES => WebAuthnHttpResponse {
            status,
            content_type: WEBAUTHN_JSON_CONTENT_TYPE,
            headers: WEBAUTHN_RESPONSE_SECURITY_HEADERS,
            body,
        },
        Ok(_) | Err(_) => webauthn_http_error(500, "temporarily_unavailable"),
    }
}

fn webauthn_http_error(status: u16, code: &'static str) -> WebAuthnHttpResponse {
    webauthn_json_response(status, &serde_json::json!({"error": code}))
}

fn webauthn_service_error(error: WebAuthnExampleError) -> WebAuthnHttpResponse {
    match error {
        WebAuthnExampleError::Replay => webauthn_http_error(401, "authentication_failed"),
        WebAuthnExampleError::StoreUnavailable
        | WebAuthnExampleError::CapacityReached
        | WebAuthnExampleError::StateTooLarge => {
            webauthn_http_error(503, "temporarily_unavailable")
        }
        WebAuthnExampleError::CredentialLimit => webauthn_http_error(409, "invalid_request"),
        WebAuthnExampleError::InvalidConfiguration | WebAuthnExampleError::InvalidRequest => {
            webauthn_http_error(400, "invalid_request")
        }
    }
}

fn encode_handle(handle: &LoginStateHandle) -> String {
    use core::fmt::Write;
    let mut output = String::with_capacity(HANDLE_BYTES * 2);
    for byte in handle.as_bytes() {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_handle(value: &str) -> Result<LoginStateHandle, WebAuthnExampleError> {
    if value.len() != HANDLE_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WebAuthnExampleError::InvalidRequest);
    }
    let mut bytes = [0u8; HANDLE_BYTES];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
    }
    LoginStateHandle::from_bytes(&bytes).ok_or(WebAuthnExampleError::InvalidRequest)
}

fn parse_response<T>(body: &[u8]) -> Result<T, WebAuthnExampleError>
where
    T: serde::de::DeserializeOwned,
{
    if body.is_empty() || body.len() > MAX_CLIENT_RESPONSE_BYTES {
        return Err(WebAuthnExampleError::InvalidRequest);
    }
    serde_json::from_slice(body).map_err(|_| WebAuthnExampleError::InvalidRequest)
}

fn validate_user_field(value: &str) -> Result<(), WebAuthnExampleError> {
    if value.is_empty() || value.len() > MAX_USER_FIELD_BYTES || value.chars().any(char::is_control)
    {
        return Err(WebAuthnExampleError::InvalidRequest);
    }
    Ok(())
}

fn is_allowed_origin(origin: &Url) -> bool {
    if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
        return false;
    }
    if origin.scheme() == "https" {
        return origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none();
    }
    if origin.scheme() != "http" || !origin.username().is_empty() || origin.password().is_some() {
        return false;
    }
    matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn service() -> WebAuthnExampleService {
        WebAuthnExampleService::new(
            "example.com",
            "https://login.example.com",
            "Secure Keypad Example",
            Duration::from_secs(60),
        )
        .expect("valid service")
    }

    #[test]
    fn origin_and_rp_id_are_bound_at_configuration_time() {
        assert!(WebAuthnExampleService::new(
            "example.com",
            "https://attacker.example.net",
            "Example",
            Duration::from_secs(60),
        )
        .is_err());
        assert!(WebAuthnExampleService::new(
            "example.com",
            "http://login.example.com",
            "Example",
            Duration::from_secs(60),
        )
        .is_err());
        assert!(WebAuthnExampleService::new(
            "localhost",
            "http://localhost:3000",
            "Example",
            Duration::from_secs(60),
        )
        .is_ok());
        assert!(WebAuthnExampleService::new(
            "localhost",
            "http://localhost:3000",
            "Example",
            Duration::MAX,
        )
        .is_err());
    }

    #[test]
    fn registration_state_is_consumed_before_response_processing() {
        let service = service();
        let user_id = Uuid::new_v4();
        let start = service
            .start_registration(user_id, "alice", "Alice")
            .expect("start");
        assert_eq!(start.handle.len(), 64);
        assert_eq!(service.credential_count(user_id).expect("count"), 0);
        assert_eq!(
            service.finish_registration(&start.handle, b"{}"),
            Err(WebAuthnExampleError::InvalidRequest)
        );
        assert_eq!(
            service.finish_registration(&start.handle, b"{}"),
            Err(WebAuthnExampleError::Replay)
        );
    }

    #[test]
    fn ceremony_debug_redacts_handle_and_browser_options() {
        let service = service();
        let start = service
            .start_registration(Uuid::new_v4(), "alice", "Alice")
            .expect("start");
        let debug = format!("{start:?}");

        assert!(debug.contains("handle_len"));
        assert!(!debug.contains(&start.handle));
        assert!(!debug.contains("challenge"));
    }

    #[test]
    fn unknown_authentication_does_not_enumerate_accounts() {
        let service = service();
        let error = service
            .start_authentication(Uuid::new_v4())
            .expect_err("unknown account must fail");
        assert_eq!(error, WebAuthnExampleError::InvalidRequest);
    }

    #[test]
    fn response_body_limit_is_enforced_before_json_parsing() {
        let service = service();
        let user_id = Uuid::new_v4();
        let start = service
            .start_registration(user_id, "alice", "Alice")
            .expect("start");
        let oversized = vec![b'{'; MAX_CLIENT_RESPONSE_BYTES + 1];
        assert_eq!(
            service.finish_registration(&start.handle, &oversized),
            Err(WebAuthnExampleError::InvalidRequest)
        );
    }

    #[test]
    fn response_body_limit_is_enforced_on_json_serialization() {
        let value = "x".repeat(MAX_CLIENT_RESPONSE_BYTES + 1);
        let response = webauthn_json_response(200, &value);
        assert_eq!(response.status, 500);
        assert_eq!(response.body, br#"{"error":"temporarily_unavailable"}"#);
    }

    #[test]
    fn ceremony_state_serialization_is_versioned_and_rejects_downgrades() {
        let encoded = serialize_state(&7u8).expect("serialize");
        let json: Value = serde_json::from_slice(&encoded).expect("json");
        assert_eq!(json["version"], WEBAUTHN_CEREMONY_STATE_VERSION);
        assert_eq!(
            deserialize_state::<u8>(br#"{"version":0,"state":7}"#),
            Err(WebAuthnExampleError::StoreUnavailable)
        );
    }

    proptest! {
        #[test]
        fn malformed_handles_never_enter_the_state_store(value in "[A-Fa-f0-9]{0,140}") {
            prop_assert!(decode_handle(&value).is_err());
        }
    }
}
