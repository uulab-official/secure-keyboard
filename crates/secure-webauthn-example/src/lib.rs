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
//! The included state and credential stores are process-local examples. A
//! production deployment must replace them with an encrypted, access
//! controlled store and an atomic consume operation for ceremony state.

use rand::{rngs::OsRng, RngCore};
use secure_auth_server::LoginStateHandle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};
use zeroize::Zeroize;

/// Maximum JSON response body accepted by the reference boundary.
pub const MAX_CLIENT_RESPONSE_BYTES: usize = 128 * 1024;
/// Maximum number of credentials associated with one example account.
pub const MAX_CREDENTIALS_PER_USER: usize = 64;
/// Maximum number of pending ceremony states in one example process.
pub const MAX_PENDING_CEREMONIES: usize = 100_000;
/// Maximum user name or display name accepted by the example boundary.
pub const MAX_USER_FIELD_BYTES: usize = 256;
const HANDLE_BYTES: usize = 32;
const HANDLE_ATTEMPTS: usize = 4;

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
#[derive(Debug, Serialize)]
pub struct CeremonyStart {
    /// Fixed-size lowercase hexadecimal one-time handle.
    pub handle: String,
    /// Server-generated `WebAuthn` options for the browser adapter.
    pub options: Value,
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

struct PendingState<T> {
    expires_at: Instant,
    value: T,
}

struct OneTimeCeremonyStore<T> {
    entries: Mutex<HashMap<LoginStateHandle, PendingState<T>>>,
    max_entries: usize,
    ttl: Duration,
}

impl<T> OneTimeCeremonyStore<T> {
    fn new(max_entries: usize, ttl: Duration) -> Result<Self, WebAuthnExampleError> {
        if max_entries == 0 || max_entries > MAX_PENDING_CEREMONIES || ttl.is_zero() {
            return Err(WebAuthnExampleError::InvalidConfiguration);
        }
        Ok(Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
            ttl,
        })
    }

    fn prune_expired(entries: &mut HashMap<LoginStateHandle, PendingState<T>>, now: Instant) {
        entries.retain(|_, entry| entry.expires_at > now);
    }

    fn insert(&self, value: T) -> Result<LoginStateHandle, WebAuthnExampleError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
        Self::prune_expired(&mut entries, now);
        if entries.len() >= self.max_entries {
            return Err(WebAuthnExampleError::CapacityReached);
        }
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = fresh_handle();
            if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(handle) {
                slot.insert(PendingState {
                    expires_at: now + self.ttl,
                    value,
                });
                return Ok(handle);
            }
        }
        Err(WebAuthnExampleError::StoreUnavailable)
    }

    fn take(&self, handle: &LoginStateHandle) -> Result<T, WebAuthnExampleError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
        Self::prune_expired(&mut entries, now);
        entries
            .remove(handle)
            .map(|entry| entry.value)
            .ok_or(WebAuthnExampleError::Replay)
    }
}

struct RegistrationPending {
    user_id: Uuid,
    state: PasskeyRegistration,
}

struct AuthenticationPending {
    user_id: Uuid,
    state: PasskeyAuthentication,
}

/// An in-memory passkey-first reference service.
pub struct WebAuthnExampleService {
    webauthn: Webauthn,
    registration_states: OneTimeCeremonyStore<RegistrationPending>,
    authentication_states: OneTimeCeremonyStore<AuthenticationPending>,
    credentials: Mutex<HashMap<Uuid, Vec<Passkey>>>,
}

impl WebAuthnExampleService {
    /// Builds a service with strict origin/RP-ID binding.
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
        if rp_id.is_empty()
            || rp_id.len() > 253
            || rp_id.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(WebAuthnExampleError::InvalidConfiguration);
        }
        validate_user_field(rp_name).map_err(|_| WebAuthnExampleError::InvalidConfiguration)?;
        let parsed_origin =
            Url::parse(origin).map_err(|_| WebAuthnExampleError::InvalidConfiguration)?;
        if !is_allowed_origin(&parsed_origin) {
            return Err(WebAuthnExampleError::InvalidConfiguration);
        }
        let webauthn = WebauthnBuilder::new(rp_id, &parsed_origin)
            .map_err(|_| WebAuthnExampleError::InvalidConfiguration)?
            .rp_name(rp_name)
            .build()
            .map_err(|_| WebAuthnExampleError::InvalidConfiguration)?;
        Ok(Self {
            webauthn,
            registration_states: OneTimeCeremonyStore::new(MAX_PENDING_CEREMONIES, ceremony_ttl)?,
            authentication_states: OneTimeCeremonyStore::new(MAX_PENDING_CEREMONIES, ceremony_ttl)?,
            credentials: Mutex::new(HashMap::new()),
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
        let existing = self.credentials_for(user_id)?;
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
        let handle = self
            .registration_states
            .insert(RegistrationPending { user_id, state })?;
        let options =
            serde_json::to_value(options).map_err(|_| WebAuthnExampleError::InvalidRequest)?;
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
        let pending = self.registration_states.take(&handle)?;
        if expected_principal.is_some_and(|principal| principal != pending.user_id) {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let response: RegisterPublicKeyCredential = parse_response(response_body)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&response, &pending.state)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let mut credentials = self
            .credentials
            .lock()
            .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
        let user_credentials = credentials.entry(pending.user_id).or_default();
        if user_credentials.iter().any(|existing| existing == &passkey) {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        if user_credentials.len() >= MAX_CREDENTIALS_PER_USER {
            return Err(WebAuthnExampleError::CredentialLimit);
        }
        user_credentials.push(passkey);
        Ok(RegistrationOutcome {
            user_id: pending.user_id,
        })
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
        let credentials = self.credentials_for(user_id)?;
        if credentials.is_empty() {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let handle = self
            .authentication_states
            .insert(AuthenticationPending { user_id, state })?;
        let options =
            serde_json::to_value(options).map_err(|_| WebAuthnExampleError::InvalidRequest)?;
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
        let pending = self.authentication_states.take(&handle)?;
        if expected_principal.is_some_and(|principal| principal != pending.user_id) {
            return Err(WebAuthnExampleError::InvalidRequest);
        }
        let response: PublicKeyCredential = parse_response(response_body)?;
        let result: AuthenticationResult = self
            .webauthn
            .finish_passkey_authentication(&response, &pending.state)
            .map_err(|_| WebAuthnExampleError::InvalidRequest)?;
        let mut credentials = self
            .credentials
            .lock()
            .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
        let user_credentials = credentials
            .get_mut(&pending.user_id)
            .ok_or(WebAuthnExampleError::InvalidRequest)?;
        let mut updated = false;
        for credential in user_credentials {
            if let Some(changed) = credential.update_credential(&result) {
                updated = changed;
                break;
            }
        }
        Ok(AuthenticationOutcome {
            user_id: pending.user_id,
            credential_updated: updated,
        })
    }

    /// Returns the number of credentials in the reference store for tests and
    /// operational health checks. It exposes no credential material.
    ///
    /// # Errors
    ///
    /// Returns [`WebAuthnExampleError::StoreUnavailable`] if the store lock is
    /// poisoned.
    pub fn credential_count(&self, user_id: Uuid) -> Result<usize, WebAuthnExampleError> {
        Ok(self.credentials_for(user_id)?.len())
    }

    fn credentials_for(&self, user_id: Uuid) -> Result<Vec<Passkey>, WebAuthnExampleError> {
        let credentials = self
            .credentials
            .lock()
            .map_err(|_| WebAuthnExampleError::StoreUnavailable)?;
        Ok(credentials.get(&user_id).cloned().unwrap_or_default())
    }
}

/// Exact API prefix used by the framework-neutral `WebAuthn` routes.
pub const WEBAUTHN_API_PREFIX: &str = "/v1/webauthn";
/// JSON media type emitted by the `WebAuthn` route contract.
pub const WEBAUTHN_JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

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
    /// Raw bounded JSON body.
    pub body: &'a [u8],
}

/// An owned bounded JSON response. Response bytes are cleared on drop.
pub struct WebAuthnHttpResponse {
    /// HTTP status selected by the route contract.
    pub status: u16,
    /// Always [`WEBAUTHN_JSON_CONTENT_TYPE`].
    pub content_type: &'static str,
    /// JSON body bytes, cleared when the response is dropped.
    pub body: Vec<u8>,
}

impl Drop for WebAuthnHttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// Framework-neutral bounded `WebAuthn` route handler.
pub struct WebAuthnHttpRouter<'a> {
    service: &'a WebAuthnExampleService,
}

impl<'a> WebAuthnHttpRouter<'a> {
    /// Creates a router around a configured reference service.
    #[must_use]
    pub const fn new(service: &'a WebAuthnExampleService) -> Self {
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
        Ok(body) => WebAuthnHttpResponse {
            status,
            content_type: WEBAUTHN_JSON_CONTENT_TYPE,
            body,
        },
        Err(_) => webauthn_http_error(500, "temporarily_unavailable"),
    }
}

fn webauthn_http_error(status: u16, code: &'static str) -> WebAuthnHttpResponse {
    webauthn_json_response(status, &serde_json::json!({"error": code}))
}

fn webauthn_service_error(error: WebAuthnExampleError) -> WebAuthnHttpResponse {
    match error {
        WebAuthnExampleError::Replay => webauthn_http_error(401, "authentication_failed"),
        WebAuthnExampleError::StoreUnavailable | WebAuthnExampleError::CapacityReached => {
            webauthn_http_error(503, "temporarily_unavailable")
        }
        WebAuthnExampleError::CredentialLimit => webauthn_http_error(409, "invalid_request"),
        WebAuthnExampleError::InvalidConfiguration | WebAuthnExampleError::InvalidRequest => {
            webauthn_http_error(400, "invalid_request")
        }
    }
}

fn fresh_handle() -> LoginStateHandle {
    let mut bytes = [0u8; HANDLE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    LoginStateHandle::from_bytes(&bytes).expect("fixed handle length")
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

    proptest! {
        #[test]
        fn malformed_handles_never_enter_the_state_store(value in "[A-Fa-f0-9]{0,140}") {
            prop_assert!(decode_handle(&value).is_err());
        }
    }
}
