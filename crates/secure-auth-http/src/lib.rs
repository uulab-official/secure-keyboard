#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded HTTP/JSON route contracts for the Secure Keypad OPAQUE service.
//!
//! This crate intentionally stops at a framework-neutral request/response
//! boundary. It enforces HTTP method, media type, body size, JSON schema,
//! generic public errors, and one-time login-handle consumption. The caller
//! must provide a [`HttpDeploymentContext`] proving that TLS and upstream
//! body/connection limits were established; certificate policy, proxy source
//! allowlisting, and session-token issuance remain responsibilities of the
//! embedding server. Each request must also carry explicit host-validated CSRF
//! and rate-limit admission results.

use secure_auth::{AuthEnvelope, CredentialFile, MAX_IDENTIFIER_BYTES, MAX_JSON_BODY_BYTES};
use secure_auth_server::{
    BoundOneTimeLoginStateStore, LoginStateHandle, PublicAuthCode, ServerAuthError,
    ServerAuthService, StoreError,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroize;

/// Exact API prefix used by the reference routes.
pub const API_PREFIX: &str = "/v1/opaque";
/// Version of the framework-neutral HTTP/JSON route contract.
///
/// The Node/TypeScript transport bridge is checked against this value by the
/// repository's release parity gate. It is independent from the OPAQUE
/// protocol version carried inside [`AuthEnvelope`].
pub const HTTP_CONTRACT_VERSION: u16 = 1;
/// Maximum request body accepted by the route boundary.
pub const MAX_HTTP_BODY_BYTES: usize = MAX_JSON_BODY_BYTES;
/// JSON content type emitted by every response.
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
/// Stable successful login response. It contains no session token or secret.
pub const AUTHENTICATED_RESPONSE: &[u8] = br#"{"authenticated":true}"#;
/// Stable successful registration-storage response. The credential file is
/// persisted by the repository and is never returned to the HTTP caller.
pub const REGISTRATION_STORED_RESPONSE: &[u8] = br#"{"credentialStored":true}"#;
/// Stable generic response for a host rate-limit denial.
pub const RATE_LIMITED_RESPONSE: &[u8] = br#"{"error":"rate_limited"}"#;

/// A static response header that a framework adapter can copy verbatim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHeader {
    /// Lowercase HTTP header name.
    pub name: &'static str,
    /// Header value.
    pub value: &'static str,
}

/// Security headers attached to every authentication response.
pub const RESPONSE_SECURITY_HEADERS: &[HttpHeader] = &[
    HttpHeader {
        name: "cache-control",
        value: "no-store",
    },
    HttpHeader {
        name: "pragma",
        value: "no-cache",
    },
    HttpHeader {
        name: "x-content-type-options",
        value: "nosniff",
    },
    HttpHeader {
        name: "referrer-policy",
        value: "no-referrer",
    },
    HttpHeader {
        name: "content-security-policy",
        value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    },
];

/// Failure classes for a declared HTTP `Content-Length` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentLengthError {
    /// The value is malformed or not representable as a non-negative
    /// machine-sized decimal integer.
    Invalid,
    /// The value is valid but exceeds the caller's enforced body limit.
    TooLarge,
}

/// Validates one declared HTTP `Content-Length` value before body buffering.
///
/// An absent header is valid because chunked or streaming requests do not have
/// to declare their size. A present value must contain only ASCII decimal
/// digits after surrounding whitespace is removed; signs, comma-separated
/// values, overflow, and values above `limit` are rejected. Framework
/// adapters must separately reject duplicate header fields and invalid header
/// bytes before calling this function.
///
/// # Errors
///
/// Returns [`ContentLengthError::Invalid`] for malformed or overflowing
/// values, and [`ContentLengthError::TooLarge`] when the parsed value exceeds
/// `limit`.
pub fn validate_content_length(
    value: Option<&str>,
    limit: usize,
) -> Result<(), ContentLengthError> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ContentLengthError::Invalid);
    }
    let length = value
        .parse::<usize>()
        .map_err(|_| ContentLengthError::Invalid)?;
    if length > limit {
        return Err(ContentLengthError::TooLarge);
    }
    Ok(())
}

const REGISTRATION_START_PATH: &str = "/v1/opaque/registration/start";
const REGISTRATION_FINISH_PATH: &str = "/v1/opaque/registration/finish";
const LOGIN_START_PATH: &str = "/v1/opaque/login/start";
const LOGIN_FINISH_PATH: &str = "/v1/opaque/login/finish";
const HANDLE_BYTES: usize = 32;

/// Transport state established by the embedding HTTP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportSecurity {
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

impl TransportSecurity {
    const fn is_encrypted(self) -> bool {
        !matches!(self, Self::Plaintext)
    }
}

/// Host-side request admission result established before body buffering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestAdmission {
    /// The account/IP/deployment rate-limit checks allowed this request.
    Allowed,
    /// A configured rate-limit policy denied this request.
    RateLimited,
    /// The admission backend could not make a safe decision.
    Unavailable,
}

/// Host-side platform-integrity result established before body buffering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceIntegrityDecision {
    /// The host verified Play Integrity, App Attest, DeviceCheck, or an
    /// equivalent server-verifiable signal bound to this authentication.
    Verified,
    /// The host verified that the request must not authenticate.
    Rejected,
    /// The host could not make a safe integrity decision.
    Unavailable,
}

/// Deployment controls that must be established before a route reads JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpDeploymentContext {
    transport: TransportSecurity,
    upstream_body_limit_bytes: usize,
    connection_limits_enforced: bool,
}

impl HttpDeploymentContext {
    /// Creates a context from host-validated transport and proxy limits.
    ///
    /// `upstream_body_limit_bytes` must be no greater than
    /// [`MAX_HTTP_BODY_BYTES`]. The host must enforce this limit before
    /// buffering the request body, and must enforce connection/read timeouts
    /// before calling the route.
    #[must_use]
    pub const fn new(
        transport: TransportSecurity,
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
        Self::new(TransportSecurity::DirectTls, MAX_HTTP_BODY_BYTES, true)
    }

    /// Returns the standard context for a previously validated trusted proxy.
    #[must_use]
    pub const fn trusted_proxy_tls() -> Self {
        Self::new(
            TransportSecurity::TrustedProxyTls,
            MAX_HTTP_BODY_BYTES,
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
            && self.upstream_body_limit_bytes <= MAX_HTTP_BODY_BYTES
            && self.connection_limits_enforced
    }
}

/// A borrowed HTTP request view suitable for an Axum, Actix, Go, Java, or
/// ASP.NET adapter.
#[derive(Clone, Copy)]
pub struct HttpRequest<'a> {
    /// HTTP method, expected to be `POST` for every auth route.
    pub method: &'a str,
    /// Exact route path without query parameters.
    pub path: &'a str,
    /// Request media type from the transport layer.
    pub content_type: Option<&'a str>,
    /// Whether the embedding server validated its CSRF/origin policy for this
    /// request. The route never derives this value from the JSON body.
    pub csrf_validated: bool,
    /// The host's pre-buffering account/IP/deployment admission decision.
    pub admission: RequestAdmission,
    /// Raw request body. It is bounded before JSON deserialization.
    pub body: &'a [u8],
}

/// An owned response. OPAQUE response bytes are zeroized when the response is
/// dropped; callers should write the body to the TLS response stream promptly.
pub struct HttpResponse {
    /// HTTP status code selected by the generic route contract.
    pub status: u16,
    /// Always [`JSON_CONTENT_TYPE`] for this adapter.
    pub content_type: &'static str,
    /// Static cache, MIME, referrer, and CSP headers for the adapter to emit.
    pub headers: &'static [HttpHeader],
    /// JSON body bytes, zeroized on drop.
    pub body: Vec<u8>,
}

/// Builds the generic response for a pre-buffering admission decision.
#[must_use]
pub fn request_admission_response(admission: RequestAdmission) -> Option<HttpResponse> {
    match admission {
        RequestAdmission::Allowed => None,
        RequestAdmission::RateLimited => Some(static_response(429, RATE_LIMITED_RESPONSE)),
        RequestAdmission::Unavailable => {
            Some(error_response(503, PublicAuthCode::TemporarilyUnavailable))
        }
    }
}

/// Builds the generic response for a financial device-integrity decision.
#[must_use]
pub fn device_integrity_response(decision: DeviceIntegrityDecision) -> Option<HttpResponse> {
    match decision {
        DeviceIntegrityDecision::Verified => None,
        DeviceIntegrityDecision::Rejected => {
            Some(error_response(403, PublicAuthCode::InvalidRequest))
        }
        DeviceIntegrityDecision::Unavailable => {
            Some(error_response(503, PublicAuthCode::TemporarilyUnavailable))
        }
    }
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl HttpResponse {
    /// Transfers the response body to a framework response writer.
    ///
    /// The returned body is now owned by the framework and must be written
    /// promptly. The response shell is dropped with an empty body so it does
    /// not duplicate or retain the transferred bytes.
    #[must_use]
    pub fn into_parts(self) -> (u16, &'static str, &'static [HttpHeader], Vec<u8>) {
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

/// Protected credential-file persistence boundary.
pub trait CredentialRepository {
    /// Loads a protected copy of the credential file for a public account
    /// identifier without removing the stored record. Unknown accounts must
    /// return `Ok(None)` so the OPAQUE dummy path can run. Credential lookup is
    /// persistent; only the separate login state handle is one-time.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Unavailable`] when the protected store
    /// cannot safely serve the lookup.
    fn load(&self, identifier: &[u8]) -> Result<Option<CredentialFile>, RepositoryError>;

    /// Creates a credential file under a public identifier without replacing
    /// an existing record. Implementations must enforce this create-only
    /// operation atomically with the uniqueness check, and must encrypt or
    /// access-control the file at rest.
    ///
    /// # Errors
    ///
    /// Returns a repository error when protected persistence is unavailable,
    /// rejects the identifier, or already contains a credential for it. The
    /// create-only check must be atomic with persistence.
    fn create(&self, identifier: &[u8], credential: CredentialFile) -> Result<(), RepositoryError>;
}

/// Stable repository failure classes. Internal database errors must be mapped
/// to these classes before reaching the route boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// The protected credential backend cannot safely serve the request.
    Unavailable,
    /// The repository rejected the bounded public identifier.
    InvalidIdentifier,
    /// A credential already exists for the public identifier. The route maps
    /// this to the same generic invalid-request response as other enrollment
    /// conflicts.
    AlreadyExists,
}

/// Framework-neutral OPAQUE HTTP route handler.
pub struct HttpAuthRouter<S, R> {
    service: ServerAuthService<S>,
    repository: R,
}

impl<S, R> HttpAuthRouter<S, R>
where
    S: BoundOneTimeLoginStateStore,
    R: CredentialRepository,
{
    /// Creates the route handler around a configured OPAQUE service and a
    /// protected credential repository.
    #[must_use]
    pub fn new(service: ServerAuthService<S>, repository: R) -> Self {
        Self {
            service,
            repository,
        }
    }

    /// Handles one bounded request without logging its body, identifiers,
    /// handles, or protocol errors.
    ///
    /// The context is mandatory so a framework adapter cannot accidentally
    /// expose the route over plaintext HTTP or omit the reverse-proxy body and
    /// connection limits.
    #[must_use]
    pub fn handle(&self, request: HttpRequest<'_>, context: HttpDeploymentContext) -> HttpResponse {
        if !context.transport.is_encrypted() {
            return error_response(400, PublicAuthCode::InvalidRequest);
        }
        if !context.has_valid_limits() {
            return error_response(503, PublicAuthCode::TemporarilyUnavailable);
        }
        if !request.csrf_validated {
            return error_response(403, PublicAuthCode::InvalidRequest);
        }
        if let Some(response) = request_admission_response(request.admission) {
            return response;
        }
        if request.body.len() > context.upstream_body_limit_bytes {
            return error_response(413, PublicAuthCode::InvalidRequest);
        }
        if request.method != "POST" {
            return error_response(405, PublicAuthCode::InvalidRequest);
        }
        if !is_json_content_type(request.content_type) {
            return error_response(415, PublicAuthCode::InvalidRequest);
        }

        match request.path {
            REGISTRATION_START_PATH => self.registration_start(request.body),
            REGISTRATION_FINISH_PATH => self.registration_finish(request.body),
            LOGIN_START_PATH => self.login_start(request.body),
            LOGIN_FINISH_PATH => self.login_finish(request.body),
            _ => error_response(404, PublicAuthCode::InvalidRequest),
        }
    }

    fn registration_start(&self, body: &[u8]) -> HttpResponse {
        let request: RegistrationStartRequest = match parse_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        if !valid_identifier(request.identifier.as_bytes()) {
            return error_response(400, PublicAuthCode::InvalidRequest);
        }
        let response = match self
            .service
            .begin_registration(request.envelope, request.identifier.as_bytes())
        {
            Ok(response) => response,
            Err(error) => return auth_error_response(error),
        };
        json_response(RegistrationStartResponse { envelope: response })
    }

    fn registration_finish(&self, body: &[u8]) -> HttpResponse {
        let request: EnvelopeRequest = match parse_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        if !valid_identifier(request.identifier.as_bytes()) {
            return error_response(400, PublicAuthCode::InvalidRequest);
        }
        let credential = match self.service.finish_registration(request.envelope) {
            Ok(credential) => credential,
            Err(error) => return auth_error_response(error),
        };
        if let Err(error) = self
            .repository
            .create(request.identifier.as_bytes(), credential)
        {
            return repository_error_response(error);
        }
        static_response(200, REGISTRATION_STORED_RESPONSE)
    }

    fn login_start(&self, body: &[u8]) -> HttpResponse {
        let request: LoginStartRequest = match parse_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        if !valid_identifier(request.credential_identifier.as_bytes())
            || !valid_identifier(request.client_identifier.as_bytes())
            || !valid_identifier(request.server_identifier.as_bytes())
        {
            return error_response(400, PublicAuthCode::InvalidRequest);
        }
        let credential = match self
            .repository
            .load(request.credential_identifier.as_bytes())
        {
            Ok(credential) => credential,
            Err(error) => return repository_error_response(error),
        };
        let (response, handle) = match self.service.begin_login(
            request.envelope,
            credential.as_ref(),
            request.credential_identifier.as_bytes(),
            request.client_identifier.as_bytes(),
            request.server_identifier.as_bytes(),
        ) {
            Ok(result) => result,
            Err(error) => return auth_error_response(error),
        };
        json_response(LoginStartResponse {
            envelope: response,
            handle: encode_handle(&handle),
        })
    }

    fn login_finish(&self, body: &[u8]) -> HttpResponse {
        let request: LoginFinishRequest = match parse_json(body) {
            Ok(request) => request,
            Err(response) => return response,
        };
        let Some(handle) = decode_handle(&request.handle) else {
            return error_response(400, PublicAuthCode::InvalidRequest);
        };
        let output = match self.service.finish_login(request.envelope, &handle) {
            Ok(output) => output,
            Err(error) => return auth_error_response(error),
        };
        drop(output);
        static_response(200, AUTHENTICATED_RESPONSE)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationStartRequest {
    identifier: String,
    envelope: AuthEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeRequest {
    identifier: String,
    envelope: AuthEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStartRequest {
    credential_identifier: String,
    client_identifier: String,
    server_identifier: String,
    envelope: AuthEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishRequest {
    handle: String,
    envelope: AuthEnvelope,
}

#[derive(Serialize)]
struct RegistrationStartResponse {
    envelope: AuthEnvelope,
}

#[derive(Serialize)]
struct LoginStartResponse {
    envelope: AuthEnvelope,
    handle: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, HttpResponse> {
    serde_json::from_slice(body).map_err(|_| error_response(400, PublicAuthCode::InvalidRequest))
}

fn valid_identifier(identifier: &[u8]) -> bool {
    !identifier.is_empty() && identifier.len() <= MAX_IDENTIFIER_BYTES
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn auth_error_response(error: ServerAuthError) -> HttpResponse {
    let code = error.public_code();
    let status = match code {
        PublicAuthCode::InvalidRequest => 400,
        PublicAuthCode::AuthenticationFailed => 401,
        PublicAuthCode::TemporarilyUnavailable => 503,
    };
    error_response(status, code)
}

fn repository_error_response(error: RepositoryError) -> HttpResponse {
    let code = match error {
        RepositoryError::Unavailable => PublicAuthCode::TemporarilyUnavailable,
        RepositoryError::InvalidIdentifier | RepositoryError::AlreadyExists => {
            PublicAuthCode::InvalidRequest
        }
    };
    error_response(
        match code {
            PublicAuthCode::InvalidRequest => 400,
            PublicAuthCode::AuthenticationFailed => 401,
            PublicAuthCode::TemporarilyUnavailable => 503,
        },
        code,
    )
}

fn error_response(status: u16, code: PublicAuthCode) -> HttpResponse {
    json_response_with_status(
        status,
        ErrorResponse {
            error: code.as_str(),
        },
    )
}

fn json_response<T: Serialize>(value: T) -> HttpResponse {
    json_response_with_status(200, value)
}

fn json_response_with_status<T: Serialize>(status: u16, value: T) -> HttpResponse {
    let body = serde_json::to_vec(&value)
        .unwrap_or_else(|_| br#"{"error":"temporarily_unavailable"}"#.to_vec());
    if body.len() > MAX_HTTP_BODY_BYTES {
        return static_response(503, br#"{"error":"temporarily_unavailable"}"#);
    }
    HttpResponse {
        status,
        content_type: JSON_CONTENT_TYPE,
        headers: RESPONSE_SECURITY_HEADERS,
        body,
    }
}

fn static_response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        content_type: JSON_CONTENT_TYPE,
        headers: RESPONSE_SECURITY_HEADERS,
        body: body.to_vec(),
    }
}

fn encode_handle(handle: &LoginStateHandle) -> String {
    let mut output = String::with_capacity(HANDLE_BYTES * 2);
    for byte in handle.as_bytes() {
        use core::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_handle(value: &str) -> Option<LoginStateHandle> {
    if value.len() != HANDLE_BYTES * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; HANDLE_BYTES];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    LoginStateHandle::from_bytes(&bytes)
}

impl From<StoreError> for RepositoryError {
    fn from(_: StoreError) -> Self {
        Self::Unavailable
    }
}
