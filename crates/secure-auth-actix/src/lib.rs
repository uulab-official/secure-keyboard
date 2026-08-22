#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Compile-tested Actix Web adapter for the framework-neutral OPAQUE HTTP
//! contract.
//!
//! The adapter does not terminate TLS, inspect forwarded transport headers, or
//! create application sessions. The host must establish a validated
//! [`HttpDeploymentContext`] and provide a request-parts-only CSRF callback.
//! Request bodies are rejected before buffering when the callback or the
//! deployment context fails, and Actix's bounded payload collector is used for
//! every request that reaches JSON dispatch.

use actix_web::{
    http::{header, StatusCode},
    web::{self, Data, Payload},
    HttpRequest, HttpResponse, Scope,
};
use secure_auth_http::{
    validate_content_length, ContentLengthError, CredentialRepository, HttpAuthRouter,
    HttpDeploymentContext, HttpRequest as ContractRequest, HttpResponse as ContractResponse,
    JSON_CONTENT_TYPE, RESPONSE_SECURITY_HEADERS,
};
use secure_auth_server::BoundOneTimeLoginStateStore;
use std::sync::Arc;

#[cfg(feature = "webauthn")]
use secure_webauthn_example::{
    CeremonyStateStore, CredentialStore, WebAuthnDeploymentContext, WebAuthnHttpRequest,
    WebAuthnHttpResponse, WebAuthnHttpRouter, WebAuthnService, WEBAUTHN_JSON_CONTENT_TYPE,
    WEBAUTHN_RESPONSE_SECURITY_HEADERS,
};
#[cfg(feature = "webauthn")]
use uuid::Uuid;

struct AppState<S, R, P> {
    router: HttpAuthRouter<S, R>,
    context: HttpDeploymentContext,
    csrf: Arc<P>,
}

/// Builds an Actix [`Scope`] for the Secure Keypad OPAQUE routes.
///
/// Mount the returned scope on the application without a path rewrite, for
/// example with `App::new().service(secure_auth_actix::router(...))`. The
/// adapter forwards every path to the framework-neutral contract so unknown
/// paths receive its generic JSON error rather than an Actix error page.
///
/// `csrf` must validate the host's same-origin/CSRF policy using request parts
/// only. It is called before the request payload is buffered. TLS termination,
/// reverse-proxy source validation, connection/read timeouts, rate limiting,
/// credential persistence, and session issuance remain application
/// responsibilities.
pub fn router<S, R, P>(
    auth_router: HttpAuthRouter<S, R>,
    context: HttpDeploymentContext,
    csrf: P,
) -> Scope
where
    S: BoundOneTimeLoginStateStore + Send + Sync + 'static,
    R: CredentialRepository + Send + Sync + 'static,
    P: Fn(&HttpRequest) -> bool + Send + Sync + 'static,
{
    let state = Data::new(AppState {
        router: auth_router,
        context,
        csrf: Arc::new(csrf),
    });
    web::scope("")
        .app_data(state)
        .default_service(web::to(handle_request::<S, R, P>))
}

async fn handle_request<S, R, P>(
    state: Data<AppState<S, R, P>>,
    request: HttpRequest,
    payload: Payload,
) -> HttpResponse
where
    S: BoundOneTimeLoginStateStore + Send + Sync + 'static,
    R: CredentialRepository + Send + Sync + 'static,
    P: Fn(&HttpRequest) -> bool + Send + Sync + 'static,
{
    if !state.context.is_ready() {
        return deployment_unavailable_response();
    }

    if !(state.csrf)(&request) {
        return invalid_request_response(403);
    }

    let body_limit = state.context.body_limit_bytes();
    if let Some(error) = content_length_error(request.headers(), body_limit) {
        return invalid_request_response(content_length_status(error));
    }

    let method = request.method().as_str().to_owned();
    let path = request.path().to_owned();
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Ok(Ok(body)) = payload.to_bytes_limited(body_limit).await else {
        return invalid_request_response(413);
    };

    response_from(state.router.handle(
        ContractRequest {
            method: &method,
            path: &path,
            content_type: content_type.as_deref(),
            csrf_validated: true,
            body: &body,
        },
        state.context,
    ))
}

fn content_length_error(
    headers: &actix_web::http::header::HeaderMap,
    limit: usize,
) -> Option<ContentLengthError> {
    let mut values = headers.get_all(header::CONTENT_LENGTH);
    let first = values.next()?;
    if values.next().is_some() {
        return Some(ContentLengthError::Invalid);
    }
    let Ok(value) = first.to_str() else {
        return Some(ContentLengthError::Invalid);
    };
    validate_content_length(Some(value), limit).err()
}

fn content_length_status(error: ContentLengthError) -> u16 {
    match error {
        ContentLengthError::Invalid => 400,
        ContentLengthError::TooLarge => 413,
    }
}

fn response_from(response: ContractResponse) -> HttpResponse {
    let (status, content_type, response_headers, body) = response.into_parts();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    builder.insert_header((header::CONTENT_TYPE, content_type));
    for item in response_headers {
        builder.insert_header((item.name, item.value));
    }
    builder.body(body)
}

/// Creates the generic response used when the Actix host rejects a request
/// before route dispatch.
#[must_use]
pub fn invalid_request_response(status: u16) -> HttpResponse {
    static_error_response(status, br#"{"error":"invalid_request"}"#)
}

/// Creates the generic response used when the host did not establish a safe
/// deployment context.
#[must_use]
pub fn deployment_unavailable_response() -> HttpResponse {
    static_error_response(503, br#"{"error":"temporarily_unavailable"}"#)
}

fn static_error_response(status: u16, body: &[u8]) -> HttpResponse {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    builder.insert_header((header::CONTENT_TYPE, JSON_CONTENT_TYPE));
    for item in RESPONSE_SECURITY_HEADERS {
        builder.insert_header((item.name, item.value));
    }
    builder.body(body.to_vec())
}

#[cfg(feature = "webauthn")]
struct WebAuthnAppState<C, S, P, X> {
    service: Arc<WebAuthnService<C, S>>,
    context: WebAuthnDeploymentContext,
    principal: Arc<P>,
    csrf: Arc<X>,
}

#[cfg(feature = "webauthn")]
/// Builds an Actix [`Scope`] for the framework-neutral `WebAuthn` routes.
///
/// The host `principal` resolver receives only Actix request metadata and must
/// resolve the account from the host session. It is called after bounded body
/// collection, while `csrf` is called before collection. Neither resolver may
/// read a browser-supplied JSON principal. TLS termination, proxy validation,
/// credential/ceremony persistence, and session issuance remain host duties.
pub fn webauthn_router<C, S, P, X>(
    service: Arc<WebAuthnService<C, S>>,
    context: WebAuthnDeploymentContext,
    principal: P,
    csrf: X,
) -> Scope
where
    C: CredentialStore + Send + Sync + 'static,
    S: CeremonyStateStore + Send + Sync + 'static,
    P: Fn(&HttpRequest) -> Option<Uuid> + Send + Sync + 'static,
    X: Fn(&HttpRequest) -> bool + Send + Sync + 'static,
{
    let state = Data::new(WebAuthnAppState {
        service,
        context,
        principal: Arc::new(principal),
        csrf: Arc::new(csrf),
    });
    web::scope("")
        .app_data(state)
        .default_service(web::to(webauthn_handle_request::<C, S, P, X>))
}

#[cfg(feature = "webauthn")]
async fn webauthn_handle_request<C, S, P, X>(
    state: Data<WebAuthnAppState<C, S, P, X>>,
    request: HttpRequest,
    payload: Payload,
) -> HttpResponse
where
    C: CredentialStore + Send + Sync + 'static,
    S: CeremonyStateStore + Send + Sync + 'static,
    P: Fn(&HttpRequest) -> Option<Uuid> + Send + Sync + 'static,
    X: Fn(&HttpRequest) -> bool + Send + Sync + 'static,
{
    if !state.context.is_ready() {
        return webauthn_deployment_unavailable_response();
    }
    if !(state.csrf)(&request) {
        return webauthn_invalid_request_response(403);
    }

    let body_limit = state.context.body_limit_bytes();
    if let Some(error) = content_length_error(request.headers(), body_limit) {
        return webauthn_invalid_request_response(content_length_status(error));
    }

    let method = request.method().as_str().to_owned();
    let path = request.path().to_owned();
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Ok(Ok(body)) = payload.to_bytes_limited(body_limit).await else {
        return webauthn_invalid_request_response(413);
    };
    let principal = (state.principal)(&request);
    let response = WebAuthnHttpRouter::new(state.service.as_ref()).handle(
        WebAuthnHttpRequest {
            method: &method,
            path: &path,
            content_type: content_type.as_deref(),
            principal,
            csrf_validated: true,
            body: &body,
        },
        state.context,
    );
    webauthn_response_from(response)
}

#[cfg(feature = "webauthn")]
fn webauthn_response_from(response: WebAuthnHttpResponse) -> HttpResponse {
    let (status, content_type, response_headers, body) = response.into_parts();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    builder.insert_header((header::CONTENT_TYPE, content_type));
    for item in response_headers {
        builder.insert_header((item.name, item.value));
    }
    builder.body(body)
}

#[cfg(feature = "webauthn")]
fn webauthn_invalid_request_response(status: u16) -> HttpResponse {
    webauthn_static_error_response(status, br#"{"error":"invalid_request"}"#)
}

#[cfg(feature = "webauthn")]
fn webauthn_deployment_unavailable_response() -> HttpResponse {
    webauthn_static_error_response(503, br#"{"error":"temporarily_unavailable"}"#)
}

#[cfg(feature = "webauthn")]
fn webauthn_static_error_response(status: u16, body: &[u8]) -> HttpResponse {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    builder.insert_header((header::CONTENT_TYPE, WEBAUTHN_JSON_CONTENT_TYPE));
    for item in WEBAUTHN_RESPONSE_SECURITY_HEADERS {
        builder.insert_header((item.name, item.value));
    }
    builder.body(body.to_vec())
}
