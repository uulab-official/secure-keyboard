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
    CredentialRepository, HttpAuthRouter, HttpDeploymentContext, HttpRequest as ContractRequest,
    HttpResponse as ContractResponse, JSON_CONTENT_TYPE, RESPONSE_SECURITY_HEADERS,
};
use secure_auth_server::BoundOneTimeLoginStateStore;
use std::sync::Arc;

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
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > body_limit)
    {
        return invalid_request_response(413);
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
