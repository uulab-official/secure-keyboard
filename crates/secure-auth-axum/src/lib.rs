#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Compile-tested Axum adapter for the framework-neutral OPAQUE HTTP contract.
//!
//! This adapter deliberately does not terminate TLS or infer trust from
//! forwarded headers. The embedding application must validate the transport,
//! proxy source, and connection limits, then pass a
//! [`HttpDeploymentContext`].

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, request::Parts, Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use secure_auth_http::{
    request_admission_response, validate_content_length, ContentLengthError, CredentialRepository,
    HttpAuthRouter, HttpDeploymentContext, HttpRequest, HttpResponse, RequestAdmission,
    JSON_CONTENT_TYPE, RESPONSE_SECURITY_HEADERS,
};
use secure_auth_server::BoundOneTimeLoginStateStore;
use std::sync::Arc;

struct AppState<S, R, P, Q> {
    router: HttpAuthRouter<S, R>,
    context: HttpDeploymentContext,
    csrf: Arc<P>,
    rate_limit: Arc<Q>,
}

/// Builds an Axum router that delegates the authentication contract to
/// [`secure_auth_http::HttpAuthRouter`].
///
/// The adapter bounds body buffering with Axum's streaming `to_bytes` limit,
/// copies the route's static security headers, and exposes no framework error
/// details. The returned router has no application session or TLS behavior;
/// those remain host responsibilities. `csrf` must validate the host's
/// same-origin/CSRF policy from request parts without reading the body; the
/// route fails closed before buffering JSON when either callback rejects the
/// request. `rate_limit` must perform the host's account/IP/deployment
/// admission check without reading the body.
pub fn router<S, R, P, Q>(
    auth_router: HttpAuthRouter<S, R>,
    context: HttpDeploymentContext,
    csrf: P,
    rate_limit: Q,
) -> Router
where
    S: BoundOneTimeLoginStateStore + Send + Sync + 'static,
    R: CredentialRepository + Send + Sync + 'static,
    P: Fn(&Parts) -> bool + Send + Sync + 'static,
    Q: Fn(&Parts) -> RequestAdmission + Send + Sync + 'static,
{
    let state = Arc::new(AppState {
        router: auth_router,
        context,
        csrf: Arc::new(csrf),
        rate_limit: Arc::new(rate_limit),
    });
    Router::new()
        .fallback(handle_request::<S, R, P, Q>)
        .with_state(state)
}

async fn handle_request<S, R, P, Q>(
    State(state): State<Arc<AppState<S, R, P, Q>>>,
    request: Request<Body>,
) -> Response
where
    S: BoundOneTimeLoginStateStore + Send + Sync + 'static,
    R: CredentialRepository + Send + Sync + 'static,
    P: Fn(&Parts) -> bool + Send + Sync + 'static,
    Q: Fn(&Parts) -> RequestAdmission + Send + Sync + 'static,
{
    if !state.context.is_ready() {
        return deployment_unavailable_response();
    }

    let body_limit = state.context.body_limit_bytes();
    let (parts, body) = request.into_parts();
    if !(state.csrf)(&parts) {
        return invalid_request_response(403);
    }
    if let Some(response) = request_admission_response((state.rate_limit)(&parts)) {
        return response_from(response);
    }
    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if let Some(error) = content_length_error(&parts.headers, body_limit) {
        return response_from(HttpResponse {
            status: content_length_status(error),
            content_type: JSON_CONTENT_TYPE,
            headers: RESPONSE_SECURITY_HEADERS,
            body: br#"{"error":"invalid_request"}"#.to_vec(),
        });
    }

    let Ok(body) = to_bytes(body, body_limit).await else {
        return response_from(HttpResponse {
            status: 413,
            content_type: JSON_CONTENT_TYPE,
            headers: RESPONSE_SECURITY_HEADERS,
            body: br#"{"error":"invalid_request"}"#.to_vec(),
        });
    };
    let response = state.router.handle(
        HttpRequest {
            method: &method,
            path: &path,
            content_type: content_type.as_deref(),
            csrf_validated: true,
            admission: RequestAdmission::Allowed,
            body: &body,
        },
        state.context,
    );
    response_from(response)
}

fn content_length_error(
    headers: &axum::http::HeaderMap,
    limit: usize,
) -> Option<ContentLengthError> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
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

fn response_from(response: HttpResponse) -> Response {
    let (status, content_type, response_headers, body) = response.into_parts();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut output = (status, Body::from(body)).into_response();
    *output.status_mut() = status;
    let headers = output.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    for item in response_headers {
        let name =
            header::HeaderName::from_bytes(item.name.as_bytes()).expect("static header name");
        let value = header::HeaderValue::from_static(item.value);
        headers.insert(name, value);
    }
    output
}

/// Maps a generic route error into a response for adapters that need to
/// reject a request before the Axum handler is reached.
#[must_use]
pub fn invalid_request_response(status: u16) -> Response {
    static_error_response(status, br#"{"error":"invalid_request"}"#)
}

/// Returns the generic response used when the host did not provide a safe
/// deployment context.
#[must_use]
pub fn deployment_unavailable_response() -> Response {
    static_error_response(503, br#"{"error":"temporarily_unavailable"}"#)
}

fn static_error_response(status: u16, body: &[u8]) -> Response {
    response_from(HttpResponse {
        status,
        content_type: JSON_CONTENT_TYPE,
        headers: RESPONSE_SECURITY_HEADERS,
        body: body.to_vec(),
    })
}

#[cfg(feature = "webauthn")]
mod webauthn_adapter {
    use super::{header, to_bytes, Body, Request, Response, Router, State, StatusCode};
    use axum::http::request::Parts;
    use axum::response::IntoResponse;
    use secure_webauthn_example::{
        CeremonyStateStore, CredentialStore, WebAuthnDeploymentContext, WebAuthnHttpRequest,
        WebAuthnHttpResponse, WebAuthnHttpRouter, WebAuthnService, WEBAUTHN_JSON_CONTENT_TYPE,
        WEBAUTHN_RESPONSE_SECURITY_HEADERS,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    struct AppState<C, S, P, X> {
        service: Arc<WebAuthnService<C, S>>,
        context: WebAuthnDeploymentContext,
        principal: Arc<P>,
        csrf: Arc<X>,
    }

    /// Builds an Axum router for the framework-neutral `WebAuthn` route
    /// contract.
    ///
    /// `principal` must resolve the account from the host's authenticated
    /// session or equivalent server-side context. It receives only HTTP
    /// request parts, never the JSON body, and the adapter never derives a
    /// principal from request fields. `csrf` must validate the host's
    /// same-origin/CSRF policy from request parts without reading the body;
    /// the route fails closed before buffering JSON when it returns `false`.
    /// TLS, proxy validation, session issuance, and durable
    /// ceremony/credential stores remain application responsibilities.
    pub fn router<C, S, P, X>(
        service: Arc<WebAuthnService<C, S>>,
        context: WebAuthnDeploymentContext,
        principal: P,
        csrf: X,
    ) -> Router
    where
        C: CredentialStore + Send + Sync + 'static,
        S: CeremonyStateStore + Send + Sync + 'static,
        P: Fn(&Parts) -> Option<Uuid> + Send + Sync + 'static,
        X: Fn(&Parts) -> bool + Send + Sync + 'static,
    {
        let state = Arc::new(AppState {
            service,
            context,
            principal: Arc::new(principal),
            csrf: Arc::new(csrf),
        });
        Router::new()
            .fallback(handle_request::<C, S, P, X>)
            .with_state(state)
    }

    async fn handle_request<C, S, P, X>(
        State(state): State<Arc<AppState<C, S, P, X>>>,
        request: Request<Body>,
    ) -> Response
    where
        C: CredentialStore + Send + Sync + 'static,
        S: CeremonyStateStore + Send + Sync + 'static,
        P: Fn(&Parts) -> Option<Uuid> + Send + Sync + 'static,
        X: Fn(&Parts) -> bool + Send + Sync + 'static,
    {
        if !state.context.is_ready() {
            return deployment_unavailable_response();
        }

        let body_limit = state.context.body_limit_bytes();
        let (parts, body) = request.into_parts();
        if !(state.csrf)(&parts) {
            return response_from(WebAuthnHttpResponse {
                status: 403,
                content_type: WEBAUTHN_JSON_CONTENT_TYPE,
                headers: WEBAUTHN_RESPONSE_SECURITY_HEADERS,
                body: br#"{"error":"invalid_request"}"#.to_vec(),
            });
        }
        let method = parts.method.as_str().to_owned();
        let path = parts.uri.path().to_owned();
        let content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        if let Some(error) = super::content_length_error(&parts.headers, body_limit) {
            return response_from(WebAuthnHttpResponse {
                status: super::content_length_status(error),
                content_type: WEBAUTHN_JSON_CONTENT_TYPE,
                headers: WEBAUTHN_RESPONSE_SECURITY_HEADERS,
                body: br#"{"error":"invalid_request"}"#.to_vec(),
            });
        }

        let Ok(body) = to_bytes(body, body_limit).await else {
            return response_from(WebAuthnHttpResponse {
                status: 413,
                content_type: WEBAUTHN_JSON_CONTENT_TYPE,
                headers: WEBAUTHN_RESPONSE_SECURITY_HEADERS,
                body: br#"{"error":"invalid_request"}"#.to_vec(),
            });
        };
        let principal = (state.principal)(&parts);
        let response = WebAuthnHttpRouter::<C, S>::new(state.service.as_ref()).handle(
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
        response_from(response)
    }

    fn response_from(response: WebAuthnHttpResponse) -> Response {
        let (status, content_type, response_headers, body) = response.into_parts();
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut output = (status, Body::from(body)).into_response();
        *output.status_mut() = status;
        let headers = output.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            content_type.parse().expect("static content type"),
        );
        for item in response_headers {
            let name =
                header::HeaderName::from_bytes(item.name.as_bytes()).expect("static header name");
            let value = header::HeaderValue::from_static(item.value);
            headers.insert(name, value);
        }
        output
    }

    fn deployment_unavailable_response() -> Response {
        response_from(WebAuthnHttpResponse {
            status: 503,
            content_type: WEBAUTHN_JSON_CONTENT_TYPE,
            headers: WEBAUTHN_RESPONSE_SECURITY_HEADERS,
            body: br#"{"error":"temporarily_unavailable"}"#.to_vec(),
        })
    }
}

#[cfg(feature = "webauthn")]
pub use webauthn_adapter::router as webauthn_router;
