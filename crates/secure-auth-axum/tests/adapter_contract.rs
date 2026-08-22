use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use secure_auth::{ServerSetupBytes, CIPHER_SUITE_ID, MAX_JSON_BODY_BYTES};
use secure_auth_axum::router;
use secure_auth_http::{
    CredentialRepository, HttpDeploymentContext, HttpResponse, RepositoryError, RequestAdmission,
    TransportSecurity,
};
use secure_auth_server::{InMemoryOneTimeLoginStore, ServerAuthService};
use std::time::Duration;
use tower::ServiceExt;

#[cfg(feature = "webauthn")]
use secure_webauthn_example::{WebAuthnDeploymentContext, WebAuthnExampleService};
#[cfg(feature = "webauthn")]
use uuid::Uuid;

struct EmptyRepository;

impl CredentialRepository for EmptyRepository {
    fn load(
        &self,
        _identifier: &[u8],
    ) -> Result<Option<secure_auth::CredentialFile>, RepositoryError> {
        Ok(None)
    }

    fn create(
        &self,
        _identifier: &[u8],
        _credential: secure_auth::CredentialFile,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }
}

fn app_with_context(context: HttpDeploymentContext) -> axum::Router {
    app_with_csrf(context, true)
}

fn app_with_csrf(context: HttpDeploymentContext, csrf_valid: bool) -> axum::Router {
    let service = ServerAuthService::new(
        ServerSetupBytes::generate().unwrap(),
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    router(
        secure_auth_http::HttpAuthRouter::new(service, EmptyRepository),
        context,
        move |_parts| csrf_valid,
        |_parts| RequestAdmission::Allowed,
    )
}

fn app_with_rate_limit(context: HttpDeploymentContext, decision: RequestAdmission) -> axum::Router {
    let service = ServerAuthService::new(
        ServerSetupBytes::generate().unwrap(),
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    router(
        secure_auth_http::HttpAuthRouter::new(service, EmptyRepository),
        context,
        |_parts| true,
        move |_parts| decision,
    )
}

fn app() -> axum::Router {
    app_with_context(HttpDeploymentContext::direct_tls())
}

#[tokio::test]
async fn adapter_preserves_generic_route_errors_and_security_headers() {
    let request = Request::builder()
        .method("GET")
        .uri("/v1/opaque/login/start")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(request).await.unwrap();

    assert_eq!(response.status(), 405);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[tokio::test]
async fn adapter_rejects_unvalidated_csrf_before_body_processing() {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/opaque/login/start")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; MAX_JSON_BODY_BYTES + 1]))
        .unwrap();
    let response = app_with_csrf(HttpDeploymentContext::direct_tls(), false)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[tokio::test]
async fn adapter_rejects_rate_limited_admission_before_body_processing() {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/opaque/login/start")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; MAX_JSON_BODY_BYTES + 1]))
        .unwrap();
    let response = app_with_rate_limit(
        HttpDeploymentContext::direct_tls(),
        RequestAdmission::RateLimited,
    )
    .oneshot(request)
    .await
    .unwrap();

    assert_eq!(response.status(), 429);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"error":"rate_limited"}"#);
}

#[tokio::test]
async fn adapter_bounds_streaming_body_before_route_parsing() {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/opaque/login/start")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; MAX_JSON_BODY_BYTES + 1]))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();

    assert_eq!(response.status(), 413);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[tokio::test]
async fn adapter_rejects_malformed_content_length_before_route_dispatch() {
    let request = Request::builder()
        .method("POST")
        .uri("/not-an-auth-route")
        .header("content-type", "application/json")
        .header("content-length", "not-a-number")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(request).await.unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn adapter_rejects_duplicate_content_length_before_route_dispatch() {
    let request = Request::builder()
        .method("POST")
        .uri("/not-an-auth-route")
        .header("content-type", "application/json")
        .header("content-length", "0")
        .header("content-length", "0")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(request).await.unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn adapter_fails_closed_for_invalid_context_and_custom_body_limit() {
    let invalid_context = app_with_context(HttpDeploymentContext::new(
        TransportSecurity::Plaintext,
        MAX_JSON_BODY_BYTES,
        true,
    ));
    let response = invalid_context
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/opaque/login/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);

    let bounded_context = app_with_context(HttpDeploymentContext::new(
        TransportSecurity::DirectTls,
        4,
        true,
    ));
    let response = bounded_context
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/opaque/login/start")
                .header("content-type", "application/json")
                .body(Body::from("12345"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[test]
fn response_shell_can_transfer_body_without_retaining_a_copy() {
    let response = HttpResponse {
        status: 200,
        content_type: "application/json; charset=utf-8",
        headers: secure_auth_http::RESPONSE_SECURITY_HEADERS,
        body: b"fixture".to_vec(),
    };
    let (_, _, _, body) = response.into_parts();
    assert_eq!(&body[..], b"fixture");
}

#[cfg(feature = "webauthn")]
#[tokio::test]
async fn webauthn_adapter_requires_host_principal_and_preserves_security_headers() {
    let service = WebAuthnExampleService::new(
        "localhost",
        "http://localhost:3000",
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    let app = secure_auth_axum::webauthn_router(
        std::sync::Arc::new(service),
        WebAuthnDeploymentContext::direct_tls(),
        |_request| None,
        |_parts| true,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webauthn/registration/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    br#"{"userName":"alice","displayName":"Alice"}"#.to_vec(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

#[cfg(feature = "webauthn")]
#[tokio::test]
async fn webauthn_adapter_passes_host_principal_to_the_framework_neutral_router() {
    let service = WebAuthnExampleService::new(
        "localhost",
        "http://localhost:3000",
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    let app = secure_auth_axum::webauthn_router(
        std::sync::Arc::new(service),
        WebAuthnDeploymentContext::direct_tls(),
        |parts| {
            assert_eq!(parts.uri.path(), "/v1/webauthn/registration/start");
            Some(Uuid::from_u128(1))
        },
        |_parts| true,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webauthn/registration/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    br#"{"userName":"alice","displayName":"Alice"}"#.to_vec(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[cfg(feature = "webauthn")]
#[tokio::test]
async fn webauthn_adapter_bounds_streaming_body_before_principal_or_json_processing() {
    let service = WebAuthnExampleService::new(
        "localhost",
        "http://localhost:3000",
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    let app = secure_auth_axum::webauthn_router(
        std::sync::Arc::new(service),
        WebAuthnDeploymentContext::new(
            secure_webauthn_example::WebAuthnTransportSecurity::DirectTls,
            4,
            true,
        ),
        |_parts| panic!("principal resolver must not run for an oversized body"),
        |_parts| true,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webauthn/authentication/start")
                .header("content-type", "application/json")
                .body(Body::from("{}{}x"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}

#[cfg(feature = "webauthn")]
#[tokio::test]
async fn webauthn_adapter_rejects_unvalidated_csrf_before_principal() {
    let service = WebAuthnExampleService::new(
        "localhost",
        "http://localhost:3000",
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    let app = secure_auth_axum::webauthn_router(
        std::sync::Arc::new(service),
        WebAuthnDeploymentContext::direct_tls(),
        |_parts| panic!("principal resolver must not run before CSRF validation"),
        |_parts| false,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webauthn/registration/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    br#"{"userName":"alice","displayName":"Alice"}"#.to_vec(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}
