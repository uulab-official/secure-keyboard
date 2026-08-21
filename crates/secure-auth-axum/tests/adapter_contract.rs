use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use secure_auth::{ServerSetupBytes, CIPHER_SUITE_ID, MAX_JSON_BODY_BYTES};
use secure_auth_axum::router;
use secure_auth_http::{
    CredentialRepository, HttpDeploymentContext, HttpResponse, RepositoryError, TransportSecurity,
};
use secure_auth_server::{InMemoryOneTimeLoginStore, ServerAuthService};
use std::time::Duration;
use tower::ServiceExt;

struct EmptyRepository;

impl CredentialRepository for EmptyRepository {
    fn load(
        &self,
        _identifier: &[u8],
    ) -> Result<Option<secure_auth::CredentialFile>, RepositoryError> {
        Ok(None)
    }

    fn store(
        &self,
        _identifier: &[u8],
        _credential: secure_auth::CredentialFile,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }
}

fn app_with_context(context: HttpDeploymentContext) -> axum::Router {
    let service = ServerAuthService::new(
        ServerSetupBytes::generate().unwrap(),
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    router(
        secure_auth_http::HttpAuthRouter::new(service, EmptyRepository),
        context,
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
