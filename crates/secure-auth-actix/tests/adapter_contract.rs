use actix_web::{body::to_bytes, http::StatusCode, test as actix_test, App, Scope};
use secure_auth::{ServerSetupBytes, CIPHER_SUITE_ID, MAX_JSON_BODY_BYTES};
use secure_auth_actix::router;
use secure_auth_http::{
    CredentialRepository, HttpDeploymentContext, HttpResponse as ContractResponse, RepositoryError,
    TransportSecurity,
};
use secure_auth_server::{InMemoryOneTimeLoginStore, ServerAuthService};
use std::time::Duration;

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

fn app_with_context(context: HttpDeploymentContext) -> Scope {
    app_with_csrf(context, true)
}

fn app_with_csrf(context: HttpDeploymentContext, csrf_valid: bool) -> Scope {
    let service = ServerAuthService::new(
        ServerSetupBytes::generate().unwrap(),
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    router(
        secure_auth_http::HttpAuthRouter::new(service, EmptyRepository),
        context,
        move |_request| csrf_valid,
    )
}

#[actix_web::test]
async fn adapter_preserves_generic_route_errors_and_security_headers() {
    let app = actix_test::init_service(
        App::new().service(app_with_context(HttpDeploymentContext::direct_tls())),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/v1/opaque/login/start")
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[actix_web::test]
async fn adapter_rejects_unvalidated_csrf_before_body_processing() {
    let app = actix_test::init_service(
        App::new().service(app_with_csrf(HttpDeploymentContext::direct_tls(), false)),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/opaque/login/start")
            .insert_header(("content-type", "application/json"))
            .set_payload(vec![b'x'; MAX_JSON_BODY_BYTES + 1])
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[actix_web::test]
async fn adapter_bounds_streaming_body_before_route_parsing() {
    let app = actix_test::init_service(
        App::new().service(app_with_context(HttpDeploymentContext::direct_tls())),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/opaque/login/start")
            .insert_header(("content-type", "application/json"))
            .set_payload(vec![b'x'; MAX_JSON_BODY_BYTES + 1])
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], br#"{"error":"invalid_request"}"#);
}

#[actix_web::test]
async fn adapter_rejects_malformed_content_length_before_route_dispatch() {
    let app = actix_test::init_service(
        App::new().service(app_with_context(HttpDeploymentContext::direct_tls())),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/not-an-auth-route")
            .insert_header(("content-type", "application/json"))
            .insert_header(("content-length", "not-a-number"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn adapter_rejects_duplicate_content_length_before_route_dispatch() {
    let app = actix_test::init_service(
        App::new().service(app_with_context(HttpDeploymentContext::direct_tls())),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/not-an-auth-route")
            .insert_header(("content-type", "application/json"))
            .insert_header(("content-length", "0"))
            .append_header(("content-length", "0"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn adapter_fails_closed_for_invalid_context_and_custom_body_limit() {
    let app = actix_test::init_service(App::new().service(app_with_context(
        HttpDeploymentContext::new(TransportSecurity::Plaintext, MAX_JSON_BODY_BYTES, true),
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/v1/opaque/login/start")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let app = actix_test::init_service(App::new().service(app_with_context(
        HttpDeploymentContext::new(TransportSecurity::DirectTls, 4, true),
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/opaque/login/start")
            .insert_header(("content-type", "application/json"))
            .set_payload("12345")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn response_shell_can_transfer_body_without_retaining_a_copy() {
    let response = ContractResponse {
        status: 200,
        content_type: "application/json; charset=utf-8",
        headers: secure_auth_http::RESPONSE_SECURITY_HEADERS,
        body: b"fixture".to_vec(),
    };
    let (_, _, _, body) = response.into_parts();
    assert_eq!(&body[..], b"fixture");
}
