#![cfg(feature = "webauthn")]

use actix_web::{body::to_bytes, http::StatusCode, test as actix_test, App, Scope};
use secure_auth_actix::webauthn_router;
use secure_webauthn_example::{WebAuthnDeploymentContext, WebAuthnExampleService};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn app_with_principal(
    context: WebAuthnDeploymentContext,
    principal: impl Fn(&actix_web::HttpRequest) -> Option<Uuid> + Send + Sync + 'static,
    csrf_valid: bool,
) -> Scope {
    let service = WebAuthnExampleService::new(
        "localhost",
        "http://localhost:3000",
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    webauthn_router(Arc::new(service), context, principal, move |_request| {
        csrf_valid
    })
}

#[actix_web::test]
async fn webauthn_adapter_requires_host_principal_and_preserves_security_headers() {
    let app = actix_test::init_service(App::new().service(app_with_principal(
        WebAuthnDeploymentContext::direct_tls(),
        |_request| None,
        true,
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/webauthn/registration/start")
            .insert_header(("content-type", "application/json"))
            .set_payload(br#"{"userName":"alice","displayName":"Alice"}"#.to_vec())
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], br#"{"error":"unauthenticated"}"#);
}

#[actix_web::test]
async fn webauthn_adapter_passes_host_principal_to_the_framework_neutral_router() {
    let app = actix_test::init_service(App::new().service(app_with_principal(
        WebAuthnDeploymentContext::direct_tls(),
        |request| {
            assert_eq!(request.path(), "/v1/webauthn/registration/start");
            Some(Uuid::from_u128(1))
        },
        true,
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/webauthn/registration/start")
            .insert_header(("content-type", "application/json"))
            .set_payload(br#"{"userName":"alice","displayName":"Alice"}"#.to_vec())
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

#[actix_web::test]
async fn webauthn_adapter_bounds_body_before_principal_resolution() {
    let app = actix_test::init_service(App::new().service(app_with_principal(
        WebAuthnDeploymentContext::new(
            secure_webauthn_example::WebAuthnTransportSecurity::DirectTls,
            4,
            true,
        ),
        |_request| panic!("principal resolver must not run for an oversized body"),
        true,
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/webauthn/authentication/start")
            .insert_header(("content-type", "application/json"))
            .set_payload("{}{}x")
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn webauthn_adapter_rejects_csrf_before_principal_resolution() {
    let app = actix_test::init_service(App::new().service(app_with_principal(
        WebAuthnDeploymentContext::direct_tls(),
        |_request| panic!("principal resolver must not run before CSRF validation"),
        false,
    )))
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/v1/webauthn/registration/start")
            .insert_header(("content-type", "application/json"))
            .set_payload(br#"{"userName":"alice","displayName":"Alice"}"#.to_vec())
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
