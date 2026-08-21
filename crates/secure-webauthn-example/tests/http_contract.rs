use secure_webauthn_example::{WebAuthnHttpRequest, WebAuthnHttpRouter, MAX_CLIENT_RESPONSE_BYTES};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

const ORIGIN: &str = "http://localhost:3000";

fn router() -> WebAuthnHttpRouter<'static> {
    let service = Box::leak(Box::new(
        secure_webauthn_example::WebAuthnExampleService::new(
            "localhost",
            ORIGIN,
            "Secure Keypad Test",
            Duration::from_secs(60),
        )
        .unwrap(),
    ));
    WebAuthnHttpRouter::new(service)
}

#[test]
fn registration_start_binds_to_host_principal_and_returns_browser_options() {
    let router = router();
    let user_id = Uuid::from_u128(1);
    let response = router.handle(WebAuthnHttpRequest {
        method: "POST",
        path: "/v1/webauthn/registration/start",
        content_type: Some("application/json"),
        principal: Some(user_id),
        body: br#"{"userName":"alice","displayName":"Alice"}"#,
    });

    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["handle"].as_str().unwrap().len(), 64);
    assert!(body["options"].is_object());
}

#[test]
fn routes_reject_missing_principal_and_oversized_body_without_parsing() {
    let router = router();
    let missing_principal = router.handle(WebAuthnHttpRequest {
        method: "POST",
        path: "/v1/webauthn/registration/start",
        content_type: Some("application/json"),
        principal: None,
        body: br#"{"userName":"alice","displayName":"Alice"}"#,
    });
    assert_eq!(missing_principal.status, 401);
    assert_eq!(missing_principal.body, br#"{"error":"unauthenticated"}"#);

    let oversized = router.handle(WebAuthnHttpRequest {
        method: "POST",
        path: "/v1/webauthn/registration/start",
        content_type: Some("application/json"),
        principal: Some(Uuid::from_u128(1)),
        body: &vec![b'{'; MAX_CLIENT_RESPONSE_BYTES + 1],
    });
    assert_eq!(oversized.status, 413);
    assert_eq!(oversized.body, br#"{"error":"invalid_request"}"#);
}

#[test]
fn principal_mismatch_consumes_the_ceremony_before_response_processing() {
    let service = secure_webauthn_example::WebAuthnExampleService::new(
        "localhost",
        ORIGIN,
        "Secure Keypad Test",
        Duration::from_secs(60),
    )
    .unwrap();
    let owner = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let start = service.start_registration(owner, "alice", "Alice").unwrap();

    assert_eq!(
        service
            .finish_registration_for_principal(&start.handle, other, b"not-json")
            .unwrap_err(),
        secure_webauthn_example::WebAuthnExampleError::InvalidRequest
    );
    assert_eq!(
        service
            .finish_registration_for_principal(&start.handle, owner, b"not-json")
            .unwrap_err(),
        secure_webauthn_example::WebAuthnExampleError::Replay
    );
}
