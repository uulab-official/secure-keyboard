use secure_auth::{
    client_login_finish, client_login_start, client_registration_finish, client_registration_start,
    server_registration_finish, server_registration_start, AuthEnvelope, AuthMessageKind,
    CredentialFile, ServerSetupBytes, CIPHER_SUITE_ID, MAX_JSON_BODY_BYTES,
};
use secure_auth_http::{
    CredentialRepository, HttpAuthRouter, HttpDeploymentContext, HttpRequest, RepositoryError,
    TransportSecurity, AUTHENTICATED_RESPONSE, REGISTRATION_STORED_RESPONSE,
};
use secure_auth_server::{InMemoryOneTimeLoginStore, LoginStateHandle, ServerAuthService};
use serde::Serialize;
use std::{collections::HashMap, sync::Mutex, time::Duration};

const CLIENT_ID: &[u8] = b"fixture-client";
const SERVER_ID: &[u8] = b"fixture-server";
const CREDENTIAL_ID: &[u8] = b"fixture-user";
const PASSWORD: &[u8] = b"fixture-only-secret";

#[test]
fn route_requires_tls_and_proxy_limits_before_parsing() {
    let (setup, credential) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let router = HttpAuthRouter::new(service, FixtureRepository::with(CREDENTIAL_ID, credential));
    let request = HttpRequest {
        method: "POST",
        path: "/v1/opaque/login/start",
        content_type: Some("application/json"),
        body: b"not-json",
    };

    let plaintext = router.handle(
        request,
        HttpDeploymentContext::new(TransportSecurity::Plaintext, MAX_JSON_BODY_BYTES, true),
    );
    assert_eq!(plaintext.status, 400);
    assert_eq!(plaintext.body, br#"{"error":"invalid_request"}"#);

    let missing_proxy_limit = router.handle(
        request,
        HttpDeploymentContext::new(TransportSecurity::DirectTls, MAX_JSON_BODY_BYTES, false),
    );
    assert_eq!(missing_proxy_limit.status, 503);
    assert_eq!(
        missing_proxy_limit.body,
        br#"{"error":"temporarily_unavailable"}"#
    );
}

struct FixtureRepository {
    entries: Mutex<HashMap<Vec<u8>, CredentialFile>>,
}

impl FixtureRepository {
    fn with(identifier: &[u8], credential: CredentialFile) -> Self {
        let mut entries = HashMap::new();
        entries.insert(identifier.to_vec(), credential);
        Self {
            entries: Mutex::new(entries),
        }
    }
}

impl CredentialRepository for FixtureRepository {
    fn load(&self, identifier: &[u8]) -> Result<Option<CredentialFile>, RepositoryError> {
        self.entries
            .lock()
            .map_err(|_| RepositoryError::Unavailable)
            .map(|mut entries| entries.remove(identifier))
    }

    fn store(&self, identifier: &[u8], credential: CredentialFile) -> Result<(), RepositoryError> {
        self.entries
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .insert(identifier.to_vec(), credential);
        Ok(())
    }
}

fn registered_fixture() -> (ServerSetupBytes, CredentialFile) {
    let setup = ServerSetupBytes::generate().unwrap();
    let (state, request) = client_registration_start(PASSWORD).unwrap();
    let response = server_registration_start(&setup, &request, CREDENTIAL_ID).unwrap();
    let (upload, _) =
        client_registration_finish(state, PASSWORD, &response, CLIENT_ID, SERVER_ID).unwrap();
    (setup, server_registration_finish(&upload).unwrap())
}

#[derive(Serialize)]
struct RegistrationStartBody<'a> {
    identifier: &'a str,
    envelope: &'a AuthEnvelope,
}

#[derive(Serialize)]
struct LoginStartBody<'a> {
    credential_identifier: &'a str,
    client_identifier: &'a str,
    server_identifier: &'a str,
    envelope: &'a AuthEnvelope,
}

#[derive(Serialize)]
struct LoginFinishBody<'a> {
    handle: &'a str,
    envelope: &'a AuthEnvelope,
}

#[derive(Serialize)]
struct RegistrationFinishBody<'a> {
    identifier: &'a str,
    envelope: &'a AuthEnvelope,
}

#[derive(serde::Deserialize)]
struct LoginStartResponse {
    envelope: AuthEnvelope,
    handle: String,
}

#[derive(serde::Deserialize)]
struct RegistrationStartResponse {
    envelope: AuthEnvelope,
}

#[test]
fn route_rejects_non_json_and_oversized_bodies_before_deserialization() {
    let (setup, credential) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let router = HttpAuthRouter::new(service, FixtureRepository::with(CREDENTIAL_ID, credential));

    let content_type_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/start",
            content_type: Some("text/plain"),
            body: b"{}",
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(content_type_response.status, 415);

    let oversized_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/start",
            content_type: Some("application/json"),
            body: &vec![b'x'; MAX_JSON_BODY_BYTES + 1],
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(oversized_response.status, 413);
    assert_eq!(oversized_response.body, br#"{"error":"invalid_request"}"#);
}

#[test]
fn login_routes_complete_opaque_flow_and_consume_handle_once() {
    let (setup, credential) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let router = HttpAuthRouter::new(service, FixtureRepository::with(CREDENTIAL_ID, credential));

    let (client_state, request) = client_login_start(PASSWORD).unwrap();
    let envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        CIPHER_SUITE_ID,
        &request,
    )
    .unwrap();
    let body = serde_json::to_vec(&LoginStartBody {
        credential_identifier: "fixture-user",
        client_identifier: "fixture-client",
        server_identifier: "fixture-server",
        envelope: &envelope,
    })
    .unwrap();
    let response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/start",
            content_type: Some("application/json"),
            body: &body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(response.status, 200);
    let start: LoginStartResponse = serde_json::from_slice(&response.body).unwrap();
    assert!(!start.handle.is_empty());

    let response_message = start
        .envelope
        .into_message(AuthMessageKind::CredentialResponse, CIPHER_SUITE_ID)
        .unwrap();
    let (finalization, _) = client_login_finish(
        client_state,
        PASSWORD,
        &response_message,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let finalization_envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialFinalization,
        CIPHER_SUITE_ID,
        &finalization,
    )
    .unwrap();
    let finish_body = serde_json::to_vec(&LoginFinishBody {
        handle: &start.handle,
        envelope: &finalization_envelope,
    })
    .unwrap();
    let finish_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/finish",
            content_type: Some("application/json"),
            body: &finish_body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(finish_response.status, 200);
    assert_eq!(finish_response.body, AUTHENTICATED_RESPONSE);

    let replay_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/finish",
            content_type: Some("application/json"),
            body: &finish_body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(replay_response.status, 401);
    assert_eq!(
        replay_response.body,
        br#"{"error":"authentication_failed"}"#
    );
}

#[test]
fn login_start_with_unknown_identifier_keeps_generic_wire_response() {
    let (setup, credential) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let router = HttpAuthRouter::new(service, FixtureRepository::with(CREDENTIAL_ID, credential));
    let (_, request) = client_login_start(PASSWORD).unwrap();
    let envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        CIPHER_SUITE_ID,
        &request,
    )
    .unwrap();
    let body = serde_json::to_vec(&LoginStartBody {
        credential_identifier: "unknown-user",
        client_identifier: "fixture-client",
        server_identifier: "fixture-server",
        envelope: &envelope,
    })
    .unwrap();
    let response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/login/start",
            content_type: Some("application/json"),
            body: &body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(response.status, 200);
    assert!(!response.body.is_empty());
    assert!(!response
        .body
        .windows(b"fixture-only-secret".len())
        .any(|window| window == b"fixture-only-secret"));
}

#[test]
fn registration_start_response_is_not_a_credential_file_endpoint() {
    let (setup, _) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let router = HttpAuthRouter::new(
        service,
        FixtureRepository::with(CREDENTIAL_ID, registered_fixture().1),
    );
    let (_, request) = client_registration_start(PASSWORD).unwrap();
    let envelope = AuthEnvelope::new(
        AuthMessageKind::RegistrationRequest,
        CIPHER_SUITE_ID,
        &request,
    )
    .unwrap();
    let body = serde_json::to_vec(&RegistrationStartBody {
        identifier: "fixture-user",
        envelope: &envelope,
    })
    .unwrap();
    let response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/registration/start",
            content_type: Some("application/json; charset=utf-8"),
            body: &body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(response.status, 200);
    assert!(!response
        .body
        .windows(b"fixture-only-secret".len())
        .any(|window| window == b"fixture-only-secret"));
}

#[test]
fn registration_finish_stores_credential_without_returning_file_bytes() {
    let (setup, _) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let repository = FixtureRepository::with(CREDENTIAL_ID, registered_fixture().1);
    let router = HttpAuthRouter::new(service, repository);

    let (state, request) = client_registration_start(PASSWORD).unwrap();
    let request_envelope = AuthEnvelope::new(
        AuthMessageKind::RegistrationRequest,
        CIPHER_SUITE_ID,
        &request,
    )
    .unwrap();
    let start_body = serde_json::to_vec(&RegistrationStartBody {
        identifier: "new-user",
        envelope: &request_envelope,
    })
    .unwrap();
    let start_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/registration/start",
            content_type: Some("application/json"),
            body: &start_body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(start_response.status, 200);
    let start: RegistrationStartResponse = serde_json::from_slice(&start_response.body).unwrap();
    let response_message = start
        .envelope
        .into_message(AuthMessageKind::RegistrationResponse, CIPHER_SUITE_ID)
        .unwrap();
    let (upload, _) =
        client_registration_finish(state, PASSWORD, &response_message, CLIENT_ID, SERVER_ID)
            .unwrap();
    let upload_envelope = AuthEnvelope::new(
        AuthMessageKind::RegistrationUpload,
        CIPHER_SUITE_ID,
        &upload,
    )
    .unwrap();
    let finish_body = serde_json::to_vec(&RegistrationFinishBody {
        identifier: "new-user",
        envelope: &upload_envelope,
    })
    .unwrap();
    let finish_response = router.handle(
        HttpRequest {
            method: "POST",
            path: "/v1/opaque/registration/finish",
            content_type: Some("application/json"),
            body: &finish_body,
        },
        HttpDeploymentContext::direct_tls(),
    );
    assert_eq!(finish_response.status, 200);
    assert_eq!(finish_response.body, REGISTRATION_STORED_RESPONSE);
    assert!(!finish_response
        .body
        .windows(b"fixture-only-secret".len())
        .any(|window| window == b"fixture-only-secret"));
}

#[test]
fn login_state_handle_decoder_rejects_non_fixed_handles() {
    assert!(LoginStateHandle::from_bytes(&[0u8; 31]).is_none());
    assert!(LoginStateHandle::from_bytes(&[0u8; 33]).is_none());
}
