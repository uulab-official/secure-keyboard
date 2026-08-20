use secure_auth::{
    client_login_finish, client_login_start, client_registration_finish, client_registration_start,
    server_registration_finish, server_registration_start, AuthEnvelope, AuthMessageKind,
    ServerSetupBytes, CIPHER_SUITE_ID,
};
use secure_auth_server::{
    InMemoryOneTimeLoginStore, PublicAuthCode, ServerAuthError, ServerAuthService, StoreError,
};
use secure_core::{InputPolicy, KeyId, SecureSession};

const CLIENT_ID: &[u8] = b"fixture-user";
const SERVER_ID: &[u8] = b"fixture-server";
const PASSWORD: &[u8] = b"fixture-only-secret";

fn registered_fixture() -> (ServerSetupBytes, secure_auth::CredentialFile) {
    registered_fixture_for(PASSWORD, CLIENT_ID)
}

fn registered_fixture_for(
    password: &[u8],
    credential_identifier: &[u8],
) -> (ServerSetupBytes, secure_auth::CredentialFile) {
    let setup = ServerSetupBytes::generate().unwrap();
    let (registration_state, registration_request) = client_registration_start(password).unwrap();
    let registration_response =
        server_registration_start(&setup, &registration_request, credential_identifier).unwrap();
    let (upload, _) = client_registration_finish(
        registration_state,
        password,
        &registration_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let credential_file = server_registration_finish(&upload).unwrap();
    (setup, credential_file)
}

#[test]
fn service_completes_versioned_registration_without_exposing_server_state() {
    let setup = ServerSetupBytes::generate().unwrap();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, std::time::Duration::from_secs(60)).unwrap(),
    )
    .unwrap();

    let (registration_state, registration_request) = client_registration_start(PASSWORD).unwrap();
    let request_envelope = AuthEnvelope::new(
        AuthMessageKind::RegistrationRequest,
        CIPHER_SUITE_ID,
        &registration_request,
    )
    .unwrap();
    let response_envelope = service
        .begin_registration(request_envelope, CLIENT_ID)
        .unwrap();
    let response = response_envelope
        .into_message(AuthMessageKind::RegistrationResponse, CIPHER_SUITE_ID)
        .unwrap();
    let (upload, client_export_key) = client_registration_finish(
        registration_state,
        PASSWORD,
        &response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let upload_envelope = AuthEnvelope::new(
        AuthMessageKind::RegistrationUpload,
        CIPHER_SUITE_ID,
        &upload,
    )
    .unwrap();

    let credential_file = service.finish_registration(upload_envelope).unwrap();
    assert!(!credential_file.as_bytes().is_empty());
    assert!(!client_export_key.is_empty());
}

#[test]
fn service_completes_versioned_login_without_reaccepting_context() {
    let (setup, credential_file) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, std::time::Duration::from_secs(60)).unwrap(),
    )
    .unwrap();

    let (login_state, login_request) = client_login_start(PASSWORD).unwrap();
    let request_envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        CIPHER_SUITE_ID,
        &login_request,
    )
    .unwrap();
    let (response_envelope, handle) = service
        .begin_login(
            request_envelope,
            Some(&credential_file),
            CLIENT_ID,
            CLIENT_ID,
            SERVER_ID,
        )
        .unwrap();
    let response = response_envelope
        .into_message(AuthMessageKind::CredentialResponse, CIPHER_SUITE_ID)
        .unwrap();
    let (finalization, client_session_key) =
        client_login_finish(login_state, PASSWORD, &response, CLIENT_ID, SERVER_ID).unwrap();
    let finalization_envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialFinalization,
        CIPHER_SUITE_ID,
        &finalization,
    )
    .unwrap();

    let server_session_key = service
        .finish_login(finalization_envelope, &handle)
        .unwrap();
    assert!(client_session_key.constant_time_eq(&server_session_key));

    let replay_envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialFinalization,
        CIPHER_SUITE_ID,
        &finalization,
    )
    .unwrap();
    assert!(matches!(
        service.finish_login(replay_envelope, &handle),
        Err(ServerAuthError::MissingLoginState)
    ));
}

#[test]
fn service_rejects_wrong_server_key_before_opaque_processing() {
    let (setup, credential_file) = registered_fixture();
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, std::time::Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let (_, request) = client_login_start(PASSWORD).unwrap();
    let wrong_key_request = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        "wrong-server-key",
        &request,
    )
    .unwrap();

    assert!(matches!(
        service.begin_login(
            wrong_key_request,
            Some(&credential_file),
            CLIENT_ID,
            CLIENT_ID,
            SERVER_ID,
        ),
        Err(ServerAuthError::Auth(
            secure_auth::AuthError::UnexpectedServerKey
        ))
    ));
}

#[test]
fn service_rejects_invalid_server_key_configuration() {
    let (setup, _) = registered_fixture();
    assert!(matches!(
        ServerAuthService::new(
            setup,
            "",
            InMemoryOneTimeLoginStore::new(1, std::time::Duration::from_secs(1)).unwrap(),
        ),
        Err(ServerAuthError::InvalidServerKeyId)
    ));
}

#[test]
fn public_error_mapping_hides_authentication_and_replay_details() {
    assert_eq!(
        ServerAuthError::Auth(secure_auth::AuthError::InvalidLogin).public_code(),
        PublicAuthCode::AuthenticationFailed
    );
    assert_eq!(
        ServerAuthError::MissingLoginState.public_code(),
        PublicAuthCode::AuthenticationFailed
    );
    assert_eq!(
        ServerAuthError::Auth(secure_auth::AuthError::UnexpectedServerKey).public_code(),
        PublicAuthCode::InvalidRequest
    );
    assert_eq!(
        ServerAuthError::Store(StoreError::Unavailable).public_code(),
        PublicAuthCode::TemporarilyUnavailable
    );
    assert_eq!(
        ServerAuthError::InvalidServerKeyId.public_code(),
        PublicAuthCode::TemporarilyUnavailable
    );
    assert_eq!(
        PublicAuthCode::AuthenticationFailed.as_str(),
        "authentication_failed"
    );
}

#[test]
fn service_can_start_from_a_native_keypad_credential_identifier() {
    let (setup, credential_file) = registered_fixture_for(b"12", b"12");
    let service = ServerAuthService::new(
        setup,
        CIPHER_SUITE_ID,
        InMemoryOneTimeLoginStore::new(8, std::time::Duration::from_secs(60)).unwrap(),
    )
    .unwrap();

    let mut session = SecureSession::begin(InputPolicy::numeric(2));
    session.press_key(&KeyId::new("digit-1")).unwrap();
    session.press_key(&KeyId::new("digit-2")).unwrap();
    let submission = session.submit().unwrap();
    let (native_login_state, request) =
        secure_auth::client_login_start_from_submission(submission).unwrap();
    let request_envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        CIPHER_SUITE_ID,
        &request,
    )
    .unwrap();

    let (response_envelope, handle) = service
        .begin_login(
            request_envelope,
            Some(&credential_file),
            b"12",
            CLIENT_ID,
            SERVER_ID,
        )
        .unwrap();
    let response = response_envelope
        .into_message(AuthMessageKind::CredentialResponse, CIPHER_SUITE_ID)
        .unwrap();
    let (finalization, client_session_key) = secure_auth::client_login_finish_from_native_state(
        native_login_state,
        &response,
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
    let server_session_key = service
        .finish_login(finalization_envelope, &handle)
        .unwrap();
    assert!(client_session_key.constant_time_eq(&server_session_key));
}
