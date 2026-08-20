use secure_auth::{
    client_login_finish, client_login_finish_from_native_state, client_login_start,
    client_login_start_from_submission, client_registration_finish, client_registration_start,
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
    ServerSetupBytes,
};
use secure_core::{InputPolicy, KeyId, SecureSession};

const CLIENT_ID: &[u8] = b"fixture-user";
const SERVER_ID: &[u8] = b"fixture-server";
const PASSWORD: &[u8] = b"fixture-only-secret";

#[test]
fn registration_and_login_derive_the_same_session_key() {
    let setup = ServerSetupBytes::generate().unwrap();
    let (registration_state, registration_request) = client_registration_start(PASSWORD).unwrap();
    let registration_response =
        server_registration_start(&setup, &registration_request, CLIENT_ID).unwrap();
    let (upload, client_export_key) = client_registration_finish(
        registration_state,
        PASSWORD,
        &registration_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    assert!(!client_export_key.is_empty());

    let credential_file = server_registration_finish(&upload).unwrap();
    let (login_state, login_request) = client_login_start(PASSWORD).unwrap();
    let (login_response, server_login_state) = server_login_start(
        &setup,
        Some(&credential_file),
        &login_request,
        CLIENT_ID,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let (finalization, client_session_key) =
        client_login_finish(login_state, PASSWORD, &login_response, CLIENT_ID, SERVER_ID).unwrap();
    let server_session_key =
        server_login_finish(server_login_state, &finalization, CLIENT_ID, SERVER_ID).unwrap();

    assert!(client_session_key.constant_time_eq(&server_session_key));
}

#[test]
fn wrong_password_does_not_finish_login() {
    let setup = ServerSetupBytes::generate().unwrap();
    let (registration_state, registration_request) = client_registration_start(PASSWORD).unwrap();
    let registration_response =
        server_registration_start(&setup, &registration_request, CLIENT_ID).unwrap();
    let (upload, _) = client_registration_finish(
        registration_state,
        PASSWORD,
        &registration_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let credential_file = server_registration_finish(&upload).unwrap();

    let (login_state, login_request) = client_login_start(b"wrong-fixture-secret").unwrap();
    let (login_response, _) = server_login_start(
        &setup,
        Some(&credential_file),
        &login_request,
        CLIENT_ID,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();

    assert!(client_login_finish(
        login_state,
        b"wrong-fixture-secret",
        &login_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .is_err());
}

#[test]
fn setup_persistence_round_trips() {
    let setup = ServerSetupBytes::generate().unwrap();
    let restored = ServerSetupBytes::from_bytes(setup.as_bytes()).unwrap();
    assert_eq!(setup.as_bytes(), restored.as_bytes());
}

#[test]
fn native_submission_reaches_opaque_without_a_password_getter() {
    let setup = ServerSetupBytes::generate().unwrap();
    let (registration_state, registration_request) = client_registration_start(b"12").unwrap();
    let registration_response =
        server_registration_start(&setup, &registration_request, CLIENT_ID).unwrap();
    let (upload, _) = client_registration_finish(
        registration_state,
        b"12",
        &registration_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let credential_file = server_registration_finish(&upload).unwrap();

    let mut session = SecureSession::begin(InputPolicy::numeric(2));
    session.press_key(&KeyId::new("digit-1")).unwrap();
    session.press_key(&KeyId::new("digit-2")).unwrap();
    let submission = session.submit().unwrap();
    let (native_state, login_request) = client_login_start_from_submission(submission).unwrap();
    let (login_response, server_state) = server_login_start(
        &setup,
        Some(&credential_file),
        &login_request,
        CLIENT_ID,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let (finalization, client_session_key) =
        client_login_finish_from_native_state(native_state, &login_response, CLIENT_ID, SERVER_ID)
            .unwrap();
    let server_session_key =
        server_login_finish(server_state, &finalization, CLIENT_ID, SERVER_ID).unwrap();

    assert!(client_session_key.constant_time_eq(&server_session_key));
}
