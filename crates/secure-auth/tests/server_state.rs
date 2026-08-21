use secure_auth::{
    client_login_start, client_registration_finish, client_registration_start, server_login_finish,
    server_login_start, server_registration_finish, server_registration_start, AuthError, Message,
    ServerLoginStateBytes, ServerSetupBytes, CIPHER_SUITE_ID, MAX_CREDENTIAL_FILE_BYTES,
    MAX_IDENTIFIER_BYTES, MAX_SERVER_LOGIN_STATE_BYTES, MAX_SERVER_SETUP_BYTES,
    SERVER_LOGIN_STATE_VERSION,
};

const CLIENT_ID: &[u8] = b"fixture-user";
const SERVER_ID: &[u8] = b"fixture-server";
const PASSWORD: &[u8] = b"fixture-only-secret";

#[test]
fn server_login_state_round_trips_through_zeroizing_bytes() {
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

    let (login_state, login_request) = client_login_start(PASSWORD).unwrap();
    let (login_response, server_state) = server_login_start(
        &setup,
        Some(&credential_file),
        &login_request,
        CLIENT_ID,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let state_bytes = server_state.into_bytes();
    assert!(!state_bytes.as_bytes().is_empty());
    assert!(state_bytes.as_bytes().len() >= 6);
    assert_eq!(
        u16::from_le_bytes([state_bytes.as_bytes()[4], state_bytes.as_bytes()[5]]),
        SERVER_LOGIN_STATE_VERSION
    );

    let restored_state = state_bytes.into_state().unwrap();
    let (finalization, _) = secure_auth::client_login_finish(
        login_state,
        PASSWORD,
        &login_response,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let session_key = server_login_finish(restored_state, &finalization, CLIENT_ID, SERVER_ID);
    assert!(session_key.is_ok());
}

#[test]
fn server_login_state_rejects_version_and_suite_downgrades() {
    let mut unsupported_version = vec![b'S', b'K', b'L', b'S', 0xff, 0xff];
    unsupported_version.extend_from_slice(CIPHER_SUITE_ID.as_bytes());
    assert!(matches!(
        ServerLoginStateBytes::from_bytes(&unsupported_version)
            .unwrap()
            .into_state(),
        Err(AuthError::UnsupportedVersion)
    ));

    let mut unsupported_suite = vec![b'S', b'K', b'L', b'S', 1, 0];
    unsupported_suite.extend(std::iter::repeat_n(b'x', CIPHER_SUITE_ID.len()));
    unsupported_suite.extend_from_slice(b"fixture-state");
    let unsupported_suite = ServerLoginStateBytes::from_bytes(&unsupported_suite).unwrap();
    assert!(matches!(
        unsupported_suite.into_state(),
        Err(AuthError::UnsupportedSuite)
    ));
}

#[test]
fn malformed_server_login_state_is_rejected_without_secret_diagnostics() {
    let malformed = ServerLoginStateBytes::from_bytes(b"fixture-not-a-login-state").unwrap();
    match malformed.into_state() {
        Ok(_) => panic!("malformed state was accepted"),
        Err(error) => assert_eq!(error.to_string(), "opaque protocol error"),
    }
}

#[test]
fn public_identifiers_are_bounded_before_protocol_processing() {
    let setup = ServerSetupBytes::generate().unwrap();
    let request = Message::from_bytes(b"fixture-request").unwrap();
    let oversized = vec![b'x'; MAX_IDENTIFIER_BYTES + 1];

    assert!(matches!(
        server_registration_start(&setup, &request, &oversized),
        Err(AuthError::InvalidArgument)
    ));
    assert!(matches!(
        server_registration_start(&setup, &request, &[]),
        Err(AuthError::InvalidArgument)
    ));
}

#[test]
fn sensitive_persistence_containers_reject_oversized_inputs_before_decode() {
    assert!(matches!(
        ServerSetupBytes::from_bytes(&vec![0u8; MAX_SERVER_SETUP_BYTES + 1]),
        Err(AuthError::InvalidSetup)
    ));
    assert!(matches!(
        secure_auth::CredentialFile::from_bytes(&vec![0u8; MAX_CREDENTIAL_FILE_BYTES + 1]),
        Err(AuthError::InvalidCredentialFile)
    ));
    assert!(matches!(
        ServerLoginStateBytes::from_bytes(&vec![0u8; MAX_SERVER_LOGIN_STATE_BYTES + 1]),
        Err(AuthError::MessageTooLarge)
    ));
}
