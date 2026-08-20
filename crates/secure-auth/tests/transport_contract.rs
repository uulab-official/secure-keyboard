use secure_auth::{
    AuthEnvelope, AuthError, AuthMessageKind, Message, CIPHER_SUITE_ID, PROTOCOL_VERSION,
};

#[test]
fn versioned_envelope_round_trips_a_typed_opaque_message() {
    let message = Message::from_bytes(b"fixture-opaque-message");
    let envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        &message,
    )
    .unwrap();

    assert_eq!(envelope.protocol_version(), PROTOCOL_VERSION);
    assert_eq!(envelope.suite_id(), CIPHER_SUITE_ID);
    assert_eq!(envelope.server_key_id(), "server-key-2026");

    let recovered = envelope
        .into_message(AuthMessageKind::CredentialRequest, "server-key-2026")
        .unwrap();
    assert_eq!(recovered.as_bytes(), b"fixture-opaque-message");
}

#[test]
fn envelope_rejects_version_suite_kind_and_key_downgrades() {
    let message = Message::from_bytes(b"fixture");
    let wrong_version = AuthEnvelope::from_parts(
        PROTOCOL_VERSION - 1,
        CIPHER_SUITE_ID,
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        message.as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        wrong_version.into_message(AuthMessageKind::CredentialRequest, "server-key-2026"),
        Err(AuthError::UnsupportedVersion)
    ));

    let wrong_suite = AuthEnvelope::from_parts(
        PROTOCOL_VERSION,
        "opaque-legacy-suite",
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        message.as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        wrong_suite.into_message(AuthMessageKind::CredentialRequest, "server-key-2026"),
        Err(AuthError::UnsupportedSuite)
    ));

    let wrong_kind = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        &message,
    )
    .unwrap();
    assert!(matches!(
        wrong_kind.into_message(AuthMessageKind::RegistrationRequest, "server-key-2026"),
        Err(AuthError::UnexpectedMessageKind)
    ));

    let wrong_key = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        &message,
    )
    .unwrap();
    assert!(matches!(
        wrong_key.into_message(AuthMessageKind::CredentialRequest, "server-key-2027"),
        Err(AuthError::UnexpectedServerKey)
    ));
}

#[test]
fn envelope_rejects_empty_or_oversized_transport_messages() {
    let empty = Message::from_bytes(&[]);
    assert!(matches!(
        AuthEnvelope::new(
            AuthMessageKind::CredentialRequest,
            "server-key-2026",
            &empty
        ),
        Err(AuthError::EmptyMessage)
    ));

    let oversized = Message::from_bytes(&vec![0u8; 16 * 1024 + 1]);
    assert!(matches!(
        AuthEnvelope::new(
            AuthMessageKind::CredentialRequest,
            "server-key-2026",
            &oversized
        ),
        Err(AuthError::MessageTooLarge)
    ));
}
