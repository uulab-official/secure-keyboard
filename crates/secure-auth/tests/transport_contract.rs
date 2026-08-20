use secure_auth::{
    AuthEnvelope, AuthError, AuthMessageKind, Message, CIPHER_SUITE_ID, MAX_JSON_BODY_BYTES,
    PROTOCOL_VERSION,
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

#[test]
fn serde_deserialization_preserves_a_valid_envelope() {
    let wire = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "suite_id": CIPHER_SUITE_ID,
        "message_kind": "CredentialRequest",
        "server_key_id": "server-key-2026",
        "payload": [102, 105, 120, 116, 117, 114, 101]
    });

    let envelope: AuthEnvelope = serde_json::from_value(wire).unwrap();
    assert_eq!(envelope.message_kind(), AuthMessageKind::CredentialRequest);
    let message = envelope
        .into_message(AuthMessageKind::CredentialRequest, "server-key-2026")
        .unwrap();
    assert_eq!(message.as_bytes(), b"fixture");
}

#[test]
fn serde_deserialization_rejects_invalid_payload_bounds() {
    let empty = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "suite_id": CIPHER_SUITE_ID,
        "message_kind": "CredentialRequest",
        "server_key_id": "server-key-2026",
        "payload": []
    });
    assert!(serde_json::from_value::<AuthEnvelope>(empty).is_err());

    let oversized = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "suite_id": CIPHER_SUITE_ID,
        "message_kind": "CredentialRequest",
        "server_key_id": "server-key-2026",
        "payload": vec![0u8; 16 * 1024 + 1]
    });
    assert!(serde_json::from_value::<AuthEnvelope>(oversized).is_err());
}

#[test]
fn json_decoder_returns_a_validated_envelope() {
    let envelope = AuthEnvelope::new(
        AuthMessageKind::CredentialRequest,
        "server-key-2026",
        &Message::from_bytes(b"fixture"),
    )
    .unwrap();
    let wire = serde_json::to_vec(&envelope).unwrap();

    let decoded = AuthEnvelope::from_json(&wire).unwrap();
    let message = decoded
        .into_message(AuthMessageKind::CredentialRequest, "server-key-2026")
        .unwrap();
    assert_eq!(message.as_bytes(), b"fixture");
}

#[test]
fn json_decoder_rejects_oversized_bodies_and_malformed_envelopes() {
    let oversized_body = vec![b' '; MAX_JSON_BODY_BYTES + 1];
    assert!(matches!(
        AuthEnvelope::from_json(&oversized_body),
        Err(AuthError::RequestBodyTooLarge)
    ));
    assert!(matches!(
        AuthEnvelope::from_json(b"{}"),
        Err(AuthError::MalformedTransport)
    ));
}
