use secure_core::{DisplayState, InputPolicy, KeyId, SecretBuffer, SecureSession};
use std::time::Duration;

#[test]
fn key_events_accept_ids_and_state_is_masked() {
    let mut session = SecureSession::begin(InputPolicy::numeric(8));
    session.press_key(&KeyId::new("digit-1")).unwrap();
    session.press_key(&KeyId::new("digit-2")).unwrap();
    assert_eq!(session.masked_state().length, 2);
    assert_eq!(session.masked_state().display_state, DisplayState::Masked);
}

#[test]
fn secret_buffer_is_empty_after_clear() {
    let mut buffer = SecretBuffer::from_bytes(&[0x31, 0x32]);
    buffer.clear();
    assert!(buffer.is_empty());
}

#[test]
fn no_secret_getter_exists_in_the_public_contract() {
    let public_api = include_str!("../src/lib.rs");
    assert!(!public_api.contains("get_password"));
    assert!(!public_api.contains("password: String"));
}

#[test]
fn native_submission_handoff_cannot_return_a_secret_value() {
    let public_api = include_str!("../src/lib.rs");
    assert!(!public_api.contains("with_native_bytes<R>"));
    assert!(public_api.contains("pub fn with_native_bytes(&self, operation: impl FnOnce(&[u8]))"));
}

#[test]
fn submit_seals_the_session_and_returns_only_opaque_state() {
    let mut session = SecureSession::begin(InputPolicy::numeric(8));
    session.press_key(&KeyId::new("digit-1")).unwrap();
    let _submission = session.submit().unwrap();

    assert_eq!(session.masked_state().length, 0);
    assert_eq!(
        session.masked_state().display_state,
        DisplayState::Submitted
    );
    assert!(session.press_key(&KeyId::new("digit-2")).is_err());
}

#[test]
fn cancel_closes_and_clears_the_session() {
    let mut session = SecureSession::begin(InputPolicy::numeric(8));
    session.press_key(&KeyId::new("digit-1")).unwrap();
    session.cancel();

    assert_eq!(session.masked_state().length, 0);
    assert_eq!(
        session.masked_state().display_state,
        DisplayState::Cancelled
    );
    assert!(session.submit().is_err());
}

#[test]
fn zero_timeout_expires_before_the_next_operation() {
    let mut session = SecureSession::begin_with_timeout(InputPolicy::numeric(8), Duration::ZERO);
    assert!(session.expire_if_needed());
    assert_eq!(session.refresh().display_state, DisplayState::Cancelled);
    assert!(session.press_key(&KeyId::new("digit-1")).is_err());
}
