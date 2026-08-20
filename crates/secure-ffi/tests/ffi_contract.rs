use std::ptr;

use secure_ffi::{
    secure_keypad_session_backspace, secure_keypad_session_clear, secure_keypad_session_free,
    secure_keypad_session_new_hangul, secure_keypad_session_new_numeric,
    secure_keypad_session_press_key, secure_keypad_session_refresh, secure_keypad_session_submit,
    secure_keypad_submission_free, SecureKeypadDisplayState, SecureKeypadError,
    SecureKeypadMaskedState, SecureKeypadSession, SecureKeypadSubmission,
};

#[test]
fn numeric_ffi_exposes_only_masked_state_and_opaque_submission() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    assert!(!session.is_null());

    let mut state = SecureKeypadMaskedState::default();
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.length, 0);
    assert_eq!(state.display_state, SecureKeypadDisplayState::Empty);

    let key = b"digit-7";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.length, 1);
    assert_eq!(state.display_state, SecureKeypadDisplayState::Masked);

    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    assert!(!submission.is_null());
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.display_state, SecureKeypadDisplayState::Submitted);

    unsafe { secure_keypad_submission_free(submission) };
    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn ffi_rejects_null_and_invalid_public_key_inputs() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, ptr::null_mut()) },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );

    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, ptr::null(), 0) },
        SecureKeypadError::InvalidArgument
    );
    let invalid_utf8 = [0xff];
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, invalid_utf8.as_ptr(), 1) },
        SecureKeypadError::InvalidUtf8
    );
    let unknown = b"digit-10";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, unknown.as_ptr(), unknown.len()) },
        SecureKeypadError::InvalidKey
    );

    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn hangul_ffi_preserves_composed_rendered_length() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_hangul(8, 60_000, &mut session) },
        SecureKeypadError::Ok
    );

    let leading = b"jamo-giyeok";
    let vowel = b"vowel-a";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, leading.as_ptr(), leading.len()) },
        SecureKeypadError::Ok
    );
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, vowel.as_ptr(), vowel.len()) },
        SecureKeypadError::Ok
    );

    let mut state = SecureKeypadMaskedState::default();
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.length, 1);

    assert_eq!(
        unsafe { secure_keypad_session_backspace(session) },
        SecureKeypadError::Ok
    );
    assert_eq!(
        unsafe { secure_keypad_session_clear(session) },
        SecureKeypadError::Ok
    );

    unsafe { secure_keypad_session_free(session) };
}
