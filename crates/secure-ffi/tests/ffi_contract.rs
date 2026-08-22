use std::mem::size_of;
use std::ptr;

use secure_auth::{
    client_registration_finish, client_registration_start, server_login_finish, server_login_start,
    server_registration_finish, server_registration_start, Message, ServerSetupBytes,
};
use secure_ffi::{
    secure_keypad_abi_version, secure_keypad_auth_message_copy, secure_keypad_auth_message_free,
    secure_keypad_auth_message_new, secure_keypad_auth_message_size,
    secure_keypad_client_login_finish, secure_keypad_client_login_free,
    secure_keypad_client_login_start, secure_keypad_client_registration_finish,
    secure_keypad_client_registration_free, secure_keypad_client_registration_start,
    secure_keypad_session_backspace, secure_keypad_session_cancel, secure_keypad_session_clear,
    secure_keypad_session_free, secure_keypad_session_new_ascii, secure_keypad_session_new_hangul,
    secure_keypad_session_new_numeric, secure_keypad_session_press_key,
    secure_keypad_session_refresh, secure_keypad_session_submit, secure_keypad_submission_free,
    SecureKeypadAuthMessage, SecureKeypadClientLogin, SecureKeypadClientRegistration,
    SecureKeypadDisplayState, SecureKeypadError, SecureKeypadMaskedState, SecureKeypadSession,
    SecureKeypadSubmission,
};

fn submitted_numeric_submission() -> *mut SecureKeypadSubmission {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-1";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };
    submission
}

#[test]
fn ffi_reports_the_compiled_abi_version_before_session_creation() {
    assert_eq!(secure_keypad_abi_version(), 2);
}

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
fn ffi_rejects_key_buffers_that_overlap_the_session_object() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );

    let overlapping_key = session.cast::<u8>();
    assert_eq!(
        unsafe {
            secure_keypad_session_press_key(
                session,
                overlapping_key,
                size_of::<SecureKeypadSession>().min(1),
            )
        },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn ffi_rejects_masked_state_output_that_overlaps_the_session_object() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );

    let overlapping_output = session.cast::<SecureKeypadMaskedState>();
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, overlapping_output) },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn ffi_rejects_submission_output_that_overlaps_the_session_object() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );

    let overlapping_output = session.cast::<*mut SecureKeypadSubmission>();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, overlapping_output) },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn ffi_rejects_aliased_login_output_slots_without_consuming_submission() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-1";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };
    let original_submission = submission;

    let aliased_login_output = (&mut submission as *mut *mut SecureKeypadSubmission)
        .cast::<*mut SecureKeypadClientLogin>();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_login_start(&mut submission, aliased_login_output, &mut request)
        },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(submission, original_submission);
    assert!(request.is_null());

    unsafe { secure_keypad_submission_free(submission) };
}

#[test]
fn ffi_rejects_aliased_login_request_output_without_leaking_handles() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-1";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };
    let original_submission = submission;

    let mut login: *mut SecureKeypadClientLogin = ptr::null_mut();
    let aliased_request_output =
        (&mut login as *mut *mut SecureKeypadClientLogin).cast::<*mut SecureKeypadAuthMessage>();
    assert_eq!(
        unsafe {
            secure_keypad_client_login_start(&mut submission, &mut login, aliased_request_output)
        },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(submission, original_submission);
    assert!(login.is_null());

    unsafe { secure_keypad_submission_free(submission) };
}

#[test]
fn ffi_rejects_aliased_registration_output_slots_without_consuming_submission() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-1";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };
    let original_submission = submission;

    let mut registration: *mut SecureKeypadClientRegistration = ptr::null_mut();
    let aliased_request_output = (&mut registration as *mut *mut SecureKeypadClientRegistration)
        .cast::<*mut SecureKeypadAuthMessage>();
    assert_eq!(
        unsafe {
            secure_keypad_client_registration_start(
                &mut submission,
                &mut registration,
                aliased_request_output,
            )
        },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(submission, original_submission);
    assert!(registration.is_null());

    unsafe { secure_keypad_submission_free(submission) };
}

#[test]
fn ffi_rejects_aliased_login_finish_output_without_losing_state() {
    let mut submission = submitted_numeric_submission();
    let mut login: *mut SecureKeypadClientLogin = ptr::null_mut();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_client_login_start(&mut submission, &mut login, &mut request) },
        SecureKeypadError::Ok
    );
    assert!(submission.is_null());
    let original_login = login;
    let aliased_finalization_output =
        (&mut login as *mut *mut SecureKeypadClientLogin).cast::<*mut SecureKeypadAuthMessage>();

    assert_eq!(
        unsafe {
            secure_keypad_client_login_finish(
                &mut login,
                request,
                ptr::null(),
                0,
                ptr::null(),
                0,
                aliased_finalization_output,
            )
        },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(login, original_login);

    unsafe {
        secure_keypad_client_login_free(original_login);
        secure_keypad_auth_message_free(request);
    }
}

#[test]
fn ffi_rejects_aliased_registration_finish_output_without_losing_state() {
    let mut submission = submitted_numeric_submission();
    let mut registration: *mut SecureKeypadClientRegistration = ptr::null_mut();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_registration_start(
                &mut submission,
                &mut registration,
                &mut request,
            )
        },
        SecureKeypadError::Ok
    );
    assert!(submission.is_null());
    let original_registration = registration;
    let aliased_upload_output = (&mut registration as *mut *mut SecureKeypadClientRegistration)
        .cast::<*mut SecureKeypadAuthMessage>();

    assert_eq!(
        unsafe {
            secure_keypad_client_registration_finish(
                &mut registration,
                request,
                ptr::null(),
                0,
                ptr::null(),
                0,
                aliased_upload_output,
            )
        },
        SecureKeypadError::InvalidArgument
    );
    assert_eq!(registration, original_registration);

    unsafe {
        secure_keypad_client_registration_free(original_registration);
        secure_keypad_auth_message_free(request);
    }
}

#[test]
fn ffi_rejects_aliased_auth_message_input_and_output_slots() {
    let mut message: *mut SecureKeypadAuthMessage = ptr::null_mut();
    let aliased_bytes = (&mut message as *mut *mut SecureKeypadAuthMessage).cast::<u8>();
    assert_eq!(
        unsafe { secure_keypad_auth_message_new(aliased_bytes, 1, &mut message) },
        SecureKeypadError::InvalidArgument
    );
    assert!(message.is_null());
}

#[repr(C, align(8))]
struct AlignedCopyBuffer {
    bytes: [u8; 16 * 1024],
}

#[test]
fn ffi_rejects_aliased_auth_message_output_and_length_slots() {
    let payload = b"fixture-opaque-message";
    let mut message: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_auth_message_new(payload.as_ptr(), payload.len(), &mut message) },
        SecureKeypadError::Ok
    );

    let mut storage = AlignedCopyBuffer {
        bytes: [0u8; 16 * 1024],
    };
    let aliased_output_written = storage.bytes.as_mut_ptr().cast::<usize>();
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_copy(
                message,
                storage.bytes.as_mut_ptr(),
                storage.bytes.len(),
                aliased_output_written,
            )
        },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_auth_message_free(message) };
}

#[test]
fn ffi_rejects_auth_message_size_output_that_overlaps_the_message_object() {
    let payload = b"fixture-opaque-message";
    let mut message: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_auth_message_new(payload.as_ptr(), payload.len(), &mut message) },
        SecureKeypadError::Ok
    );

    let overlapping_output = message.cast::<usize>();
    assert_eq!(
        unsafe { secure_keypad_auth_message_size(message, overlapping_output) },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_auth_message_free(message) };
}

#[test]
fn ffi_rejects_auth_message_copy_output_that_overlaps_the_message_object() {
    let payload = b"fixture-opaque-message";
    let mut message: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_auth_message_new(payload.as_ptr(), payload.len(), &mut message) },
        SecureKeypadError::Ok
    );

    let overlapping_output = message.cast::<u8>();
    let mut written = 0;
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_copy(
                message,
                overlapping_output,
                size_of::<SecureKeypadAuthMessage>(),
                &mut written,
            )
        },
        SecureKeypadError::InvalidArgument
    );

    unsafe { secure_keypad_auth_message_free(message) };
}

#[test]
fn ascii_constructor_accepts_bounded_policy() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_ascii(8, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    assert!(!session.is_null());
    let ascii = b"ascii-41";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, ascii.as_ptr(), ascii.len()) },
        SecureKeypadError::Ok
    );
    let label = b"A";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, label.as_ptr(), label.len()) },
        SecureKeypadError::InvalidKey
    );
    let mut state = SecureKeypadMaskedState::default();
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.length, 1);
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

#[test]
fn ffi_cancel_zeroizes_input_and_closes_the_session() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(4, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-7";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );

    assert_eq!(
        unsafe { secure_keypad_session_cancel(session) },
        SecureKeypadError::Ok
    );
    let mut state = SecureKeypadMaskedState::default();
    assert_eq!(
        unsafe { secure_keypad_session_refresh(session, &mut state) },
        SecureKeypadError::Ok
    );
    assert_eq!(state.length, 0);
    assert_eq!(state.display_state, SecureKeypadDisplayState::Cancelled);
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Inactive
    );

    unsafe { secure_keypad_session_free(session) };
}

#[test]
fn native_auth_ffi_consumes_submission_without_returning_a_session_key() {
    const CLIENT_ID: &[u8] = b"fixture-user";
    const SERVER_ID: &[u8] = b"fixture-server";
    const PASSWORD: &[u8] = b"12";

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

    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    for key in [b"digit-1".as_slice(), b"digit-2".as_slice()] {
        assert_eq!(
            unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
            SecureKeypadError::Ok
        );
    }
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };

    let mut client_login: *mut SecureKeypadClientLogin = ptr::null_mut();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_login_start(&mut submission, &mut client_login, &mut request)
        },
        SecureKeypadError::Ok
    );
    assert!(submission.is_null());

    let request_bytes = copy_auth_message(request);
    let (response, server_state) = server_login_start(
        &setup,
        Some(&credential_file),
        &Message::from_bytes(&request_bytes).unwrap(),
        CLIENT_ID,
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    let mut response_handle: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_new(
                response.as_bytes().as_ptr(),
                response.as_bytes().len(),
                &mut response_handle,
            )
        },
        SecureKeypadError::Ok
    );

    let mut finalization: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_login_finish(
                &mut client_login,
                response_handle,
                CLIENT_ID.as_ptr(),
                CLIENT_ID.len(),
                SERVER_ID.as_ptr(),
                SERVER_ID.len(),
                &mut finalization,
            )
        },
        SecureKeypadError::Ok
    );
    assert!(client_login.is_null());
    let finalization_bytes = copy_auth_message(finalization);
    let server_key = server_login_finish(
        server_state,
        &Message::from_bytes(&finalization_bytes).unwrap(),
        CLIENT_ID,
        SERVER_ID,
    )
    .unwrap();
    assert!(!server_key.is_empty());

    unsafe {
        secure_keypad_auth_message_free(request);
        secure_keypad_auth_message_free(response_handle);
        secure_keypad_auth_message_free(finalization);
    }
}

#[test]
fn native_registration_ffi_consumes_submission_without_returning_password_bytes() {
    const CLIENT_ID: &[u8] = b"fixture-user";
    const SERVER_ID: &[u8] = b"fixture-server";

    let setup = ServerSetupBytes::generate().unwrap();
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    for key in [b"digit-1".as_slice(), b"digit-2".as_slice()] {
        assert_eq!(
            unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
            SecureKeypadError::Ok
        );
    }
    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };

    let mut client_registration: *mut SecureKeypadClientRegistration = ptr::null_mut();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_registration_start(
                &mut submission,
                &mut client_registration,
                &mut request,
            )
        },
        SecureKeypadError::Ok
    );
    assert!(submission.is_null());

    let request_bytes = copy_auth_message(request);
    let registration_response = server_registration_start(
        &setup,
        &Message::from_bytes(&request_bytes).unwrap(),
        CLIENT_ID,
    )
    .unwrap();
    let mut response_handle: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_new(
                registration_response.as_bytes().as_ptr(),
                registration_response.as_bytes().len(),
                &mut response_handle,
            )
        },
        SecureKeypadError::Ok
    );

    let mut upload: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_registration_finish(
                &mut client_registration,
                response_handle,
                CLIENT_ID.as_ptr(),
                CLIENT_ID.len(),
                SERVER_ID.as_ptr(),
                SERVER_ID.len(),
                &mut upload,
            )
        },
        SecureKeypadError::Ok
    );
    assert!(client_registration.is_null());
    let upload_bytes = copy_auth_message(upload);
    let credential_file = server_registration_finish(&Message::from_bytes(&upload_bytes).unwrap());
    assert!(credential_file.is_ok());

    unsafe {
        secure_keypad_auth_message_free(request);
        secure_keypad_auth_message_free(response_handle);
        secure_keypad_auth_message_free(upload);
        secure_keypad_client_registration_free(ptr::null_mut());
    }
}

fn copy_auth_message(message: *mut SecureKeypadAuthMessage) -> Vec<u8> {
    let mut size = 0;
    assert_eq!(
        unsafe { secure_keypad_auth_message_size(message, &mut size) },
        SecureKeypadError::Ok
    );
    let mut bytes = vec![0u8; size];
    let mut written = 0;
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_copy(message, bytes.as_mut_ptr(), bytes.len(), &mut written)
        },
        SecureKeypadError::Ok
    );
    bytes.truncate(written);
    bytes
}

#[test]
fn client_login_free_is_safe_for_an_aborted_native_flow() {
    unsafe { secure_keypad_client_login_free(ptr::null_mut()) };
}

#[test]
fn client_registration_free_is_safe_for_an_aborted_native_flow() {
    let mut session: *mut SecureKeypadSession = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_new_numeric(2, 60_000, &mut session) },
        SecureKeypadError::Ok
    );
    let key = b"digit-1";
    assert_eq!(
        unsafe { secure_keypad_session_press_key(session, key.as_ptr(), key.len()) },
        SecureKeypadError::Ok
    );

    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_session_submit(session, &mut submission) },
        SecureKeypadError::Ok
    );
    unsafe { secure_keypad_session_free(session) };

    let mut registration: *mut SecureKeypadClientRegistration = ptr::null_mut();
    let mut request: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe {
            secure_keypad_client_registration_start(
                &mut submission,
                &mut registration,
                &mut request,
            )
        },
        SecureKeypadError::Ok
    );
    assert!(submission.is_null());
    assert!(!registration.is_null());
    assert!(!request.is_null());

    unsafe {
        secure_keypad_client_registration_free(registration);
        secure_keypad_auth_message_free(request);
    }
}

#[test]
fn auth_message_copy_reports_required_size_without_partial_secret_copy() {
    let payload = b"fixture-opaque-message";
    let mut message: *mut SecureKeypadAuthMessage = ptr::null_mut();
    assert_eq!(
        unsafe { secure_keypad_auth_message_new(payload.as_ptr(), payload.len(), &mut message) },
        SecureKeypadError::Ok
    );

    let mut output = [0xA5u8; 4];
    let mut written = 0;
    assert_eq!(
        unsafe {
            secure_keypad_auth_message_copy(
                message,
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        SecureKeypadError::BufferTooSmall
    );
    assert_eq!(written, payload.len());
    assert_eq!(output, [0xA5; 4]);
    unsafe { secure_keypad_auth_message_free(message) };
}
