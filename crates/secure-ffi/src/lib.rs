#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! C ABI boundary for the framework-neutral secure keypad core.
//!
//! The ABI exposes public key identifiers, masked state, and opaque ownership
//! handles only. It has no function that returns accumulated secret bytes.
//! Handles are single-owner and must be used from one native thread at a time.

use core::time::Duration;
use std::{panic::catch_unwind, panic::AssertUnwindSafe, ptr, slice, str};

use secure_auth::{
    client_login_finish_from_native_state, client_login_start_from_submission,
    client_registration_finish_from_native_state, client_registration_start_from_submission,
    AuthError, Message,
};
use secure_core::{DisplayState, InputPolicy, MaskedState, SecureSession, SessionError};

const MAX_KEY_ID_BYTES: usize = 64;
const MAX_PUBLIC_ID_BYTES: usize = 256;
const MAX_TOKENS: u32 = secure_core::MAX_INPUT_TOKENS as u32;
const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// ABI version implemented by this linked native library.
pub const SECURE_KEYPAD_ABI_VERSION: u32 = 2;

/// Returns the ABI version implemented by the linked native library.
///
/// Native hosts must compare this value with the header's
/// `SECURE_KEYPAD_ABI_VERSION` before creating a session and fail closed when
/// the values differ.
#[no_mangle]
pub extern "C" fn secure_keypad_abi_version() -> u32 {
    SECURE_KEYPAD_ABI_VERSION
}

/// Stable result codes returned by the C ABI.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureKeypadError {
    /// The operation completed successfully.
    Ok = 0,
    /// A required pointer, length, or configuration value is invalid.
    InvalidArgument = 1,
    /// A key identifier was not valid UTF-8.
    InvalidUtf8 = 2,
    /// A key identifier is not allowed by the active input policy.
    InvalidKey = 3,
    /// The configured token limit has been reached.
    LimitReached = 4,
    /// The session has no buffered input.
    Empty = 5,
    /// The session has already been submitted, cancelled, or expired.
    Inactive = 6,
    /// The native boundary encountered an internal representation failure.
    Internal = 7,
    /// A native auth message exceeds the fixed payload limit.
    MessageTooLarge = 8,
    /// The supplied output buffer is smaller than the message.
    BufferTooSmall = 9,
    /// The native OPAQUE engine rejected a protocol message.
    AuthProtocol = 10,
    /// The native OPAQUE proof was invalid.
    AuthInvalidLogin = 11,
    /// A Rust panic was contained at the ABI boundary.
    Panic = 255,
}

/// Non-secret display state values shared with the native header.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecureKeypadDisplayState {
    /// No input is currently buffered.
    #[default]
    Empty = 0,
    /// Input exists and must be rendered as a mask.
    Masked = 1,
    /// A submission was created and the session is closed.
    Submitted = 2,
    /// The session was cancelled and its input was cleared.
    Cancelled = 3,
}

/// Masked state returned to a native UI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecureKeypadMaskedState {
    /// Number of rendered characters, never the characters themselves.
    pub length: u32,
    /// Non-secret display state.
    pub display_state: SecureKeypadDisplayState,
}

/// Opaque native-owned keypad session.
#[repr(C)]
pub struct SecureKeypadSession {
    core: SecureSession,
}

/// Opaque native-owned submission. There is intentionally no byte accessor.
#[repr(C)]
pub struct SecureKeypadSubmission {
    core: secure_core::Submission,
}

/// Opaque native-owned OPAQUE transport message.
#[repr(C)]
pub struct SecureKeypadAuthMessage {
    core: Message,
}

/// Opaque native-owned OPAQUE client login state.
#[repr(C)]
pub struct SecureKeypadClientLogin {
    core: secure_auth::NativeClientLoginState,
}

/// Opaque native-only OPAQUE client registration state.
#[repr(C)]
pub struct SecureKeypadClientRegistration {
    core: secure_auth::NativeClientRegistrationState,
}

fn contain_panic(operation: impl FnOnce() -> SecureKeypadError) -> SecureKeypadError {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => SecureKeypadError::Panic,
    }
}

fn map_session_error(error: SessionError) -> SecureKeypadError {
    match error {
        SessionError::InvalidKey(_) => SecureKeypadError::InvalidKey,
        SessionError::LimitReached => SecureKeypadError::LimitReached,
        SessionError::Empty => SecureKeypadError::Empty,
        SessionError::Inactive => SecureKeypadError::Inactive,
    }
}

fn map_auth_error(error: AuthError) -> SecureKeypadError {
    match error {
        AuthError::InvalidLogin => SecureKeypadError::AuthInvalidLogin,
        _ => SecureKeypadError::AuthProtocol,
    }
}

fn write_masked_state(
    output: *mut SecureKeypadMaskedState,
    state: MaskedState,
) -> SecureKeypadError {
    let Ok(length) = u32::try_from(state.length) else {
        return SecureKeypadError::Internal;
    };
    let display_state = match state.display_state {
        DisplayState::Empty => SecureKeypadDisplayState::Empty,
        DisplayState::Masked => SecureKeypadDisplayState::Masked,
        DisplayState::Submitted => SecureKeypadDisplayState::Submitted,
        DisplayState::Cancelled => SecureKeypadDisplayState::Cancelled,
    };
    // SAFETY: The caller must provide a valid, writable output pointer. This
    // precondition is documented on each exported function that calls here.
    unsafe {
        *output = SecureKeypadMaskedState {
            length,
            display_state,
        };
    }
    SecureKeypadError::Ok
}

fn create_session(
    policy: InputPolicy,
    timeout_ms: u64,
    output: *mut *mut SecureKeypadSession,
) -> SecureKeypadError {
    if output.is_null() || timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return SecureKeypadError::InvalidArgument;
    }
    // SAFETY: `output` was checked for null above and is required to be a
    // writable pointer by the exported function contract.
    unsafe {
        *output = ptr::null_mut();
    }
    let session = SecureKeypadSession {
        core: SecureSession::begin_with_timeout(policy, Duration::from_millis(timeout_ms)),
    };
    // SAFETY: The raw pointer is returned to the same caller that supplied the
    // output slot and must later be released exactly once by the matching free
    // function.
    unsafe {
        *output = Box::into_raw(Box::new(session));
    }
    SecureKeypadError::Ok
}

unsafe fn parse_key_id(
    key_id: *const u8,
    key_id_len: usize,
) -> Result<secure_core::KeyId, SecureKeypadError> {
    if key_id.is_null() || key_id_len == 0 || key_id_len > MAX_KEY_ID_BYTES {
        return Err(SecureKeypadError::InvalidArgument);
    }
    // SAFETY: The caller must provide a readable buffer of `key_id_len` bytes;
    // this is the standard pointer/length precondition documented below.
    let bytes = unsafe { slice::from_raw_parts(key_id, key_id_len) };
    let value = str::from_utf8(bytes).map_err(|_| SecureKeypadError::InvalidUtf8)?;
    Ok(secure_core::KeyId::new(value))
}

unsafe fn parse_public_id(
    identifier: *const u8,
    identifier_len: usize,
) -> Result<Vec<u8>, SecureKeypadError> {
    if identifier.is_null() || identifier_len == 0 || identifier_len > MAX_PUBLIC_ID_BYTES {
        return Err(SecureKeypadError::InvalidArgument);
    }
    // SAFETY: The caller contract guarantees a readable public identifier
    // buffer for the duration of the enclosing FFI call.
    Ok(unsafe { slice::from_raw_parts(identifier, identifier_len) }.to_vec())
}

/// Creates a numeric keypad session.
///
/// `timeout_ms` is a monotonic inactivity timeout and must be between 1 ms and
/// 24 hours. The returned session is owned by the caller.
///
/// # Safety
///
/// `output` must be a valid, writable pointer to a `*mut SecureKeypadSession`.
/// The returned handle must be freed exactly once with
/// [`secure_keypad_session_free`], and must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_new_numeric(
    max_tokens: u32,
    timeout_ms: u64,
    output: *mut *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if max_tokens == 0 || max_tokens > MAX_TOKENS {
            return SecureKeypadError::InvalidArgument;
        }
        create_session(
            InputPolicy::numeric(max_tokens as usize),
            timeout_ms,
            output,
        )
    })
}

/// Creates a printable-ASCII keypad session.
///
/// The native caller supplies public IDs in the `ascii-XX` form, where `XX`
/// is a lowercase hexadecimal printable-ASCII code point. Labels and host
/// strings are never used as secret input values.
///
/// # Safety
///
/// `output` must be a valid, writable pointer to a `*mut SecureKeypadSession`.
/// The returned handle must be freed exactly once with
/// [`secure_keypad_session_free`], and must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_new_ascii(
    max_tokens: u32,
    timeout_ms: u64,
    output: *mut *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if max_tokens == 0 || max_tokens > MAX_TOKENS {
            return SecureKeypadError::InvalidArgument;
        }
        create_session(InputPolicy::ascii(max_tokens as usize), timeout_ms, output)
    })
}

/// Creates a Hangul jamo keypad session with the locked NFC-oriented policy.
///
/// # Safety
///
/// `output` must be a valid, writable pointer to a `*mut SecureKeypadSession`.
/// The returned handle must be freed exactly once with
/// [`secure_keypad_session_free`], and must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_new_hangul(
    max_tokens: u32,
    timeout_ms: u64,
    output: *mut *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if max_tokens == 0 || max_tokens > MAX_TOKENS {
            return SecureKeypadError::InvalidArgument;
        }
        create_session(InputPolicy::hangul(max_tokens as usize), timeout_ms, output)
    })
}

/// Frees a keypad session and zeroizes any buffered input.
///
/// # Safety
///
/// `session` must be null or a handle returned by a constructor in this crate
/// that has not already been freed. After this call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_free(session: *mut SecureKeypadSession) {
    let _ = contain_panic(|| {
        if !session.is_null() {
            // SAFETY: The caller contract requires ownership of a live handle.
            unsafe { drop(Box::from_raw(session)) };
        }
        SecureKeypadError::Ok
    });
}

/// Frees an opaque submission and zeroizes its secret buffer.
///
/// # Safety
///
/// `submission` must be null or a handle returned by
/// [`secure_keypad_session_submit`] that has not already been freed. After this
/// call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_submission_free(submission: *mut SecureKeypadSubmission) {
    let _ = contain_panic(|| {
        if !submission.is_null() {
            // SAFETY: The caller contract requires ownership of a live handle.
            unsafe { drop(Box::from_raw(submission)) };
        }
        SecureKeypadError::Ok
    });
}

/// Presses a public key identifier without returning accumulated input.
///
/// # Safety
///
/// `session` must be a live handle owned by the caller. `key_id` must point to
/// a readable UTF-8 buffer of exactly `key_id_len` bytes for the duration of
/// this call. The session must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_press_key(
    session: *mut SecureKeypadSession,
    key_id: *const u8,
    key_id_len: usize,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        let session = unsafe { &mut *session };
        // SAFETY: The caller contract for this function validates the key
        // buffer's readability and lifetime.
        let key_id = match unsafe { parse_key_id(key_id, key_id_len) } {
            Ok(key_id) => key_id,
            Err(error) => return error,
        };
        session
            .core
            .press_key(&key_id)
            .map_or_else(map_session_error, |_| SecureKeypadError::Ok)
    })
}

/// Removes the last key identifier from a session.
///
/// # Safety
///
/// `session` must be a live, exclusively owned handle and must not be used
/// concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_backspace(
    session: *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        unsafe { &mut *session }
            .core
            .backspace()
            .map_or_else(map_session_error, |_| SecureKeypadError::Ok)
    })
}

/// Clears all buffered input in a session.
///
/// # Safety
///
/// `session` must be a live, exclusively owned handle and must not be used
/// concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_clear(
    session: *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        unsafe { &mut *session }
            .core
            .clear()
            .map_or_else(map_session_error, |_| SecureKeypadError::Ok)
    })
}

/// Cancels a session and zeroizes any buffered input without creating a
/// submission. Cancellation is idempotent for a live session.
///
/// # Safety
///
/// `session` must be a live, exclusively owned handle and must not be used
/// concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_cancel(
    session: *mut SecureKeypadSession,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        unsafe { &mut *session }.core.cancel();
        SecureKeypadError::Ok
    })
}

/// Refreshes timeout state and writes only masked state to `output`.
///
/// # Safety
///
/// `session` must be a live, exclusively owned handle. `output` must be a
/// valid, writable pointer for the duration of this call. The session must not
/// be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_refresh(
    session: *mut SecureKeypadSession,
    output: *mut SecureKeypadMaskedState,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() || output.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        let state = unsafe { &mut *session }.core.refresh();
        write_masked_state(output, state)
    })
}

/// Seals the current input and returns an opaque submission handle.
///
/// The submission has no C ABI byte accessor. It must be handed to a native
/// authentication implementation or freed with
/// [`secure_keypad_submission_free`].
///
/// # Safety
///
/// `session` must be a live, exclusively owned handle. `output` must be a
/// valid, writable pointer to a `*mut SecureKeypadSubmission`. The session and
/// output handle must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_session_submit(
    session: *mut SecureKeypadSession,
    output: *mut *mut SecureKeypadSubmission,
) -> SecureKeypadError {
    contain_panic(|| {
        if session.is_null() || output.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: `output` is checked for null and is required to be writable.
        unsafe {
            *output = ptr::null_mut();
        }
        // SAFETY: The caller contract guarantees a live, exclusive session.
        let session = unsafe { &mut *session };
        let submission = match session.core.submit() {
            Ok(submission) => submission,
            Err(error) => return map_session_error(error),
        };
        // SAFETY: Ownership transfers to the caller through the output slot.
        unsafe {
            *output = Box::into_raw(Box::new(SecureKeypadSubmission { core: submission }));
        }
        SecureKeypadError::Ok
    })
}

/// Creates an opaque OPAQUE transport message from native network bytes.
///
/// This is for native networking only. The message is not a password, but it
/// is sensitive protocol data and must not be logged or sent through a
/// JavaScript/Dart bridge.
///
/// # Safety
///
/// `bytes` must point to a readable buffer of `length` bytes, and `output` must
/// be a valid writable pointer. The returned handle must be freed exactly once
/// with [`secure_keypad_auth_message_free`].
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_auth_message_new(
    bytes: *const u8,
    length: usize,
    output: *mut *mut SecureKeypadAuthMessage,
) -> SecureKeypadError {
    contain_panic(|| {
        if output.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: `output` is checked for null and must be writable.
        unsafe {
            *output = ptr::null_mut();
        }
        if bytes.is_null() || length == 0 {
            return SecureKeypadError::InvalidArgument;
        }
        if length > secure_auth::MAX_MESSAGE_BYTES {
            return SecureKeypadError::MessageTooLarge;
        }
        // SAFETY: The caller contract guarantees the input buffer is readable
        // for exactly `length` bytes during this call.
        let bytes = unsafe { slice::from_raw_parts(bytes, length) };
        let message = match Message::from_bytes(bytes) {
            Ok(message) => message,
            Err(error) => return map_auth_error(error),
        };
        // SAFETY: Ownership transfers to the caller through the output slot.
        unsafe {
            *output = Box::into_raw(Box::new(SecureKeypadAuthMessage { core: message }));
        }
        SecureKeypadError::Ok
    })
}

/// Returns the length of an opaque OPAQUE transport message.
///
/// # Safety
///
/// `message` must be a live message handle and `output_length` must be a valid
/// writable pointer.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_auth_message_size(
    message: *const SecureKeypadAuthMessage,
    output_length: *mut usize,
) -> SecureKeypadError {
    contain_panic(|| {
        if message.is_null() || output_length.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees live message and output
        // pointers.
        unsafe {
            *output_length = (*message).core.as_bytes().len();
        }
        SecureKeypadError::Ok
    })
}

/// Copies an opaque OPAQUE transport message into a native network buffer.
///
/// # Safety
///
/// `message` must be live. `output_written` must be a valid writable pointer.
/// When the message is non-empty, `output` must point to a writable buffer of
/// at least `output_length` bytes. The caller must not use the handles
/// concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_auth_message_copy(
    message: *const SecureKeypadAuthMessage,
    output: *mut u8,
    output_length: usize,
    output_written: *mut usize,
) -> SecureKeypadError {
    contain_panic(|| {
        if message.is_null() || output_written.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees a live message and writable
        // output-length pointer.
        let bytes = unsafe { &(*message).core.as_bytes() };
        // SAFETY: `output_written` is checked for null and must be writable.
        unsafe {
            *output_written = 0;
        }
        if output.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        if output_length < bytes.len() {
            // SAFETY: `output_written` is valid and writable as checked above.
            unsafe {
                *output_written = bytes.len();
            }
            return SecureKeypadError::BufferTooSmall;
        }
        // SAFETY: The caller contract guarantees a writable output buffer of
        // `output_length` bytes; `bytes.len()` is no larger than it.
        unsafe {
            slice::from_raw_parts_mut(output, bytes.len()).copy_from_slice(bytes);
            *output_written = bytes.len();
        }
        SecureKeypadError::Ok
    })
}

/// Frees an opaque OPAQUE transport message and zeroizes its bytes.
///
/// # Safety
///
/// `message` must be null or a live handle returned by
/// [`secure_keypad_auth_message_new`] that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_auth_message_free(message: *mut SecureKeypadAuthMessage) {
    let _ = contain_panic(|| {
        if !message.is_null() {
            // SAFETY: The caller contract requires ownership of a live handle.
            unsafe { drop(Box::from_raw(message)) };
        }
        SecureKeypadError::Ok
    });
}

/// Starts native OPAQUE login by consuming a sealed keypad submission.
///
/// The caller receives only the first OPAQUE transport message and an opaque
/// native login handle. The password never crosses this ABI.
///
/// # Safety
///
/// `submission` must point to a live submission pointer and `output_login` and
/// `output_request` must be valid writable pointers. On success the submission
/// pointer is set to null and ownership is consumed. All handles are
/// single-owner and must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_login_start(
    submission: *mut *mut SecureKeypadSubmission,
    output_login: *mut *mut SecureKeypadClientLogin,
    output_request: *mut *mut SecureKeypadAuthMessage,
) -> SecureKeypadError {
    contain_panic(|| {
        if submission.is_null() || output_login.is_null() || output_request.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: All output pointers are checked for null and must be writable.
        unsafe {
            *output_login = ptr::null_mut();
            *output_request = ptr::null_mut();
        }
        // SAFETY: `submission` is checked and must point to a live submission
        // handle owned by the caller.
        let submission_pointer = unsafe { *submission };
        if submission_pointer.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // Mark the caller's handle consumed before any protocol operation.
        unsafe {
            *submission = ptr::null_mut();
        }
        // SAFETY: Ownership was validated and transferred above.
        let submission = unsafe { *Box::from_raw(submission_pointer) }.core;
        let (state, request) = match client_login_start_from_submission(submission) {
            Ok(result) => result,
            Err(error) => return map_auth_error(error),
        };
        let login_handle = Box::new(SecureKeypadClientLogin { core: state });
        let request_handle = Box::new(SecureKeypadAuthMessage { core: request });
        // SAFETY: Ownership transfers through the output slots.
        unsafe {
            *output_login = Box::into_raw(login_handle);
            *output_request = Box::into_raw(request_handle);
        }
        SecureKeypadError::Ok
    })
}

/// Starts native OPAQUE registration by consuming a sealed keypad submission.
///
/// The caller receives only the first OPAQUE transport message and an opaque
/// native registration handle. The password never crosses this ABI.
///
/// # Safety
///
/// `submission` must point to a live submission pointer and `output_registration`
/// and `output_request` must be valid writable pointers. On success the
/// submission pointer is set to null and ownership is consumed. All handles are
/// single-owner and must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_registration_start(
    submission: *mut *mut SecureKeypadSubmission,
    output_registration: *mut *mut SecureKeypadClientRegistration,
    output_request: *mut *mut SecureKeypadAuthMessage,
) -> SecureKeypadError {
    contain_panic(|| {
        if submission.is_null() || output_registration.is_null() || output_request.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: All output pointers are checked for null and must be writable.
        unsafe {
            *output_registration = ptr::null_mut();
            *output_request = ptr::null_mut();
        }
        // SAFETY: `submission` is checked and must point to a live submission
        // handle owned by the caller.
        let submission_pointer = unsafe { *submission };
        if submission_pointer.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // Mark the caller's handle consumed before any protocol operation.
        unsafe {
            *submission = ptr::null_mut();
        }
        // SAFETY: Ownership was validated and transferred above.
        let submission = unsafe { *Box::from_raw(submission_pointer) }.core;
        let (state, request) = match client_registration_start_from_submission(submission) {
            Ok(result) => result,
            Err(error) => return map_auth_error(error),
        };
        let registration_handle = Box::new(SecureKeypadClientRegistration { core: state });
        let request_handle = Box::new(SecureKeypadAuthMessage { core: request });
        // SAFETY: Ownership transfers through the output slots.
        unsafe {
            *output_registration = Box::into_raw(registration_handle);
            *output_request = Box::into_raw(request_handle);
        }
        SecureKeypadError::Ok
    })
}

/// Aborts and frees a native OPAQUE login handle.
///
/// # Safety
///
/// `login` must be null or a live handle returned by
/// [`secure_keypad_client_login_start`] that has not already been consumed or
/// freed.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_login_free(login: *mut SecureKeypadClientLogin) {
    let _ = contain_panic(|| {
        if !login.is_null() {
            // SAFETY: The caller contract requires ownership of a live handle.
            unsafe { drop(Box::from_raw(login)) };
        }
        SecureKeypadError::Ok
    });
}

/// Aborts and frees a native OPAQUE registration handle.
///
/// # Safety
///
/// `registration` must be null or a live handle returned by
/// [`secure_keypad_client_registration_start`] that has not already been
/// consumed or freed. After this call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_registration_free(
    registration: *mut SecureKeypadClientRegistration,
) {
    let _ = contain_panic(|| {
        if !registration.is_null() {
            // SAFETY: The caller contract requires ownership of a live handle.
            unsafe { drop(Box::from_raw(registration)) };
        }
        SecureKeypadError::Ok
    });
}

/// Finishes native OPAQUE login and returns only the finalization message.
///
/// The derived client session key is immediately dropped and zeroized inside
/// Rust. The application should exchange the finalization message over its
/// native transport and receive an ordinary application session token from the
/// server rather than exposing the OPAQUE key to a framework bridge.
///
/// # Safety
///
/// `login` must point to a live login pointer and is consumed on entry;
/// `response` must be a live message handle; identifier buffers must be
/// readable for their declared lengths; and `output_finalization` must be a
/// valid writable pointer. All pointers must remain valid for this call and
/// must not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_login_finish(
    login: *mut *mut SecureKeypadClientLogin,
    response: *const SecureKeypadAuthMessage,
    client_identifier: *const u8,
    client_identifier_len: usize,
    server_identifier: *const u8,
    server_identifier_len: usize,
    output_finalization: *mut *mut SecureKeypadAuthMessage,
) -> SecureKeypadError {
    contain_panic(|| {
        if login.is_null() || response.is_null() || output_finalization.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The output pointer is checked for null and must be writable.
        unsafe {
            *output_finalization = ptr::null_mut();
        }
        // SAFETY: `login` is checked and must point to a live owned handle.
        let login_pointer = unsafe { *login };
        if login_pointer.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        unsafe {
            *login = ptr::null_mut();
        }
        // SAFETY: Ownership was validated and transferred above.
        let login = unsafe { *Box::from_raw(login_pointer) }.core;
        // SAFETY: The caller contract guarantees a live response handle.
        let response = unsafe { &(*response).core };
        // SAFETY: Identifier buffers are validated by the helper and remain
        // readable for the duration of this call.
        let client_identifier =
            match unsafe { parse_public_id(client_identifier, client_identifier_len) } {
                Ok(identifier) => identifier,
                Err(error) => return error,
            };
        let server_identifier =
            match unsafe { parse_public_id(server_identifier, server_identifier_len) } {
                Ok(identifier) => identifier,
                Err(error) => return error,
            };
        let (finalization, session_key) = match client_login_finish_from_native_state(
            login,
            response,
            &client_identifier,
            &server_identifier,
        ) {
            Ok(result) => result,
            Err(error) => return map_auth_error(error),
        };
        drop(session_key);
        // SAFETY: Ownership transfers through the output slot.
        unsafe {
            *output_finalization =
                Box::into_raw(Box::new(SecureKeypadAuthMessage { core: finalization }));
        }
        SecureKeypadError::Ok
    })
}

/// Finishes native OPAQUE registration and returns only the upload message.
///
/// The derived client export key is immediately dropped and zeroized inside
/// Rust. The application must send the upload through the native protected
/// transport and must not expose it through a framework bridge.
///
/// # Safety
///
/// `registration` must point to a live registration pointer and is consumed on
/// entry; `response` must be a live message handle; identifier buffers must be
/// readable for their declared lengths; and `output_upload` must be a valid
/// writable pointer. All pointers must remain valid for this call and must not
/// be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn secure_keypad_client_registration_finish(
    registration: *mut *mut SecureKeypadClientRegistration,
    response: *const SecureKeypadAuthMessage,
    client_identifier: *const u8,
    client_identifier_len: usize,
    server_identifier: *const u8,
    server_identifier_len: usize,
    output_upload: *mut *mut SecureKeypadAuthMessage,
) -> SecureKeypadError {
    contain_panic(|| {
        if registration.is_null() || response.is_null() || output_upload.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        // SAFETY: The output pointer is checked for null and must be writable.
        unsafe {
            *output_upload = ptr::null_mut();
        }
        // SAFETY: `registration` is checked and must point to a live owned handle.
        let registration_pointer = unsafe { *registration };
        if registration_pointer.is_null() {
            return SecureKeypadError::InvalidArgument;
        }
        unsafe {
            *registration = ptr::null_mut();
        }
        // SAFETY: Ownership was validated and transferred above.
        let registration = unsafe { *Box::from_raw(registration_pointer) }.core;
        // SAFETY: The caller contract guarantees a live response handle.
        let response = unsafe { &(*response).core };
        // SAFETY: Identifier buffers are validated by the helper and remain
        // readable for the duration of this call.
        let client_identifier =
            match unsafe { parse_public_id(client_identifier, client_identifier_len) } {
                Ok(identifier) => identifier,
                Err(error) => return error,
            };
        let server_identifier =
            match unsafe { parse_public_id(server_identifier, server_identifier_len) } {
                Ok(identifier) => identifier,
                Err(error) => return error,
            };
        let (upload, export_key) = match client_registration_finish_from_native_state(
            registration,
            response,
            &client_identifier,
            &server_identifier,
        ) {
            Ok(result) => result,
            Err(error) => return map_auth_error(error),
        };
        drop(export_key);
        // SAFETY: Ownership transfers through the output slot.
        unsafe {
            *output_upload = Box::into_raw(Box::new(SecureKeypadAuthMessage { core: upload }));
        }
        SecureKeypadError::Ok
    })
}
