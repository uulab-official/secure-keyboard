#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! C ABI boundary for the framework-neutral secure keypad core.
//!
//! The ABI exposes public key identifiers, masked state, and opaque ownership
//! handles only. It has no function that returns accumulated secret bytes.
//! Handles are single-owner and must be used from one native thread at a time.

use core::time::Duration;
use std::{panic::catch_unwind, panic::AssertUnwindSafe, ptr, slice, str};

use secure_core::{DisplayState, InputPolicy, MaskedState, SecureSession, SessionError};

const MAX_KEY_ID_BYTES: usize = 64;
const MAX_TOKENS: u32 = 4_096;
const MAX_TIMEOUT_MS: u64 = 86_400_000;

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
