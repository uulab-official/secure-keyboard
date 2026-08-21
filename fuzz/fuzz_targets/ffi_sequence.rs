#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_ffi::{
    secure_keypad_session_backspace, secure_keypad_session_cancel, secure_keypad_session_clear,
    secure_keypad_session_free, secure_keypad_session_new_hangul,
    secure_keypad_session_new_numeric, secure_keypad_session_press_key,
    secure_keypad_session_refresh, secure_keypad_session_submit,
    secure_keypad_submission_free, SecureKeypadError, SecureKeypadMaskedState,
    SecureKeypadSession, SecureKeypadSubmission,
};
use std::ptr;

const NUMERIC_KEYS: [&[u8]; 10] = [
    b"digit-0",
    b"digit-1",
    b"digit-2",
    b"digit-3",
    b"digit-4",
    b"digit-5",
    b"digit-6",
    b"digit-7",
    b"digit-8",
    b"digit-9",
];

const HANGUL_KEYS: [&[u8]; 3] = [b"jamo-giyeok", b"vowel-a", b"tail-giyeok"];

// Exercises the exported C ABI with valid and malformed public pointers while
// keeping all accepted input inside the native opaque session. The harness
// observes only return codes, masked state, and ownership handles; it never
// reads a submission or logs the fuzz bytes.
fuzz_target!(|input: &[u8]| {
    let first = input.first().copied().unwrap_or_default();
    let hangul = first & 1 == 1;
    let max_tokens = 1 + u32::from(first >> 1) % 64;
    let timeout_ms = 1 + u64::from(first);
    let mut session: *mut SecureKeypadSession = ptr::null_mut();

    // SAFETY: `session` is a valid writable output slot for the duration of
    // the call, and the constructor returns ownership to this harness.
    let constructor = unsafe {
        if hangul {
            secure_keypad_session_new_hangul(max_tokens, timeout_ms, &mut session)
        } else {
            secure_keypad_session_new_numeric(max_tokens, timeout_ms, &mut session)
        }
    };
    if constructor != SecureKeypadError::Ok || session.is_null() {
        return;
    }

    let mut cursor = usize::from(!input.is_empty());
    while cursor < input.len() {
        let action = input[cursor];
        cursor += 1;
        // SAFETY: `session` remains exclusively owned by this single-threaded
        // harness until the matching free call below.
        unsafe {
            match action % 6 {
                0 => {
                    let keys = if hangul { &HANGUL_KEYS[..] } else { &NUMERIC_KEYS[..] };
                    if action & 2 == 0 {
                        let key = keys[usize::from(action >> 2) % keys.len()];
                        let _ = secure_keypad_session_press_key(session, key.as_ptr(), key.len());
                    } else {
                        // Exercise null, empty, invalid UTF-8, and oversized
                        // public key-id paths without exposing any secret API.
                        let remaining = &input[cursor..];
                        let length = usize::from(action >> 2).min(remaining.len());
                        let pointer = if action & 0x80 == 0 {
                            remaining.as_ptr()
                        } else {
                            ptr::null()
                        };
                        let _ = secure_keypad_session_press_key(session, pointer, length);
                        cursor += length;
                    }
                }
                1 => {
                    let _ = secure_keypad_session_backspace(session);
                }
                2 => {
                    let _ = secure_keypad_session_clear(session);
                }
                3 => {
                    let _ = secure_keypad_session_cancel(session);
                }
                4 => {
                    let mut state = SecureKeypadMaskedState::default();
                    let _ = secure_keypad_session_refresh(session, &mut state);
                }
                _ => {
                    let mut submission: *mut SecureKeypadSubmission = ptr::null_mut();
                    let result = secure_keypad_session_submit(session, &mut submission);
                    if result == SecureKeypadError::Ok && !submission.is_null() {
                        secure_keypad_submission_free(submission);
                    }
                }
            }
        }
    }

    // SAFETY: `session` is the live constructor-owned handle and is released
    // exactly once after all operations have completed.
    unsafe { secure_keypad_session_free(session) };
});
