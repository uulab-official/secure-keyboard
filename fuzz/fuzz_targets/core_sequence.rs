#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_core::{InputPolicy, KeyId, SecureSession};

const NUMERIC_KEYS: [&str; 10] = [
    "digit-0", "digit-1", "digit-2", "digit-3", "digit-4", "digit-5", "digit-6", "digit-7",
    "digit-8", "digit-9",
];

// Exercises the native/core state machine with arbitrary action sequences.
// The harness deliberately observes only the public masked state and never
// serializes or logs the private input buffer.
fuzz_target!(|input: &[u8]| {
    let mut session = SecureSession::begin(InputPolicy::numeric(64));
    for byte in input {
        match byte % 4 {
            0 => {
                let key = KeyId::new(NUMERIC_KEYS[usize::from(*byte >> 2) % NUMERIC_KEYS.len()]);
                let _ = session.press_key(&key);
            }
            1 => {
                let _ = session.backspace();
            }
            2 => {
                let _ = session.clear();
            }
            _ => {
                let _ = session.refresh();
            }
        }
    }
    let _ = session.masked_state();
});
