#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_core::{InputPolicy, KeyId, SecureSession};

const NUMERIC_KEYS: [&str; 10] = [
    "digit-0", "digit-1", "digit-2", "digit-3", "digit-4", "digit-5", "digit-6", "digit-7",
    "digit-8", "digit-9",
];

const ASCII_KEYS: [&str; 6] = ["ascii-20", "ascii-21", "ascii-41", "ascii-5a", "ascii-62", "ascii-7e"];
const HANGUL_KEYS: [&str; 3] = ["jamo-giyeok", "vowel-a", "tail-giyeok"];

// Exercises the native/core state machine with arbitrary action sequences.
// The harness deliberately observes only the public masked state and never
// serializes or logs the private input buffer.
fuzz_target!(|input: &[u8]| {
    let policy = input.first().copied().unwrap_or_default() % 3;
    let mut session = match policy {
        0 => SecureSession::begin(InputPolicy::numeric(64)),
        1 => SecureSession::begin(InputPolicy::ascii(64)),
        _ => SecureSession::begin(InputPolicy::hangul(64)),
    };
    for byte in input.iter().skip(1) {
        match byte % 4 {
            0 => {
                let key = match policy {
                    0 => KeyId::new(NUMERIC_KEYS[usize::from(*byte >> 2) % NUMERIC_KEYS.len()]),
                    1 => KeyId::new(ASCII_KEYS[usize::from(*byte >> 2) % ASCII_KEYS.len()]),
                    _ => KeyId::new(HANGUL_KEYS[usize::from(*byte >> 2) % HANGUL_KEYS.len()]),
                };
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
