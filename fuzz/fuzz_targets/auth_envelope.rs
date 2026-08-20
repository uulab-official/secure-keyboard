#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_auth::AuthEnvelope;

// Exercises the pre-deserialization body bound and bounded payload visitor.
// The target intentionally does not log input bytes or retain successful
// envelopes after each iteration.
fuzz_target!(|body: &[u8]| {
    let _ = AuthEnvelope::from_json(body);
});
