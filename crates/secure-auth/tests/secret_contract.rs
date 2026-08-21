#[test]
fn secret_output_handoff_cannot_return_secret_bytes() {
    let public_api = include_str!("../src/lib.rs");
    assert!(!public_api.contains("pub fn with_bytes<R>"));
    assert!(public_api.contains("pub fn with_bytes(&self, operation: impl FnOnce(&[u8]))"));
}
