use secure_core::{InputPolicy, KeyId, SecureSession};

#[test]
fn numeric_policy_accepts_only_declared_key_ids() {
    let policy = InputPolicy::numeric(6);
    assert!(policy.resolve(&KeyId::new("digit-1")).is_ok());
    assert!(policy.resolve(&KeyId::new("jamo-giyeok")).is_err());
}

#[test]
fn hangul_policy_composes_the_declared_vector() {
    let mut session = SecureSession::begin(InputPolicy::hangul(32));
    for key in ["jamo-giyeok", "vowel-a"] {
        session.press_key(&KeyId::new(key)).unwrap();
    }
    assert_eq!(session.masked_state().length, 1);
}

#[test]
fn hangul_backspace_recomputes_the_composed_length() {
    let mut session = SecureSession::begin(InputPolicy::hangul(32));
    session.press_key(&KeyId::new("jamo-giyeok")).unwrap();
    session.press_key(&KeyId::new("vowel-a")).unwrap();
    assert_eq!(session.masked_state().length, 1);

    session.backspace().unwrap();
    assert_eq!(session.masked_state().length, 1);
    session.backspace().unwrap();
    assert_eq!(session.masked_state().length, 0);
}

#[test]
fn hangul_policy_accepts_all_primitive_key_families() {
    let policy = InputPolicy::hangul(32);
    assert!(policy.resolve(&KeyId::new("jamo-hieuh")).is_ok());
    assert!(policy.resolve(&KeyId::new("vowel-i")).is_ok());
    assert!(policy.resolve(&KeyId::new("tail-hieuh")).is_ok());
}
