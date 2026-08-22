use secure_core::{InputPolicy, KeyId, SecureSession};

#[test]
fn numeric_policy_accepts_only_declared_key_ids() {
    let policy = InputPolicy::numeric(6);
    assert!(policy.resolve(&KeyId::new("digit-1")).is_ok());
    assert!(policy.resolve(&KeyId::new("digit-01")).is_err());
    assert!(policy.resolve(&KeyId::new("digit-+1")).is_err());
    assert!(policy.resolve(&KeyId::new("jamo-giyeok")).is_err());
}

#[test]
fn ascii_policy_accepts_printable_ascii_ids_without_accepting_labels() {
    let policy = InputPolicy::ascii(8);
    assert!(policy.resolve(&KeyId::new("ascii-20")).is_ok());
    assert!(policy.resolve(&KeyId::new("ascii-41")).is_ok());
    assert!(policy.resolve(&KeyId::new("ascii-7e")).is_ok());
    assert!(policy.resolve(&KeyId::new("A")).is_err());
    assert!(policy.resolve(&KeyId::new("ascii-1f")).is_err());
    assert!(policy.resolve(&KeyId::new("ascii-7F")).is_err());
}

#[test]
fn ascii_policy_renders_printable_characters_but_exposes_only_masked_state() {
    let mut session = SecureSession::begin(InputPolicy::ascii(8));
    for key in ["ascii-41", "ascii-62", "ascii-21"] {
        session.press_key(&KeyId::new(key)).unwrap();
    }
    assert_eq!(session.masked_state().length, 3);
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
