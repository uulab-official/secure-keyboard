use secure_auth::ServerLoginStateBytes;
use secure_auth_server::{
    InMemoryOneTimeLoginStore, StoreError, MAX_IN_MEMORY_ENTRIES, MAX_STORED_STATE_BYTES,
};
use std::time::Duration;

#[test]
fn a_login_state_is_consumed_at_most_once() {
    let store = InMemoryOneTimeLoginStore::new(4, Duration::from_secs(60)).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state"))
        .unwrap();

    let state = store
        .take(&handle)
        .unwrap()
        .expect("state should be available once");
    assert_eq!(state.as_bytes(), b"fixture-state");
    assert!(store.take(&handle).unwrap().is_none());
}

#[test]
fn expired_state_is_not_returned() {
    let store = InMemoryOneTimeLoginStore::new(4, Duration::ZERO).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state"))
        .unwrap();

    assert!(store.take(&handle).unwrap().is_none());
    assert_eq!(store.len().unwrap(), 0);
}

#[test]
fn store_enforces_capacity_and_recovers_after_consumption() {
    let store = InMemoryOneTimeLoginStore::new(1, Duration::from_secs(60)).unwrap();
    let first = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-first"))
        .unwrap();
    assert!(matches!(
        store.insert(ServerLoginStateBytes::from_bytes(b"fixture-second")),
        Err(StoreError::CapacityReached)
    ));

    assert!(store.take(&first).unwrap().is_some());
    assert!(store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-third"))
        .is_ok());
}

#[test]
fn handles_are_fixed_size_opaque_values() {
    let store = InMemoryOneTimeLoginStore::new(1, Duration::from_secs(60)).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state"))
        .unwrap();

    assert_eq!(handle.as_bytes().len(), 32);
}

#[test]
fn store_rejects_unsafe_capacity_ttl_and_state_size() {
    assert!(matches!(
        InMemoryOneTimeLoginStore::new(0, Duration::from_secs(1)),
        Err(StoreError::InvalidCapacity)
    ));
    assert!(matches!(
        InMemoryOneTimeLoginStore::new(MAX_IN_MEMORY_ENTRIES + 1, Duration::from_secs(1)),
        Err(StoreError::InvalidCapacity)
    ));
    assert!(matches!(
        InMemoryOneTimeLoginStore::new(1, Duration::MAX),
        Err(StoreError::InvalidTtl)
    ));

    let store = InMemoryOneTimeLoginStore::new(1, Duration::from_secs(1)).unwrap();
    let oversized = vec![0u8; MAX_STORED_STATE_BYTES + 1];
    assert!(matches!(
        store.insert(ServerLoginStateBytes::from_bytes(&oversized)),
        Err(StoreError::StateTooLarge)
    ));
}
