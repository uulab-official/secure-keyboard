use secure_auth::ServerLoginStateBytes;
use secure_auth_server::{
    BoundLoginState, InMemoryOneTimeLoginStore, LoginStateHandle, OneTimeLoginStateStore,
    StoreError, MAX_IN_MEMORY_ENTRIES, MAX_STORED_STATE_BYTES,
};
use std::time::Duration;

fn take_through_backend_contract<S: OneTimeLoginStateStore>(
    store: &S,
    handle: &LoginStateHandle,
) -> bool {
    store.take(handle).unwrap().is_some()
}

#[test]
fn a_login_state_is_consumed_at_most_once() {
    let store = InMemoryOneTimeLoginStore::new(4, Duration::from_secs(60)).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap())
        .unwrap();

    let state = store
        .take(&handle)
        .unwrap()
        .expect("state should be available once");
    assert_eq!(state.as_bytes(), b"fixture-state");
    assert!(!take_through_backend_contract(&store, &handle));
}

#[test]
fn expired_state_is_not_returned() {
    let store = InMemoryOneTimeLoginStore::new(4, Duration::ZERO).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap())
        .unwrap();

    assert!(store.take(&handle).unwrap().is_none());
    assert_eq!(store.len().unwrap(), 0);
}

#[test]
fn store_enforces_capacity_and_recovers_after_consumption() {
    let store = InMemoryOneTimeLoginStore::new(1, Duration::from_secs(60)).unwrap();
    let first = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-first").unwrap())
        .unwrap();
    assert!(matches!(
        store.insert(ServerLoginStateBytes::from_bytes(b"fixture-second").unwrap()),
        Err(StoreError::CapacityReached)
    ));

    assert!(store.take(&first).unwrap().is_some());
    assert!(store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-third").unwrap())
        .is_ok());
}

#[test]
fn handles_are_fixed_size_opaque_values() {
    let store = InMemoryOneTimeLoginStore::new(1, Duration::from_secs(60)).unwrap();
    let handle = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap())
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

    let oversized = vec![0u8; MAX_STORED_STATE_BYTES + 1];
    assert!(matches!(
        ServerLoginStateBytes::from_bytes(&oversized),
        Err(secure_auth::AuthError::MessageTooLarge)
    ));
}

#[test]
fn bound_and_unbound_handles_cannot_be_consumed_through_the_wrong_contract() {
    let store = InMemoryOneTimeLoginStore::new(2, Duration::from_secs(60)).unwrap();
    let unbound = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-unbound").unwrap())
        .unwrap();
    let bound = store
        .insert_bound(
            BoundLoginState::new(
                ServerLoginStateBytes::from_bytes(b"fixture-bound").unwrap(),
                b"fixture-client",
                b"fixture-server",
            )
            .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        store.take_bound(&unbound),
        Err(StoreError::StateTypeMismatch)
    ));
    assert!(matches!(
        store.take(&bound),
        Err(StoreError::StateTypeMismatch)
    ));
    assert!(matches!(
        BoundLoginState::new(
            ServerLoginStateBytes::from_bytes(b"fixture").unwrap(),
            b"",
            b"server"
        ),
        Err(StoreError::InvalidIdentifier)
    ));
}

#[test]
fn a_type_mismatch_does_not_consume_the_pending_state() {
    let store = InMemoryOneTimeLoginStore::new(2, Duration::from_secs(60)).unwrap();
    let unbound = store
        .insert(ServerLoginStateBytes::from_bytes(b"fixture-unbound").unwrap())
        .unwrap();
    let bound = store
        .insert_bound(
            BoundLoginState::new(
                ServerLoginStateBytes::from_bytes(b"fixture-bound").unwrap(),
                b"fixture-client",
                b"fixture-server",
            )
            .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        store.take_bound(&unbound),
        Err(StoreError::StateTypeMismatch)
    ));
    assert!(store.take(&unbound).unwrap().is_some());

    assert!(matches!(
        store.take(&bound),
        Err(StoreError::StateTypeMismatch)
    ));
    assert!(store.take_bound(&bound).unwrap().is_some());
}
