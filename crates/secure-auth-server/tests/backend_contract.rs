use secure_auth::{ServerLoginStateBytes, MAX_MESSAGE_BYTES};
use secure_auth_server::{
    BoundLoginState, BoundOneTimeLoginStateStore, LoginStateHandle, StoreError,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
};

struct AtomicBoundStore {
    entries: Mutex<HashMap<LoginStateHandle, BoundLoginState>>,
}

impl AtomicBoundStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl BoundOneTimeLoginStateStore for AtomicBoundStore {
    fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError> {
        let handle = LoginStateHandle::generate();
        self.entries
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(handle, state);
        Ok(handle)
    }

    fn take_bound(&self, handle: &LoginStateHandle) -> Result<Option<BoundLoginState>, StoreError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .remove(handle))
    }
}

#[test]
fn external_backend_can_implement_atomic_bound_state_contract() {
    let store = AtomicBoundStore::new();
    let state = BoundLoginState::new(
        ServerLoginStateBytes::from_bytes(&vec![0u8; MAX_MESSAGE_BYTES]),
        b"fixture-client",
        b"fixture-server",
    )
    .unwrap();
    let handle = store.insert_bound(state).unwrap();

    assert!(store.take_bound(&handle).unwrap().is_some());
    assert!(store.take_bound(&handle).unwrap().is_none());
}

#[test]
fn external_backend_take_is_atomic_under_concurrency() {
    let store = Arc::new(AtomicBoundStore::new());
    let state = BoundLoginState::new(
        ServerLoginStateBytes::from_bytes(b"fixture-state"),
        b"fixture-client",
        b"fixture-server",
    )
    .unwrap();
    let handle = store.insert_bound(state).unwrap();

    thread::scope(|scope| {
        let results = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                scope.spawn(move || store.take_bound(&handle).unwrap().is_some())
            })
            .collect::<Vec<_>>();
        let successful_takes = results
            .into_iter()
            .map(|result| result.join().unwrap())
            .filter(|was_present| *was_present)
            .count();
        assert_eq!(successful_takes, 1);
    });
}
