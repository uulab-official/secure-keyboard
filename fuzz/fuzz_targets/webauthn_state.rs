#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_auth_server::LoginStateHandle;
use secure_webauthn_example::{
    CeremonyKind, CeremonyState, CeremonyStateStore, CeremonyStoreError, CredentialStore,
    WebAuthnService, MAX_CEREMONY_STATE_BYTES,
};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

#[derive(Clone)]
struct FuzzCeremonyStore {
    state: Arc<Mutex<Vec<u8>>>,
}

impl CeremonyStateStore for FuzzCeremonyStore {
    fn insert(
        &self,
        _kind: CeremonyKind,
        _user_id: Uuid,
        _state: &[u8],
        _ttl: Duration,
    ) -> Result<LoginStateHandle, CeremonyStoreError> {
        Ok(LoginStateHandle::from_bytes(&[9; 32]).expect("fixed handle"))
    }

    fn take(
        &self,
        kind: CeremonyKind,
        handle: &LoginStateHandle,
    ) -> Result<Option<CeremonyState>, CeremonyStoreError> {
        if handle.as_bytes() != &[0; 32] {
            return Ok(None);
        }
        let state = self.state.lock().expect("fuzz store lock").clone();
        if state.is_empty() {
            return Ok(None);
        }
        CeremonyState::new(kind, Uuid::from_u128(1), state).map(Some)
    }
}

struct EmptyCredentialStore;

impl CredentialStore for EmptyCredentialStore {
    fn load(&self, _user_id: Uuid) -> Result<Vec<Passkey>, secure_webauthn_example::CredentialStoreError> {
        Ok(Vec::new())
    }

    fn insert(&self, _user_id: Uuid, _passkey: Passkey) -> Result<(), secure_webauthn_example::CredentialStoreError> {
        Err(secure_webauthn_example::CredentialStoreError::Unavailable)
    }

    fn update_after_auth(
        &self,
        _user_id: Uuid,
        _result: &AuthenticationResult,
    ) -> Result<bool, secure_webauthn_example::CredentialStoreError> {
        Err(secure_webauthn_example::CredentialStoreError::Unavailable)
    }
}

type FuzzService = WebAuthnService<EmptyCredentialStore, FuzzCeremonyStore>;
static SERVICE: OnceLock<(FuzzService, Arc<Mutex<Vec<u8>>>)> = OnceLock::new();

fn service() -> &'static (FuzzService, Arc<Mutex<Vec<u8>>>) {
    SERVICE.get_or_init(|| {
        let state = Arc::new(Mutex::new(Vec::new()));
        let store = FuzzCeremonyStore {
            state: Arc::clone(&state),
        };
        let service = WebAuthnService::new_with_stores(
            "example.com",
            "https://login.example.com",
            "Secure Keypad Fuzz",
            Duration::from_secs(60),
            store.clone(),
            store,
            EmptyCredentialStore,
        )
        .expect("valid fuzz service");
        (service, state)
    })
}

// Exercises bounded version-envelope deserialization for server-owned state.
// The harness never serializes the bytes to a client or logs them.
fuzz_target!(|input: &[u8]| {
    let (service, state) = service();
    let bounded = &input[..input.len().min(MAX_CEREMONY_STATE_BYTES + 1)];
    *state.lock().expect("fuzz state lock") = bounded.to_vec();
    let _ = service.finish_registration(&"00".repeat(32), b"{}");
});
