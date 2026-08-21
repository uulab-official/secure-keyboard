use secure_auth_server::LoginStateHandle;
use secure_webauthn_example::{
    CeremonyKind, CeremonyStateStore, CredentialStore, CredentialStoreError,
    InMemoryCeremonyStateStore, InMemoryCredentialStore, WebAuthnDeploymentContext,
    WebAuthnExampleError, WebAuthnHttpRequest, WebAuthnHttpRouter, WebAuthnService,
    MAX_CEREMONY_STATE_BYTES, MAX_CEREMONY_TTL,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

#[test]
fn in_memory_ceremony_store_is_one_time_and_kind_bound() {
    let store = InMemoryCeremonyStateStore::new(4).unwrap();
    let user_id = Uuid::from_u128(1);
    let handle = store
        .insert(
            CeremonyKind::Registration,
            user_id,
            b"serialized-state",
            Duration::from_secs(60),
        )
        .unwrap();

    assert!(store
        .take(CeremonyKind::Authentication, &handle)
        .unwrap()
        .is_none());
    let state = store
        .take(CeremonyKind::Registration, &handle)
        .unwrap()
        .unwrap();
    assert_eq!(state.user_id(), user_id);
    assert_eq!(state.kind(), CeremonyKind::Registration);
    assert_eq!(state.as_bytes(), b"serialized-state");
    assert!(store
        .take(CeremonyKind::Registration, &handle)
        .unwrap()
        .is_none());
}

#[test]
fn in_memory_ceremony_store_rejects_unsafe_bounds() {
    let store = InMemoryCeremonyStateStore::new(4).unwrap();
    assert!(matches!(
        store.insert(
            CeremonyKind::Registration,
            Uuid::from_u128(1),
            &vec![0; MAX_CEREMONY_STATE_BYTES + 1],
            Duration::from_secs(60),
        ),
        Err(secure_webauthn_example::CeremonyStoreError::StateTooLarge)
    ));
    assert!(matches!(
        store.insert(
            CeremonyKind::Registration,
            Uuid::from_u128(1),
            b"state",
            Duration::ZERO,
        ),
        Err(secure_webauthn_example::CeremonyStoreError::InvalidTtl)
    ));
    assert!(matches!(
        store.insert(
            CeremonyKind::Registration,
            Uuid::from_u128(1),
            b"state",
            MAX_CEREMONY_TTL + Duration::from_secs(1),
        ),
        Err(secure_webauthn_example::CeremonyStoreError::InvalidTtl)
    ));
}

#[test]
fn in_memory_ceremony_store_consumes_a_handle_once_under_concurrency() {
    let store = Arc::new(InMemoryCeremonyStateStore::new(4).unwrap());
    let handle = store
        .insert(
            CeremonyKind::Authentication,
            Uuid::from_u128(1),
            b"serialized-state",
            Duration::from_secs(60),
        )
        .unwrap();
    let threads = (0..16)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                store
                    .take(CeremonyKind::Authentication, &handle)
                    .unwrap()
                    .is_some()
            })
        })
        .collect::<Vec<_>>();
    let consumed = threads
        .into_iter()
        .filter_map(|thread| thread.join().ok())
        .filter(|consumed| *consumed)
        .count();
    assert_eq!(consumed, 1);
}

#[test]
fn service_accepts_external_storage_contracts() {
    let ceremonies = RecordingCeremonyStore::default();
    let registrations = RecordingCeremonyStore::default();
    let credentials = EmptyCredentialStore;
    let service = WebAuthnService::new_with_stores(
        "example.com",
        "https://login.example.com",
        "Secure Keypad Example",
        Duration::from_secs(60),
        registrations.clone(),
        ceremonies.clone(),
        credentials,
    )
    .unwrap();

    let start = service
        .start_registration(Uuid::from_u128(1), "alice", "Alice")
        .unwrap();
    assert_eq!(start.handle.len(), 64);
    assert_eq!(registrations.last_kind(), Some(CeremonyKind::Registration));
    assert!(registrations.last_state_len() > 0);
    assert!(ceremonies.last_kind().is_none());

    let router = WebAuthnHttpRouter::new(&service);
    let response = router.handle(
        WebAuthnHttpRequest {
            method: "POST",
            path: "/v1/webauthn/registration/start",
            content_type: Some("application/json"),
            principal: Some(Uuid::from_u128(1)),
            csrf_validated: true,
            body: br#"{"userName":"alice","displayName":"Alice"}"#,
        },
        WebAuthnDeploymentContext::direct_tls(),
    );
    assert_eq!(response.status, 200);
}

#[derive(Clone, Default)]
struct RecordingCeremonyStore {
    last: Arc<Mutex<Option<(CeremonyKind, usize)>>>,
}

impl RecordingCeremonyStore {
    fn last_kind(&self) -> Option<CeremonyKind> {
        self.last.lock().unwrap().map(|(kind, _)| kind)
    }

    fn last_state_len(&self) -> usize {
        self.last.lock().unwrap().map_or(0, |(_, length)| length)
    }
}

impl CeremonyStateStore for RecordingCeremonyStore {
    fn insert(
        &self,
        kind: CeremonyKind,
        _user_id: Uuid,
        state: &[u8],
        _ttl: Duration,
    ) -> Result<LoginStateHandle, secure_webauthn_example::CeremonyStoreError> {
        *self.last.lock().unwrap() = Some((kind, state.len()));
        Ok(LoginStateHandle::from_bytes(&[7; 32]).unwrap())
    }

    fn take(
        &self,
        _kind: CeremonyKind,
        _handle: &LoginStateHandle,
    ) -> Result<
        Option<secure_webauthn_example::CeremonyState>,
        secure_webauthn_example::CeremonyStoreError,
    > {
        Ok(None)
    }
}

struct EmptyCredentialStore;

impl CredentialStore for EmptyCredentialStore {
    fn load(&self, _user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError> {
        Ok(Vec::new())
    }

    fn insert(&self, _user_id: Uuid, _passkey: Passkey) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }

    fn update_after_auth(
        &self,
        _user_id: Uuid,
        _result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }
}

#[test]
fn in_memory_credential_store_starts_empty() {
    let store = InMemoryCredentialStore::new();
    assert!(store.load(Uuid::from_u128(1)).unwrap().is_empty());
    assert_eq!(store.credential_count(Uuid::from_u128(1)).unwrap(), 0);
}

#[test]
fn service_maps_backend_unavailability_to_generic_error() {
    let service = WebAuthnService::new_with_stores(
        "example.com",
        "https://login.example.com",
        "Secure Keypad Example",
        Duration::from_secs(60),
        RecordingCeremonyStore::default(),
        RecordingCeremonyStore::default(),
        UnavailableCredentialStore,
    )
    .unwrap();
    assert!(matches!(
        service.start_authentication(Uuid::from_u128(1)),
        Err(WebAuthnExampleError::StoreUnavailable)
    ));
}

struct UnavailableCredentialStore;

impl CredentialStore for UnavailableCredentialStore {
    fn load(&self, _user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }

    fn insert(&self, _user_id: Uuid, _passkey: Passkey) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }

    fn update_after_auth(
        &self,
        _user_id: Uuid,
        _result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError> {
        Err(CredentialStoreError::Unavailable)
    }
}
