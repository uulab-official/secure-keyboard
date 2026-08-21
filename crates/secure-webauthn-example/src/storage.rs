use crate::{MAX_CEREMONY_STATE_BYTES, MAX_CREDENTIALS_PER_USER, MAX_PENDING_CEREMONIES};
use rand::{rngs::OsRng, RngCore};
use secure_auth_server::LoginStateHandle;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};
use zeroize::Zeroize;

/// The ceremony operation namespace used to prevent registration/authentication
/// handles from being consumed through the wrong route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyKind {
    /// A registration ceremony state.
    Registration,
    /// An authentication ceremony state.
    Authentication,
}

/// Errors returned by a ceremony state backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyStoreError {
    /// The configured capacity is outside the supported bound.
    InvalidCapacity,
    /// The requested TTL is zero or cannot be represented by the process clock.
    InvalidTtl,
    /// The backend has reached its configured bounded capacity.
    CapacityReached,
    /// The serialized ceremony state exceeds its bound.
    StateTooLarge,
    /// The serialized ceremony state is empty or otherwise invalid.
    InvalidState,
    /// A random handle collision occurred repeatedly.
    HandleCollision,
    /// The backend cannot safely complete the operation.
    Unavailable,
}

/// A server-owned, bounded, one-time `WebAuthn` ceremony state.
///
/// The bytes contain a serialized `webauthn-rs` state and must never be sent
/// to a browser, logged, or stored without access control/encryption. The
/// state is zeroized when this value is dropped.
pub struct CeremonyState {
    kind: CeremonyKind,
    user_id: Uuid,
    state: Vec<u8>,
}

impl CeremonyState {
    /// Creates a bounded ceremony state record.
    ///
    /// # Errors
    ///
    /// Returns a state error when `state` is empty or exceeds
    /// [`MAX_CEREMONY_STATE_BYTES`].
    pub fn new(
        kind: CeremonyKind,
        user_id: Uuid,
        state: Vec<u8>,
    ) -> Result<Self, CeremonyStoreError> {
        validate_state(&state)?;
        Ok(Self {
            kind,
            user_id,
            state,
        })
    }

    /// Returns the ceremony namespace.
    #[must_use]
    pub const fn kind(&self) -> CeremonyKind {
        self.kind
    }

    /// Returns the server-authenticated account principal bound to the state.
    #[must_use]
    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// Borrows the serialized state bytes.
    ///
    /// Callers must treat the returned bytes as sensitive and must not retain
    /// or log them beyond the protected backend operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.state
    }

    /// Consumes the record into its namespace, principal, and state bytes.
    ///
    /// The returned bytes become the caller's responsibility and should be
    /// wrapped in a zeroizing container while deserializing them.
    #[must_use]
    pub fn into_parts(self) -> (CeremonyKind, Uuid, Vec<u8>) {
        let mut state = self;
        let bytes = core::mem::take(&mut state.state);
        (state.kind, state.user_id, bytes)
    }
}

impl Drop for CeremonyState {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// Backend contract for bounded, one-time `WebAuthn` ceremony state.
///
/// `insert` must apply the supplied TTL and reject duplicate handles. `take`
/// must atomically delete and return a matching state at most once. A Redis
/// implementation should use `SET NX EX` plus `GETDEL` (or an equivalent
/// atomic script); a database implementation should use a single
/// `DELETE ... RETURNING` statement with an expiry predicate.
pub trait CeremonyStateStore: Send + Sync {
    /// Inserts a server-owned serialized ceremony state.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration, capacity, state, or backend error.
    fn insert(
        &self,
        kind: CeremonyKind,
        user_id: Uuid,
        state: &[u8],
        ttl: Duration,
    ) -> Result<LoginStateHandle, CeremonyStoreError>;

    /// Atomically consumes a matching ceremony state at most once.
    ///
    /// A kind mismatch must behave as a miss and must not consume a state in
    /// another namespace.
    ///
    /// # Errors
    ///
    /// Returns a backend availability error when atomic consumption cannot be
    /// proven.
    fn take(
        &self,
        kind: CeremonyKind,
        handle: &LoginStateHandle,
    ) -> Result<Option<CeremonyState>, CeremonyStoreError>;
}

struct CeremonyEntry {
    expires_at: Instant,
    kind: CeremonyKind,
    user_id: Uuid,
    state: Vec<u8>,
}

/// Bounded process-local implementation of [`CeremonyStateStore`].
///
/// This is suitable for tests and single-process development only. Production
/// deployments must provide a shared atomic backend implementation.
pub struct InMemoryCeremonyStateStore {
    entries: Mutex<HashMap<LoginStateHandle, CeremonyEntry>>,
    max_entries: usize,
}

impl InMemoryCeremonyStateStore {
    /// Creates a bounded ceremony store.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyStoreError::InvalidCapacity`] when the capacity is
    /// zero or exceeds [`MAX_PENDING_CEREMONIES`].
    pub fn new(max_entries: usize) -> Result<Self, CeremonyStoreError> {
        if max_entries == 0 || max_entries > MAX_PENDING_CEREMONIES {
            return Err(CeremonyStoreError::InvalidCapacity);
        }
        Ok(Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries.min(1024))),
            max_entries,
        })
    }

    /// Returns the number of live ceremony states.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyStoreError::Unavailable`] when the process-local lock
    /// is poisoned.
    pub fn len(&self) -> Result<usize, CeremonyStoreError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        entries.retain(|_, entry| entry.expires_at > now);
        Ok(entries.len())
    }

    /// Returns whether there are no live ceremony states.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyStoreError::Unavailable`] when the process-local lock
    /// is poisoned.
    pub fn is_empty(&self) -> Result<bool, CeremonyStoreError> {
        Ok(self.len()? == 0)
    }
}

impl CeremonyStateStore for InMemoryCeremonyStateStore {
    fn insert(
        &self,
        kind: CeremonyKind,
        user_id: Uuid,
        state: &[u8],
        ttl: Duration,
    ) -> Result<LoginStateHandle, CeremonyStoreError> {
        validate_state(state)?;
        let now = Instant::now();
        let expires_at = now.checked_add(ttl).ok_or(CeremonyStoreError::InvalidTtl)?;
        if ttl.is_zero() {
            return Err(CeremonyStoreError::InvalidTtl);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.len() >= self.max_entries {
            return Err(CeremonyStoreError::CapacityReached);
        }
        let handle = fresh_handle(&entries)?;
        entries.insert(
            handle,
            CeremonyEntry {
                expires_at,
                kind,
                user_id,
                state: state.to_vec(),
            },
        );
        Ok(handle)
    }

    fn take(
        &self,
        kind: CeremonyKind,
        handle: &LoginStateHandle,
    ) -> Result<Option<CeremonyState>, CeremonyStoreError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let Some(entry) = entries.get(handle) else {
            return Ok(None);
        };
        if entry.kind != kind {
            return Ok(None);
        }
        let entry = entries
            .remove(handle)
            .expect("entry was checked under lock");
        if entry.expires_at <= now {
            return Ok(None);
        }
        CeremonyState::new(entry.kind, entry.user_id, entry.state).map(Some)
    }
}

fn fresh_handle(
    entries: &HashMap<LoginStateHandle, CeremonyEntry>,
) -> Result<LoginStateHandle, CeremonyStoreError> {
    for _ in 0..4 {
        let mut candidate = [0u8; 32];
        OsRng.fill_bytes(&mut candidate);
        let handle = LoginStateHandle::from_bytes(&candidate).expect("fixed handle length");
        if !entries.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(CeremonyStoreError::HandleCollision)
}

fn validate_state(state: &[u8]) -> Result<(), CeremonyStoreError> {
    if state.is_empty() {
        return Err(CeremonyStoreError::InvalidState);
    }
    if state.len() > MAX_CEREMONY_STATE_BYTES {
        return Err(CeremonyStoreError::StateTooLarge);
    }
    Ok(())
}

/// Errors returned by a credential persistence backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStoreError {
    /// The backend cannot safely complete the operation.
    Unavailable,
    /// The account has reached the configured credential limit.
    CapacityReached,
    /// The credential already exists for the account.
    Duplicate,
    /// The account or credential record is invalid.
    InvalidRecord,
}

/// Backend contract for protected `WebAuthn` credential persistence.
///
/// `insert` must enforce uniqueness and the per-account limit atomically.
/// `update_after_auth` must atomically apply authenticator counter and backup
/// state changes after successful verification; implementations must reject
/// stale or conflicting updates rather than allowing a last-writer-wins
/// downgrade.
pub trait CredentialStore: Send + Sync {
    /// Loads public credential records for an account.
    ///
    /// Unknown accounts must return an empty vector without exposing account
    /// existence through a distinct error.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Unavailable`] when protected storage
    /// cannot safely complete the lookup.
    fn load(&self, user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError>;

    /// Atomically inserts a unique credential under the account limit.
    ///
    /// # Errors
    ///
    /// Returns a duplicate, capacity, invalid-record, or backend error.
    fn insert(&self, user_id: Uuid, passkey: Passkey) -> Result<(), CredentialStoreError>;

    /// Atomically applies post-authentication counter/backup-state changes.
    ///
    /// Returns whether the credential record changed.
    ///
    /// # Errors
    ///
    /// Returns an invalid-record or backend error.
    fn update_after_auth(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError>;
}

/// Bounded process-local implementation of [`CredentialStore`].
///
/// This is suitable for tests and single-process development only. Production
/// deployments must replace it with encrypted/access-controlled persistence.
pub struct InMemoryCredentialStore {
    credentials: Mutex<HashMap<Uuid, Vec<Passkey>>>,
}

impl InMemoryCredentialStore {
    /// Creates an empty credential store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the number of credentials for an account without exposing them.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Unavailable`] when the process-local
    /// lock is poisoned.
    pub fn credential_count(&self, user_id: Uuid) -> Result<usize, CredentialStoreError> {
        let credentials = self
            .credentials
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(credentials.get(&user_id).map_or(0, Vec::len))
    }
}

impl Default for InMemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for InMemoryCredentialStore {
    fn load(&self, user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError> {
        let credentials = self
            .credentials
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(credentials.get(&user_id).cloned().unwrap_or_default())
    }

    fn insert(&self, user_id: Uuid, passkey: Passkey) -> Result<(), CredentialStoreError> {
        let mut credentials = self
            .credentials
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let user_credentials = credentials.entry(user_id).or_default();
        if user_credentials.iter().any(|existing| existing == &passkey) {
            return Err(CredentialStoreError::Duplicate);
        }
        if user_credentials.len() >= MAX_CREDENTIALS_PER_USER {
            return Err(CredentialStoreError::CapacityReached);
        }
        user_credentials.push(passkey);
        Ok(())
    }

    fn update_after_auth(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError> {
        let mut credentials = self
            .credentials
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let user_credentials = credentials
            .get_mut(&user_id)
            .ok_or(CredentialStoreError::InvalidRecord)?;
        for credential in user_credentials {
            if let Some(changed) = credential.update_credential(result) {
                return Ok(changed);
            }
        }
        Ok(false)
    }
}
