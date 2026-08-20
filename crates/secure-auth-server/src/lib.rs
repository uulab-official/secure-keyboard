#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Server-side storage primitives for the Secure Keypad authentication flow.
//!
//! This crate provides a bounded, process-local reference store for the
//! serialized OPAQUE server state. Production deployments spanning multiple
//! instances must implement the same one-use `take` semantics with an atomic
//! Redis, database, or equivalent store.

mod rate_limit;
mod service;

pub use rate_limit::{
    InMemoryRateLimiter, RateLimitDecision, RateLimitError, RateLimitPolicy, RateLimiter,
    MAX_IN_MEMORY_RATE_KEYS, MAX_RATE_LIMIT_KEY_BYTES,
};
pub use service::{PublicAuthCode, ServerAuthError, ServerAuthService, MAX_SERVER_KEY_IDS};

use rand::{rngs::OsRng, RngCore};
use secure_auth::{ServerLoginStateBytes, MAX_IDENTIFIER_BYTES, MAX_MESSAGE_BYTES};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const HANDLE_BYTES: usize = 32;
const HANDLE_ATTEMPTS: usize = 4;

/// Maximum number of pending states held by the reference store.
pub const MAX_IN_MEMORY_ENTRIES: usize = 100_000;
/// Maximum serialized state size accepted by the reference store.
pub const MAX_STORED_STATE_BYTES: usize = MAX_MESSAGE_BYTES + 256;

/// A fixed-size opaque bearer handle for one pending login state.
///
/// Treat this handle as sensitive authentication material: do not log it,
/// place it in analytics, or expose it in error messages.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LoginStateHandle([u8; HANDLE_BYTES]);

impl LoginStateHandle {
    /// Borrows the handle bytes for transport encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HANDLE_BYTES] {
        &self.0
    }

    /// Generates a fresh 32-byte CSPRNG-backed handle for a distributed
    /// backend adapter.
    #[must_use]
    pub fn generate() -> Self {
        Self::random()
    }

    fn random() -> Self {
        let mut bytes = [0u8; HANDLE_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Errors produced by the bounded reference store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// The configured maximum entry count is outside the supported range.
    InvalidCapacity,
    /// The configured TTL cannot be represented by the process clock.
    InvalidTtl,
    /// The store has reached its configured entry limit.
    CapacityReached,
    /// The serialized state exceeds the bounded store payload size.
    StateTooLarge,
    /// A public identifier is empty or exceeds its bound.
    InvalidIdentifier,
    /// The caller used an unbound/bound API with the wrong state type.
    StateTypeMismatch,
    /// The process-local lock is poisoned and the store cannot be used safely.
    Unavailable,
    /// A random handle collision occurred repeatedly.
    HandleCollision,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity => "invalid login state store capacity",
            Self::InvalidTtl => "invalid login state store ttl",
            Self::CapacityReached => "login state store capacity reached",
            Self::StateTooLarge => "login state store state too large",
            Self::InvalidIdentifier => "invalid login state identifier",
            Self::StateTypeMismatch => "login state store state type mismatch",
            Self::Unavailable => "login state store unavailable",
            Self::HandleCollision => "login state handle collision",
        })
    }
}

impl std::error::Error for StoreError {}

/// A server-login state bound to the identifiers used during OPAQUE start.
///
/// The binding prevents a finish operation from accepting caller-supplied
/// identifiers that differ from the identifiers authenticated at start.
pub struct BoundLoginState {
    state: ServerLoginStateBytes,
    client_identifier: Vec<u8>,
    server_identifier: Vec<u8>,
}

impl BoundLoginState {
    /// Creates a state record with bounded, non-empty public identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidIdentifier`] for an empty or oversized
    /// identifier.
    pub fn new(
        state: ServerLoginStateBytes,
        client_identifier: &[u8],
        server_identifier: &[u8],
    ) -> Result<Self, StoreError> {
        validate_identifier(client_identifier)?;
        validate_identifier(server_identifier)?;
        Ok(Self {
            state,
            client_identifier: client_identifier.to_vec(),
            server_identifier: server_identifier.to_vec(),
        })
    }

    /// Consumes the record into the state and its authenticated identifiers.
    #[must_use]
    pub fn into_parts(self) -> (ServerLoginStateBytes, Vec<u8>, Vec<u8>) {
        (self.state, self.client_identifier, self.server_identifier)
    }
}

enum StoredState {
    Unbound(ServerLoginStateBytes),
    Bound(BoundLoginState),
}

struct Entry {
    expires_at: Instant,
    state: StoredState,
}

/// Backend contract for one-use serialized server-login state.
///
/// A distributed Redis/database adapter should implement these operations with
/// an atomic remove in `take`. It must preserve the same error behavior and
/// never log handles or state bytes.
pub trait OneTimeLoginStateStore {
    /// Stores a pending state and returns its opaque handle.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the backend rejects the state or cannot
    /// create a handle.
    fn insert(&self, state: ServerLoginStateBytes) -> Result<LoginStateHandle, StoreError>;

    /// Atomically removes and returns a state at most once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] or the backend's equivalent when
    /// the atomic read-and-delete operation cannot be completed safely.
    fn take(&self, handle: &LoginStateHandle) -> Result<Option<ServerLoginStateBytes>, StoreError>;
}

/// Backend contract for login state bound to its OPAQUE identifiers.
pub trait BoundOneTimeLoginStateStore {
    /// Stores a bound state and returns its opaque handle.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the backend rejects the state or cannot
    /// create a handle.
    fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError>;

    /// Atomically removes and returns a bound state at most once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] or the backend's equivalent when
    /// the atomic read-and-delete operation cannot be completed safely.
    fn take_bound(&self, handle: &LoginStateHandle) -> Result<Option<BoundLoginState>, StoreError>;
}

/// A bounded, process-local one-time login state store.
///
/// `take` removes a state before returning it, so a handle can succeed only
/// once. Expired state is discarded and its zeroizing container is dropped.
/// This type is not a distributed store and must not be used as one behind a
/// load balancer without external affinity and failover guarantees.
pub struct InMemoryOneTimeLoginStore {
    entries: Mutex<HashMap<LoginStateHandle, Entry>>,
    max_entries: usize,
    ttl: Duration,
}

impl InMemoryOneTimeLoginStore {
    /// Creates a bounded store with the given maximum entries and state TTL.
    ///
    /// A zero TTL is allowed for deterministic tests and means every state is
    /// immediately expired.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidCapacity`] when `max_entries` is zero or
    /// exceeds [`MAX_IN_MEMORY_ENTRIES`], or [`StoreError::InvalidTtl`] when
    /// the TTL would overflow the process clock.
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Self, StoreError> {
        if max_entries == 0 || max_entries > MAX_IN_MEMORY_ENTRIES {
            return Err(StoreError::InvalidCapacity);
        }
        if Instant::now().checked_add(ttl).is_none() {
            return Err(StoreError::InvalidTtl);
        }
        Ok(Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries.min(1024))),
            max_entries,
            ttl,
        })
    }

    /// Inserts a pending state and returns a random 32-byte bearer handle.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CapacityReached`] when the bounded store is full,
    /// or [`StoreError::StateTooLarge`] when the state exceeds the payload
    /// bound.
    pub fn insert(&self, state: ServerLoginStateBytes) -> Result<LoginStateHandle, StoreError> {
        self.insert_stored(StoredState::Unbound(state))
    }

    /// Inserts a state bound to the OPAQUE start identifiers.
    ///
    /// # Errors
    ///
    /// Returns the same capacity and payload errors as [`Self::insert`].
    pub fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError> {
        self.insert_stored(StoredState::Bound(state))
    }

    fn insert_stored(&self, state: StoredState) -> Result<LoginStateHandle, StoreError> {
        let state_len = match &state {
            StoredState::Unbound(state) => state.as_bytes().len(),
            StoredState::Bound(state) => state.state.as_bytes().len(),
        };
        if state_len > MAX_STORED_STATE_BYTES {
            return Err(StoreError::StateTooLarge);
        }
        let now = Instant::now();
        let expires_at = now.checked_add(self.ttl).ok_or(StoreError::InvalidTtl)?;
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        purge_expired(&mut entries, now);
        if entries.len() >= self.max_entries {
            return Err(StoreError::CapacityReached);
        }

        for _ in 0..HANDLE_ATTEMPTS {
            let handle = LoginStateHandle::random();
            if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(handle) {
                slot.insert(Entry { expires_at, state });
                return Ok(handle);
            }
        }
        Err(StoreError::HandleCollision)
    }

    /// Atomically removes and returns a pending state, at most once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process-local lock is
    /// poisoned.
    pub fn take(
        &self,
        handle: &LoginStateHandle,
    ) -> Result<Option<ServerLoginStateBytes>, StoreError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let Some(entry) = entries.remove(handle) else {
            return Ok(None);
        };
        if entry.expires_at <= now {
            return Ok(None);
        }
        match entry.state {
            StoredState::Unbound(state) => Ok(Some(state)),
            StoredState::Bound(_) => Err(StoreError::StateTypeMismatch),
        }
    }

    /// Atomically removes and returns a bound state, at most once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process-local lock is
    /// poisoned, or [`StoreError::StateTypeMismatch`] when the handle refers
    /// to an unbound state.
    pub fn take_bound(
        &self,
        handle: &LoginStateHandle,
    ) -> Result<Option<BoundLoginState>, StoreError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let Some(entry) = entries.remove(handle) else {
            return Ok(None);
        };
        if entry.expires_at <= now {
            return Ok(None);
        }
        match entry.state {
            StoredState::Unbound(_) => Err(StoreError::StateTypeMismatch),
            StoredState::Bound(state) => Ok(Some(state)),
        }
    }

    /// Returns the number of currently live states.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process-local lock is
    /// poisoned.
    pub fn len(&self) -> Result<usize, StoreError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        purge_expired(&mut entries, now);
        Ok(entries.len())
    }

    /// Returns whether the store currently has no live states.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process-local lock is
    /// poisoned.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

impl OneTimeLoginStateStore for InMemoryOneTimeLoginStore {
    fn insert(&self, state: ServerLoginStateBytes) -> Result<LoginStateHandle, StoreError> {
        InMemoryOneTimeLoginStore::insert(self, state)
    }

    fn take(&self, handle: &LoginStateHandle) -> Result<Option<ServerLoginStateBytes>, StoreError> {
        InMemoryOneTimeLoginStore::take(self, handle)
    }
}

impl BoundOneTimeLoginStateStore for InMemoryOneTimeLoginStore {
    fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError> {
        InMemoryOneTimeLoginStore::insert_bound(self, state)
    }

    fn take_bound(&self, handle: &LoginStateHandle) -> Result<Option<BoundLoginState>, StoreError> {
        InMemoryOneTimeLoginStore::take_bound(self, handle)
    }
}

fn validate_identifier(identifier: &[u8]) -> Result<(), StoreError> {
    if identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(StoreError::InvalidIdentifier);
    }
    Ok(())
}

fn purge_expired(entries: &mut HashMap<LoginStateHandle, Entry>, now: Instant) {
    entries.retain(|_, entry| entry.expires_at > now);
}
