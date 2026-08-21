use crate::opaque_state_codec::{
    decode_bound_state, encode_bound_state, MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES,
};
use crate::{
    BoundLoginState, BoundOneTimeLoginStateStore, LoginStateHandle, StoreError,
    MAX_DISTRIBUTED_LOGIN_STATE_TTL, MAX_IN_MEMORY_ENTRIES,
};
use postgres::{config::SslMode, tls::MakeTlsConnect, Config, Socket};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

const HANDLE_ATTEMPTS: usize = 8;
const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_POOL_SIZE: u32 = 256;
/// SQL schema required by [`PostgresOneTimeLoginStateStore`].
pub const POSTGRES_ONE_TIME_LOGIN_STATE_SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS secure_keypad_opaque_login_states (
    namespace TEXT NOT NULL,
    handle_hash BYTEA NOT NULL,
    state BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (namespace, handle_hash),
    CONSTRAINT secure_keypad_opaque_state_namespace_length
        CHECK (octet_length(namespace) BETWEEN 1 AND 64),
    CONSTRAINT secure_keypad_opaque_state_namespace_chars
        CHECK (namespace ~ '^[A-Za-z0-9._-]+$'),
    CONSTRAINT secure_keypad_opaque_state_handle_hash_length
        CHECK (octet_length(handle_hash) = 32),
    CONSTRAINT secure_keypad_opaque_state_length
        CHECK (octet_length(state) BETWEEN 1 AND 32768)
);
CREATE INDEX IF NOT EXISTS secure_keypad_opaque_login_states_expiry_idx
    ON secure_keypad_opaque_login_states (expires_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_opaque_login_states'::regclass
          AND conname = 'secure_keypad_opaque_state_namespace_length'
    ) THEN
        ALTER TABLE secure_keypad_opaque_login_states
            ADD CONSTRAINT secure_keypad_opaque_state_namespace_length
            CHECK (octet_length(namespace) BETWEEN 1 AND 64);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_opaque_login_states'::regclass
          AND conname = 'secure_keypad_opaque_state_namespace_chars'
    ) THEN
        ALTER TABLE secure_keypad_opaque_login_states
            ADD CONSTRAINT secure_keypad_opaque_state_namespace_chars
            CHECK (namespace ~ '^[A-Za-z0-9._-]+$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_opaque_login_states'::regclass
          AND conname = 'secure_keypad_opaque_state_handle_hash_length'
    ) THEN
        ALTER TABLE secure_keypad_opaque_login_states
            ADD CONSTRAINT secure_keypad_opaque_state_handle_hash_length
            CHECK (octet_length(handle_hash) = 32);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_opaque_login_states'::regclass
          AND conname = 'secure_keypad_opaque_state_length'
    ) THEN
        ALTER TABLE secure_keypad_opaque_login_states
            ADD CONSTRAINT secure_keypad_opaque_state_length
            CHECK (octet_length(state) BETWEEN 1 AND 32768);
    END IF;
END
$$;
";

/// Configuration errors returned while constructing a `PostgreSQL` one-time store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresOneTimeStateConfigError {
    /// The namespace is empty, oversized, or contains unsafe key characters.
    InvalidNamespace,
    /// The connection pool size is outside the bounded adapter limit.
    InvalidPoolSize,
    /// The active state capacity is outside the bounded adapter limit.
    InvalidCapacity,
    /// The state TTL is zero, too large, or cannot be represented in SQL.
    InvalidTtl,
    /// The production configuration does not require `PostgreSQL` TLS.
    InsecureConfig,
    /// The connection pool could not be constructed.
    PoolBuild,
}

impl fmt::Display for PostgresOneTimeStateConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNamespace => "invalid PostgreSQL opaque-state namespace",
            Self::InvalidPoolSize => "invalid PostgreSQL opaque-state pool size",
            Self::InvalidCapacity => "invalid PostgreSQL opaque-state capacity",
            Self::InvalidTtl => "invalid PostgreSQL opaque-state TTL",
            Self::InsecureConfig => "PostgreSQL opaque-state config must require TLS",
            Self::PoolBuild => "PostgreSQL opaque-state pool construction failed",
        })
    }
}

impl std::error::Error for PostgresOneTimeStateConfigError {}

/// PostgreSQL-backed implementation of the bound one-time OPAQUE state
/// contract. The insert capacity check is serialized by a namespace advisory
/// lock; consume is one `DELETE ... RETURNING` operation.
#[derive(Clone)]
pub struct PostgresOneTimeLoginStateStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    pool: Pool<PostgresConnectionManager<T>>,
    namespace: String,
    ttl_millis: i64,
    max_entries: usize,
}

impl<T> PostgresOneTimeLoginStateStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    /// Creates a store with an explicit `PostgreSQL` TLS connector.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the TLS mode, namespace, pool,
    /// capacity, or TTL violates the bounded production policy.
    pub fn from_config(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
    ) -> Result<Self, PostgresOneTimeStateConfigError> {
        Self::build(config, tls, namespace, pool_size, max_entries, ttl, true)
    }

    fn build(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
        require_tls: bool,
    ) -> Result<Self, PostgresOneTimeStateConfigError> {
        if require_tls && config.get_ssl_mode() != SslMode::Require {
            return Err(PostgresOneTimeStateConfigError::InsecureConfig);
        }
        validate_namespace(namespace)?;
        if pool_size == 0 || pool_size > MAX_POOL_SIZE {
            return Err(PostgresOneTimeStateConfigError::InvalidPoolSize);
        }
        if max_entries == 0 || max_entries > MAX_IN_MEMORY_ENTRIES {
            return Err(PostgresOneTimeStateConfigError::InvalidCapacity);
        }
        let ttl_millis = ttl_millis(ttl)?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)
            .map_err(|_| PostgresOneTimeStateConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
            ttl_millis,
            max_entries,
        })
    }

    fn connection(&self) -> Result<PooledConnection<PostgresConnectionManager<T>>, StoreError> {
        self.pool.get().map_err(|_| StoreError::Unavailable)
    }
}

impl PostgresOneTimeLoginStateStore<NoTls> {
    /// Creates a plaintext store only for an isolated local test instance.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the namespace, pool, capacity, or
    /// TTL violates the bounded local-test policy.
    pub fn from_config_for_local_testing(
        config: Config,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
    ) -> Result<Self, PostgresOneTimeStateConfigError> {
        Self::build(config, NoTls, namespace, pool_size, max_entries, ttl, false)
    }
}

impl<T> BoundOneTimeLoginStateStore for PostgresOneTimeLoginStateStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError> {
        let encoded = encode_bound_state(state)?;
        if encoded.len() > MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES {
            return Err(StoreError::StateTooLarge);
        }
        let mut client = self.connection()?;
        let mut transaction = client.transaction().map_err(|_| StoreError::Unavailable)?;
        let namespace_lock = format!("{}:opaque-login-state", self.namespace);
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&namespace_lock],
            )
            .map_err(|_| StoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM secure_keypad_opaque_login_states
                 WHERE namespace = $1 AND expires_at <= now()",
                &[&self.namespace],
            )
            .map_err(|_| StoreError::Unavailable)?;
        let active: i64 = transaction
            .query_one(
                "SELECT count(*) FROM secure_keypad_opaque_login_states
                 WHERE namespace = $1 AND expires_at > now()",
                &[&self.namespace],
            )
            .map_err(|_| StoreError::Unavailable)?
            .get(0);
        if active >= i64::try_from(self.max_entries).unwrap_or(i64::MAX) {
            return Err(StoreError::CapacityReached);
        }
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = LoginStateHandle::generate();
            let handle_hash: [u8; 32] = Sha256::digest(handle.as_bytes()).into();
            let rows = transaction
                .execute(
                    "INSERT INTO secure_keypad_opaque_login_states
                     (namespace, handle_hash, state, expires_at)
                     VALUES ($1, $2, $3,
                             now() + ($4::double precision * interval '1 millisecond'))
                     ON CONFLICT (namespace, handle_hash) DO NOTHING",
                    &[
                        &self.namespace,
                        &&handle_hash[..],
                        &encoded.as_slice(),
                        &self.ttl_millis,
                    ],
                )
                .map_err(|_| StoreError::Unavailable)?;
            if rows == 1 {
                transaction.commit().map_err(|_| StoreError::Unavailable)?;
                return Ok(handle);
            }
        }
        Err(StoreError::HandleCollision)
    }

    fn take_bound(&self, handle: &LoginStateHandle) -> Result<Option<BoundLoginState>, StoreError> {
        let mut client = self.connection()?;
        let handle_hash: [u8; 32] = Sha256::digest(handle.as_bytes()).into();
        let row = client
            .query_opt(
                "DELETE FROM secure_keypad_opaque_login_states
                 WHERE namespace = $1 AND handle_hash = $2 AND expires_at > now()
                 RETURNING state",
                &[&self.namespace, &&handle_hash[..]],
            )
            .map_err(|_| StoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let encoded: Vec<u8> = row.get(0);
        decode_bound_state(encoded).map(Some)
    }
}

fn ttl_millis(ttl: Duration) -> Result<i64, PostgresOneTimeStateConfigError> {
    if ttl.is_zero() || ttl > MAX_DISTRIBUTED_LOGIN_STATE_TTL {
        return Err(PostgresOneTimeStateConfigError::InvalidTtl);
    }
    i64::try_from(ttl.as_millis())
        .ok()
        .filter(|millis| *millis > 0)
        .ok_or(PostgresOneTimeStateConfigError::InvalidTtl)
}

fn validate_namespace(namespace: &str) -> Result<(), PostgresOneTimeStateConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PostgresOneTimeStateConfigError::InvalidNamespace);
    }
    Ok(())
}
