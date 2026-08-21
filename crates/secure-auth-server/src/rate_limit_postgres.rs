use crate::{
    RateLimitDecision, RateLimitError, RateLimitPolicy, RateLimiter,
    MAX_DISTRIBUTED_RATE_LIMIT_WINDOW, MAX_IN_MEMORY_RATE_KEYS, MAX_RATE_LIMIT_KEY_BYTES,
};
use postgres::{config::SslMode, tls::MakeTlsConnect, Config, Socket};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

const MAX_NAMESPACE_BYTES: usize = 64;

/// SQL schema required by [`PostgresRateLimiter`].
pub const POSTGRES_RATE_LIMIT_SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS secure_keypad_rate_limit_windows (
    namespace TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    attempts BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (namespace, key_hash),
    CONSTRAINT secure_keypad_rate_limit_namespace_length
        CHECK (octet_length(namespace) BETWEEN 1 AND 64),
    CONSTRAINT secure_keypad_rate_limit_namespace_chars
        CHECK (namespace ~ '^[A-Za-z0-9._-]+$'),
    CHECK (octet_length(key_hash) = 32),
    CHECK (attempts BETWEEN 1 AND 4294967295)
);
CREATE INDEX IF NOT EXISTS secure_keypad_rate_limit_windows_expiry_idx
    ON secure_keypad_rate_limit_windows (expires_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_rate_limit_windows'::regclass
          AND conname = 'secure_keypad_rate_limit_namespace_length'
    ) THEN
        ALTER TABLE secure_keypad_rate_limit_windows
            ADD CONSTRAINT secure_keypad_rate_limit_namespace_length
            CHECK (octet_length(namespace) BETWEEN 1 AND 64);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_rate_limit_windows'::regclass
          AND conname = 'secure_keypad_rate_limit_namespace_chars'
    ) THEN
        ALTER TABLE secure_keypad_rate_limit_windows
            ADD CONSTRAINT secure_keypad_rate_limit_namespace_chars
            CHECK (namespace ~ '^[A-Za-z0-9._-]+$');
    END IF;
END
$$;
";

/// Configuration errors returned while constructing a `PostgreSQL` rate limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresRateLimitConfigError {
    /// The namespace is empty, oversized, or contains unsafe key characters.
    InvalidNamespace,
    /// The connection pool size is zero or exceeds the bounded adapter limit.
    InvalidPoolSize,
    /// The active-key capacity is zero or exceeds the bounded adapter limit.
    InvalidCapacity,
    /// The fixed-window duration cannot be represented by `PostgreSQL`.
    InvalidPolicy,
    /// The supplied production configuration does not require `PostgreSQL` TLS.
    InsecureConfig,
    /// The connection pool could not be constructed.
    PoolBuild,
}

impl fmt::Display for PostgresRateLimitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNamespace => "invalid PostgreSQL rate-limit namespace",
            Self::InvalidPoolSize => "invalid PostgreSQL rate-limit pool size",
            Self::InvalidCapacity => "invalid PostgreSQL rate-limit capacity",
            Self::InvalidPolicy => "invalid PostgreSQL rate-limit policy",
            Self::InsecureConfig => "PostgreSQL rate-limit config must require TLS",
            Self::PoolBuild => "PostgreSQL rate-limit pool construction failed",
        })
    }
}

impl std::error::Error for PostgresRateLimitConfigError {}

/// A PostgreSQL-backed implementation of [`RateLimiter`].
///
/// Each check takes a namespace advisory transaction lock, removes expired
/// rows, and updates or inserts the hashed key in the same transaction. This
/// makes the attempt count and active-key capacity atomic across instances.
/// The adapter is blocking and must run outside an async executor thread.
#[derive(Clone)]
pub struct PostgresRateLimiter<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    pool: Pool<PostgresConnectionManager<T>>,
    namespace: String,
    policy: RateLimitPolicy,
    window_millis: i64,
    max_keys: usize,
}

impl<T> PostgresRateLimiter<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    /// Creates a rate limiter with an explicit `PostgreSQL` TLS connector.
    ///
    /// `pool_size` and `max_keys` are independently bounded. The namespace
    /// advisory lock keeps capacity and attempt updates atomic.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the namespace, pool size, capacity,
    /// or policy is invalid, or when the pool cannot be built.
    pub fn from_config(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
    ) -> Result<Self, PostgresRateLimitConfigError> {
        Self::build(config, tls, namespace, pool_size, max_keys, policy, true)
    }

    fn build(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
        require_tls: bool,
    ) -> Result<Self, PostgresRateLimitConfigError> {
        if require_tls && config.get_ssl_mode() != SslMode::Require {
            return Err(PostgresRateLimitConfigError::InsecureConfig);
        }
        validate_namespace(namespace)?;
        validate_pool_size(pool_size)?;
        if max_keys == 0 || max_keys > MAX_IN_MEMORY_RATE_KEYS {
            return Err(PostgresRateLimitConfigError::InvalidCapacity);
        }
        let window_millis = policy_window_millis(policy)?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)
            .map_err(|_| PostgresRateLimitConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
            policy,
            window_millis,
            max_keys,
        })
    }

    fn connection(&self) -> Result<PooledConnection<PostgresConnectionManager<T>>, RateLimitError> {
        self.pool.get().map_err(|_| RateLimitError::Unavailable)
    }
}

impl PostgresRateLimiter<NoTls> {
    /// Creates a plaintext `PostgreSQL` limiter for an isolated local test.
    ///
    /// Do not use this constructor for a production or shared environment.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the namespace, pool size, capacity,
    /// or policy is invalid, or when the pool cannot be built.
    pub fn from_config_for_local_testing(
        config: Config,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
    ) -> Result<Self, PostgresRateLimitConfigError> {
        Self::build(config, NoTls, namespace, pool_size, max_keys, policy, false)
    }
}

impl<T> RateLimiter for PostgresRateLimiter<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    fn check(&self, key: &[u8]) -> Result<RateLimitDecision, RateLimitError> {
        if key.is_empty() || key.len() > MAX_RATE_LIMIT_KEY_BYTES {
            return Err(RateLimitError::InvalidKey);
        }
        let key_hash: [u8; 32] = Sha256::digest(key).into();
        let mut client = self.connection()?;
        let mut transaction = client
            .transaction()
            .map_err(|_| RateLimitError::Unavailable)?;
        let namespace_lock = format!("{}:rate-limit", self.namespace);
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&namespace_lock],
            )
            .map_err(|_| RateLimitError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM secure_keypad_rate_limit_windows
                 WHERE namespace = $1 AND expires_at <= now()",
                &[&self.namespace],
            )
            .map_err(|_| RateLimitError::Unavailable)?;

        let row = transaction
            .query_opt(
                "SELECT attempts,
                        GREATEST(1, CEIL(EXTRACT(EPOCH FROM (expires_at - now())) * 1000))::BIGINT
                 FROM secure_keypad_rate_limit_windows
                 WHERE namespace = $1 AND key_hash = $2 AND expires_at > now()
                 FOR UPDATE",
                &[&self.namespace, &&key_hash[..]],
            )
            .map_err(|_| RateLimitError::Unavailable)?;
        if let Some(row) = row {
            let attempts: i64 = row.get(0);
            let retry_millis: i64 = row.get(1);
            if attempts >= i64::from(self.policy.max_attempts()) {
                let retry_after = retry_after(retry_millis)?;
                transaction
                    .commit()
                    .map_err(|_| RateLimitError::Unavailable)?;
                return Ok(RateLimitDecision::Limited { retry_after });
            }
            let next_attempts = attempts.checked_add(1).ok_or(RateLimitError::Unavailable)?;
            transaction
                .execute(
                    "UPDATE secure_keypad_rate_limit_windows
                     SET attempts = $3
                     WHERE namespace = $1 AND key_hash = $2",
                    &[&self.namespace, &&key_hash[..], &next_attempts],
                )
                .map_err(|_| RateLimitError::Unavailable)?;
            transaction
                .commit()
                .map_err(|_| RateLimitError::Unavailable)?;
            return Ok(RateLimitDecision::Allowed {
                remaining: self
                    .policy
                    .max_attempts()
                    .checked_sub(
                        u32::try_from(next_attempts).map_err(|_| RateLimitError::Unavailable)?,
                    )
                    .ok_or(RateLimitError::Unavailable)?,
            });
        }

        let active_keys: i64 = transaction
            .query_one(
                "SELECT count(*) FROM secure_keypad_rate_limit_windows
                 WHERE namespace = $1 AND expires_at > now()",
                &[&self.namespace],
            )
            .map_err(|_| RateLimitError::Unavailable)?
            .get(0);
        if active_keys >= i64::try_from(self.max_keys).unwrap_or(i64::MAX) {
            return Err(RateLimitError::CapacityReached);
        }
        let initial_attempts: i64 = 1;
        transaction
            .execute(
                "INSERT INTO secure_keypad_rate_limit_windows
                 (namespace, key_hash, attempts, expires_at)
                 VALUES ($1, $2, $3,
                         now() + ($4::double precision * interval '1 millisecond'))",
                &[
                    &self.namespace,
                    &&key_hash[..],
                    &initial_attempts,
                    &self.window_millis,
                ],
            )
            .map_err(|_| RateLimitError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| RateLimitError::Unavailable)?;
        Ok(RateLimitDecision::Allowed {
            remaining: self.policy.max_attempts() - 1,
        })
    }
}

fn policy_window_millis(policy: RateLimitPolicy) -> Result<i64, PostgresRateLimitConfigError> {
    let millis = u64::try_from(policy.window().as_millis())
        .map_err(|_| PostgresRateLimitConfigError::InvalidPolicy)?;
    if policy.window() > MAX_DISTRIBUTED_RATE_LIMIT_WINDOW {
        return Err(PostgresRateLimitConfigError::InvalidPolicy);
    }
    i64::try_from(millis)
        .ok()
        .filter(|millis| *millis > 0)
        .ok_or(PostgresRateLimitConfigError::InvalidPolicy)
}

fn retry_after(millis: i64) -> Result<Duration, RateLimitError> {
    let millis = u64::try_from(millis).map_err(|_| RateLimitError::Unavailable)?;
    if millis == 0 {
        return Err(RateLimitError::Unavailable);
    }
    Ok(Duration::from_millis(millis))
}

fn validate_pool_size(pool_size: u32) -> Result<(), PostgresRateLimitConfigError> {
    if pool_size == 0 || pool_size > 256 {
        return Err(PostgresRateLimitConfigError::InvalidPoolSize);
    }
    Ok(())
}

fn validate_namespace(namespace: &str) -> Result<(), PostgresRateLimitConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PostgresRateLimitConfigError::InvalidNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::POSTGRES_RATE_LIMIT_SCHEMA_SQL;

    #[test]
    fn schema_enforces_the_application_namespace_contract() {
        assert!(POSTGRES_RATE_LIMIT_SCHEMA_SQL
            .contains("CHECK (octet_length(namespace) BETWEEN 1 AND 64)"));
        assert!(POSTGRES_RATE_LIMIT_SCHEMA_SQL.contains("CHECK (namespace ~ '^[A-Za-z0-9._-]+$')"));
        assert!(
            POSTGRES_RATE_LIMIT_SCHEMA_SQL.contains("ALTER TABLE secure_keypad_rate_limit_windows")
        );
        assert!(POSTGRES_RATE_LIMIT_SCHEMA_SQL.contains("FROM pg_constraint"));
    }
}
