use crate::opaque_state_codec::{
    decode_bound_state, encode_bound_state, StateProtector,
    MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES, MAX_DISTRIBUTED_LOGIN_STATE_STORAGE_BYTES,
};
use crate::{
    BoundLoginState, BoundOneTimeLoginStateStore, LoginStateHandle, OpaqueStateKey, StoreError,
    MAX_DISTRIBUTED_LOGIN_STATE_TTL, MAX_IN_MEMORY_ENTRIES,
};
use r2d2::{Pool, PooledConnection};
use redis::Script;
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

const HANDLE_ATTEMPTS: usize = 8;
const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_POOL_SIZE: u32 = 256;
const INSERT_SCRIPT: &str = r"
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then
  return 0
end
local inserted = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2])
if not inserted then
  return -1
end
redis.call('ZADD', KEYS[2], now_ms + tonumber(ARGV[2]), ARGV[4])
local index_ttl = redis.call('PTTL', KEYS[2])
if index_ttl < tonumber(ARGV[2]) then
  redis.call('PEXPIRE', KEYS[2], ARGV[2])
end
return 1
";

const CONSUME_SCRIPT: &str = r"
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local ttl = redis.call('PTTL', KEYS[1])
if ttl == -1 or ttl == 0 or ttl > tonumber(ARGV[3]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
  return {-2, false}
end
local length = redis.call('STRLEN', KEYS[1])
if length > tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
  return {-2, false}
end
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
end
if not value then
  redis.call('ZREM', KEYS[2], ARGV[1])
  return {0, false}
end
return {1, value}
";

/// Configuration errors returned while constructing a Redis one-time store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisOneTimeStateConfigError {
    /// The URL could not be parsed by redis-rs.
    InvalidUrl,
    /// The URL is not TLS-protected.
    InsecureUrl,
    /// The namespace is empty, oversized, or contains unsafe key characters.
    InvalidNamespace,
    /// The connection pool size is outside the bounded adapter limit.
    InvalidPoolSize,
    /// The active state capacity is outside the bounded adapter limit.
    InvalidCapacity,
    /// The state TTL is zero, too large, or cannot be represented in Redis PX.
    InvalidTtl,
    /// The connection pool could not be constructed.
    PoolBuild,
}

impl fmt::Display for RedisOneTimeStateConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid redis URL",
            Self::InsecureUrl => "opaque one-time state requires a TLS Redis URL",
            Self::InvalidNamespace => "invalid Redis opaque-state namespace",
            Self::InvalidPoolSize => "invalid Redis opaque-state pool size",
            Self::InvalidCapacity => "invalid Redis opaque-state capacity",
            Self::InvalidTtl => "invalid Redis opaque-state TTL",
            Self::PoolBuild => "Redis opaque-state pool construction failed",
        })
    }
}

impl std::error::Error for RedisOneTimeStateConfigError {}

/// Redis-backed implementation of the bound one-time OPAQUE state contract.
///
/// Insertion is an atomic `SET NX PX` plus active-key capacity script. Consume
/// is an atomic read/delete/index-removal script. Handles are SHA-256 hashed
/// before entering Redis and all operations are blocking.
#[derive(Clone)]
pub struct RedisOneTimeLoginStateStore {
    pool: Pool<redis::Client>,
    namespace: String,
    ttl_millis: u64,
    max_entries: usize,
    protector: StateProtector,
}

impl RedisOneTimeLoginStateStore {
    /// Creates a TLS-protected Redis one-time state store.
    ///
    /// The supplied 32-byte key encrypts and authenticates each durable OPAQUE
    /// state record before it enters Redis. Keep it stable for at least the
    /// configured TTL and load it from a secret manager or KMS-backed config.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, pool, capacity,
    /// or TTL violates the bounded production policy.
    pub fn from_url(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
        encryption_key: OpaqueStateKey,
    ) -> Result<Self, RedisOneTimeStateConfigError> {
        Self::build(
            url,
            namespace,
            pool_size,
            max_entries,
            ttl,
            encryption_key,
            true,
        )
    }

    /// Creates a plaintext-connection store only for an isolated local test
    /// instance. State records remain encrypted and authenticated at rest.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, pool, capacity,
    /// or TTL violates the bounded local-test policy.
    pub fn from_insecure_url_for_local_testing(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
        encryption_key: OpaqueStateKey,
    ) -> Result<Self, RedisOneTimeStateConfigError> {
        Self::build(
            url,
            namespace,
            pool_size,
            max_entries,
            ttl,
            encryption_key,
            false,
        )
    }

    fn build(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_entries: usize,
        ttl: Duration,
        encryption_key: OpaqueStateKey,
        require_tls: bool,
    ) -> Result<Self, RedisOneTimeStateConfigError> {
        validate_namespace(namespace)?;
        if pool_size == 0 || pool_size > MAX_POOL_SIZE {
            return Err(RedisOneTimeStateConfigError::InvalidPoolSize);
        }
        if max_entries == 0 || max_entries > MAX_IN_MEMORY_ENTRIES {
            return Err(RedisOneTimeStateConfigError::InvalidCapacity);
        }
        let ttl_millis = ttl_millis(ttl)?;
        if require_tls && !url.starts_with("rediss://") {
            return Err(RedisOneTimeStateConfigError::InsecureUrl);
        }
        let client =
            redis::Client::open(url).map_err(|_| RedisOneTimeStateConfigError::InvalidUrl)?;
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(client)
            .map_err(|_| RedisOneTimeStateConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
            ttl_millis,
            max_entries,
            protector: StateProtector::new(encryption_key, namespace),
        })
    }

    fn connection(&self) -> Result<PooledConnection<redis::Client>, StoreError> {
        self.pool.get().map_err(|_| StoreError::Unavailable)
    }

    fn state_key(&self, hash: &str) -> String {
        format!("{}:opaque:v1:login:{hash}", self.namespace)
    }

    fn pending_index_key(&self) -> String {
        format!("{}:opaque:v1:login:pending", self.namespace)
    }
}

impl BoundOneTimeLoginStateStore for RedisOneTimeLoginStateStore {
    fn insert_bound(&self, state: BoundLoginState) -> Result<LoginStateHandle, StoreError> {
        let encoded = encode_bound_state(state)?;
        if encoded.len() > MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES {
            return Err(StoreError::StateTooLarge);
        }
        let protected = self.protector.seal(encoded.as_slice())?;
        let mut connection = self.connection()?;
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = LoginStateHandle::generate();
            let handle_hash = hash_handle(&handle);
            let inserted: i64 = Script::new(INSERT_SCRIPT)
                .key(self.state_key(&handle_hash))
                .key(self.pending_index_key())
                .arg(protected.as_slice())
                .arg(self.ttl_millis)
                .arg(self.max_entries)
                .arg(&handle_hash)
                .invoke(&mut *connection)
                .map_err(|_| StoreError::Unavailable)?;
            match inserted {
                1 => return Ok(handle),
                0 => return Err(StoreError::CapacityReached),
                -1 => {}
                _ => return Err(StoreError::Unavailable),
            }
        }
        Err(StoreError::HandleCollision)
    }

    fn take_bound(&self, handle: &LoginStateHandle) -> Result<Option<BoundLoginState>, StoreError> {
        let handle_hash = hash_handle(handle);
        let mut connection = self.connection()?;
        let (status, protected): (i64, Option<Vec<u8>>) = Script::new(CONSUME_SCRIPT)
            .key(self.state_key(&handle_hash))
            .key(self.pending_index_key())
            .arg(&handle_hash)
            .arg(MAX_DISTRIBUTED_LOGIN_STATE_STORAGE_BYTES)
            .arg(self.ttl_millis)
            .invoke(&mut *connection)
            .map_err(|_| StoreError::Unavailable)?;
        let protected = match status {
            0 => return Ok(None),
            1 => protected.ok_or(StoreError::Unavailable)?,
            _ => return Err(StoreError::Unavailable),
        };
        let encoded = self.protector.open(protected)?;
        Ok(Some(decode_bound_state(encoded.to_vec())?))
    }
}

fn ttl_millis(ttl: Duration) -> Result<u64, RedisOneTimeStateConfigError> {
    let millis = u64::try_from(ttl.as_millis())
        .ok()
        .filter(|millis| *millis > 0 && i64::try_from(*millis).is_ok())
        .ok_or(RedisOneTimeStateConfigError::InvalidTtl)?;
    if ttl > MAX_DISTRIBUTED_LOGIN_STATE_TTL {
        return Err(RedisOneTimeStateConfigError::InvalidTtl);
    }
    Ok(millis)
}

fn hash_handle(handle: &LoginStateHandle) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(handle.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_namespace(namespace: &str) -> Result<(), RedisOneTimeStateConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RedisOneTimeStateConfigError::InvalidNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::CONSUME_SCRIPT;

    #[test]
    fn consume_checks_length_before_get() {
        let length_check = CONSUME_SCRIPT
            .find("STRLEN")
            .expect("opaque consume must check length");
        let get = CONSUME_SCRIPT
            .find("'GET'")
            .expect("opaque consume must retrieve an accepted value");
        assert!(length_check < get);
        assert!(CONSUME_SCRIPT.contains("tonumber(ARGV[2])"));
        assert!(CONSUME_SCRIPT.contains("return {-2, false}"));
    }

    #[test]
    fn consume_removes_a_stale_index_when_the_state_key_is_missing() {
        let missing_value = CONSUME_SCRIPT
            .find("if not value then")
            .expect("opaque consume must handle a missing state key");
        let cleanup = CONSUME_SCRIPT[missing_value..]
            .find("redis.call('ZREM', KEYS[2], ARGV[1])")
            .expect("missing opaque state must release its pending-index slot");
        assert!(
            cleanup
                < CONSUME_SCRIPT[missing_value..]
                    .find("return {0, false}")
                    .unwrap()
        );
    }

    #[test]
    fn consume_rejects_state_ttl_drift_before_materialization() {
        assert!(CONSUME_SCRIPT.contains("local ttl = redis.call('PTTL', KEYS[1])"));
        assert!(CONSUME_SCRIPT.contains("ttl > tonumber(ARGV[3])"));
        assert!(CONSUME_SCRIPT.contains("return {-2, false}"));
    }
}
