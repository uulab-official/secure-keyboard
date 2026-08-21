use crate::{
    RateLimitDecision, RateLimitError, RateLimitPolicy, RateLimiter,
    MAX_DISTRIBUTED_RATE_LIMIT_WINDOW, MAX_IN_MEMORY_RATE_KEYS, MAX_RATE_LIMIT_KEY_BYTES,
};
use r2d2::{Pool, PooledConnection};
use redis::Script;
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};

const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_RATE_COUNTER_BYTES: usize = 32;
const RATE_LIMIT_SCRIPT: &str = r"
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local current_length = redis.call('STRLEN', KEYS[1])
if current_length > tonumber(ARGV[5]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[4])
  return {-2, 0, 0}
end
local current = redis.call('GET', KEYS[1])
if current then
  local attempts = tonumber(current)
  if not attempts then
    return {-2, 0, 0}
  end
  if attempts >= tonumber(ARGV[1]) then
    local ttl = redis.call('PTTL', KEYS[1])
    if ttl < 1 then
      return {-2, 0, 0}
    end
    return {0, 0, ttl}
  end
  local next_attempts = redis.call('INCR', KEYS[1])
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 1 then
    return {-2, 0, 0}
  end
  return {1, tonumber(ARGV[1]) - next_attempts, ttl}
end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then
  return {-1, 0, 0}
end
redis.call('SET', KEYS[1], 1, 'PX', ARGV[3])
redis.call('ZADD', KEYS[2], now_ms + tonumber(ARGV[3]), ARGV[4])
local index_ttl = redis.call('PTTL', KEYS[2])
if index_ttl < tonumber(ARGV[3]) then
  redis.call('PEXPIRE', KEYS[2], ARGV[3])
end
return {1, tonumber(ARGV[1]) - 1, tonumber(ARGV[3])}
";

/// Configuration errors returned while constructing a Redis rate limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisRateLimitConfigError {
    /// The URL could not be parsed by redis-rs.
    InvalidUrl,
    /// The URL is not TLS-protected. Use the explicit local-test constructor
    /// only for an isolated development Redis instance.
    InsecureUrl,
    /// The namespace is empty, oversized, or contains unsafe key characters.
    InvalidNamespace,
    /// The connection pool size is zero or exceeds the bounded adapter limit.
    InvalidPoolSize,
    /// The active-key capacity is zero or exceeds the bounded adapter limit.
    InvalidCapacity,
    /// The fixed-window duration cannot be represented by Redis PX.
    InvalidPolicy,
    /// The connection pool could not be constructed.
    PoolBuild,
}

impl fmt::Display for RedisRateLimitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid redis URL",
            Self::InsecureUrl => "rate limiting requires a TLS Redis URL",
            Self::InvalidNamespace => "invalid Redis rate-limit namespace",
            Self::InvalidPoolSize => "invalid Redis rate-limit pool size",
            Self::InvalidCapacity => "invalid Redis rate-limit capacity",
            Self::InvalidPolicy => "invalid Redis rate-limit policy",
            Self::PoolBuild => "Redis rate-limit pool construction failed",
        })
    }
}

impl std::error::Error for RedisRateLimitConfigError {}

/// A Redis-backed implementation of [`RateLimiter`].
///
/// The check-and-count operation is one Lua script. It uses a fixed-window
/// counter with a server-side TTL and a bounded sorted-set index for active
/// key capacity. Public keys are SHA-256 hashed before entering Redis. All
/// operations are blocking and must run outside an async executor thread.
#[derive(Clone)]
pub struct RedisRateLimiter {
    pool: Pool<redis::Client>,
    namespace: String,
    policy: RateLimitPolicy,
    window_millis: u64,
    max_keys: usize,
}

impl RedisRateLimiter {
    /// Creates a TLS-protected Redis rate limiter.
    ///
    /// The URL must use `rediss://`. The active-key capacity is bounded to
    /// prevent an untrusted key space from exhausting Redis memory.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, capacity, or
    /// policy is invalid, or when the pool cannot be built.
    pub fn from_url(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
    ) -> Result<Self, RedisRateLimitConfigError> {
        Self::build(url, namespace, pool_size, max_keys, policy, true)
    }

    /// Creates a Redis rate limiter for an isolated local test instance.
    ///
    /// This intentionally requires a separate method so production config
    /// cannot silently downgrade from `rediss://` to plaintext `redis://`.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, capacity, or
    /// policy is invalid, or when the pool cannot be built.
    pub fn from_insecure_url_for_local_testing(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
    ) -> Result<Self, RedisRateLimitConfigError> {
        Self::build(url, namespace, pool_size, max_keys, policy, false)
    }

    fn build(
        url: &str,
        namespace: &str,
        pool_size: u32,
        max_keys: usize,
        policy: RateLimitPolicy,
        require_tls: bool,
    ) -> Result<Self, RedisRateLimitConfigError> {
        validate_namespace(namespace)?;
        if pool_size == 0 || pool_size > 256 {
            return Err(RedisRateLimitConfigError::InvalidPoolSize);
        }
        if max_keys == 0 || max_keys > MAX_IN_MEMORY_RATE_KEYS {
            return Err(RedisRateLimitConfigError::InvalidCapacity);
        }
        let window_millis = policy_window_millis(policy)?;
        if require_tls && !url.starts_with("rediss://") {
            return Err(RedisRateLimitConfigError::InsecureUrl);
        }
        let client = redis::Client::open(url).map_err(|_| RedisRateLimitConfigError::InvalidUrl)?;
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(client)
            .map_err(|_| RedisRateLimitConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
            policy,
            window_millis,
            max_keys,
        })
    }

    fn connection(&self) -> Result<PooledConnection<redis::Client>, RateLimitError> {
        self.pool.get().map_err(|_| RateLimitError::Unavailable)
    }

    fn key_name(&self, key_hash: &str) -> String {
        format!("{}:ratelimit:v1:key:{key_hash}", self.namespace)
    }

    fn index_name(&self) -> String {
        format!("{}:ratelimit:v1:index", self.namespace)
    }
}

impl RateLimiter for RedisRateLimiter {
    fn check(&self, key: &[u8]) -> Result<RateLimitDecision, RateLimitError> {
        if key.is_empty() || key.len() > MAX_RATE_LIMIT_KEY_BYTES {
            return Err(RateLimitError::InvalidKey);
        }
        let key_hash = hash_key(key);
        let mut connection = self.connection()?;
        let response: Vec<i64> = Script::new(RATE_LIMIT_SCRIPT)
            .key(self.key_name(&key_hash))
            .key(self.index_name())
            .arg(self.policy.max_attempts())
            .arg(self.max_keys)
            .arg(self.window_millis)
            .arg(&key_hash)
            .arg(MAX_RATE_COUNTER_BYTES)
            .invoke(&mut *connection)
            .map_err(|_| RateLimitError::Unavailable)?;
        if response.len() != 3 {
            return Err(RateLimitError::Unavailable);
        }
        match response[0] {
            -2 => Err(RateLimitError::Unavailable),
            -1 => Err(RateLimitError::CapacityReached),
            0 => Ok(RateLimitDecision::Limited {
                retry_after: retry_after(response[2])?,
            }),
            1 => Ok(RateLimitDecision::Allowed {
                remaining: u32::try_from(response[1]).map_err(|_| RateLimitError::Unavailable)?,
            }),
            _ => Err(RateLimitError::Unavailable),
        }
    }
}

fn policy_window_millis(policy: RateLimitPolicy) -> Result<u64, RedisRateLimitConfigError> {
    let millis = u64::try_from(policy.window().as_millis())
        .map_err(|_| RedisRateLimitConfigError::InvalidPolicy)?;
    if millis == 0
        || millis > i64::MAX as u64
        || policy.window() > MAX_DISTRIBUTED_RATE_LIMIT_WINDOW
    {
        return Err(RedisRateLimitConfigError::InvalidPolicy);
    }
    Ok(millis)
}

fn retry_after(millis: i64) -> Result<Duration, RateLimitError> {
    let millis = u64::try_from(millis).map_err(|_| RateLimitError::Unavailable)?;
    if millis == 0 {
        return Err(RateLimitError::Unavailable);
    }
    Ok(Duration::from_millis(millis))
}

fn hash_key(key: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(key);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_namespace(namespace: &str) -> Result<(), RedisRateLimitConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RedisRateLimitConfigError::InvalidNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RATE_LIMIT_SCRIPT;

    #[test]
    fn rate_limit_script_checks_counter_length_before_get() {
        let length_check = RATE_LIMIT_SCRIPT
            .find("STRLEN")
            .expect("rate-limit script must check counter length");
        let get = RATE_LIMIT_SCRIPT
            .find("'GET'")
            .expect("rate-limit script must retrieve an accepted counter");
        assert!(length_check < get);
        assert!(RATE_LIMIT_SCRIPT.contains("tonumber(ARGV[5])"));
        assert!(RATE_LIMIT_SCRIPT.contains("return {-2, 0, 0}"));
    }
}
