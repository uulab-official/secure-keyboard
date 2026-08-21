use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Maximum number of active keys held by the in-memory reference limiter.
pub const MAX_IN_MEMORY_RATE_KEYS: usize = 100_000;
/// Maximum size of a single account, IP, or deployment rate-limit key.
pub const MAX_RATE_LIMIT_KEY_BYTES: usize = 256;
/// Maximum fixed-window duration accepted by distributed adapters.
///
/// Keeping the window bounded preserves millisecond precision in Redis Lua
/// scores and prevents an accidental multi-year key retention policy.
pub const MAX_DISTRIBUTED_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Fixed-window rate-limit configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitPolicy {
    max_attempts: u32,
    window: Duration,
}

impl RateLimitPolicy {
    /// Creates a policy with a positive attempt count and non-zero window.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::InvalidPolicy`] for a zero attempt count or
    /// zero window.
    pub fn new(max_attempts: u32, window: Duration) -> Result<Self, RateLimitError> {
        if max_attempts == 0 || window.is_zero() {
            return Err(RateLimitError::InvalidPolicy);
        }
        Ok(Self {
            max_attempts,
            window,
        })
    }

    /// Returns the maximum attempts allowed in one window.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Returns the fixed window duration.
    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }
}

/// Errors produced by a rate-limit configuration or backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitError {
    /// The attempt/window policy is not enforceable.
    InvalidPolicy,
    /// The active-key capacity is outside the supported bound.
    InvalidCapacity,
    /// A key is empty or exceeds [`MAX_RATE_LIMIT_KEY_BYTES`].
    InvalidKey,
    /// The limiter cannot retain a new key without exceeding its bound.
    CapacityReached,
    /// The process-local limiter lock is poisoned.
    Unavailable,
}

impl core::fmt::Display for RateLimitError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid rate limit policy",
            Self::InvalidCapacity => "invalid rate limit capacity",
            Self::InvalidKey => "invalid rate limit key",
            Self::CapacityReached => "rate limit capacity reached",
            Self::Unavailable => "rate limiter unavailable",
        })
    }
}

impl std::error::Error for RateLimitError {}

/// Result of a single rate-limit check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    /// The attempt is allowed and this many attempts remain in the window.
    Allowed {
        /// Number of attempts remaining in the current window.
        remaining: u32,
    },
    /// The attempt is denied until the returned duration elapses.
    Limited {
        /// Minimum duration before a new attempt may be accepted.
        retry_after: Duration,
    },
}

/// Backend contract for an atomic rate-limit check.
///
/// A distributed Redis/database implementation must make the check-and-count
/// operation atomic and return the same decision semantics. It must also bound
/// key size and avoid logging keys or authentication payloads.
pub trait RateLimiter {
    /// Checks and, when allowed, counts one attempt for a key.
    ///
    /// # Errors
    ///
    /// Returns a key, capacity, or backend availability error.
    fn check(&self, key: &[u8]) -> Result<RateLimitDecision, RateLimitError>;
}

struct WindowEntry {
    started_at: Instant,
    attempts: u32,
}

/// Bounded, process-local fixed-window rate limiter.
///
/// Instantiate separate limiters or namespace keys for account, IP, and
/// deployment-wide controls. This reference implementation is atomic within
/// one process; a multi-instance deployment must use a shared atomic backend
/// with equivalent `check` semantics.
pub struct InMemoryRateLimiter {
    entries: Mutex<HashMap<Vec<u8>, WindowEntry>>,
    max_keys: usize,
    policy: RateLimitPolicy,
}

impl InMemoryRateLimiter {
    /// Creates a bounded in-memory limiter.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::InvalidCapacity`] when `max_keys` is zero or
    /// exceeds [`MAX_IN_MEMORY_RATE_KEYS`].
    pub fn new(max_keys: usize, policy: RateLimitPolicy) -> Result<Self, RateLimitError> {
        if max_keys == 0 || max_keys > MAX_IN_MEMORY_RATE_KEYS {
            return Err(RateLimitError::InvalidCapacity);
        }
        Ok(Self {
            entries: Mutex::new(HashMap::with_capacity(max_keys.min(1024))),
            max_keys,
            policy,
        })
    }

    /// Checks a key using the process monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns a key, capacity, or backend availability error.
    pub fn check(&self, key: &[u8]) -> Result<RateLimitDecision, RateLimitError> {
        self.check_at(key, Instant::now())
    }

    /// Checks a key at a supplied monotonic instant.
    ///
    /// This is useful for deterministic tests and an application-controlled
    /// monotonic clock. Production callers should normally use [`Self::check`].
    ///
    /// # Errors
    ///
    /// Returns a key, capacity, or backend availability error.
    pub fn check_at(&self, key: &[u8], now: Instant) -> Result<RateLimitDecision, RateLimitError> {
        validate_key(key)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RateLimitError::Unavailable)?;
        let policy = self.policy;

        entries.retain(|_, entry| {
            now.checked_duration_since(entry.started_at)
                .is_none_or(|elapsed| elapsed < policy.window)
        });

        if let Some(entry) = entries.get_mut(key) {
            let elapsed = now
                .checked_duration_since(entry.started_at)
                .unwrap_or_default();
            if elapsed >= policy.window {
                entry.started_at = now;
                entry.attempts = 1;
                return Ok(RateLimitDecision::Allowed {
                    remaining: policy.max_attempts - 1,
                });
            }
            if entry.attempts >= policy.max_attempts {
                return Ok(RateLimitDecision::Limited {
                    retry_after: policy.window.saturating_sub(elapsed),
                });
            }
            entry.attempts += 1;
            return Ok(RateLimitDecision::Allowed {
                remaining: policy.max_attempts - entry.attempts,
            });
        }

        if entries.len() >= self.max_keys {
            return Err(RateLimitError::CapacityReached);
        }
        entries.insert(
            key.to_vec(),
            WindowEntry {
                started_at: now,
                attempts: 1,
            },
        );
        Ok(RateLimitDecision::Allowed {
            remaining: policy.max_attempts - 1,
        })
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check(&self, key: &[u8]) -> Result<RateLimitDecision, RateLimitError> {
        InMemoryRateLimiter::check(self, key)
    }
}

fn validate_key(key: &[u8]) -> Result<(), RateLimitError> {
    if key.is_empty() || key.len() > MAX_RATE_LIMIT_KEY_BYTES {
        return Err(RateLimitError::InvalidKey);
    }
    Ok(())
}
