use secure_auth_server::{
    InMemoryRateLimiter, RateLimitDecision, RateLimitError, RateLimitPolicy, RateLimiter,
    MAX_IN_MEMORY_RATE_KEYS, MAX_RATE_LIMIT_KEY_BYTES,
};
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[test]
fn rate_limiter_allows_bounded_attempts_and_resets_after_window() {
    let policy = RateLimitPolicy::new(2, Duration::from_secs(10)).unwrap();
    let limiter = InMemoryRateLimiter::new(4, policy).unwrap();
    let start = Instant::now();

    assert_eq!(
        limiter.check_at(b"account:1", start),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    );
    assert_eq!(
        limiter.check_at(b"account:1", start),
        Ok(RateLimitDecision::Allowed { remaining: 0 })
    );
    assert_eq!(
        limiter.check_at(b"account:1", start),
        Ok(RateLimitDecision::Limited {
            retry_after: Duration::from_secs(10)
        })
    );
    assert_eq!(
        limiter.check_at(b"account:1", start + Duration::from_secs(10)),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    );
}

#[test]
fn rate_limiter_bounds_keys_and_capacity() {
    assert!(matches!(
        RateLimitPolicy::new(0, Duration::from_secs(1)),
        Err(RateLimitError::InvalidPolicy)
    ));
    assert!(matches!(
        InMemoryRateLimiter::new(
            MAX_IN_MEMORY_RATE_KEYS + 1,
            RateLimitPolicy::new(1, Duration::from_secs(1)).unwrap()
        ),
        Err(RateLimitError::InvalidCapacity)
    ));

    let limiter =
        InMemoryRateLimiter::new(1, RateLimitPolicy::new(1, Duration::from_secs(1)).unwrap())
            .unwrap();
    let now = Instant::now();
    assert!(matches!(
        limiter.check_at(&[], now),
        Err(RateLimitError::InvalidKey)
    ));
    assert!(matches!(
        limiter.check_at(&vec![0u8; MAX_RATE_LIMIT_KEY_BYTES + 1], now),
        Err(RateLimitError::InvalidKey)
    ));
    assert_eq!(
        limiter.check_at(b"first", now),
        Ok(RateLimitDecision::Allowed { remaining: 0 })
    );
    assert!(matches!(
        limiter.check_at(b"second", now),
        Err(RateLimitError::CapacityReached)
    ));
}

#[test]
fn rate_limiter_is_atomic_for_concurrent_attempts() {
    let limiter = Arc::new(
        InMemoryRateLimiter::new(4, RateLimitPolicy::new(2, Duration::from_secs(10)).unwrap())
            .unwrap(),
    );
    let start = Instant::now();

    thread::scope(|scope| {
        let results = (0..16)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                scope.spawn(move || limiter.check_at(b"ip:1", start))
            })
            .collect::<Vec<_>>();
        let allowed = results
            .into_iter()
            .map(|result| result.join().unwrap())
            .filter(|result| matches!(result, Ok(RateLimitDecision::Allowed { .. })))
            .count();
        assert_eq!(allowed, 2);
    });
}

#[test]
fn rate_limiter_exposes_a_shared_backend_contract() {
    fn check_backend(backend: &impl RateLimiter) -> RateLimitDecision {
        backend.check(b"deployment").unwrap()
    }

    let limiter =
        InMemoryRateLimiter::new(1, RateLimitPolicy::new(1, Duration::from_secs(1)).unwrap())
            .unwrap();
    assert_eq!(
        check_backend(&limiter),
        RateLimitDecision::Allowed { remaining: 0 }
    );
}
