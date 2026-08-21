#[cfg(feature = "postgres-backend")]
use secure_auth_server::PostgresRateLimitConfigError;
#[cfg(feature = "redis-backend")]
use secure_auth_server::RedisRateLimitConfigError;
#[cfg(any(feature = "redis-backend", feature = "postgres-backend"))]
use secure_auth_server::{RateLimitDecision, RateLimitPolicy, RateLimiter};

#[cfg(feature = "redis-backend")]
#[test]
fn redis_configuration_fails_closed_by_default() {
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(10)).unwrap();
    assert!(matches!(
        secure_auth_server::RedisRateLimiter::from_url(
            "redis://127.0.0.1:6379",
            "test",
            4,
            4,
            policy,
        ),
        Err(RedisRateLimitConfigError::InsecureUrl)
    ));
    assert!(matches!(
        secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
            "redis://127.0.0.1:6379",
            "test:unsafe",
            4,
            4,
            policy,
        ),
        Err(RedisRateLimitConfigError::InvalidNamespace)
    ));
    let long_policy =
        RateLimitPolicy::new(1, std::time::Duration::from_secs(7 * 24 * 60 * 60 + 1)).unwrap();
    assert!(matches!(
        secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
            "redis://127.0.0.1:6379",
            "test",
            4,
            4,
            long_policy,
        ),
        Err(RedisRateLimitConfigError::InvalidPolicy)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_configuration_is_bounded() {
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(10)).unwrap();
    let config = "host=127.0.0.1 user=postgres"
        .parse()
        .expect("valid postgres config");
    assert!(matches!(
        secure_auth_server::PostgresRateLimiter::from_config_for_local_testing(
            config, "test", 4, 0, policy,
        ),
        Err(PostgresRateLimitConfigError::InvalidCapacity)
    ));
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_rate_limit_check_is_atomic_and_fixed_window() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = if url.starts_with("rediss://") {
        secure_auth_server::RedisRateLimiter::from_url(&url, &namespace, 4, 4, policy)
    } else {
        secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
            &url, &namespace, 4, 4, policy,
        )
    }
    .expect("Redis limiter should construct");

    assert_eq!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    );
    assert_eq!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Allowed { remaining: 0 })
    );
    assert!(matches!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Limited { retry_after }) if retry_after > std::time::Duration::ZERO
    ));

    let concurrent_namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let concurrent = std::sync::Arc::new(
        if url.starts_with("rediss://") {
            secure_auth_server::RedisRateLimiter::from_url(
                &url,
                &concurrent_namespace,
                4,
                8,
                policy,
            )
        } else {
            secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
                &url,
                &concurrent_namespace,
                4,
                8,
                policy,
            )
        }
        .expect("concurrent Redis limiter should construct"),
    );
    let results = (0..16)
        .map(|_| {
            let limiter = std::sync::Arc::clone(&concurrent);
            std::thread::spawn(move || limiter.check(b"concurrent-account"))
        })
        .map(|thread| thread.join().expect("Redis worker should join"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(RateLimitDecision::Allowed { .. })))
            .count(),
        2
    );

    let capacity_namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let capacity = if url.starts_with("rediss://") {
        secure_auth_server::RedisRateLimiter::from_url(&url, &capacity_namespace, 4, 1, policy)
    } else {
        secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
            &url,
            &capacity_namespace,
            4,
            1,
            policy,
        )
    }
    .expect("capacity Redis limiter should construct");
    assert!(matches!(
        capacity.check(b"first"),
        Ok(RateLimitDecision::Allowed { .. })
    ));
    assert_eq!(
        capacity.check(b"second"),
        Err(secure_auth_server::RateLimitError::CapacityReached)
    );
}

#[cfg(feature = "postgres-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_POSTGRES_URL and an isolated PostgreSQL service"]
fn postgres_rate_limit_check_is_atomic_and_fixed_window() {
    let url = std::env::var("SECURE_KEYPAD_POSTGRES_URL").expect("PostgreSQL URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let mut migration = postgres::Client::connect(&url, postgres::NoTls)
        .expect("PostgreSQL should accept the test connection");
    migration
        .batch_execute(secure_auth_server::POSTGRES_RATE_LIMIT_SCHEMA_SQL)
        .expect("PostgreSQL rate-limit schema should apply");
    let config = url.parse().expect("PostgreSQL config should parse");
    let limiter = secure_auth_server::PostgresRateLimiter::from_config_for_local_testing(
        config, &namespace, 4, 4, policy,
    )
    .expect("PostgreSQL limiter should construct");

    assert_eq!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    );
    assert_eq!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Allowed { remaining: 0 })
    );
    assert!(matches!(
        limiter.check(b"account-ci"),
        Ok(RateLimitDecision::Limited { retry_after }) if retry_after > std::time::Duration::ZERO
    ));

    let concurrent_namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let concurrent = std::sync::Arc::new(
        secure_auth_server::PostgresRateLimiter::from_config_for_local_testing(
            url.parse().expect("PostgreSQL config should parse"),
            &concurrent_namespace,
            4,
            8,
            policy,
        )
        .expect("concurrent PostgreSQL limiter should construct"),
    );
    let results = (0..16)
        .map(|_| {
            let limiter = std::sync::Arc::clone(&concurrent);
            std::thread::spawn(move || limiter.check(b"concurrent-account"))
        })
        .map(|thread| thread.join().expect("PostgreSQL worker should join"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(RateLimitDecision::Allowed { .. })))
            .count(),
        2
    );

    let capacity_namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let capacity = secure_auth_server::PostgresRateLimiter::from_config_for_local_testing(
        url.parse().expect("PostgreSQL config should parse"),
        &capacity_namespace,
        4,
        1,
        policy,
    )
    .expect("capacity PostgreSQL limiter should construct");
    assert!(matches!(
        capacity.check(b"first"),
        Ok(RateLimitDecision::Allowed { .. })
    ));
    assert_eq!(
        capacity.check(b"second"),
        Err(secure_auth_server::RateLimitError::CapacityReached)
    );
}
