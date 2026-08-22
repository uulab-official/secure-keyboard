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

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_production_configuration_requires_tls() {
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(10)).unwrap();
    let config = "host=127.0.0.1 user=postgres"
        .parse()
        .expect("valid postgres config");
    assert!(matches!(
        secure_auth_server::PostgresRateLimiter::from_config(
            config,
            postgres::NoTls,
            "test",
            4,
            4,
            policy,
        ),
        Err(PostgresRateLimitConfigError::InsecureConfig)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_production_configuration_rejects_no_tls_with_required_sslmode() {
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(10)).unwrap();
    let config = "host=127.0.0.1 user=postgres sslmode=require"
        .parse()
        .expect("valid postgres config");
    assert!(matches!(
        secure_auth_server::PostgresRateLimiter::from_config(
            config,
            postgres::NoTls,
            "test",
            4,
            4,
            policy,
        ),
        Err(PostgresRateLimitConfigError::InsecureConfig)
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

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_oversized_counter_is_removed_before_lua_get() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 4, policy,
    )
    .expect("Redis limiter should construct");
    let key = b"oversized-counter";
    let digest = {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(key);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    };
    let counter_key = format!("{namespace}:ratelimit:v1:key:{digest}");
    let index_key = format!("{namespace}:ratelimit:v1:index");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("SET")
        .arg(&counter_key)
        .arg(vec![b'9'; 33])
        .query::<()>(&mut inspection)
        .expect("Redis oversized counter should be writable for the migration test");
    redis::cmd("ZADD")
        .arg(&index_key)
        .arg(9_999_999_999_999_i64)
        .arg(&digest)
        .query::<()>(&mut inspection)
        .expect("Redis active-key index seed should succeed");
    assert_eq!(
        limiter.check(key),
        Err(secure_auth_server::RateLimitError::Unavailable)
    );
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&counter_key)
        .query(&mut inspection)
        .expect("Redis counter existence check should succeed");
    let indexed: Option<f64> = redis::cmd("ZSCORE")
        .arg(&index_key)
        .arg(&digest)
        .query(&mut inspection)
        .expect("Redis active-key index check should succeed");
    assert_eq!(exists, 0);
    assert_eq!(indexed, None);
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_wrong_type_counter_is_removed_before_string_operations() {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 1, policy,
    )
    .expect("Redis limiter should construct");
    let key = b"wrong-type-counter";
    let digest = Sha256::digest(key);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    let counter_key = format!("{namespace}:ratelimit:v1:key:{encoded}");
    let index_key = format!("{namespace}:ratelimit:v1:index");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("SADD")
        .arg(&counter_key)
        .arg("poisoned")
        .query::<i64>(&mut inspection)
        .expect("Redis wrong-type counter should be writable for the migration test");
    redis::cmd("ZADD")
        .arg(&index_key)
        .arg(9_999_999_999_999_i64)
        .arg(&encoded)
        .query::<()>(&mut inspection)
        .expect("Redis active-key index seed should succeed");

    assert_eq!(
        limiter.check(key),
        Err(secure_auth_server::RateLimitError::Unavailable)
    );
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&counter_key)
        .query(&mut inspection)
        .expect("Redis counter existence check should succeed");
    let indexed: Option<f64> = redis::cmd("ZSCORE")
        .arg(&index_key)
        .arg(&encoded)
        .query(&mut inspection)
        .expect("Redis active-key index check should succeed");
    assert_eq!(exists, 0);
    assert_eq!(indexed, None);
    assert_eq!(
        limiter.check(key),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    );
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_wrong_type_active_index_is_repaired_before_sorted_set_operations() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 1, policy,
    )
    .expect("Redis limiter should construct");
    let index_key = format!("{namespace}:ratelimit:v1:index");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("SADD")
        .arg(&index_key)
        .arg("poisoned")
        .query::<i64>(&mut inspection)
        .expect("Redis wrong-type active index should be writable for the migration test");

    assert_eq!(
        limiter.check(b"repaired-index"),
        Err(secure_auth_server::RateLimitError::Unavailable)
    );
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&index_key)
        .query(&mut inspection)
        .expect("Redis active-index existence check should succeed");
    assert_eq!(exists, 0);
    assert!(matches!(
        limiter.check(b"repaired-index"),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    ));
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_repairs_missing_active_index_and_rejects_counter_ttl_drift() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 1, policy,
    )
    .expect("Redis limiter should construct");
    let key = b"index-repair";
    assert!(matches!(
        limiter.check(key),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
    ));

    let digest = {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        Sha256::digest(key)
            .iter()
            .flat_map(|byte| {
                [
                    HEX[(byte >> 4) as usize] as char,
                    HEX[(byte & 0x0f) as usize] as char,
                ]
            })
            .collect::<String>()
    };
    let counter_key = format!("{namespace}:ratelimit:v1:key:{digest}");
    let index_key = format!("{namespace}:ratelimit:v1:index");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("DEL")
        .arg(&index_key)
        .query::<()>(&mut inspection)
        .expect("Redis active-key index should be deletable for the migration test");

    assert!(matches!(
        limiter.check(key),
        Ok(RateLimitDecision::Allowed { remaining: 0 })
    ));
    assert_eq!(
        limiter.check(b"second-key"),
        Err(secure_auth_server::RateLimitError::CapacityReached)
    );

    redis::cmd("PEXPIRE")
        .arg(&counter_key)
        .arg(60_000)
        .query::<()>(&mut inspection)
        .expect("Redis counter TTL should be writable for the migration test");
    assert_eq!(
        limiter.check(key),
        Err(secure_auth_server::RateLimitError::Unavailable)
    );
    let counter_exists: i64 = redis::cmd("EXISTS")
        .arg(&counter_key)
        .query(&mut inspection)
        .expect("Redis counter existence check should succeed");
    assert_eq!(counter_exists, 0);
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_poisoned_counter_is_removed_before_increment_or_limited_response() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 4, policy,
    )
    .expect("Redis limiter should construct");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");

    for (key, value) in [
        (b"fractional-counter".as_slice(), "1.0"),
        (b"persistent-limited".as_slice(), "2"),
    ] {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(key);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        let counter_key = format!("{namespace}:ratelimit:v1:key:{encoded}");
        let index_key = format!("{namespace}:ratelimit:v1:index");
        redis::cmd("SET")
            .arg(&counter_key)
            .arg(value)
            .query::<()>(&mut inspection)
            .expect("Redis poisoned counter should be writable for the migration test");
        redis::cmd("ZADD")
            .arg(&index_key)
            .arg(9_999_999_999_999_i64)
            .arg(&encoded)
            .query::<()>(&mut inspection)
            .expect("Redis active-key index seed should succeed");

        assert_eq!(
            limiter.check(key),
            Err(secure_auth_server::RateLimitError::Unavailable)
        );
        let exists: i64 = redis::cmd("EXISTS")
            .arg(&counter_key)
            .query(&mut inspection)
            .expect("Redis counter existence check should succeed");
        let indexed: Option<f64> = redis::cmd("ZSCORE")
            .arg(&index_key)
            .arg(&encoded)
            .query(&mut inspection)
            .expect("Redis active-key index check should succeed");
        assert_eq!(exists, 0);
        assert_eq!(indexed, None);
    }
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_missing_counter_releases_active_key_capacity() {
    use sha2::{Digest, Sha256};

    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let policy = RateLimitPolicy::new(2, std::time::Duration::from_secs(30)).unwrap();
    let limiter = secure_auth_server::RedisRateLimiter::from_insecure_url_for_local_testing(
        &url, &namespace, 2, 1, policy,
    )
    .expect("Redis limiter should construct");
    let key = b"evicted-counter";
    let digest = {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(key);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    };
    let index_key = format!("{namespace}:ratelimit:v1:index");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("ZADD")
        .arg(&index_key)
        .arg(9_999_999_999_999_i64)
        .arg(&digest)
        .query::<()>(&mut inspection)
        .expect("Redis stale active-key index seed should succeed");

    assert_eq!(
        limiter.check(key),
        Ok(RateLimitDecision::Allowed { remaining: 1 })
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
