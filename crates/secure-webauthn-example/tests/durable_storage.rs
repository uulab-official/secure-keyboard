#[cfg(any(feature = "redis-backend", feature = "postgres-backend"))]
use secure_webauthn_example::{CeremonyKind, CeremonyStateStore};

#[cfg(feature = "redis-backend")]
use std::fmt::Write as _;

#[cfg(feature = "postgres-backend")]
use secure_webauthn_example::PostgresStorageConfigError;

#[cfg(feature = "redis-backend")]
use secure_webauthn_example::RedisStorageConfigError;

#[cfg(feature = "redis-backend")]
#[test]
fn redis_configuration_fails_closed_by_default() {
    assert!(matches!(
        secure_webauthn_example::RedisWebAuthnStore::from_url(
            "redis://127.0.0.1:6379",
            "test",
            4,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        ),
        Err(RedisStorageConfigError::InsecureUrl)
    ));
    assert!(matches!(
        secure_webauthn_example::RedisWebAuthnStore::from_insecure_url_for_local_testing(
            "redis://127.0.0.1:6379",
            "test:unsafe",
            4,
        ),
        Err(RedisStorageConfigError::InvalidNamespace)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_configuration_is_bounded() {
    let config = "host=127.0.0.1 user=postgres"
        .parse()
        .expect("valid config");
    assert!(matches!(
        secure_webauthn_example::PostgresWebAuthnStore::from_config_for_local_testing(
            config, "test", 0,
        ),
        Err(PostgresStorageConfigError::InvalidPoolSize)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_production_configuration_requires_tls() {
    let config = "host=127.0.0.1 user=postgres"
        .parse()
        .expect("valid config");
    assert!(matches!(
        secure_webauthn_example::PostgresWebAuthnStore::from_config(
            config,
            postgres::NoTls,
            "test",
            4,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        ),
        Err(PostgresStorageConfigError::InsecureConfig)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_production_configuration_rejects_no_tls_with_required_sslmode() {
    let config = "host=127.0.0.1 user=postgres sslmode=require"
        .parse()
        .expect("valid config");
    assert!(matches!(
        secure_webauthn_example::PostgresWebAuthnStore::from_config(
            config,
            postgres::NoTls,
            "test",
            4,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        ),
        Err(PostgresStorageConfigError::InsecureConfig)
    ));
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_ceremony_state_is_atomic_and_one_time() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let store = if url.starts_with("rediss://") {
        secure_webauthn_example::RedisWebAuthnStore::from_url(
            &url,
            &namespace,
            4,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        )
    } else {
        secure_webauthn_example::RedisWebAuthnStore::from_insecure_url_for_local_testing(
            &url, &namespace, 4,
        )
    }
    .expect("Redis store should construct");
    let user_id = uuid::Uuid::new_v4();
    let handle = store
        .insert(
            CeremonyKind::Registration,
            user_id,
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("Redis insert should succeed");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    let pending_index = format!("{namespace}:webauthn:v1:pending");
    let pending_count: i64 = redis::cmd("ZCARD")
        .arg(&pending_index)
        .query(&mut inspection)
        .expect("Redis pending count should succeed");
    assert_eq!(pending_count, 1);
    assert!(store
        .take(CeremonyKind::Authentication, &handle)
        .expect("Redis kind lookup should succeed")
        .is_none());
    assert_eq!(
        store
            .take(CeremonyKind::Registration, &handle)
            .expect("Redis consume should succeed")
            .expect("Redis state should exist")
            .user_id(),
        user_id
    );
    let pending_count: i64 = redis::cmd("ZCARD")
        .arg(&pending_index)
        .query(&mut inspection)
        .expect("Redis pending count after consume should succeed");
    assert_eq!(pending_count, 0);
    assert!(store
        .take(CeremonyKind::Registration, &handle)
        .expect("Redis replay lookup should succeed")
        .is_none());
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_ceremony_ttl_drift_is_removed_before_materialization() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let store = if url.starts_with("rediss://") {
        secure_webauthn_example::RedisWebAuthnStore::from_url(
            &url,
            &namespace,
            2,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        )
    } else {
        secure_webauthn_example::RedisWebAuthnStore::from_insecure_url_for_local_testing(
            &url, &namespace, 2,
        )
    }
    .expect("Redis store should construct");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    let pending_index = format!("{namespace}:webauthn:v1:pending");

    let missing_ttl_handle = store
        .insert(
            CeremonyKind::Authentication,
            uuid::Uuid::new_v4(),
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("Redis insert should succeed");
    let mut missing_ttl_handle_hex = String::with_capacity(64);
    for byte in missing_ttl_handle.as_bytes() {
        let _ = write!(missing_ttl_handle_hex, "{byte:02x}");
    }
    let missing_ttl_key =
        format!("{namespace}:webauthn:v1:authentication:{missing_ttl_handle_hex}");
    redis::cmd("PERSIST")
        .arg(&missing_ttl_key)
        .query::<()>(&mut inspection)
        .expect("Redis PERSIST should succeed");
    assert!(matches!(
        store.take(CeremonyKind::Authentication, &missing_ttl_handle),
        Err(secure_webauthn_example::CeremonyStoreError::Unavailable)
    ));
    let missing_exists: i64 = redis::cmd("EXISTS")
        .arg(&missing_ttl_key)
        .query(&mut inspection)
        .expect("Redis missing-TTL key check should succeed");
    let missing_pending: i64 = redis::cmd("ZCARD")
        .arg(&pending_index)
        .query(&mut inspection)
        .expect("Redis missing-TTL pending index check should succeed");
    assert_eq!(missing_exists, 0);
    assert_eq!(missing_pending, 0);

    let over_bound_handle = store
        .insert(
            CeremonyKind::Authentication,
            uuid::Uuid::new_v4(),
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("Redis second insert should succeed");
    let mut over_bound_handle_hex = String::with_capacity(64);
    for byte in over_bound_handle.as_bytes() {
        let _ = write!(over_bound_handle_hex, "{byte:02x}");
    }
    let over_bound_key = format!("{namespace}:webauthn:v1:authentication:{over_bound_handle_hex}");
    redis::cmd("PEXPIRE")
        .arg(&over_bound_key)
        .arg(secure_webauthn_example::MAX_CEREMONY_TTL.as_millis() as u64 + 1)
        .query::<()>(&mut inspection)
        .expect("Redis over-bound PEXPIRE should succeed");
    assert!(matches!(
        store.take(CeremonyKind::Authentication, &over_bound_handle),
        Err(secure_webauthn_example::CeremonyStoreError::Unavailable)
    ));
    let over_bound_exists: i64 = redis::cmd("EXISTS")
        .arg(&over_bound_key)
        .query(&mut inspection)
        .expect("Redis over-bound key check should succeed");
    let over_bound_pending: i64 = redis::cmd("ZCARD")
        .arg(&pending_index)
        .query(&mut inspection)
        .expect("Redis over-bound pending index check should succeed");
    assert_eq!(over_bound_exists, 0);
    assert_eq!(over_bound_pending, 0);
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_oversized_ceremony_value_is_removed_before_materialization() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let store = if url.starts_with("rediss://") {
        secure_webauthn_example::RedisWebAuthnStore::from_url(
            &url,
            &namespace,
            2,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        )
    } else {
        secure_webauthn_example::RedisWebAuthnStore::from_insecure_url_for_local_testing(
            &url, &namespace, 2,
        )
    }
    .expect("Redis store should construct");
    let handle = store
        .insert(
            CeremonyKind::Authentication,
            uuid::Uuid::new_v4(),
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("Redis insert should succeed");
    let mut handle_hex = String::with_capacity(64);
    for byte in handle.as_bytes() {
        let _ = write!(handle_hex, "{byte:02x}");
    }
    let key = format!("{namespace}:webauthn:v1:authentication:{handle_hex}");
    let pending_index = format!("{namespace}:webauthn:v1:pending");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("SET")
        .arg(&key)
        .arg(vec![
            0x55u8;
            secure_webauthn_example::MAX_PROTECTED_CEREMONY_RECORD_BYTES
                + 1
        ])
        .query::<()>(&mut inspection)
        .expect("Redis oversized record should be writable for the migration test");
    assert!(matches!(
        store.take(CeremonyKind::Authentication, &handle),
        Err(secure_webauthn_example::CeremonyStoreError::Unavailable)
    ));
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&key)
        .query(&mut inspection)
        .expect("Redis key existence check should succeed");
    let pending_count: i64 = redis::cmd("ZCARD")
        .arg(&pending_index)
        .query(&mut inspection)
        .expect("Redis pending index check should succeed");
    assert_eq!(exists, 0);
    assert_eq!(pending_count, 0);
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_REDIS_URL and an isolated Redis service"]
fn redis_oversized_credential_value_fails_closed_before_json_decode() {
    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").expect("Redis URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let store = if url.starts_with("rediss://") {
        secure_webauthn_example::RedisWebAuthnStore::from_url(
            &url,
            &namespace,
            2,
            secure_webauthn_example::WebAuthnStateKey::generate(),
        )
    } else {
        secure_webauthn_example::RedisWebAuthnStore::from_insecure_url_for_local_testing(
            &url, &namespace, 2,
        )
    }
    .expect("Redis store should construct");
    let user_id = uuid::Uuid::new_v4();
    let key = format!("{namespace}:webauthn:v1:credentials:{user_id}");
    let mut inspection = redis::Client::open(url.as_str())
        .expect("Redis inspection client should construct")
        .get_connection()
        .expect("Redis inspection connection should succeed");
    redis::cmd("SET")
        .arg(&key)
        .arg(vec![
            0x55u8;
            secure_webauthn_example::MAX_CREDENTIAL_RECORD_BYTES + 1
        ])
        .query::<()>(&mut inspection)
        .expect("Redis oversized credential should be writable for the migration test");
    assert!(matches!(
        secure_webauthn_example::CredentialStore::load(&store, user_id),
        Err(secure_webauthn_example::CredentialStoreError::InvalidRecord)
    ));
    redis::cmd("DEL")
        .arg(&key)
        .query::<()>(&mut inspection)
        .expect("Redis oversized credential cleanup should succeed");
}

#[cfg(feature = "postgres-backend")]
#[test]
#[ignore = "requires SECURE_KEYPAD_POSTGRES_URL and an isolated PostgreSQL service"]
fn postgres_ceremony_state_is_atomic_and_one_time() {
    let url = std::env::var("SECURE_KEYPAD_POSTGRES_URL").expect("PostgreSQL URL is required");
    let namespace = format!("ci{}", uuid::Uuid::new_v4().simple());
    let mut migration = postgres::Client::connect(&url, postgres::NoTls)
        .expect("PostgreSQL should accept the test connection");
    migration
        .batch_execute(secure_webauthn_example::POSTGRES_SCHEMA_SQL)
        .expect("PostgreSQL schema should apply");
    let config = url.parse().expect("PostgreSQL config should parse");
    let store = secure_webauthn_example::PostgresWebAuthnStore::from_config_for_local_testing(
        config, &namespace, 4,
    )
    .expect("PostgreSQL store should construct");
    let user_id = uuid::Uuid::new_v4();
    let expired = store
        .insert(
            CeremonyKind::Authentication,
            user_id,
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_millis(1),
        )
        .expect("PostgreSQL expired insert should succeed");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let handle = store
        .insert(
            CeremonyKind::Registration,
            user_id,
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("PostgreSQL insert should succeed");
    let mut inspection = postgres::Client::connect(&url, postgres::NoTls)
        .expect("PostgreSQL inspection connection should succeed");
    let pending_count: i64 = inspection
        .query_one(
            "SELECT count(*) FROM secure_keypad_webauthn_ceremonies WHERE namespace = $1",
            &[&namespace],
        )
        .expect("PostgreSQL pending count should succeed")
        .get(0);
    assert_eq!(pending_count, 1);
    assert!(store
        .take(CeremonyKind::Authentication, &expired)
        .expect("expired PostgreSQL lookup should succeed")
        .is_none());
    assert!(store
        .take(CeremonyKind::Authentication, &handle)
        .expect("PostgreSQL kind lookup should succeed")
        .is_none());
    assert_eq!(
        store
            .take(CeremonyKind::Registration, &handle)
            .expect("PostgreSQL consume should succeed")
            .expect("PostgreSQL state should exist")
            .user_id(),
        user_id
    );
    assert!(store
        .take(CeremonyKind::Registration, &handle)
        .expect("PostgreSQL replay lookup should succeed")
        .is_none());
}
