use secure_webauthn_example::{CeremonyKind, CeremonyStateStore};

#[cfg(feature = "postgres-backend")]
use secure_webauthn_example::PostgresStorageConfigError;

#[cfg(feature = "redis-backend")]
use secure_webauthn_example::RedisStorageConfigError;

#[cfg(feature = "redis-backend")]
#[test]
fn redis_configuration_fails_closed_by_default() {
    assert!(matches!(
        secure_webauthn_example::RedisWebAuthnStore::from_url("redis://127.0.0.1:6379", "test", 4,),
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
        secure_webauthn_example::RedisWebAuthnStore::from_url(&url, &namespace, 4)
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
