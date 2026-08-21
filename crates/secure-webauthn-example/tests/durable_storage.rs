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
    let handle = store
        .insert(
            CeremonyKind::Registration,
            user_id,
            br#"{"version":1,"state":{}}"#,
            std::time::Duration::from_secs(30),
        )
        .expect("PostgreSQL insert should succeed");
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
