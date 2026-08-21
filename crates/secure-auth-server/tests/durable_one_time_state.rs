use secure_auth::ServerLoginStateBytes;
use secure_auth_server::{BoundLoginState, OpaqueStateKey};
use std::time::Duration;

fn fixture_state() -> BoundLoginState {
    BoundLoginState::new(
        ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
        b"fixture-client",
        b"fixture-server",
    )
    .unwrap()
}

fn fixture_key() -> OpaqueStateKey {
    OpaqueStateKey::from_bytes(&[0x42u8; 32]).unwrap()
}

#[cfg(feature = "redis-backend")]
#[test]
fn redis_configuration_rejects_plaintext_in_production_constructor() {
    assert!(matches!(
        secure_auth_server::RedisOneTimeLoginStateStore::from_url(
            "redis://127.0.0.1:6379",
            "fixture-opaque",
            1,
            8,
            Duration::from_secs(30),
            fixture_key(),
        ),
        Err(secure_auth_server::RedisOneTimeStateConfigError::InsecureUrl)
    ));
}

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_configuration_rejects_non_tls_production_config() {
    let config: postgres::Config = "host=127.0.0.1 port=5432 user=postgres".parse().unwrap();
    assert!(matches!(
        secure_auth_server::PostgresOneTimeLoginStateStore::from_config(
            config,
            r2d2_postgres::postgres::NoTls,
            "fixture-opaque",
            1,
            8,
            Duration::from_secs(30),
            fixture_key(),
        ),
        Err(secure_auth_server::PostgresOneTimeStateConfigError::InsecureConfig)
    ));
}

#[cfg(feature = "redis-backend")]
#[test]
#[ignore = "requires an isolated Redis service"]
fn redis_state_is_consumed_atomically_once() {
    use secure_auth_server::{BoundOneTimeLoginStateStore, RedisOneTimeLoginStateStore};
    use std::sync::Arc;
    use std::thread;

    let url = std::env::var("SECURE_KEYPAD_REDIS_URL").unwrap();
    let store = Arc::new(
        RedisOneTimeLoginStateStore::from_insecure_url_for_local_testing(
            &url,
            &format!("opaque-test-{}", std::process::id()),
            4,
            8,
            Duration::from_secs(30),
            fixture_key(),
        )
        .unwrap(),
    );
    let handle = store.insert_bound(fixture_state()).unwrap();
    thread::scope(|scope| {
        let attempts = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                scope.spawn(move || store.take_bound(&handle).unwrap().is_some())
            })
            .collect::<Vec<_>>();
        let successes = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    });
    assert!(store.take_bound(&handle).unwrap().is_none());
}

#[cfg(feature = "postgres-backend")]
#[test]
#[ignore = "requires an isolated PostgreSQL service"]
fn postgres_state_is_consumed_atomically_once() {
    use secure_auth_server::{
        BoundOneTimeLoginStateStore, PostgresOneTimeLoginStateStore,
        POSTGRES_ONE_TIME_LOGIN_STATE_SCHEMA_SQL,
    };
    use std::sync::Arc;
    use std::thread;

    let url = std::env::var("SECURE_KEYPAD_POSTGRES_URL").unwrap();
    let mut schema_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    schema_client
        .batch_execute(POSTGRES_ONE_TIME_LOGIN_STATE_SCHEMA_SQL)
        .unwrap();
    drop(schema_client);
    let config: postgres::Config = url.parse().unwrap();
    let store = Arc::new(
        PostgresOneTimeLoginStateStore::from_config_for_local_testing(
            config,
            &format!("opaque_test_{}", std::process::id()),
            4,
            8,
            Duration::from_secs(30),
            fixture_key(),
        )
        .unwrap(),
    );
    let handle = store.insert_bound(fixture_state()).unwrap();
    thread::scope(|scope| {
        let attempts = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                scope.spawn(move || store.take_bound(&handle).unwrap().is_some())
            })
            .collect::<Vec<_>>();
        let successes = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    });
    assert!(store.take_bound(&handle).unwrap().is_none());
}
