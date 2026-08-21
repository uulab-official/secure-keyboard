#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
use secure_auth::ServerLoginStateBytes;
#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
use secure_auth_server::BoundLoginState;
#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
use secure_auth_server::OpaqueStateKey;
#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
use std::time::Duration;

#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
fn fixture_state() -> BoundLoginState {
    BoundLoginState::new(
        ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
        b"fixture-client",
        b"fixture-server",
    )
    .unwrap()
}

#[cfg(any(feature = "postgres-backend", feature = "redis-backend"))]
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

#[cfg(feature = "postgres-backend")]
#[test]
fn postgres_production_configuration_rejects_no_tls_with_required_sslmode() {
    let config: postgres::Config = "host=127.0.0.1 port=5432 user=postgres sslmode=require"
        .parse()
        .unwrap();
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
    let namespace = format!("opaque-test-{}", std::process::id());
    let store = Arc::new(
        RedisOneTimeLoginStateStore::from_insecure_url_for_local_testing(
            &url,
            &namespace,
            4,
            8,
            Duration::from_secs(30),
            fixture_key(),
        )
        .unwrap(),
    );
    let handle = store.insert_bound(fixture_state()).unwrap();
    let handle_hash = {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(handle.as_bytes());
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    };
    let key = format!("{namespace}:opaque:v1:login:{handle_hash}");
    let mut raw_connection = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw_value: Vec<u8> = redis::cmd("GET")
        .arg(key)
        .query(&mut raw_connection)
        .unwrap();
    assert_eq!(raw_value.get(..4), Some(b"SKPE".as_slice()));
    let second_store = RedisOneTimeLoginStateStore::from_insecure_url_for_local_testing(
        &url,
        &namespace,
        2,
        8,
        Duration::from_secs(30),
        fixture_key(),
    )
    .unwrap();
    let cross_instance_handle = store.insert_bound(fixture_state()).unwrap();
    assert!(second_store
        .take_bound(&cross_instance_handle)
        .unwrap()
        .is_some());
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
    let handle_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(handle.as_bytes()).into()
    };
    let mut raw_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let raw_value: Vec<u8> = raw_client
        .query_one(
            "SELECT state FROM secure_keypad_opaque_login_states
             WHERE namespace = $1 AND handle_hash = $2",
            &[
                &format!("opaque_test_{}", std::process::id()),
                &&handle_hash[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(raw_value.get(..4), Some(b"SKPE".as_slice()));
    let second_config: postgres::Config = url.parse().unwrap();
    let second_store = PostgresOneTimeLoginStateStore::from_config_for_local_testing(
        second_config,
        &format!("opaque_test_{}", std::process::id()),
        2,
        8,
        Duration::from_secs(30),
        fixture_key(),
    )
    .unwrap();
    let cross_instance_handle = store.insert_bound(fixture_state()).unwrap();
    assert!(second_store
        .take_bound(&cross_instance_handle)
        .unwrap()
        .is_some());
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
