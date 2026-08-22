use crate::{
    storage::{
        decode_ceremony_record, encode_ceremony_record, validate_backend_ttl, CeremonyKind,
        CeremonyState, CeremonyStateStore, CeremonyStoreError, CredentialStore,
        CredentialStoreError, WebAuthnStateKey, WebAuthnStateProtector,
    },
    MAX_CEREMONY_STATE_BYTES, MAX_CEREMONY_TTL, MAX_CREDENTIALS_PER_USER,
    MAX_CREDENTIAL_RECORD_BYTES, MAX_PENDING_CEREMONIES, MAX_PROTECTED_CEREMONY_RECORD_BYTES,
};
use r2d2::{Pool, PooledConnection};
use redis::Script;
use secure_auth_server::LoginStateHandle;
use std::{fmt, time::Duration};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};
use zeroize::Zeroizing;

const HANDLE_ATTEMPTS: usize = 8;
const MAX_NAMESPACE_BYTES: usize = 64;
const PENDING_INDEX_SUFFIX: &str = "pending";
const MAX_CEREMONY_TTL_MILLIS: u64 = MAX_CEREMONY_TTL.as_secs() * 1_000;
const INSERT_SCRIPT: &str = r"
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then
  return 0
end
local inserted = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2])
if not inserted then
  return -1
end
redis.call('ZADD', KEYS[2], now_ms + tonumber(ARGV[2]), KEYS[1])
local index_ttl = redis.call('PTTL', KEYS[2])
if index_ttl < tonumber(ARGV[2]) then
  redis.call('PEXPIRE', KEYS[2], ARGV[2])
end
return 1
";
const CONSUME_SCRIPT: &str = r"
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 or ttl > tonumber(ARGV[3]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], KEYS[1])
  return {-2, false}
end
local length = redis.call('STRLEN', KEYS[1])
if length > tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], KEYS[1])
  return {-2, false}
end
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], KEYS[1])
end
if not value then
  return {0, false}
end
return {1, value}
";
const BOUNDED_CREDENTIAL_GET_SCRIPT: &str = r"
local length = redis.call('STRLEN', KEYS[1])
if length > tonumber(ARGV[1]) then
  return {0, false}
end
local value = redis.call('GET', KEYS[1])
if not value then
  return {1, false}
end
return {2, value}
";

/// Configuration errors returned while constructing a Redis-backed store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisStorageConfigError {
    /// The URL could not be parsed by redis-rs.
    InvalidUrl,
    /// The URL is not TLS-protected. Use the explicit local-test constructor
    /// only for an isolated development Redis instance.
    InsecureUrl,
    /// The namespace is empty, oversized, or contains unsafe key characters.
    InvalidNamespace,
    /// The connection pool size is zero or exceeds the bounded adapter limit.
    InvalidPoolSize,
    /// The connection pool could not be constructed.
    PoolBuild,
}

impl fmt::Display for RedisStorageConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid redis URL",
            Self::InsecureUrl => "redis storage requires a TLS URL",
            Self::InvalidNamespace => "invalid redis key namespace",
            Self::InvalidPoolSize => "invalid redis connection pool size",
            Self::PoolBuild => "redis connection pool construction failed",
        })
    }
}

impl std::error::Error for RedisStorageConfigError {}

/// A Redis-backed implementation of both `WebAuthn` storage contracts.
///
/// The adapter uses a bounded `r2d2` pool, `SET NX PX` for one-time ceremony
/// insertion, a Lua `GET` + `DEL` script for atomic consume-once semantics,
/// and Redis `WATCH`/`MULTI` transactions for credential uniqueness and
/// post-authentication updates. The default constructor requires `rediss://`.
/// All operations are blocking and must run outside an async executor thread.
#[derive(Clone)]
pub struct RedisWebAuthnStore {
    pool: Pool<redis::Client>,
    namespace: String,
    protector: WebAuthnStateProtector,
}

impl RedisWebAuthnStore {
    /// Creates a TLS-protected Redis store.
    ///
    /// The URL must use `rediss://`. The pool size is bounded to prevent an
    /// accidental configuration from exhausting the Redis server. The key is
    /// used to authenticate and encrypt serialized ceremony records before
    /// persistence and must be shared by instances that consume the same
    /// namespace.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, or pool size is
    /// invalid, or when the pool cannot be built.
    pub fn from_url(
        url: &str,
        namespace: &str,
        pool_size: u32,
        encryption_key: WebAuthnStateKey,
    ) -> Result<Self, RedisStorageConfigError> {
        Self::build(url, namespace, pool_size, true, encryption_key)
    }

    /// Creates a Redis store for an isolated local test instance.
    ///
    /// This intentionally requires a separate method so a production config
    /// cannot silently downgrade from `rediss://` to plaintext `redis://`.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the URL, namespace, or pool size is
    /// invalid, or when the pool cannot be built.
    pub fn from_insecure_url_for_local_testing(
        url: &str,
        namespace: &str,
        pool_size: u32,
    ) -> Result<Self, RedisStorageConfigError> {
        Self::build(
            url,
            namespace,
            pool_size,
            false,
            WebAuthnStateKey::generate(),
        )
    }

    fn build(
        url: &str,
        namespace: &str,
        pool_size: u32,
        require_tls: bool,
        encryption_key: WebAuthnStateKey,
    ) -> Result<Self, RedisStorageConfigError> {
        validate_namespace(namespace)?;
        if pool_size == 0 || pool_size > 256 {
            return Err(RedisStorageConfigError::InvalidPoolSize);
        }
        if require_tls && !url.starts_with("rediss://") {
            return Err(RedisStorageConfigError::InsecureUrl);
        }
        let client = redis::Client::open(url).map_err(|_| RedisStorageConfigError::InvalidUrl)?;
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(client)
            .map_err(|_| RedisStorageConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
            protector: WebAuthnStateProtector::new(encryption_key, namespace),
        })
    }

    fn connection(&self) -> Result<PooledConnection<redis::Client>, CeremonyStoreError> {
        self.pool.get().map_err(|_| CeremonyStoreError::Unavailable)
    }

    fn credential_connection(
        &self,
    ) -> Result<PooledConnection<redis::Client>, CredentialStoreError> {
        self.pool
            .get()
            .map_err(|_| CredentialStoreError::Unavailable)
    }

    fn ceremony_key(&self, kind: CeremonyKind, handle: &LoginStateHandle) -> String {
        format!(
            "{}:webauthn:v1:{}:{}",
            self.namespace,
            match kind {
                CeremonyKind::Registration => "registration",
                CeremonyKind::Authentication => "authentication",
            },
            hex_handle(handle),
        )
    }

    fn credential_key(&self, user_id: Uuid) -> String {
        format!("{}:webauthn:v1:credentials:{user_id}", self.namespace)
    }

    fn pending_index_key(&self) -> String {
        format!("{}:webauthn:v1:{PENDING_INDEX_SUFFIX}", self.namespace)
    }
}

impl CeremonyStateStore for RedisWebAuthnStore {
    fn insert(
        &self,
        kind: CeremonyKind,
        user_id: Uuid,
        state: &[u8],
        ttl: Duration,
    ) -> Result<LoginStateHandle, CeremonyStoreError> {
        let ttl_millis = validate_backend_ttl(ttl)?;
        if state.len() > MAX_CEREMONY_STATE_BYTES {
            return Err(CeremonyStoreError::StateTooLarge);
        }
        let encoded = encode_ceremony_record(kind, user_id, state)?;
        let protected = self.protector.seal(encoded.as_slice())?;
        let mut connection = self.connection()?;
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = LoginStateHandle::generate();
            let key = self.ceremony_key(kind, &handle);
            let inserted: i64 = Script::new(INSERT_SCRIPT)
                .key(key)
                .key(self.pending_index_key())
                .arg(protected.as_slice())
                .arg(ttl_millis)
                .arg(MAX_PENDING_CEREMONIES)
                .invoke(&mut *connection)
                .map_err(|_| CeremonyStoreError::Unavailable)?;
            if inserted == 1 {
                return Ok(handle);
            }
            if inserted == 0 {
                return Err(CeremonyStoreError::CapacityReached);
            }
        }
        Err(CeremonyStoreError::HandleCollision)
    }

    fn take(
        &self,
        kind: CeremonyKind,
        handle: &LoginStateHandle,
    ) -> Result<Option<CeremonyState>, CeremonyStoreError> {
        let key = self.ceremony_key(kind, handle);
        let mut connection = self.connection()?;
        let (status, encoded): (i64, Option<Vec<u8>>) = Script::new(CONSUME_SCRIPT)
            .key(key)
            .key(self.pending_index_key())
            .arg(MAX_PROTECTED_CEREMONY_RECORD_BYTES)
            .arg(MAX_CEREMONY_TTL_MILLIS)
            .invoke(&mut *connection)
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let encoded = match status {
            0 => return Ok(None),
            1 => encoded.ok_or(CeremonyStoreError::Unavailable)?,
            _ => return Err(CeremonyStoreError::Unavailable),
        };
        let encoded = self.protector.open(encoded)?;
        let state = decode_ceremony_record(encoded.as_slice())?;
        if state.kind() != kind {
            return Ok(None);
        }
        Ok(Some(state))
    }
}

impl CredentialStore for RedisWebAuthnStore {
    fn load(&self, user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError> {
        let key = self.credential_key(user_id);
        let mut connection = self.credential_connection()?;
        let encoded = get_bounded_credentials(&mut connection, &key)?;
        decode_credentials(encoded.as_ref().map(|value| value.as_slice()))
    }

    fn insert(&self, user_id: Uuid, passkey: Passkey) -> Result<(), CredentialStoreError> {
        let key = self.credential_key(user_id);
        let mut connection = self.credential_connection()?;
        redis::transaction(
            &mut *connection,
            std::slice::from_ref(&key),
            |connection, pipe| {
                let current = get_bounded_credentials(connection, &key).map_err(|error| {
                    redis_error(
                        match error {
                            CredentialStoreError::InvalidRecord => {
                                redis::ErrorKind::UnexpectedReturnType
                            }
                            _ => redis::ErrorKind::Io,
                        },
                        "credential read failed",
                    )
                })?;
                let mut credentials = decode_credentials(
                    current.as_ref().map(|value| value.as_slice()),
                )
                .map_err(|_| {
                    redis_error(
                        redis::ErrorKind::UnexpectedReturnType,
                        "invalid credential record",
                    )
                })?;
                if credentials.iter().any(|existing| existing == &passkey) {
                    return Ok(Some(Err(CredentialStoreError::Duplicate)));
                }
                if credentials.len() >= MAX_CREDENTIALS_PER_USER {
                    return Ok(Some(Err(CredentialStoreError::CapacityReached)));
                }
                credentials.push(passkey.clone());
                let encoded = encode_credentials(&credentials).map_err(|_| {
                    redis_error(
                        redis::ErrorKind::UnexpectedReturnType,
                        "credential encode failed",
                    )
                })?;
                pipe.set(&key, encoded.as_slice())
                    .ignore()
                    .query(connection)
                    .map(|()| Some(Ok(())))
            },
        )
        .map_err(|_| CredentialStoreError::Unavailable)?
    }

    fn update_after_auth(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError> {
        let key = self.credential_key(user_id);
        let mut connection = self.credential_connection()?;
        redis::transaction(
            &mut *connection,
            std::slice::from_ref(&key),
            |connection, pipe| {
                let current = get_bounded_credentials(connection, &key).map_err(|error| {
                    redis_error(
                        match error {
                            CredentialStoreError::InvalidRecord => {
                                redis::ErrorKind::UnexpectedReturnType
                            }
                            _ => redis::ErrorKind::Io,
                        },
                        "credential read failed",
                    )
                })?;
                let mut credentials = decode_credentials(
                    current.as_ref().map(|value| value.as_slice()),
                )
                .map_err(|_| {
                    redis_error(
                        redis::ErrorKind::UnexpectedReturnType,
                        "invalid credential record",
                    )
                })?;
                let Some(credential) = credentials
                    .iter_mut()
                    .find(|credential| credential.cred_id() == result.cred_id())
                else {
                    return Ok(Some(Err(CredentialStoreError::InvalidRecord)));
                };
                let changed = credential.update_credential(result).ok_or_else(|| {
                    redis_error(
                        redis::ErrorKind::UnexpectedReturnType,
                        "credential update mismatch",
                    )
                })?;
                if result.needs_update() && !changed {
                    return Ok(Some(Err(CredentialStoreError::InvalidRecord)));
                }
                if !changed {
                    return Ok(Some(Ok(false)));
                }
                let encoded = encode_credentials(&credentials).map_err(|_| {
                    redis_error(
                        redis::ErrorKind::UnexpectedReturnType,
                        "credential encode failed",
                    )
                })?;
                pipe.set(&key, encoded.as_slice())
                    .ignore()
                    .query(connection)
                    .map(|()| Some(Ok(true)))
            },
        )
        .map_err(|_| CredentialStoreError::Unavailable)?
    }
}

fn get_bounded_credentials(
    connection: &mut redis::Connection,
    key: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialStoreError> {
    let (status, value): (i64, Option<Vec<u8>>) = Script::new(BOUNDED_CREDENTIAL_GET_SCRIPT)
        .key(key)
        .arg(MAX_CREDENTIAL_RECORD_BYTES)
        .invoke(connection)
        .map_err(|_| CredentialStoreError::Unavailable)?;
    match status {
        1 => Ok(None),
        2 => value
            .map(|value| Some(Zeroizing::new(value)))
            .ok_or(CredentialStoreError::InvalidRecord),
        _ => Err(CredentialStoreError::InvalidRecord),
    }
}

fn decode_credentials(encoded: Option<&[u8]>) -> Result<Vec<Passkey>, CredentialStoreError> {
    let Some(encoded) = encoded else {
        return Ok(Vec::new());
    };
    if encoded.len() > MAX_CREDENTIAL_RECORD_BYTES {
        return Err(CredentialStoreError::InvalidRecord);
    }
    let credentials: Vec<Passkey> =
        serde_json::from_slice(encoded).map_err(|_| CredentialStoreError::InvalidRecord)?;
    if credentials.len() > MAX_CREDENTIALS_PER_USER {
        return Err(CredentialStoreError::InvalidRecord);
    }
    Ok(credentials)
}

fn encode_credentials(
    credentials: &[Passkey],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CredentialStoreError> {
    let encoded =
        serde_json::to_vec(credentials).map_err(|_| CredentialStoreError::InvalidRecord)?;
    if encoded.len() > MAX_CREDENTIAL_RECORD_BYTES {
        return Err(CredentialStoreError::InvalidRecord);
    }
    Ok(zeroize::Zeroizing::new(encoded))
}

fn validate_namespace(namespace: &str) -> Result<(), RedisStorageConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RedisStorageConfigError::InvalidNamespace);
    }
    Ok(())
}

fn hex_handle(handle: &LoginStateHandle) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in handle.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn redis_error(kind: redis::ErrorKind, message: &'static str) -> redis::RedisError {
    redis::RedisError::from((kind, message))
}

#[cfg(test)]
mod tests {
    use super::{BOUNDED_CREDENTIAL_GET_SCRIPT, CONSUME_SCRIPT};

    #[test]
    fn bounded_credential_get_checks_length_before_get() {
        let length_check = BOUNDED_CREDENTIAL_GET_SCRIPT
            .find("STRLEN")
            .expect("bounded script must check length");
        let get = BOUNDED_CREDENTIAL_GET_SCRIPT
            .find("'GET'")
            .expect("bounded script must retrieve an accepted value");
        assert!(length_check < get);
        assert!(BOUNDED_CREDENTIAL_GET_SCRIPT.contains("tonumber(ARGV[1])"));
        assert!(BOUNDED_CREDENTIAL_GET_SCRIPT.contains("return {0, false}"));
    }

    #[test]
    fn ceremony_consume_checks_length_before_get() {
        let length_check = CONSUME_SCRIPT
            .find("STRLEN")
            .expect("ceremony consume must check length");
        let get = CONSUME_SCRIPT
            .find("'GET'")
            .expect("ceremony consume must retrieve an accepted value");
        assert!(length_check < get);
        assert!(CONSUME_SCRIPT.contains("tonumber(ARGV[2])"));
        assert!(CONSUME_SCRIPT.contains("return {-2, false}"));
    }

    #[test]
    fn ceremony_consume_rejects_missing_or_drifted_ttl_before_length_materialization() {
        let ttl_check = CONSUME_SCRIPT
            .find("PTTL")
            .expect("ceremony consume must validate the Redis key TTL");
        let length_check = CONSUME_SCRIPT
            .find("STRLEN")
            .expect("ceremony consume must check length");
        assert!(ttl_check < length_check);
        assert!(CONSUME_SCRIPT.contains("ttl < 1"));
        assert!(CONSUME_SCRIPT.contains("tonumber(ARGV[3])"));
    }
}
