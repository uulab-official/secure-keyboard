use crate::{
    storage::{
        CeremonyKind, CeremonyState, CeremonyStateStore, CeremonyStoreError, CredentialStore,
        CredentialStoreError,
    },
    MAX_CEREMONY_STATE_BYTES, MAX_CREDENTIALS_PER_USER, MAX_CREDENTIAL_RECORD_BYTES,
    MAX_PENDING_CEREMONIES,
};
use postgres::{config::SslMode, tls::MakeTlsConnect, Config, Socket};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};
use secure_auth_server::LoginStateHandle;
use std::{fmt, time::Duration};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

const HANDLE_ATTEMPTS: usize = 8;
const MAX_NAMESPACE_BYTES: usize = 64;

/// SQL schema required by [`PostgresWebAuthnStore`].
///
/// Apply this migration with the deployment's migration tool. The credential
/// row revision is used by the post-authentication compare-and-swap update;
/// the per-account advisory lock serializes registration count checks.
pub const POSTGRES_SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS secure_keypad_webauthn_ceremonies (
    namespace TEXT NOT NULL,
    handle BYTEA NOT NULL,
    kind SMALLINT NOT NULL,
    user_id UUID NOT NULL,
    state BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (namespace, handle, kind),
    CHECK (octet_length(handle) = 32),
    CHECK (kind IN (1, 2)),
    CHECK (octet_length(state) BETWEEN 1 AND 131072)
);
CREATE INDEX IF NOT EXISTS secure_keypad_webauthn_ceremonies_expiry_idx
    ON secure_keypad_webauthn_ceremonies (expires_at);

CREATE TABLE IF NOT EXISTS secure_keypad_webauthn_credentials (
    namespace TEXT NOT NULL,
    user_id UUID NOT NULL,
    credential_id BYTEA NOT NULL,
    passkey JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, user_id, credential_id),
    CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    CHECK (octet_length(passkey::text) BETWEEN 2 AND 262144)
);
";

/// Configuration errors returned while constructing a PostgreSQL-backed store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresStorageConfigError {
    /// The namespace is empty, oversized, or contains unsafe characters.
    InvalidNamespace,
    /// The connection pool size is zero or exceeds the bounded adapter limit.
    InvalidPoolSize,
    /// The connection pool could not be constructed.
    PoolBuild,
    /// The production configuration does not require `PostgreSQL` TLS.
    InsecureConfig,
}

impl fmt::Display for PostgresStorageConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNamespace => "invalid postgres storage namespace",
            Self::InvalidPoolSize => "invalid postgres connection pool size",
            Self::PoolBuild => "postgres connection pool construction failed",
            Self::InsecureConfig => "postgres config must require TLS",
        })
    }
}

impl std::error::Error for PostgresStorageConfigError {}

/// A PostgreSQL-backed implementation of both `WebAuthn` storage contracts.
///
/// `from_config` accepts an explicit TLS connector so production deployments
/// can use their certificate policy. `from_config_for_local_testing` is the
/// only convenience constructor and deliberately uses `NoTls`. Operations
/// use a bounded `r2d2` pool. Ceremony consumption is one `DELETE ...
/// RETURNING` statement, registration uses a per-account advisory lock, and
/// credential updates lock the row and require the expected revision.
#[derive(Clone)]
pub struct PostgresWebAuthnStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    pool: Pool<PostgresConnectionManager<T>>,
    namespace: String,
}

impl<T> PostgresWebAuthnStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    /// Creates a store with an explicit `PostgreSQL` TLS connector.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the namespace or pool size is
    /// outside the bounded adapter policy, or when the pool cannot be built.
    pub fn from_config(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
    ) -> Result<Self, PostgresStorageConfigError> {
        Self::build(config, tls, namespace, pool_size, true)
    }

    fn build(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        require_tls: bool,
    ) -> Result<Self, PostgresStorageConfigError> {
        if require_tls && config.get_ssl_mode() != SslMode::Require {
            return Err(PostgresStorageConfigError::InsecureConfig);
        }
        validate_namespace(namespace)?;
        if pool_size == 0 || pool_size > 256 {
            return Err(PostgresStorageConfigError::InvalidPoolSize);
        }
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)
            .map_err(|_| PostgresStorageConfigError::PoolBuild)?;
        Ok(Self {
            pool,
            namespace: namespace.to_owned(),
        })
    }

    fn connection(
        &self,
    ) -> Result<PooledConnection<PostgresConnectionManager<T>>, CeremonyStoreError> {
        self.pool.get().map_err(|_| CeremonyStoreError::Unavailable)
    }

    fn credential_connection(
        &self,
    ) -> Result<PooledConnection<PostgresConnectionManager<T>>, CredentialStoreError> {
        self.pool
            .get()
            .map_err(|_| CredentialStoreError::Unavailable)
    }
}

impl PostgresWebAuthnStore<NoTls> {
    /// Creates a plaintext `PostgreSQL` store for an isolated local test.
    ///
    /// Do not use this constructor for a production or shared environment.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the namespace or pool size is
    /// outside the bounded adapter policy, or when the pool cannot be built.
    pub fn from_config_for_local_testing(
        config: Config,
        namespace: &str,
        pool_size: u32,
    ) -> Result<Self, PostgresStorageConfigError> {
        Self::build(config, NoTls, namespace, pool_size, false)
    }
}

impl<T> CeremonyStateStore for PostgresWebAuthnStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    fn insert(
        &self,
        kind: CeremonyKind,
        user_id: Uuid,
        state: &[u8],
        ttl: Duration,
    ) -> Result<LoginStateHandle, CeremonyStoreError> {
        if state.is_empty() {
            return Err(CeremonyStoreError::InvalidState);
        }
        if state.len() > MAX_CEREMONY_STATE_BYTES {
            return Err(CeremonyStoreError::StateTooLarge);
        }
        let ttl_millis = i64::try_from(ttl.as_millis())
            .ok()
            .filter(|millis| *millis > 0)
            .ok_or(CeremonyStoreError::InvalidTtl)?;
        let mut client = self.connection()?;
        let mut transaction = client
            .transaction()
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let namespace_lock = format!("{}:ceremonies", self.namespace);
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&namespace_lock],
            )
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM secure_keypad_webauthn_ceremonies
                 WHERE namespace = $1 AND expires_at <= now()",
                &[&self.namespace],
            )
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let pending: i64 = transaction
            .query_one(
                "SELECT count(*) FROM secure_keypad_webauthn_ceremonies
                 WHERE namespace = $1 AND expires_at > now()",
                &[&self.namespace],
            )
            .map_err(|_| CeremonyStoreError::Unavailable)?
            .get(0);
        if pending >= i64::try_from(MAX_PENDING_CEREMONIES).unwrap_or(i64::MAX) {
            return Err(CeremonyStoreError::CapacityReached);
        }
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = LoginStateHandle::generate();
            let handle_bytes = handle.as_bytes().as_slice();
            let kind_tag = kind_tag(kind);
            let rows = transaction
                .execute(
                    "INSERT INTO secure_keypad_webauthn_ceremonies
                     (namespace, handle, kind, user_id, state, expires_at)
                     VALUES ($1, $2, $3, $4, $5, now() + ($6::double precision * interval '1 millisecond'))
                     ON CONFLICT (namespace, handle, kind) DO NOTHING",
                    &[
                        &self.namespace,
                        &handle_bytes,
                        &kind_tag,
                        &user_id,
                        &state,
                        &ttl_millis,
                    ],
            )
                .map_err(|_| CeremonyStoreError::Unavailable)?;
            if rows == 1 {
                transaction
                    .commit()
                    .map_err(|_| CeremonyStoreError::Unavailable)?;
                return Ok(handle);
            }
        }
        Err(CeremonyStoreError::HandleCollision)
    }

    fn take(
        &self,
        kind: CeremonyKind,
        handle: &LoginStateHandle,
    ) -> Result<Option<CeremonyState>, CeremonyStoreError> {
        let mut client = self.connection()?;
        let handle_bytes = handle.as_bytes().as_slice();
        let kind_tag = kind_tag(kind);
        let row = client
            .query_opt(
                "DELETE FROM secure_keypad_webauthn_ceremonies
                 WHERE namespace = $1 AND handle = $2 AND kind = $3 AND expires_at > now()
                 RETURNING kind, user_id, state",
                &[&self.namespace, &handle_bytes, &kind_tag],
            )
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_kind: i16 = row.get(0);
        let user_id: Uuid = row.get(1);
        let state: Vec<u8> = row.get(2);
        if stored_kind != kind_tag {
            return Ok(None);
        }
        CeremonyState::new(kind, user_id, state).map(Some)
    }
}

impl<T> CredentialStore for PostgresWebAuthnStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    fn load(&self, user_id: Uuid) -> Result<Vec<Passkey>, CredentialStoreError> {
        let mut client = self.credential_connection()?;
        let rows = client
            .query(
                "SELECT passkey FROM secure_keypad_webauthn_credentials
                 WHERE namespace = $1 AND user_id = $2 ORDER BY credential_id",
                &[&self.namespace, &user_id],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            let encoded: serde_json::Value = row
                .try_get(0)
                .map_err(|_| CredentialStoreError::InvalidRecord)?;
            if serde_json::to_vec(&encoded)
                .map_err(|_| CredentialStoreError::InvalidRecord)?
                .len()
                > MAX_CREDENTIAL_RECORD_BYTES
            {
                return Err(CredentialStoreError::InvalidRecord);
            }
            credentials.push(
                serde_json::from_value(encoded).map_err(|_| CredentialStoreError::InvalidRecord)?,
            );
        }
        if credentials.len() > MAX_CREDENTIALS_PER_USER {
            return Err(CredentialStoreError::InvalidRecord);
        }
        Ok(credentials)
    }

    fn insert(&self, user_id: Uuid, passkey: Passkey) -> Result<(), CredentialStoreError> {
        if passkey.cred_id().is_empty() {
            return Err(CredentialStoreError::InvalidRecord);
        }
        let mut client = self.credential_connection()?;
        let mut transaction = client
            .transaction()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let account_key = format!("{}:{user_id}", self.namespace);
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&account_key],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let credential_id = passkey.cred_id().as_ref();
        let duplicate = transaction
            .query_opt(
                "SELECT 1 FROM secure_keypad_webauthn_credentials
                 WHERE namespace = $1 AND user_id = $2 AND credential_id = $3",
                &[&self.namespace, &user_id, &credential_id],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?
            .is_some();
        if duplicate {
            return Err(CredentialStoreError::Duplicate);
        }
        let count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM secure_keypad_webauthn_credentials
                 WHERE namespace = $1 AND user_id = $2",
                &[&self.namespace, &user_id],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?
            .get(0);
        let max_credentials = i64::try_from(MAX_CREDENTIALS_PER_USER)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        if count >= max_credentials {
            return Err(CredentialStoreError::CapacityReached);
        }
        let encoded =
            serde_json::to_value(&passkey).map_err(|_| CredentialStoreError::InvalidRecord)?;
        if serde_json::to_vec(&encoded)
            .map_err(|_| CredentialStoreError::InvalidRecord)?
            .len()
            > MAX_CREDENTIAL_RECORD_BYTES
        {
            return Err(CredentialStoreError::InvalidRecord);
        }
        let inserted = transaction
            .execute(
                "INSERT INTO secure_keypad_webauthn_credentials
                 (namespace, user_id, credential_id, passkey)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, user_id, credential_id) DO NOTHING",
                &[&self.namespace, &user_id, &credential_id, &encoded],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        if inserted != 1 {
            return Err(CredentialStoreError::Duplicate);
        }
        transaction
            .commit()
            .map_err(|_| CredentialStoreError::Unavailable)
    }

    fn update_after_auth(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<bool, CredentialStoreError> {
        let mut client = self.credential_connection()?;
        let mut transaction = client
            .transaction()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let credential_id = result.cred_id().as_ref();
        let row = transaction
            .query_opt(
                "SELECT passkey, revision FROM secure_keypad_webauthn_credentials
                 WHERE namespace = $1 AND user_id = $2 AND credential_id = $3 FOR UPDATE",
                &[&self.namespace, &user_id, &credential_id],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let Some(row) = row else {
            return Err(CredentialStoreError::InvalidRecord);
        };
        let encoded: serde_json::Value = row
            .try_get(0)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let revision: i64 = row
            .try_get(1)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let mut credential: Passkey =
            serde_json::from_value(encoded).map_err(|_| CredentialStoreError::InvalidRecord)?;
        let changed = credential
            .update_credential(result)
            .ok_or(CredentialStoreError::InvalidRecord)?;
        if result.needs_update() && !changed {
            return Err(CredentialStoreError::InvalidRecord);
        }
        if !changed {
            transaction
                .commit()
                .map_err(|_| CredentialStoreError::Unavailable)?;
            return Ok(false);
        }
        let updated_credential =
            serde_json::to_value(&credential).map_err(|_| CredentialStoreError::InvalidRecord)?;
        if serde_json::to_vec(&updated_credential)
            .map_err(|_| CredentialStoreError::InvalidRecord)?
            .len()
            > MAX_CREDENTIAL_RECORD_BYTES
        {
            return Err(CredentialStoreError::InvalidRecord);
        }
        let updated = transaction
            .execute(
                "UPDATE secure_keypad_webauthn_credentials
                 SET passkey = $4, revision = revision + 1
                 WHERE namespace = $1 AND user_id = $2 AND credential_id = $3 AND revision = $5",
                &[
                    &self.namespace,
                    &user_id,
                    &credential_id,
                    &updated_credential,
                    &revision,
                ],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        if updated != 1 {
            return Err(CredentialStoreError::InvalidRecord);
        }
        transaction
            .commit()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(true)
    }
}

fn kind_tag(kind: CeremonyKind) -> i16 {
    match kind {
        CeremonyKind::Registration => 1,
        CeremonyKind::Authentication => 2,
    }
}

fn validate_namespace(namespace: &str) -> Result<(), PostgresStorageConfigError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PostgresStorageConfigError::InvalidNamespace);
    }
    Ok(())
}
