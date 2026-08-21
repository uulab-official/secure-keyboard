use crate::{
    storage::{
        decode_ceremony_record, encode_ceremony_record, validate_backend_ttl, CeremonyKind,
        CeremonyState, CeremonyStateStore, CeremonyStoreError, CredentialStore,
        CredentialStoreError, WebAuthnStateKey, WebAuthnStateProtector,
        MAX_PROTECTED_CEREMONY_RECORD_BYTES,
    },
    MAX_CEREMONY_STATE_BYTES, MAX_CREDENTIALS_PER_USER, MAX_CREDENTIAL_RECORD_BYTES,
    MAX_PENDING_CEREMONIES,
};
use postgres::{config::SslMode, tls::MakeTlsConnect, Config, Socket};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};
use secure_auth_server::LoginStateHandle;
use std::{any::TypeId, fmt, time::Duration};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

const HANDLE_ATTEMPTS: usize = 8;
const MAX_NAMESPACE_BYTES: usize = 64;
const POSTGRES_CREDENTIAL_LOAD_SQL: &str = r"
SELECT CASE
           WHEN octet_length(passkey::text) <= $4 THEN passkey
           ELSE NULL::jsonb
       END AS passkey
FROM secure_keypad_webauthn_credentials
WHERE namespace = $1 AND user_id = $2
ORDER BY credential_id
LIMIT $3
";
const POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL: &str = r"
SELECT CASE
           WHEN octet_length(passkey::text) <= $4 THEN passkey
           ELSE NULL::jsonb
       END AS passkey,
       revision
FROM secure_keypad_webauthn_credentials
WHERE namespace = $1 AND user_id = $2 AND credential_id = $3
FOR UPDATE
";
const POSTGRES_CEREMONY_CONSUME_SQL: &str = r"
DELETE FROM secure_keypad_webauthn_ceremonies
WHERE namespace = $1 AND handle = $2 AND kind = $3 AND expires_at > now()
RETURNING kind, user_id,
          CASE
              WHEN octet_length(state) <= $4 THEN state
              ELSE NULL::bytea
          END AS state
";

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
    CONSTRAINT secure_keypad_webauthn_ceremony_namespace_length
        CHECK (octet_length(namespace) BETWEEN 1 AND 64),
    CONSTRAINT secure_keypad_webauthn_ceremony_namespace_chars
        CHECK (namespace ~ '^[A-Za-z0-9._-]+$'),
    CONSTRAINT secure_keypad_webauthn_ceremony_handle_length
        CHECK (octet_length(handle) = 32),
    CONSTRAINT secure_keypad_webauthn_ceremony_kind
        CHECK (kind IN (1, 2)),
    CONSTRAINT secure_keypad_webauthn_ceremony_state_length
        CHECK (octet_length(state) BETWEEN 1 AND 131128)
);
CREATE INDEX IF NOT EXISTS secure_keypad_webauthn_ceremonies_expiry_idx
    ON secure_keypad_webauthn_ceremonies (expires_at);

-- The encrypted ceremony envelope is larger than the historical plaintext
-- bound. Recreate this one constraint so an existing deployment is upgraded
-- instead of leaving the old 131072-byte limit in place.
DO $$
BEGIN
    ALTER TABLE secure_keypad_webauthn_ceremonies
        DROP CONSTRAINT IF EXISTS secure_keypad_webauthn_ceremony_state_length;
    ALTER TABLE secure_keypad_webauthn_ceremonies
        ADD CONSTRAINT secure_keypad_webauthn_ceremony_state_length
        CHECK (octet_length(state) BETWEEN 1 AND 131128);
END
$$;

CREATE TABLE IF NOT EXISTS secure_keypad_webauthn_credentials (
    namespace TEXT NOT NULL,
    user_id UUID NOT NULL,
    credential_id BYTEA NOT NULL,
    passkey JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, user_id, credential_id),
    CONSTRAINT secure_keypad_webauthn_credential_namespace_length
        CHECK (octet_length(namespace) BETWEEN 1 AND 64),
    CONSTRAINT secure_keypad_webauthn_credential_namespace_chars
        CHECK (namespace ~ '^[A-Za-z0-9._-]+$'),
    CONSTRAINT secure_keypad_webauthn_credential_id_length
        CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    CONSTRAINT secure_keypad_webauthn_credential_passkey_length
        CHECK (octet_length(passkey::text) BETWEEN 2 AND 262144),
    CONSTRAINT secure_keypad_webauthn_credential_revision_nonnegative
        CHECK (revision >= 0)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_ceremonies'::regclass
          AND conname = 'secure_keypad_webauthn_ceremony_namespace_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_ceremonies
            ADD CONSTRAINT secure_keypad_webauthn_ceremony_namespace_length
            CHECK (octet_length(namespace) BETWEEN 1 AND 64);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_ceremonies'::regclass
          AND conname = 'secure_keypad_webauthn_ceremony_namespace_chars'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_ceremonies
            ADD CONSTRAINT secure_keypad_webauthn_ceremony_namespace_chars
            CHECK (namespace ~ '^[A-Za-z0-9._-]+$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_credentials'::regclass
          AND conname = 'secure_keypad_webauthn_credential_namespace_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_credentials
            ADD CONSTRAINT secure_keypad_webauthn_credential_namespace_length
            CHECK (octet_length(namespace) BETWEEN 1 AND 64);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_credentials'::regclass
          AND conname = 'secure_keypad_webauthn_credential_namespace_chars'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_credentials
            ADD CONSTRAINT secure_keypad_webauthn_credential_namespace_chars
            CHECK (namespace ~ '^[A-Za-z0-9._-]+$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_ceremonies'::regclass
          AND conname = 'secure_keypad_webauthn_ceremony_handle_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_ceremonies
            ADD CONSTRAINT secure_keypad_webauthn_ceremony_handle_length
            CHECK (octet_length(handle) = 32);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_ceremonies'::regclass
          AND conname = 'secure_keypad_webauthn_ceremony_kind'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_ceremonies
            ADD CONSTRAINT secure_keypad_webauthn_ceremony_kind
            CHECK (kind IN (1, 2));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_ceremonies'::regclass
          AND conname = 'secure_keypad_webauthn_ceremony_state_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_ceremonies
            ADD CONSTRAINT secure_keypad_webauthn_ceremony_state_length
            CHECK (octet_length(state) BETWEEN 1 AND 131128);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_credentials'::regclass
          AND conname = 'secure_keypad_webauthn_credential_id_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_credentials
            ADD CONSTRAINT secure_keypad_webauthn_credential_id_length
            CHECK (octet_length(credential_id) BETWEEN 1 AND 1024);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_credentials'::regclass
          AND conname = 'secure_keypad_webauthn_credential_passkey_length'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_credentials
            ADD CONSTRAINT secure_keypad_webauthn_credential_passkey_length
            CHECK (octet_length(passkey::text) BETWEEN 2 AND 262144);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'secure_keypad_webauthn_credentials'::regclass
          AND conname = 'secure_keypad_webauthn_credential_revision_nonnegative'
    ) THEN
        ALTER TABLE secure_keypad_webauthn_credentials
            ADD CONSTRAINT secure_keypad_webauthn_credential_revision_nonnegative
            CHECK (revision >= 0);
    END IF;
END
$$;
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
    /// The supplied production configuration does not require `PostgreSQL` TLS.
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
/// `from_config` accepts an explicit TLS connector and a host-managed key so
/// production deployments can use their certificate policy and authenticate
/// ceremony records at rest. `from_config_for_local_testing` is the only
/// convenience constructor and deliberately uses `NoTls`. Operations
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
    protector: WebAuthnStateProtector,
}

impl<T> PostgresWebAuthnStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    /// Creates a store with an explicit `PostgreSQL` TLS connector and a
    /// host-managed key for authenticated ceremony-state encryption.
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
        encryption_key: WebAuthnStateKey,
    ) -> Result<Self, PostgresStorageConfigError> {
        Self::build(config, tls, namespace, pool_size, true, encryption_key)
    }

    fn build(
        config: Config,
        tls: T,
        namespace: &str,
        pool_size: u32,
        require_tls: bool,
        encryption_key: WebAuthnStateKey,
    ) -> Result<Self, PostgresStorageConfigError> {
        if require_tls
            && (config.get_ssl_mode() != SslMode::Require
                || TypeId::of::<T>() == TypeId::of::<NoTls>())
        {
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
            protector: WebAuthnStateProtector::new(encryption_key, namespace),
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
        Self::build(
            config,
            NoTls,
            namespace,
            pool_size,
            false,
            WebAuthnStateKey::generate(),
        )
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
        let ttl_millis = i64::try_from(validate_backend_ttl(ttl)?)
            .map_err(|_| CeremonyStoreError::InvalidTtl)?;
        let encoded = encode_ceremony_record(kind, user_id, state)?;
        let protected = self.protector.seal(encoded.as_slice())?;
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
                        &protected.as_slice(),
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
        let max_protected_record_bytes = i64::try_from(MAX_PROTECTED_CEREMONY_RECORD_BYTES)
            .map_err(|_| CeremonyStoreError::InvalidState)?;
        let row = client
            .query_opt(
                POSTGRES_CEREMONY_CONSUME_SQL,
                &[
                    &self.namespace,
                    &handle_bytes,
                    &kind_tag,
                    &max_protected_record_bytes,
                ],
            )
            .map_err(|_| CeremonyStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_kind: i16 = row.get(0);
        let user_id: Uuid = row.get(1);
        let protected: Option<Vec<u8>> = row
            .try_get(2)
            .map_err(|_| CeremonyStoreError::InvalidState)?;
        let protected = protected.ok_or(CeremonyStoreError::InvalidState)?;
        if stored_kind != kind_tag {
            return Ok(None);
        }
        let encoded = self.protector.open(protected)?;
        let state = decode_ceremony_record(encoded.as_slice())?;
        if state.kind() != kind || state.user_id() != user_id {
            return Err(CeremonyStoreError::InvalidState);
        }
        Ok(Some(state))
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
        let max_credential_rows = i64::try_from(MAX_CREDENTIALS_PER_USER + 1)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let max_credential_record_bytes = i64::try_from(MAX_CREDENTIAL_RECORD_BYTES)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let rows = client
            .query(
                POSTGRES_CREDENTIAL_LOAD_SQL,
                &[
                    &self.namespace,
                    &user_id,
                    &max_credential_rows,
                    &max_credential_record_bytes,
                ],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            let encoded: Option<serde_json::Value> = row
                .try_get(0)
                .map_err(|_| CredentialStoreError::InvalidRecord)?;
            let encoded = encoded.ok_or(CredentialStoreError::InvalidRecord)?;
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
        let max_credential_record_bytes = i64::try_from(MAX_CREDENTIAL_RECORD_BYTES)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let row = transaction
            .query_opt(
                POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL,
                &[
                    &self.namespace,
                    &user_id,
                    &credential_id,
                    &max_credential_record_bytes,
                ],
            )
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let Some(row) = row else {
            return Err(CredentialStoreError::InvalidRecord);
        };
        let encoded: Option<serde_json::Value> = row
            .try_get(0)
            .map_err(|_| CredentialStoreError::InvalidRecord)?;
        let encoded = encoded.ok_or(CredentialStoreError::InvalidRecord)?;
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

#[cfg(test)]
mod tests {
    use super::{
        POSTGRES_CEREMONY_CONSUME_SQL, POSTGRES_CREDENTIAL_LOAD_SQL,
        POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL, POSTGRES_SCHEMA_SQL,
    };

    #[test]
    fn credential_load_query_bounds_rows_and_bytes_before_materialization() {
        assert!(POSTGRES_CREDENTIAL_LOAD_SQL.contains("LIMIT $3"));
        assert!(POSTGRES_CREDENTIAL_LOAD_SQL.contains("octet_length(passkey::text) <= $4"));
    }

    #[test]
    fn credential_update_query_bounds_bytes_before_materialization() {
        assert!(POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL.contains("FOR UPDATE"));
        assert!(POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL.contains("octet_length(passkey::text) <= $4"));
        assert!(POSTGRES_CREDENTIAL_UPDATE_LOAD_SQL.contains("ELSE NULL::jsonb"));
    }

    #[test]
    fn ceremony_consume_query_bounds_bytes_before_materialization() {
        assert!(POSTGRES_CEREMONY_CONSUME_SQL.contains("octet_length(state) <= $4"));
        assert!(POSTGRES_CEREMONY_CONSUME_SQL.contains("ELSE NULL::bytea"));
        assert!(POSTGRES_CEREMONY_CONSUME_SQL.contains("expires_at > now()"));
    }

    #[test]
    fn schema_enforces_the_application_namespace_contract() {
        assert!(POSTGRES_SCHEMA_SQL.contains("CHECK (octet_length(namespace) BETWEEN 1 AND 64)"));
        assert!(POSTGRES_SCHEMA_SQL.contains("CHECK (namespace ~ '^[A-Za-z0-9._-]+$')"));
        assert!(POSTGRES_SCHEMA_SQL.contains("CHECK (octet_length(state) BETWEEN 1 AND 131128)"));
        assert!(POSTGRES_SCHEMA_SQL
            .contains("DROP CONSTRAINT IF EXISTS secure_keypad_webauthn_ceremony_state_length"));
        assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE secure_keypad_webauthn_ceremonies"));
        assert!(POSTGRES_SCHEMA_SQL.contains("ALTER TABLE secure_keypad_webauthn_credentials"));
        assert!(POSTGRES_SCHEMA_SQL.contains("FROM pg_constraint"));
    }

    #[test]
    fn schema_upgrade_reapplies_all_ceremony_and_credential_bounds() {
        for constraint in [
            "secure_keypad_webauthn_ceremony_handle_length",
            "secure_keypad_webauthn_ceremony_kind",
            "secure_keypad_webauthn_ceremony_state_length",
            "secure_keypad_webauthn_credential_id_length",
            "secure_keypad_webauthn_credential_passkey_length",
            "secure_keypad_webauthn_credential_revision_nonnegative",
        ] {
            assert!(POSTGRES_SCHEMA_SQL.contains(constraint));
        }
        assert!(
            POSTGRES_SCHEMA_SQL
                .matches("ALTER TABLE secure_keypad_webauthn_ceremonies")
                .count()
                >= 5
        );
        assert!(
            POSTGRES_SCHEMA_SQL
                .matches("ALTER TABLE secure_keypad_webauthn_credentials")
                .count()
                >= 5
        );
    }
}
