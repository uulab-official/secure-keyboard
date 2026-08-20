use crate::{BoundLoginState, BoundOneTimeLoginStateStore, LoginStateHandle, StoreError};
use secure_auth::{
    server_login_finish, server_login_start, AuthEnvelope, AuthError, AuthMessageKind,
    CredentialFile, ServerSetupBytes, MAX_SERVER_KEY_ID_BYTES,
};

/// Errors produced by the transport-neutral server authentication service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerAuthError {
    /// The OPAQUE or envelope layer rejected the operation.
    Auth(AuthError),
    /// The pending-state backend rejected or could not complete the operation.
    Store(StoreError),
    /// The one-time handle has no live pending login state.
    MissingLoginState,
    /// The configured server key identifier is outside the supported bound.
    InvalidServerKeyId,
}

impl From<AuthError> for ServerAuthError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<StoreError> for ServerAuthError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl core::fmt::Display for ServerAuthError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Auth(error) => return error.fmt(formatter),
            Self::Store(error) => return error.fmt(formatter),
            Self::MissingLoginState => "missing or expired login state",
            Self::InvalidServerKeyId => "invalid server key identifier",
        })
    }
}

impl std::error::Error for ServerAuthError {}

/// Transport-neutral OPAQUE server flow bound to a one-time state backend.
pub struct ServerAuthService<S> {
    setup: ServerSetupBytes,
    server_key_id: String,
    state_store: S,
}

impl<S> ServerAuthService<S>
where
    S: BoundOneTimeLoginStateStore,
{
    /// Creates a server service for one pinned server key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ServerAuthError::InvalidServerKeyId`] when the key identifier
    /// is empty or exceeds [`MAX_SERVER_KEY_ID_BYTES`].
    pub fn new(
        setup: ServerSetupBytes,
        server_key_id: impl Into<String>,
        state_store: S,
    ) -> Result<Self, ServerAuthError> {
        let server_key_id = server_key_id.into();
        if server_key_id.is_empty() || server_key_id.len() > MAX_SERVER_KEY_ID_BYTES {
            return Err(ServerAuthError::InvalidServerKeyId);
        }
        Ok(Self {
            setup,
            server_key_id,
            state_store,
        })
    }

    /// Processes a client credential request and returns the response envelope
    /// plus a one-time handle for the finalization step.
    ///
    /// The client and server identifiers are bound to the pending state and
    /// are not accepted again by [`Self::finish_login`].
    ///
    /// # Errors
    ///
    /// Returns an authentication, envelope, identifier, or store error.
    pub fn begin_login(
        &self,
        request: AuthEnvelope,
        credential_file: Option<&CredentialFile>,
        credential_identifier: &[u8],
        client_identifier: &[u8],
        server_identifier: &[u8],
    ) -> Result<(AuthEnvelope, LoginStateHandle), ServerAuthError> {
        let request =
            request.into_message(AuthMessageKind::CredentialRequest, &self.server_key_id)?;
        let (response, login_state) = server_login_start(
            &self.setup,
            credential_file,
            &request,
            credential_identifier,
            client_identifier,
            server_identifier,
        )?;
        let response_envelope = AuthEnvelope::new(
            AuthMessageKind::CredentialResponse,
            &self.server_key_id,
            &response,
        )?;
        let state_bytes = login_state.into_bytes();
        let bound_state = BoundLoginState::new(state_bytes, client_identifier, server_identifier)?;
        let handle = self.state_store.insert_bound(bound_state)?;
        Ok((response_envelope, handle))
    }

    /// Consumes a one-time handle and finishes the server-side OPAQUE login.
    ///
    /// The stored identifiers are used for finalization, preventing callers
    /// from substituting a different context on the second request.
    ///
    /// # Errors
    ///
    /// Returns [`ServerAuthError::MissingLoginState`] for a missing, expired,
    /// or already-consumed handle, or an authentication/store error otherwise.
    pub fn finish_login(
        &self,
        finalization: AuthEnvelope,
        handle: &LoginStateHandle,
    ) -> Result<secure_auth::SecretOutput, ServerAuthError> {
        let finalization = finalization
            .into_message(AuthMessageKind::CredentialFinalization, &self.server_key_id)?;
        let pending = self
            .state_store
            .take_bound(handle)?
            .ok_or(ServerAuthError::MissingLoginState)?;
        let (state_bytes, client_identifier, server_identifier) = pending.into_parts();
        let state = state_bytes.into_state()?;
        server_login_finish(state, &finalization, &client_identifier, &server_identifier)
            .map_err(ServerAuthError::from)
    }
}
