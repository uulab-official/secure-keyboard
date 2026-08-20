use crate::{BoundLoginState, BoundOneTimeLoginStateStore, LoginStateHandle, StoreError};
use secure_auth::{
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
    AuthEnvelope, AuthError, AuthMessageKind, CredentialFile, ServerSetupBytes,
    MAX_SERVER_KEY_ID_BYTES,
};

/// Maximum active plus previous server key IDs accepted during rotation.
pub const MAX_SERVER_KEY_IDS: usize = 4;

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
    /// The active/previous server key set is invalid or too large.
    InvalidServerKeySet,
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

/// Stable, non-sensitive error classes suitable for an external auth response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicAuthCode {
    /// The request could not be decoded or did not match the endpoint.
    InvalidRequest,
    /// Authentication proof, credential state, or one-time state was rejected.
    AuthenticationFailed,
    /// The service or its protected state backend is not ready to serve.
    TemporarilyUnavailable,
}

impl PublicAuthCode {
    /// Returns the stable wire-safe code for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationFailed => "authentication_failed",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl ServerAuthError {
    /// Maps an internal error to a generic external response class.
    ///
    /// Applications must return this class or its stable string code to
    /// clients, and keep [`Self`] for protected server logs and metrics only.
    #[must_use]
    pub const fn public_code(&self) -> PublicAuthCode {
        match self {
            Self::Auth(error) => match error {
                AuthError::InvalidSetup | AuthError::InvalidCredentialFile => {
                    PublicAuthCode::TemporarilyUnavailable
                }
                AuthError::InvalidLogin | AuthError::Protocol => {
                    PublicAuthCode::AuthenticationFailed
                }
                AuthError::InvalidArgument
                | AuthError::RequestBodyTooLarge
                | AuthError::MalformedTransport
                | AuthError::EmptyMessage
                | AuthError::MessageTooLarge
                | AuthError::UnsupportedVersion
                | AuthError::UnsupportedSuite
                | AuthError::UnexpectedMessageKind
                | AuthError::UnexpectedServerKey => PublicAuthCode::InvalidRequest,
            },
            Self::Store(error) => match error {
                StoreError::Unavailable
                | StoreError::CapacityReached
                | StoreError::HandleCollision => PublicAuthCode::TemporarilyUnavailable,
                StoreError::InvalidCapacity
                | StoreError::InvalidTtl
                | StoreError::StateTooLarge
                | StoreError::InvalidIdentifier
                | StoreError::StateTypeMismatch => PublicAuthCode::AuthenticationFailed,
            },
            Self::MissingLoginState => PublicAuthCode::AuthenticationFailed,
            Self::InvalidServerKeyId | Self::InvalidServerKeySet => {
                PublicAuthCode::TemporarilyUnavailable
            }
        }
    }
}

impl core::fmt::Display for ServerAuthError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Auth(error) => return error.fmt(formatter),
            Self::Store(error) => return error.fmt(formatter),
            Self::MissingLoginState => "missing or expired login state",
            Self::InvalidServerKeyId => "invalid server key identifier",
            Self::InvalidServerKeySet => "invalid server key set",
        })
    }
}

impl std::error::Error for ServerAuthError {}

/// Transport-neutral OPAQUE server flow bound to a one-time state backend.
pub struct ServerAuthService<S> {
    setup: ServerSetupBytes,
    server_key_id: String,
    accepted_server_key_ids: Vec<String>,
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
        Self::new_with_key_rotation(setup, server_key_id, &[], state_store)
    }

    /// Creates a service with an active key and an optional previous-key
    /// acceptance window.
    ///
    /// Start messages may use the active or previous IDs. All service
    /// responses use the active ID, and login finalization requires the active
    /// ID. This makes rotation explicit without silently accepting a
    /// downgraded finalization message.
    ///
    /// # Errors
    ///
    /// Returns [`ServerAuthError::InvalidServerKeyId`] for an invalid active
    /// key, or [`ServerAuthError::InvalidServerKeySet`] for duplicate,
    /// invalid, or excessive previous keys.
    pub fn new_with_key_rotation(
        setup: ServerSetupBytes,
        active_server_key_id: impl Into<String>,
        previous_server_key_ids: &[&str],
        state_store: S,
    ) -> Result<Self, ServerAuthError> {
        let active_server_key_id = active_server_key_id.into();
        validate_server_key_id(&active_server_key_id)
            .map_err(|()| ServerAuthError::InvalidServerKeyId)?;
        if previous_server_key_ids.len() + 1 > MAX_SERVER_KEY_IDS {
            return Err(ServerAuthError::InvalidServerKeySet);
        }
        let mut accepted_server_key_ids = Vec::with_capacity(previous_server_key_ids.len() + 1);
        accepted_server_key_ids.push(active_server_key_id.clone());
        for previous_server_key_id in previous_server_key_ids {
            validate_server_key_id(previous_server_key_id)
                .map_err(|()| ServerAuthError::InvalidServerKeySet)?;
            if accepted_server_key_ids
                .iter()
                .any(|accepted| accepted == previous_server_key_id)
            {
                return Err(ServerAuthError::InvalidServerKeySet);
            }
            accepted_server_key_ids.push((*previous_server_key_id).to_owned());
        }
        Ok(Self {
            setup,
            server_key_id: active_server_key_id,
            accepted_server_key_ids,
            state_store,
        })
    }

    fn accepted_server_key_refs(&self) -> Vec<&str> {
        self.accepted_server_key_ids
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// Processes a client registration request and returns the response
    /// envelope.
    ///
    /// The credential identifier is public account metadata. The password is
    /// handled only by the client-side native OPAQUE boundary and never enters
    /// this server service API.
    ///
    /// # Errors
    ///
    /// Returns an authentication or envelope validation error.
    pub fn begin_registration(
        &self,
        request: AuthEnvelope,
        credential_identifier: &[u8],
    ) -> Result<AuthEnvelope, ServerAuthError> {
        let accepted_server_key_ids = self.accepted_server_key_refs();
        let request = request.into_message_for_server_keys(
            AuthMessageKind::RegistrationRequest,
            &accepted_server_key_ids,
        )?;
        let response = server_registration_start(&self.setup, &request, credential_identifier)?;
        AuthEnvelope::new(
            AuthMessageKind::RegistrationResponse,
            &self.server_key_id,
            &response,
        )
        .map_err(ServerAuthError::from)
    }

    /// Consumes a client registration upload into a protected credential file.
    ///
    /// The returned credential file is password-equivalent server secret
    /// material and must be encrypted or access-controlled by the application.
    ///
    /// # Errors
    ///
    /// Returns an authentication or envelope validation error.
    pub fn finish_registration(
        &self,
        upload: AuthEnvelope,
    ) -> Result<CredentialFile, ServerAuthError> {
        let upload =
            upload.into_message(AuthMessageKind::RegistrationUpload, &self.server_key_id)?;
        server_registration_finish(&upload).map_err(ServerAuthError::from)
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
        let accepted_server_key_ids = self.accepted_server_key_refs();
        let request = request.into_message_for_server_keys(
            AuthMessageKind::CredentialRequest,
            &accepted_server_key_ids,
        )?;
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

fn validate_server_key_id(server_key_id: &str) -> Result<(), ()> {
    if server_key_id.is_empty() || server_key_id.len() > MAX_SERVER_KEY_ID_BYTES {
        return Err(());
    }
    Ok(())
}
