#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Native/server OPAQUE protocol boundary.
//!
//! This crate accepts password bytes only inside native or server Rust code.
//! Framework adapters must not bind these APIs directly to JavaScript, Dart,
//! or ordinary UI state. Use the secure keypad submission boundary to invoke
//! this engine inside the native layer.

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Stable protocol version for this SDK surface.
pub const PROTOCOL_VERSION: u16 = 1;
/// Stable cipher-suite identifier for persistence and downgrade checks.
pub const CIPHER_SUITE_ID: &str = "opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2";
/// Maximum encoded OPAQUE payload accepted by the transport contract.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum JSON request body accepted before deserialization begins.
pub const MAX_JSON_BODY_BYTES: usize = 128 * 1024;
/// Maximum serialized server setup accepted by the persistence boundary.
pub const MAX_SERVER_SETUP_BYTES: usize = MAX_MESSAGE_BYTES;
/// Maximum serialized credential file accepted by the persistence boundary.
pub const MAX_CREDENTIAL_FILE_BYTES: usize = MAX_MESSAGE_BYTES;
/// Maximum size of a public client, server, or credential identifier.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Version of the serialized server-login state container.
pub const SERVER_LOGIN_STATE_VERSION: u16 = 1;
/// Maximum serialized server-login state accepted before protocol decoding.
pub const MAX_SERVER_LOGIN_STATE_BYTES: usize = MAX_MESSAGE_BYTES + 6 + CIPHER_SUITE_ID.len();
/// Maximum size of the public server key identifier.
pub const MAX_SERVER_KEY_ID_BYTES: usize = 128;
const MAX_SUITE_ID_BYTES: usize = 128;
const SERVER_LOGIN_STATE_MAGIC: &[u8; 4] = b"SKLS";

/// OPAQUE cipher suite used by this SDK.
pub struct SecureSuite;

impl CipherSuite for SecureSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}

/// An encoded OPAQUE message. Messages are not passwords, but must still be
/// treated as sensitive transport data and never logged.
pub struct Message(Vec<u8>);

impl Message {
    /// Copies a bounded, non-empty protocol message from transport bytes.
    ///
    /// The bound is applied before allocation so an untrusted transport buffer
    /// cannot create an arbitrarily large sensitive message container.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::EmptyMessage`] for an empty buffer or
    /// [`AuthError::MessageTooLarge`] when the buffer exceeds
    /// [`MAX_MESSAGE_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() {
            return Err(AuthError::EmptyMessage);
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(AuthError::MessageTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns transport bytes for an HTTPS request body.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn message_from_serialized<T>(mut serialized: T) -> Result<Message, AuthError>
where
    T: AsRef<[u8]> + Zeroize,
{
    let mut bytes = copy_and_zeroize_serialized(&mut serialized);
    if bytes.is_empty() {
        bytes.zeroize();
        return Err(AuthError::EmptyMessage);
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        bytes.zeroize();
        return Err(AuthError::MessageTooLarge);
    }
    Ok(Message(bytes))
}

fn copy_and_zeroize_serialized<T>(serialized: &mut T) -> Vec<u8>
where
    T: AsRef<[u8]> + Zeroize,
{
    let bytes = serialized.as_ref().to_vec();
    serialized.zeroize();
    bytes
}

impl Drop for Message {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The OPAQUE message type carried by the versioned transport envelope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthMessageKind {
    /// Client-to-server registration request.
    RegistrationRequest,
    /// Server-to-client registration response.
    RegistrationResponse,
    /// Client-to-server registration upload.
    RegistrationUpload,
    /// Client-to-server login request.
    CredentialRequest,
    /// Server-to-client login response.
    CredentialResponse,
    /// Client-to-server login finalization.
    CredentialFinalization,
}

/// Versioned, typed OPAQUE transport data.
///
/// The payload is sensitive protocol data and must use HTTPS/TLS and protected
/// logging/storage policies. This envelope rejects unsupported versions,
/// suites, message kinds, and server key IDs before a protocol state machine
/// consumes the payload. It does not itself provide replay storage, rate
/// limiting, TLS, or session-token issuance. Its [`core::fmt::Debug`] output
/// is intentionally redacted and contains only public metadata plus payload
/// length.
#[derive(Serialize)]
pub struct AuthEnvelope {
    protocol_version: u16,
    suite_id: String,
    message_kind: AuthMessageKind,
    server_key_id: String,
    payload: Vec<u8>,
}

impl core::fmt::Debug for AuthEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("suite_id", &self.suite_id)
            .field("message_kind", &self.message_kind)
            .field("server_key_id", &self.server_key_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthEnvelopeWire {
    protocol_version: u16,
    suite_id: String,
    message_kind: AuthMessageKind,
    server_key_id: String,
    payload: BoundedPayload,
}

struct BoundedPayload(Vec<u8>);

impl<'de> Deserialize<'de> for BoundedPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedPayloadVisitor;

        impl<'de> Visitor<'de> for BoundedPayloadVisitor {
            type Value = BoundedPayload;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("an authentication payload no larger than 16 KiB")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if bytes.len() > MAX_MESSAGE_BYTES {
                    return Err(E::custom("auth message too large"));
                }
                Ok(BoundedPayload(bytes.to_vec()))
            }

            fn visit_byte_buf<E>(self, mut bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if bytes.len() > MAX_MESSAGE_BYTES {
                    bytes.zeroize();
                    return Err(E::custom("auth message too large"));
                }
                Ok(BoundedPayload(bytes))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                loop {
                    let next = sequence.next_element::<u8>();
                    let byte = match next {
                        Ok(Some(byte)) => byte,
                        Ok(None) => return Ok(BoundedPayload(bytes)),
                        Err(error) => {
                            bytes.zeroize();
                            return Err(error);
                        }
                    };
                    if bytes.len() == MAX_MESSAGE_BYTES {
                        bytes.zeroize();
                        return Err(de::Error::custom("auth message too large"));
                    }
                    bytes.push(byte);
                }
            }
        }

        deserializer.deserialize_bytes(BoundedPayloadVisitor)
    }
}

impl Drop for BoundedPayload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for AuthEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthEnvelopeWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.protocol_version,
            &wire.suite_id,
            wire.message_kind,
            &wire.server_key_id,
            &wire.payload.0,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AuthEnvelope {
    /// Creates an envelope for the current protocol version and suite.
    ///
    /// # Errors
    ///
    /// Returns a transport validation error for an empty or oversized payload
    /// or an invalid server key identifier.
    pub fn new(
        message_kind: AuthMessageKind,
        server_key_id: &str,
        message: &Message,
    ) -> Result<Self, AuthError> {
        Self::from_parts(
            PROTOCOL_VERSION,
            CIPHER_SUITE_ID,
            message_kind,
            server_key_id,
            message.as_bytes(),
        )
    }

    /// Creates an envelope from decoded transport metadata.
    ///
    /// Unsupported versions and suites are retained so [`Self::into_message`]
    /// can return an explicit downgrade error at the protocol boundary.
    ///
    /// # Errors
    ///
    /// Returns a transport validation error for invalid metadata or payload
    /// size.
    pub fn from_parts(
        protocol_version: u16,
        suite_id: &str,
        message_kind: AuthMessageKind,
        server_key_id: &str,
        payload: &[u8],
    ) -> Result<Self, AuthError> {
        if suite_id.is_empty() || suite_id.len() > MAX_SUITE_ID_BYTES {
            return Err(AuthError::InvalidArgument);
        }
        if server_key_id.is_empty() || server_key_id.len() > MAX_SERVER_KEY_ID_BYTES {
            return Err(AuthError::InvalidArgument);
        }
        if payload.is_empty() {
            return Err(AuthError::EmptyMessage);
        }
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(AuthError::MessageTooLarge);
        }
        Ok(Self {
            protocol_version,
            suite_id: suite_id.to_owned(),
            message_kind,
            server_key_id: server_key_id.to_owned(),
            payload: payload.to_vec(),
        })
    }

    /// Decodes a bounded JSON request body into a validated envelope.
    ///
    /// The body limit is checked before JSON parsing. The decoded envelope is
    /// then validated through the same path as [`Self::from_parts`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RequestBodyTooLarge`] when the raw body exceeds
    /// [`MAX_JSON_BODY_BYTES`], or [`AuthError::MalformedTransport`] when the
    /// body is not a valid, bounded envelope.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > MAX_JSON_BODY_BYTES {
            return Err(AuthError::RequestBodyTooLarge);
        }
        serde_json::from_slice(bytes).map_err(|_| AuthError::MalformedTransport)
    }

    /// Returns the envelope protocol version without inspecting the payload.
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the suite identifier used for downgrade checks.
    #[must_use]
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    /// Returns the public server key identifier.
    #[must_use]
    pub fn server_key_id(&self) -> &str {
        &self.server_key_id
    }

    /// Returns the typed message kind.
    #[must_use]
    pub fn message_kind(&self) -> AuthMessageKind {
        self.message_kind
    }

    /// Validates metadata and consumes the payload into a protocol message.
    ///
    /// # Errors
    ///
    /// Returns an explicit error when the envelope does not match the current
    /// version, suite, expected message kind, or server key ID.
    pub fn into_message(
        self,
        expected_kind: AuthMessageKind,
        expected_server_key_id: &str,
    ) -> Result<Message, AuthError> {
        self.into_message_for_server_keys(expected_kind, &[expected_server_key_id])
    }

    /// Validates metadata and consumes the payload when the server key ID is
    /// in an explicitly accepted key set.
    ///
    /// This is intended for controlled key rotation. Applications should
    /// accept previous IDs only for inbound start messages and emit the active
    /// ID on responses; finalization should normally require the active ID.
    ///
    /// # Errors
    ///
    /// Returns an explicit error when the envelope does not match the current
    /// version, suite, expected message kind, or any accepted server key ID.
    pub fn into_message_for_server_keys(
        mut self,
        expected_kind: AuthMessageKind,
        accepted_server_key_ids: &[&str],
    ) -> Result<Message, AuthError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(AuthError::UnsupportedVersion);
        }
        if self.suite_id != CIPHER_SUITE_ID {
            return Err(AuthError::UnsupportedSuite);
        }
        if self.message_kind != expected_kind {
            return Err(AuthError::UnexpectedMessageKind);
        }
        if !accepted_server_key_ids.contains(&self.server_key_id.as_str()) {
            return Err(AuthError::UnexpectedServerKey);
        }
        Ok(Message(std::mem::take(&mut self.payload)))
    }
}

impl Drop for AuthEnvelope {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Serialized server setup. Store it in a server secret store, not in a
/// client bundle or ordinary application configuration.
pub struct ServerSetupBytes(Vec<u8>);

impl Drop for ServerSetupBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ServerSetupBytes {
    /// Generates a new server setup using the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidSetup`] if the generated setup cannot be
    /// serialized by the pinned OPAQUE implementation.
    pub fn generate() -> Result<Self, AuthError> {
        let mut rng = OsRng;
        let setup = ServerSetup::<SecureSuite>::new(&mut rng);
        let mut serialized = setup.serialize();
        let mut bytes = copy_and_zeroize_serialized(&mut serialized);
        if bytes.is_empty() || bytes.len() > MAX_SERVER_SETUP_BYTES {
            bytes.zeroize();
            return Err(AuthError::InvalidSetup);
        }
        Ok(Self(bytes))
    }

    /// Restores a setup previously generated by this exact protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidSetup`] when the bytes fail validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() || bytes.len() > MAX_SERVER_SETUP_BYTES {
            return Err(AuthError::InvalidSetup);
        }
        ServerSetup::<SecureSuite>::deserialize(bytes).map_err(|_| AuthError::InvalidSetup)?;
        Ok(Self(bytes.to_vec()))
    }

    fn decode(&self) -> Result<ServerSetup<SecureSuite>, AuthError> {
        ServerSetup::<SecureSuite>::deserialize(&self.0).map_err(|_| AuthError::InvalidSetup)
    }

    /// Returns serialized setup bytes for secret-store persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A server-side OPAQUE credential file. It is password-equivalent sensitive
/// material and must be encrypted or access-controlled at rest.
pub struct CredentialFile(Vec<u8>);

impl Drop for CredentialFile {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl CredentialFile {
    /// Restores a credential file after checking its encoding.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidCredentialFile`] when the bytes fail validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_FILE_BYTES {
            return Err(AuthError::InvalidCredentialFile);
        }
        ServerRegistration::<SecureSuite>::deserialize(bytes)
            .map_err(|_| AuthError::InvalidCredentialFile)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Returns serialized credential bytes for protected server storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn decode(&self) -> Result<ServerRegistration<SecureSuite>, AuthError> {
        ServerRegistration::<SecureSuite>::deserialize(&self.0)
            .map_err(|_| AuthError::InvalidCredentialFile)
    }
}

/// A secret output from OPAQUE, such as a session key or export key.
pub struct SecretOutput(Vec<u8>);

impl SecretOutput {
    /// Returns the length without revealing secret bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this output is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Compares two outputs in constant time.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Provides bytes to native/server cryptographic code for immediate use.
    ///
    /// The callback intentionally returns `()`, so this public handoff cannot
    /// return a secret slice or a copied secret value to its caller.
    ///
    /// This method must not be exposed through a framework bridge or used to
    /// create logs, strings, JSON, analytics fields, or persistent plaintext.
    pub fn with_bytes(&self, operation: impl FnOnce(&[u8])) {
        operation(&self.0);
    }
}

impl Drop for SecretOutput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Client state retained between the first and second registration messages.
pub struct ClientRegistrationState(ClientRegistration<SecureSuite>);
/// Client state retained between the first and second login messages.
pub struct ClientLoginState(ClientLogin<SecureSuite>);
/// Server state retained between the first and second login messages.
pub struct ServerLoginState(ServerLogin<SecureSuite>);

/// Zeroizing serialized server login state for a one-use HTTP/session store.
///
/// The application store must atomically remove the bytes before calling
/// [`Self::into_state`]. Serialization makes distributed storage possible; it
/// does not provide replay protection by itself.
pub struct ServerLoginStateBytes(Vec<u8>);

impl ServerLoginState {
    /// Consumes the live state into zeroizing bytes suitable for protected
    /// short-lived storage.
    #[must_use]
    pub fn into_bytes(self) -> ServerLoginStateBytes {
        let mut serialized = self.0.serialize();
        let serialized = copy_and_zeroize_serialized(&mut serialized);
        let suite_id = CIPHER_SUITE_ID.as_bytes();
        let mut bytes = Vec::with_capacity(6 + suite_id.len() + serialized.len());
        bytes.extend_from_slice(SERVER_LOGIN_STATE_MAGIC);
        bytes.extend_from_slice(&SERVER_LOGIN_STATE_VERSION.to_le_bytes());
        bytes.extend_from_slice(suite_id);
        bytes.extend_from_slice(&serialized);
        ServerLoginStateBytes(bytes)
    }
}

impl ServerLoginStateBytes {
    /// Copies bounded serialized state bytes into a zeroizing container.
    ///
    /// The size check happens before allocation so an untrusted one-time-store
    /// record cannot create an arbitrarily large sensitive buffer.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::EmptyMessage`] for an empty record or
    /// [`AuthError::MessageTooLarge`] when the record exceeds
    /// [`MAX_SERVER_LOGIN_STATE_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() {
            return Err(AuthError::EmptyMessage);
        }
        if bytes.len() > MAX_SERVER_LOGIN_STATE_BYTES {
            return Err(AuthError::MessageTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrows the serialized state for an application-owned atomic store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes and zeroizes the serialized state while restoring the live
    /// server state.
    ///
    /// # Errors
    ///
    /// Returns a transport or protocol error when the state header or bytes
    /// are malformed, unsupported, empty, or oversized.
    pub fn into_state(mut self) -> Result<ServerLoginState, AuthError> {
        let result = decode_server_login_state(&self.0).and_then(|bytes| {
            ServerLogin::<SecureSuite>::deserialize(bytes)
                .map(ServerLoginState)
                .map_err(|_| AuthError::Protocol)
        });
        self.0.zeroize();
        result
    }
}

impl Drop for ServerLoginStateBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn decode_server_login_state(bytes: &[u8]) -> Result<&[u8], AuthError> {
    let header_length = 6usize
        .checked_add(CIPHER_SUITE_ID.len())
        .ok_or(AuthError::Protocol)?;
    if bytes.len() < header_length || &bytes[..4] != SERVER_LOGIN_STATE_MAGIC {
        return Err(AuthError::Protocol);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != SERVER_LOGIN_STATE_VERSION {
        return Err(AuthError::UnsupportedVersion);
    }
    if &bytes[6..header_length] != CIPHER_SUITE_ID.as_bytes() {
        return Err(AuthError::UnsupportedSuite);
    }
    let state = &bytes[header_length..];
    if state.is_empty() {
        return Err(AuthError::EmptyMessage);
    }
    if state.len() > MAX_MESSAGE_BYTES {
        return Err(AuthError::MessageTooLarge);
    }
    Ok(state)
}

/// Native-only client login state that retains the sealed keypad submission
/// until the second OPAQUE message. Never expose this type through a framework
/// bridge.
pub struct NativeClientLoginState {
    state: Option<ClientLogin<SecureSuite>>,
    submission: Option<secure_core::Submission>,
}

/// Native-only client registration state that retains the sealed keypad
/// submission until the second OPAQUE message. Never expose this type through a
/// framework bridge.
pub struct NativeClientRegistrationState {
    state: Option<ClientRegistration<SecureSuite>>,
    submission: Option<secure_core::Submission>,
}

/// Errors that never include password or secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// A protocol message failed validation.
    Protocol,
    /// A setup blob failed validation.
    InvalidSetup,
    /// A credential file failed validation.
    InvalidCredentialFile,
    /// Authentication proof verification failed.
    InvalidLogin,
    /// A required transport argument is invalid.
    InvalidArgument,
    /// The raw JSON request body exceeds [`MAX_JSON_BODY_BYTES`].
    RequestBodyTooLarge,
    /// The request body is not a valid validated transport envelope.
    MalformedTransport,
    /// The envelope payload is empty.
    EmptyMessage,
    /// The envelope payload exceeds [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// The envelope uses an unsupported protocol version.
    UnsupportedVersion,
    /// The envelope uses an unsupported cipher suite.
    UnsupportedSuite,
    /// The envelope message kind is not the one expected by the state machine.
    UnexpectedMessageKind,
    /// The envelope server key ID does not match the active key.
    UnexpectedServerKey,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Protocol => "opaque protocol error",
            Self::InvalidSetup => "invalid server setup",
            Self::InvalidCredentialFile => "invalid credential file",
            Self::InvalidLogin => "invalid login",
            Self::InvalidArgument => "invalid auth argument",
            Self::RequestBodyTooLarge => "auth request body too large",
            Self::MalformedTransport => "malformed auth transport",
            Self::EmptyMessage => "empty auth message",
            Self::MessageTooLarge => "auth message too large",
            Self::UnsupportedVersion => "unsupported auth protocol version",
            Self::UnsupportedSuite => "unsupported auth suite",
            Self::UnexpectedMessageKind => "unexpected auth message kind",
            Self::UnexpectedServerKey => "unexpected auth server key",
        })
    }
}

impl std::error::Error for AuthError {}

fn validate_identifier(identifier: &[u8]) -> Result<(), AuthError> {
    if identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(AuthError::InvalidArgument);
    }
    Ok(())
}

fn validate_identifiers(identifiers: &[&[u8]]) -> Result<(), AuthError> {
    identifiers
        .iter()
        .try_for_each(|identifier| validate_identifier(identifier))
}

/// Starts client registration. The password is borrowed only for the protocol call.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] when the pinned OPAQUE implementation rejects
/// the password input or cannot create a registration request.
pub fn client_registration_start(
    password: &[u8],
) -> Result<(ClientRegistrationState, Message), AuthError> {
    let mut rng = OsRng;
    let result = ClientRegistration::<SecureSuite>::start(&mut rng, password)
        .map_err(|_| AuthError::Protocol)?;
    Ok((
        ClientRegistrationState(result.state),
        message_from_serialized(result.message.serialize())?,
    ))
}

/// Starts server registration for a public credential identifier.
///
/// # Errors
///
/// Returns [`AuthError::InvalidSetup`] for an invalid setup or
/// [`AuthError::Protocol`] for an invalid request.
pub fn server_registration_start(
    setup: &ServerSetupBytes,
    request: &Message,
    credential_identifier: &[u8],
) -> Result<Message, AuthError> {
    validate_identifier(credential_identifier)?;
    let setup = setup.decode()?;
    let request = RegistrationRequest::<SecureSuite>::deserialize(request.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let result = ServerRegistration::<SecureSuite>::start(&setup, request, credential_identifier)
        .map_err(|_| AuthError::Protocol)?;
    message_from_serialized(result.message.serialize())
}

/// Finishes client registration and returns the upload and client export key.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] if the response or registration state fails
/// the pinned OPAQUE checks.
pub fn client_registration_finish(
    state: ClientRegistrationState,
    password: &[u8],
    response: &Message,
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<(Message, SecretOutput), AuthError> {
    validate_identifiers(&[client_identifier, server_identifier])?;
    let response = RegistrationResponse::<SecureSuite>::deserialize(response.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let mut rng = OsRng;
    let result = state
        .0
        .finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: Some(client_identifier),
                    server: Some(server_identifier),
                },
                None,
            ),
        )
        .map_err(|_| AuthError::Protocol)?;
    Ok((
        message_from_serialized(result.message.serialize())?,
        SecretOutput(result.export_key.to_vec()),
    ))
}

/// Starts client registration directly from a secure keypad submission.
///
/// The password never crosses this API as a framework-owned byte or string.
/// The returned state retains the native submission until registration finish.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] when the pinned OPAQUE implementation cannot
/// create a registration request.
pub fn client_registration_start_from_submission(
    submission: secure_core::Submission,
) -> Result<(NativeClientRegistrationState, Message), AuthError> {
    let mut rng = OsRng;
    let result = {
        let mut result = None;
        submission.with_native_bytes(|password| {
            result = Some(ClientRegistration::<SecureSuite>::start(&mut rng, password));
        });
        result.ok_or(AuthError::Protocol)?
    }
    .map_err(|_| AuthError::Protocol)?;
    Ok((
        NativeClientRegistrationState {
            state: Some(result.state),
            submission: Some(submission),
        },
        message_from_serialized(result.message.serialize())?,
    ))
}

/// Finishes native-only client registration without returning the password to
/// the caller.
///
/// The returned export key is immediately owned by Rust and must not be exposed
/// through a framework bridge. The upload is an opaque transport message and
/// must use the native protected transport path.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] when the response, state, or identifiers are
/// invalid.
pub fn client_registration_finish_from_native_state(
    mut state: NativeClientRegistrationState,
    response: &Message,
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<(Message, SecretOutput), AuthError> {
    validate_identifiers(&[client_identifier, server_identifier])?;
    let response = RegistrationResponse::<SecureSuite>::deserialize(response.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let mut rng = OsRng;
    let registration_state = state.state.take().ok_or(AuthError::Protocol)?;
    let submission = state.submission.take().ok_or(AuthError::Protocol)?;
    let result = {
        let mut result = None;
        submission.with_native_bytes(|password| {
            result = Some(registration_state.finish(
                &mut rng,
                password,
                response,
                ClientRegistrationFinishParameters::new(
                    Identifiers {
                        client: Some(client_identifier),
                        server: Some(server_identifier),
                    },
                    None,
                ),
            ));
        });
        result.ok_or(AuthError::Protocol)?
    }
    .map_err(|_| AuthError::Protocol)?;
    Ok((
        message_from_serialized(result.message.serialize())?,
        SecretOutput(result.export_key.to_vec()),
    ))
}

/// Finalizes a server credential file from the client upload.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] if the upload is malformed.
pub fn server_registration_finish(upload: &Message) -> Result<CredentialFile, AuthError> {
    let upload = RegistrationUpload::<SecureSuite>::deserialize(upload.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let file = ServerRegistration::<SecureSuite>::finish(upload);
    let mut serialized = file.serialize();
    let mut bytes = copy_and_zeroize_serialized(&mut serialized);
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_FILE_BYTES {
        bytes.zeroize();
        return Err(AuthError::InvalidCredentialFile);
    }
    Ok(CredentialFile(bytes))
}

/// Starts client login.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] when the pinned OPAQUE implementation cannot
/// create a login request.
pub fn client_login_start(password: &[u8]) -> Result<(ClientLoginState, Message), AuthError> {
    let mut rng = OsRng;
    let result =
        ClientLogin::<SecureSuite>::start(&mut rng, password).map_err(|_| AuthError::Protocol)?;
    Ok((
        ClientLoginState(result.state),
        message_from_serialized(result.message.serialize())?,
    ))
}

/// Starts client login directly from a secure keypad submission.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] when the pinned OPAQUE implementation cannot
/// create a login request.
pub fn client_login_start_from_submission(
    submission: secure_core::Submission,
) -> Result<(NativeClientLoginState, Message), AuthError> {
    let mut rng = OsRng;
    let result = {
        let mut result = None;
        submission.with_native_bytes(|password| {
            result = Some(ClientLogin::<SecureSuite>::start(&mut rng, password));
        });
        result.ok_or(AuthError::Protocol)?
    }
    .map_err(|_| AuthError::Protocol)?;
    Ok((
        NativeClientLoginState {
            state: Some(result.state),
            submission: Some(submission),
        },
        message_from_serialized(result.message.serialize())?,
    ))
}

/// Starts server login. Pass `None` for a missing user to keep enumeration
/// behavior indistinguishable from a registered user.
///
/// # Errors
///
/// Returns [`AuthError::InvalidSetup`], [`AuthError::InvalidCredentialFile`], or
/// [`AuthError::Protocol`] when setup, credential, or request validation fails.
pub fn server_login_start(
    setup: &ServerSetupBytes,
    credential_file: Option<&CredentialFile>,
    request: &Message,
    credential_identifier: &[u8],
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<(Message, ServerLoginState), AuthError> {
    validate_identifiers(&[credential_identifier, client_identifier, server_identifier])?;
    let setup = setup.decode()?;
    let credential_file = credential_file.map(CredentialFile::decode).transpose()?;
    let request = CredentialRequest::<SecureSuite>::deserialize(request.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let mut rng = OsRng;
    let result = ServerLogin::<SecureSuite>::start(
        &mut rng,
        &setup,
        credential_file,
        request,
        credential_identifier,
        ServerLoginParameters {
            context: None,
            identifiers: Identifiers {
                client: Some(client_identifier),
                server: Some(server_identifier),
            },
        },
    )
    .map_err(|_| AuthError::Protocol)?;
    Ok((
        message_from_serialized(result.message.serialize())?,
        ServerLoginState(result.state),
    ))
}

/// Finishes client login and returns finalization plus the client session key.
///
/// # Errors
///
/// Returns [`AuthError::InvalidLogin`] when the password proof is invalid, or
/// [`AuthError::Protocol`] when the response is malformed.
pub fn client_login_finish(
    state: ClientLoginState,
    password: &[u8],
    response: &Message,
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<(Message, SecretOutput), AuthError> {
    validate_identifiers(&[client_identifier, server_identifier])?;
    let response = CredentialResponse::<SecureSuite>::deserialize(response.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let mut rng = OsRng;
    let result = state
        .0
        .finish(
            &mut rng,
            password,
            response,
            ClientLoginFinishParameters::new(
                None,
                Identifiers {
                    client: Some(client_identifier),
                    server: Some(server_identifier),
                },
                None,
            ),
        )
        .map_err(|_| AuthError::InvalidLogin)?;
    Ok((
        message_from_serialized(result.message.serialize())?,
        SecretOutput(result.session_key.to_vec()),
    ))
}

/// Finishes a native-only login without returning the password to the caller.
///
/// # Errors
///
/// Returns [`AuthError::InvalidLogin`] when the password proof is invalid, or
/// [`AuthError::Protocol`] when the response is malformed.
pub fn client_login_finish_from_native_state(
    mut state: NativeClientLoginState,
    response: &Message,
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<(Message, SecretOutput), AuthError> {
    validate_identifiers(&[client_identifier, server_identifier])?;
    let response = CredentialResponse::<SecureSuite>::deserialize(response.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let mut rng = OsRng;
    let login_state = state.state.take().ok_or(AuthError::InvalidLogin)?;
    let submission = state.submission.take().ok_or(AuthError::InvalidLogin)?;
    let result = {
        let mut result = None;
        submission.with_native_bytes(|password| {
            result = Some(login_state.finish(
                &mut rng,
                password,
                response,
                ClientLoginFinishParameters::new(
                    None,
                    Identifiers {
                        client: Some(client_identifier),
                        server: Some(server_identifier),
                    },
                    None,
                ),
            ));
        });
        result.ok_or(AuthError::InvalidLogin)?
    }
    .map_err(|_| AuthError::InvalidLogin)?;
    Ok((
        message_from_serialized(result.message.serialize())?,
        SecretOutput(result.session_key.to_vec()),
    ))
}

/// Finishes server login and returns the server session key.
///
/// # Errors
///
/// Returns [`AuthError::InvalidLogin`] when client proof verification fails, or
/// [`AuthError::Protocol`] when the finalization message is malformed.
pub fn server_login_finish(
    state: ServerLoginState,
    finalization: &Message,
    client_identifier: &[u8],
    server_identifier: &[u8],
) -> Result<SecretOutput, AuthError> {
    validate_identifiers(&[client_identifier, server_identifier])?;
    let finalization = CredentialFinalization::<SecureSuite>::deserialize(finalization.as_bytes())
        .map_err(|_| AuthError::Protocol)?;
    let result = state
        .0
        .finish(
            finalization,
            ServerLoginParameters {
                context: None,
                identifiers: Identifiers {
                    client: Some(client_identifier),
                    server: Some(server_identifier),
                },
            },
        )
        .map_err(|_| AuthError::InvalidLogin)?;
    Ok(SecretOutput(result.session_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::copy_and_zeroize_serialized;
    use zeroize::Zeroize;

    struct SensitiveSerialized(Vec<u8>);

    impl AsRef<[u8]> for SensitiveSerialized {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Zeroize for SensitiveSerialized {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    #[test]
    fn serialized_message_source_is_zeroized_after_copying() {
        let mut serialized = SensitiveSerialized(vec![1, 2, 3, 4]);
        let bytes = copy_and_zeroize_serialized(&mut serialized);

        assert_eq!(bytes, &[1, 2, 3, 4]);
        assert!(serialized.0.iter().all(|byte| *byte == 0));
    }
}
