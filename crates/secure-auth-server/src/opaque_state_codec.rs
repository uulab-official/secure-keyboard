use crate::{BoundLoginState, StoreError, MAX_STORED_STATE_BYTES};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use secure_auth::ServerLoginStateBytes;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const RECORD_MAGIC: &[u8; 4] = b"SKBS";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 4 + 2 + 4 + 2 + 2;
const PROTECTED_MAGIC: &[u8; 4] = b"SKPE";
const PROTECTED_VERSION: u16 = 1;
const PROTECTED_HEADER_BYTES: usize = 4 + 2 + 12;
const PROTECTED_TAG_BYTES: usize = 16;
const PROTECTED_AAD: &[u8] = b"secure-keypad:opaque-login-state:v1";

/// Maximum encoded durable record accepted by distributed one-time stores.
pub const MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES: usize = 32 * 1024;
/// Maximum encrypted durable record size, including the protection header and tag.
pub const MAX_DISTRIBUTED_LOGIN_STATE_STORAGE_BYTES: usize =
    PROTECTED_HEADER_BYTES + PROTECTED_TAG_BYTES + MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES;
const MAX_PROTECTED_RECORD_BYTES: usize = MAX_DISTRIBUTED_LOGIN_STATE_STORAGE_BYTES;

/// A 32-byte at-rest encryption key for distributed OPAQUE login state.
///
/// Keep this value in a secret manager or KMS-backed configuration. It has no
/// byte getter or `Debug` implementation so it cannot be accidentally logged.
pub struct OpaqueStateKey(Zeroizing<[u8; 32]>);

impl OpaqueStateKey {
    /// Restores a key only when the representation is exactly 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(Zeroizing::new(bytes.try_into().ok()?)))
    }

    /// Generates a key with the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }
}

#[derive(Clone)]
pub(crate) struct StateProtector {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl StateProtector {
    pub(crate) fn new(key: OpaqueStateKey) -> Self {
        Self {
            key: Arc::new(key.0),
        }
    }

    fn cipher(&self) -> Aes256Gcm {
        let Ok(cipher) = Aes256Gcm::new_from_slice(&self.key[..]) else {
            unreachable!("a fixed 32-byte key always initializes AES-256-GCM");
        };
        cipher
    }

    pub(crate) fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if plaintext.is_empty() || plaintext.len() > MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES {
            return Err(StoreError::StateTooLarge);
        }
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        self.cipher()
            .encrypt_in_place(Nonce::from_slice(&nonce), PROTECTED_AAD, &mut *ciphertext)
            .map_err(|_| StoreError::Unavailable)?;
        let total = PROTECTED_HEADER_BYTES
            .checked_add(ciphertext.len())
            .ok_or(StoreError::StateTooLarge)?;
        if total > MAX_PROTECTED_RECORD_BYTES {
            return Err(StoreError::StateTooLarge);
        }
        let mut protected = Vec::with_capacity(total);
        protected.extend_from_slice(PROTECTED_MAGIC);
        protected.extend_from_slice(&PROTECTED_VERSION.to_le_bytes());
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        Ok(Zeroizing::new(protected))
    }

    pub(crate) fn open(&self, protected: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let protected = Zeroizing::new(protected);
        if protected.len() < PROTECTED_HEADER_BYTES + PROTECTED_TAG_BYTES
            || protected.len() > MAX_PROTECTED_RECORD_BYTES
            || &protected[..4] != PROTECTED_MAGIC
            || u16::from_le_bytes(
                protected[4..6]
                    .try_into()
                    .map_err(|_| StoreError::Unavailable)?,
            ) != PROTECTED_VERSION
        {
            return Err(StoreError::Unavailable);
        }
        let nonce = Nonce::from_slice(&protected[6..PROTECTED_HEADER_BYTES]);
        let mut ciphertext = Zeroizing::new(protected[PROTECTED_HEADER_BYTES..].to_vec());
        self.cipher()
            .decrypt_in_place(nonce, PROTECTED_AAD, &mut *ciphertext)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Zeroizing::new(core::mem::take(&mut *ciphertext)))
    }
}

pub(crate) fn encode_bound_state(state: BoundLoginState) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let (state, client_identifier, server_identifier) = state.into_parts();
    let state_bytes = state.as_bytes();
    let client_len =
        u16::try_from(client_identifier.len()).map_err(|_| StoreError::StateTooLarge)?;
    let server_len =
        u16::try_from(server_identifier.len()).map_err(|_| StoreError::StateTooLarge)?;
    let total = RECORD_HEADER_BYTES
        .checked_add(state_bytes.len())
        .and_then(|length| length.checked_add(client_identifier.len()))
        .and_then(|length| length.checked_add(server_identifier.len()))
        .ok_or(StoreError::StateTooLarge)?;
    if state_bytes.len() > MAX_STORED_STATE_BYTES
        || total > MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES
    {
        return Err(StoreError::StateTooLarge);
    }

    let state_len = u32::try_from(state_bytes.len()).map_err(|_| StoreError::StateTooLarge)?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(RECORD_MAGIC);
    encoded.extend_from_slice(&RECORD_VERSION.to_le_bytes());
    encoded.extend_from_slice(&state_len.to_le_bytes());
    encoded.extend_from_slice(&client_len.to_le_bytes());
    encoded.extend_from_slice(&server_len.to_le_bytes());
    encoded.extend_from_slice(state_bytes);
    encoded.extend_from_slice(&client_identifier);
    encoded.extend_from_slice(&server_identifier);
    Ok(Zeroizing::new(encoded))
}

pub(crate) fn decode_bound_state(mut encoded: Vec<u8>) -> Result<BoundLoginState, StoreError> {
    let result = decode_bound_state_inner(&encoded);
    encoded.zeroize();
    result
}

fn decode_bound_state_inner(encoded: &[u8]) -> Result<BoundLoginState, StoreError> {
    if encoded.len() < RECORD_HEADER_BYTES
        || encoded.len() > MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES
        || &encoded[..4] != RECORD_MAGIC
        || u16::from_le_bytes(
            encoded[4..6]
                .try_into()
                .map_err(|_| StoreError::Unavailable)?,
        ) != RECORD_VERSION
    {
        return Err(StoreError::Unavailable);
    }
    let state_len = usize::try_from(u32::from_le_bytes(
        encoded[6..10]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ))
    .map_err(|_| StoreError::Unavailable)?;
    let client_len = usize::from(u16::from_le_bytes(
        encoded[10..12]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ));
    let server_len = usize::from(u16::from_le_bytes(
        encoded[12..14]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ));
    let expected_len = RECORD_HEADER_BYTES
        .checked_add(state_len)
        .and_then(|length| length.checked_add(client_len))
        .and_then(|length| length.checked_add(server_len))
        .ok_or(StoreError::Unavailable)?;
    if state_len == 0 || state_len > MAX_STORED_STATE_BYTES || expected_len != encoded.len() {
        return Err(StoreError::Unavailable);
    }
    let state_start = RECORD_HEADER_BYTES;
    let client_start = state_start + state_len;
    let server_start = client_start + client_len;
    let state = ServerLoginStateBytes::from_bytes(&encoded[state_start..client_start])
        .map_err(|_| StoreError::Unavailable)?;
    BoundLoginState::new(
        state,
        &encoded[client_start..server_start],
        &encoded[server_start..],
    )
    .map_err(|_| StoreError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{decode_bound_state, encode_bound_state, OpaqueStateKey, StateProtector};
    use crate::BoundLoginState;
    use secure_auth::ServerLoginStateBytes;

    #[test]
    fn durable_record_round_trips_bound_state() {
        let state = BoundLoginState::new(
            ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
            b"fixture-client",
            b"fixture-server",
        )
        .unwrap();
        let encoded = encode_bound_state(state).unwrap();
        let decoded = decode_bound_state(encoded.to_vec()).unwrap();
        let (state, client, server) = decoded.into_parts();
        assert_eq!(state.as_bytes(), b"fixture-state");
        assert_eq!(client, b"fixture-client");
        assert_eq!(server, b"fixture-server");
    }

    #[test]
    fn durable_record_rejects_tampering_and_trailing_bytes() {
        let state = BoundLoginState::new(
            ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
            b"fixture-client",
            b"fixture-server",
        )
        .unwrap();
        let encoded = encode_bound_state(state).unwrap();
        let mut tampered = encoded.to_vec();
        tampered[0] ^= 0xff;
        assert!(decode_bound_state(tampered).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_bound_state(trailing).is_err());
    }

    #[test]
    fn durable_record_is_authenticated_and_encrypted_before_storage() {
        let state = BoundLoginState::new(
            ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
            b"fixture-client",
            b"fixture-server",
        )
        .unwrap();
        let encoded = encode_bound_state(state).unwrap();
        let key = OpaqueStateKey::from_bytes(&[7u8; 32]).unwrap();
        let protector = StateProtector::new(key);
        let protected = protector.seal(encoded.as_slice()).unwrap();

        assert_ne!(protected.as_slice(), encoded.as_slice());
        let opened = protector.open(protected.to_vec()).unwrap();
        let decoded = decode_bound_state(opened.to_vec()).unwrap();
        assert_eq!(decoded.into_parts().0.as_bytes(), b"fixture-state");
    }

    #[test]
    fn durable_record_rejects_authenticated_ciphertext_tampering() {
        let state = BoundLoginState::new(
            ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
            b"fixture-client",
            b"fixture-server",
        )
        .unwrap();
        let encoded = encode_bound_state(state).unwrap();
        let key = OpaqueStateKey::from_bytes(&[9u8; 32]).unwrap();
        let protector = StateProtector::new(key);
        let mut protected = protector.seal(encoded.as_slice()).unwrap().to_vec();
        let last = protected.last_mut().unwrap();
        *last ^= 0x01;

        assert!(protector.open(protected).is_err());
    }

    #[test]
    fn opaque_state_key_requires_exactly_32_bytes() {
        assert!(OpaqueStateKey::from_bytes(&[0u8; 31]).is_none());
        assert!(OpaqueStateKey::from_bytes(&[0u8; 33]).is_none());
        assert!(OpaqueStateKey::from_bytes(&[0u8; 32]).is_some());
    }

    #[test]
    fn durable_record_requires_the_same_key_to_open() {
        let encoded = encode_bound_state(
            BoundLoginState::new(
                ServerLoginStateBytes::from_bytes(b"fixture-state").unwrap(),
                b"fixture-client",
                b"fixture-server",
            )
            .unwrap(),
        )
        .unwrap();
        let protector = StateProtector::new(OpaqueStateKey::from_bytes(&[1u8; 32]).unwrap());
        let wrong_protector = StateProtector::new(OpaqueStateKey::from_bytes(&[2u8; 32]).unwrap());
        let protected = protector.seal(encoded.as_slice()).unwrap();

        assert!(wrong_protector.open(protected.to_vec()).is_err());
    }
}
