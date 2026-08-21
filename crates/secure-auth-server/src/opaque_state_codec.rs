use crate::{BoundLoginState, StoreError, MAX_STORED_STATE_BYTES};
use secure_auth::ServerLoginStateBytes;
use zeroize::{Zeroize, Zeroizing};

const RECORD_MAGIC: &[u8; 4] = b"SKBS";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 4 + 2 + 4 + 2 + 2;

/// Maximum encoded durable record accepted by distributed one-time stores.
pub const MAX_DISTRIBUTED_LOGIN_STATE_RECORD_BYTES: usize = 32 * 1024;

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
    use super::{decode_bound_state, encode_bound_state};
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
}
