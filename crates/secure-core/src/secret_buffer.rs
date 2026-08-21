use zeroize::Zeroize;

/// A byte buffer that is explicitly cleared when dropped.
///
/// This type deliberately does not implement `Debug`, `Clone`, `Eq`, or a
/// string conversion. It is an internal/native boundary type, not an ordinary
/// application value.
pub struct SecretBuffer {
    bytes: Vec<u8>,
}

impl SecretBuffer {
    /// Creates an empty secret buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Creates a buffer from bytes without exposing an accessor to those bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Clears the buffer and releases its backing allocation.
    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
        self.bytes.shrink_to_fit();
    }

    /// Returns whether the buffer contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .expect("secret buffer length overflow");
        assert!(
            required <= self.bytes.capacity(),
            "secret buffer capacity must be provisioned before extension"
        );
        self.bytes.extend_from_slice(bytes);
    }
}

impl Default for SecretBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub(crate) struct SecretTokenBuffer {
    tokens: Box<[u32]>,
    len: usize,
}

impl SecretTokenBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            tokens: vec![0; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, token: u32) {
        debug_assert!(self.len < self.tokens.len());
        self.tokens[self.len] = token;
        self.len += 1;
    }

    pub(crate) fn pop(&mut self) {
        if self.len == 0 {
            return;
        }
        self.len -= 1;
        self.tokens[self.len].zeroize();
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn as_slice(&self) -> &[u32] {
        &self.tokens[..self.len]
    }

    pub(crate) fn clear(&mut self) {
        self.tokens[..self.len].zeroize();
        self.len = 0;
    }

    #[cfg(test)]
    pub(crate) fn storage_for_test(&self) -> &[u32] {
        &self.tokens
    }
}

impl Drop for SecretTokenBuffer {
    fn drop(&mut self) {
        self.tokens.as_mut().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::SecretTokenBuffer;

    #[test]
    fn popped_token_is_zeroized_in_place() {
        let mut buffer = SecretTokenBuffer::with_capacity(2);
        buffer.push(0x1001);
        buffer.push(0x2002);

        buffer.pop();

        assert_eq!(buffer.storage_for_test(), &[0x1001, 0]);
    }

    #[test]
    fn token_storage_does_not_reallocate_when_full() {
        let mut buffer = SecretTokenBuffer::with_capacity(2);
        buffer.push(0x1001);
        buffer.push(0x2002);

        assert_eq!(buffer.storage_for_test().len(), 2);
    }
}
