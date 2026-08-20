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
    tokens: Vec<u32>,
}

impl SecretTokenBuffer {
    pub(crate) fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    pub(crate) fn push(&mut self, token: u32) {
        self.tokens.push(token);
    }

    pub(crate) fn pop(&mut self) {
        self.tokens.pop();
    }

    pub(crate) fn len(&self) -> usize {
        self.tokens.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub(crate) fn as_slice(&self) -> &[u32] {
        &self.tokens
    }

    pub(crate) fn clear(&mut self) {
        self.tokens.zeroize();
        self.tokens.clear();
        self.tokens.shrink_to_fit();
    }
}

impl Drop for SecretTokenBuffer {
    fn drop(&mut self) {
        self.tokens.zeroize();
    }
}
