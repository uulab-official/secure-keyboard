use core::fmt;

use crate::hangul;
use crate::secret_buffer::{SecretBuffer, SecretTokenBuffer};

/// Unicode normalization behavior for text policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizationPolicy {
    /// Preserve canonical Unicode composition behavior for the locked core version.
    Nfc,
}

/// A public, non-secret key identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(String);

impl KeyId {
    /// Creates a key ID from a public layout identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The resolved semantic key. This is layout metadata, not accumulated input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedKey {
    /// A numeric digit from zero to nine.
    Digit(u8),
    /// A Hangul leading consonant index.
    Leading(u8),
    /// A Hangul vowel index.
    Vowel(u8),
    /// A Hangul trailing consonant index.
    Trailing(u8),
}

/// Allowed input policy for a secure session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputPolicy {
    /// Decimal digits with a maximum number of key tokens.
    Numeric {
        /// Maximum number of input tokens.
        max_tokens: usize,
    },
    /// Hangul jamo with deterministic NFC-oriented composition.
    Hangul {
        /// Maximum number of input tokens.
        max_tokens: usize,
        /// Normalization policy locked into the session.
        normalization: NormalizationPolicy,
    },
}

impl InputPolicy {
    /// Creates a numeric policy. Zero is clamped to one to keep sessions usable.
    #[must_use]
    pub fn numeric(max_tokens: usize) -> Self {
        Self::Numeric {
            max_tokens: max_tokens.max(1),
        }
    }

    /// Creates a Hangul policy. Zero is clamped to one to keep sessions usable.
    #[must_use]
    pub fn hangul(max_tokens: usize) -> Self {
        Self::Hangul {
            max_tokens: max_tokens.max(1),
            normalization: NormalizationPolicy::Nfc,
        }
    }

    /// Resolves a public key ID without touching accumulated input.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::InvalidKey`] when the key ID is not declared by
    /// this policy.
    pub fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey, InputError> {
        let key = key_id.as_str();
        match self {
            Self::Numeric { .. } => {
                let Some(digit) = key.strip_prefix("digit-") else {
                    return Err(InputError::InvalidKey);
                };
                let Ok(value) = digit.parse::<u8>() else {
                    return Err(InputError::InvalidKey);
                };
                (value <= 9)
                    .then_some(ResolvedKey::Digit(value))
                    .ok_or(InputError::InvalidKey)
            }
            Self::Hangul { .. } => hangul::resolve_key(key).ok_or(InputError::InvalidKey),
        }
    }

    pub(crate) fn max_tokens(&self) -> usize {
        match self {
            Self::Numeric { max_tokens } | Self::Hangul { max_tokens, .. } => *max_tokens,
        }
    }
}

/// Input-policy errors that do not contain secret data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    /// The key ID is not part of the configured policy.
    InvalidKey,
    /// The policy's maximum token count has been reached.
    LimitReached,
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => formatter.write_str("invalid key"),
            Self::LimitReached => formatter.write_str("input limit reached"),
        }
    }
}

impl std::error::Error for InputError {}

pub(crate) struct SecretInput {
    policy: InputPolicy,
    tokens: SecretTokenBuffer,
}

impl SecretInput {
    pub(crate) fn new(policy: InputPolicy) -> Self {
        Self {
            policy,
            tokens: SecretTokenBuffer::new(),
        }
    }

    pub(crate) fn push(&mut self, key_id: &KeyId) -> Result<(), InputError> {
        if self.tokens.len() >= self.policy.max_tokens() {
            return Err(InputError::LimitReached);
        }
        let resolved = self.policy.resolve(key_id)?;
        self.tokens.push(hangul::encode_key(resolved));
        Ok(())
    }

    pub(crate) fn backspace(&mut self) {
        self.tokens.pop();
    }

    pub(crate) fn clear(&mut self) {
        self.tokens.clear();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub(crate) fn rendered_length(&self) -> usize {
        hangul::render(self.tokens.as_slice()).len()
    }

    pub(crate) fn into_secret_buffer(self) -> SecretBuffer {
        let mut rendered = hangul::render(self.tokens.as_slice());
        let mut buffer = SecretBuffer::new();
        hangul::encode_utf8(&mut rendered, &mut buffer);
        buffer
    }
}
