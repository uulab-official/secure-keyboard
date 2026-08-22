use core::fmt;

use zeroize::{Zeroize, Zeroizing};

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

    /// Creates a bounded key ID from untrusted public configuration.
    ///
    /// Use this constructor when the value originates outside a trusted,
    /// already-validated native layout boundary. The byte bound matches the
    /// native FFI and framework adapter contracts.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::InvalidKey`] when the identifier is empty or
    /// exceeds [`crate::MAX_KEY_ID_BYTES`] bytes.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, InputError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > crate::MAX_KEY_ID_BYTES {
            return Err(InputError::InvalidKey);
        }
        Ok(Self(value.to_owned()))
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
    /// A printable ASCII code point from U+0020 through U+007E.
    Ascii(u8),
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
    /// Printable ASCII characters with a maximum number of input tokens.
    ///
    /// Key IDs use the public form `ascii-XX`, where `XX` is a lowercase
    /// two-digit hexadecimal code point. The label shown by a native host is
    /// never used as the secret input value.
    Ascii {
        /// Maximum number of input tokens.
        max_tokens: usize,
    },
}

impl InputPolicy {
    /// Creates a numeric policy. The token count is clamped to the supported
    /// `1..=MAX_INPUT_TOKENS` range to keep secret storage bounded.
    #[must_use]
    pub fn numeric(max_tokens: usize) -> Self {
        Self::Numeric {
            max_tokens: max_tokens.clamp(1, crate::MAX_INPUT_TOKENS),
        }
    }

    /// Creates a Hangul policy. The token count is clamped to the supported
    /// `1..=MAX_INPUT_TOKENS` range to keep secret storage bounded.
    #[must_use]
    pub fn hangul(max_tokens: usize) -> Self {
        Self::Hangul {
            max_tokens: max_tokens.clamp(1, crate::MAX_INPUT_TOKENS),
            normalization: NormalizationPolicy::Nfc,
        }
    }

    /// Creates a printable-ASCII policy. The token count is clamped to the
    /// supported `1..=MAX_INPUT_TOKENS` range to keep secret storage bounded.
    #[must_use]
    pub fn ascii(max_tokens: usize) -> Self {
        Self::Ascii {
            max_tokens: max_tokens.clamp(1, crate::MAX_INPUT_TOKENS),
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
        if key.len() > crate::MAX_KEY_ID_BYTES {
            return Err(InputError::InvalidKey);
        }
        match self {
            Self::Numeric { .. } => {
                // Numeric IDs are deliberately canonical: aliases such as
                // `digit-01` or `digit-+1` must not create a second public
                // spelling for the same native key.
                let Some(digit) = key.strip_prefix("digit-") else {
                    return Err(InputError::InvalidKey);
                };
                if digit.len() != 1 || !digit.as_bytes()[0].is_ascii_digit() {
                    return Err(InputError::InvalidKey);
                }
                Ok(ResolvedKey::Digit(digit.as_bytes()[0] - b'0'))
            }
            Self::Hangul { .. } => hangul::resolve_key(key).ok_or(InputError::InvalidKey),
            Self::Ascii { .. } => {
                let Some(codepoint) = key.strip_prefix("ascii-") else {
                    return Err(InputError::InvalidKey);
                };
                if codepoint.len() != 2
                    || !codepoint
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(InputError::InvalidKey);
                }
                let Ok(value) = u8::from_str_radix(codepoint, 16) else {
                    return Err(InputError::InvalidKey);
                };
                (0x20..=0x7e)
                    .contains(&value)
                    .then_some(ResolvedKey::Ascii(value))
                    .ok_or(InputError::InvalidKey)
            }
        }
    }

    pub(crate) fn max_tokens(&self) -> usize {
        match self {
            Self::Numeric { max_tokens }
            | Self::Hangul { max_tokens, .. }
            | Self::Ascii { max_tokens } => *max_tokens,
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
        let max_tokens = policy.max_tokens();
        Self {
            policy,
            tokens: SecretTokenBuffer::with_capacity(max_tokens),
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
        let mut rendered = hangul::render(self.tokens.as_slice());
        let length = rendered.len();
        rendered.zeroize();
        length
    }

    pub(crate) fn into_secret_buffer(self) -> SecretBuffer {
        let mut rendered = Zeroizing::new(hangul::render(self.tokens.as_slice()));
        encode_rendered_to_secret_buffer(&mut rendered)
    }
}

fn encode_rendered_to_secret_buffer(rendered: &mut Vec<u32>) -> SecretBuffer {
    let mut buffer = SecretBuffer::with_capacity(rendered.len().saturating_mul(4));
    hangul::encode_utf8(rendered, &mut buffer);
    rendered.zeroize();
    buffer
}

#[cfg(test)]
mod tests {
    use super::{encode_rendered_to_secret_buffer, InputPolicy, SecretInput};
    use crate::MAX_INPUT_TOKENS;

    #[test]
    fn rendered_secret_codepoints_are_zeroized_after_encoding() {
        let mut rendered = vec![0x1100_u32, 0x1161_u32, 0xac00_u32];
        let _encoded = encode_rendered_to_secret_buffer(&mut rendered);

        assert!(rendered.iter().all(|codepoint| *codepoint == 0));
    }

    #[test]
    fn policy_storage_is_bounded_to_the_native_contract_limit() {
        let input = SecretInput::new(InputPolicy::numeric(usize::MAX));

        assert_eq!(input.tokens.storage_for_test().len(), MAX_INPUT_TOKENS);
    }
}
