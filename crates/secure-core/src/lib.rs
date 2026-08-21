#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Framework-neutral secure keypad state and policy core.

mod hangul;
mod input;
mod secret_buffer;

use core::time::Duration;
use std::time::Instant;

pub use input::{InputError, InputPolicy, KeyId, NormalizationPolicy, ResolvedKey};
pub use secret_buffer::SecretBuffer;

/// Public contract version for the initial foundation.
pub const CONTRACT_VERSION: u32 = 1;

/// Maximum number of secret input tokens held by one session.
pub const MAX_INPUT_TOKENS: usize = 4_096;

/// The information that may be shown to a host UI while a session is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskedState {
    /// Number of rendered characters, not the secret itself.
    pub length: usize,
    /// Current non-secret presentation state.
    pub display_state: DisplayState,
}

/// Non-secret state suitable for framework bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayState {
    /// No input is currently buffered.
    Empty,
    /// Input exists and must be displayed as a mask.
    Masked,
    /// A submission was created and the session is closed.
    Submitted,
    /// The session was cancelled and its input was cleared.
    Cancelled,
}

/// Errors that do not contain secret data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The supplied key ID is not allowed by the input policy.
    InvalidKey(InputError),
    /// The configured input limit has been reached.
    LimitReached,
    /// The session has no buffered input.
    Empty,
    /// The session is no longer accepting input.
    Inactive,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidKey(_) => "invalid key",
            Self::LimitReached => "input limit reached",
            Self::Empty => "input is empty",
            Self::Inactive => "session is inactive",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionError {}

impl From<InputError> for SessionError {
    fn from(error: InputError) -> Self {
        Self::InvalidKey(error)
    }
}

/// A session that owns its input and never exposes it as a host-language string.
pub struct SecureSession {
    input: Option<input::SecretInput>,
    state: DisplayState,
    timeout: Duration,
    last_activity: Instant,
}

impl SecureSession {
    /// Starts a new session with the supplied policy.
    #[must_use]
    pub fn begin(policy: InputPolicy) -> Self {
        Self::begin_with_timeout(policy, Duration::from_secs(60))
    }

    /// Starts a session with an explicit monotonic inactivity timeout.
    #[must_use]
    pub fn begin_with_timeout(policy: InputPolicy, timeout: Duration) -> Self {
        Self {
            input: Some(input::SecretInput::new(policy)),
            state: DisplayState::Empty,
            timeout,
            last_activity: Instant::now(),
        }
    }

    /// Adds a declared key ID to the secure input buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is inactive, the key is not allowed,
    /// or the input limit has been reached.
    pub fn press_key(&mut self, key_id: &KeyId) -> Result<(), SessionError> {
        self.expire_if_needed();
        let input = self.input.as_mut().ok_or(SessionError::Inactive)?;
        input.push(key_id).map_err(|error| match error {
            InputError::LimitReached => SessionError::LimitReached,
            InputError::InvalidKey => SessionError::InvalidKey(InputError::InvalidKey),
        })?;
        self.state = DisplayState::Masked;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Removes the most recently pressed key ID.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is inactive.
    pub fn backspace(&mut self) -> Result<(), SessionError> {
        self.expire_if_needed();
        let input = self.input.as_mut().ok_or(SessionError::Inactive)?;
        input.backspace();
        self.state = if input.is_empty() {
            DisplayState::Empty
        } else {
            DisplayState::Masked
        };
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Clears all buffered input.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is inactive.
    pub fn clear(&mut self) -> Result<(), SessionError> {
        self.expire_if_needed();
        let input = self.input.as_mut().ok_or(SessionError::Inactive)?;
        input.clear();
        self.state = DisplayState::Empty;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Expires an inactive session and returns whether expiration occurred.
    pub fn expire_if_needed(&mut self) -> bool {
        if self.input.is_some() && self.last_activity.elapsed() >= self.timeout {
            self.cancel();
            true
        } else {
            false
        }
    }

    /// Refreshes timeout state and returns masked state for a host UI.
    #[must_use]
    pub fn refresh(&mut self) -> MaskedState {
        self.expire_if_needed();
        self.masked_state()
    }

    /// Returns only masked, non-secret state for a host UI.
    #[must_use]
    pub fn masked_state(&self) -> MaskedState {
        let length = self
            .input
            .as_ref()
            .map_or(0, input::SecretInput::rendered_length);
        MaskedState {
            length,
            display_state: self.state,
        }
    }

    /// Seals the input into an opaque submission for native authentication code.
    ///
    /// The returned type has no public byte or string accessor. It is intended to
    /// be consumed by a native authentication adapter in this crate or by an
    /// opaque FFI handle, never serialized into framework state.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is inactive or has no buffered input.
    pub fn submit(&mut self) -> Result<Submission, SessionError> {
        self.expire_if_needed();
        let input = self.input.as_ref().ok_or(SessionError::Inactive)?;
        if input.is_empty() {
            return Err(SessionError::Empty);
        }
        let input = self.input.take().ok_or(SessionError::Inactive)?;
        self.state = DisplayState::Submitted;
        Ok(Submission {
            buffer: input.into_secret_buffer(),
        })
    }

    /// Cancels the session and clears all input.
    pub fn cancel(&mut self) {
        self.input.take();
        self.state = DisplayState::Cancelled;
    }
}

/// An opaque sealed submission. It intentionally has no public secret accessor.
pub struct Submission {
    #[allow(dead_code)]
    buffer: SecretBuffer,
}

impl Submission {
    /// Provides the sealed bytes to native/server Rust code for immediate
    /// cryptographic consumption.
    ///
    /// The callback intentionally returns `()`, so this public handoff cannot
    /// return a secret slice or a copied secret value to its caller.
    ///
    /// This must not be exposed through a JavaScript, Dart, or UI binding and
    /// must not be used to create strings, logs, JSON, analytics, or storage.
    pub fn with_native_bytes(&self, operation: impl FnOnce(&[u8])) {
        operation(self.buffer.as_slice());
    }
}
