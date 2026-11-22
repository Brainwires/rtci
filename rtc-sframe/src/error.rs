use crypto::CryptoError;

/// A specialized `Result` for SFrame operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Why an SFrame operation failed.
///
/// No variant carries key material, plaintext, a nonce or a tag.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The input ends before the SFrame header does (RFC 9605 section 4.3).
    #[error("SFrame header is truncated")]
    TruncatedHeader,
    /// The header carries a KID or CTR that is not in its shortest form (RFC 9605 section 4.3:
    /// a value below 8 goes in the config byte, a larger one in the fewest bytes).
    #[error("SFrame header is not minimally encoded")]
    NonMinimalHeader,
    /// What follows the header is shorter than the cipher suite's authentication tag.
    #[error("SFrame ciphertext is shorter than its authentication tag")]
    TruncatedCiphertext,
    /// No key is stored for this KID.
    #[error("no SFrame key for key id {0}")]
    UnknownKeyId(u64),
    /// The key stored for this KID is marked for the other direction: a key is usable for
    /// encryption or for decryption, never both (RFC 9605 section 4.4.1).
    #[error("the SFrame key for key id {0} is marked for the other direction")]
    KeyRoleConflict(u64),
    /// The authentication tag does not match the header, the metadata and the ciphertext.
    #[error("SFrame authentication failed")]
    AuthenticationFailed,
    /// The ciphertext is authentic, but its counter was already accepted or is older than the
    /// replay window (RFC 9605 section 9.3).
    #[error("SFrame counter {ctr} of key id {kid} was already used or is too old")]
    Replayed {
        /// The KID of the ciphertext.
        kid: u64,
        /// The CTR of the ciphertext.
        ctr: u64,
    },
    /// Every counter of this key has been used: one more encryption would repeat a nonce
    /// (RFC 9605 sections 7.4 and 9.1). The sender needs a new key.
    #[error("the SFrame key for key id {0} has used every counter value")]
    CounterExhausted(u64),
    /// The key is already installed for sending under this KID. Installing it again would
    /// restart its counter and repeat (key, nonce) pairs (RFC 9605 sections 7.4 and 9.1).
    #[error("the SFrame key for key id {0} is already in use for sending")]
    KeyReuse(u64),
    /// A base key is empty.
    #[error("SFrame base key is empty")]
    EmptyBaseKey,
    /// A KID layout does not fit 64 bits, or a value does not fit its field of the KID
    /// (RFC 9605 sections 5.1 and 5.2).
    #[error("value does not fit the SFrame key id layout")]
    KeyIdLayout,
    /// An MLS epoch is older than, or contradicts, one already introduced with the same
    /// low-order bits (RFC 9605 section 5.2).
    #[error("MLS epoch {0} is older than, or contradicts, the epoch already introduced")]
    StaleEpoch(u64),
    /// No secret is stored for this MLS epoch.
    #[error("no secret for MLS epoch {0}")]
    UnknownEpoch(u64),
    /// The store already holds as many derived keys as its limit allows.
    #[error("SFrame key store is full")]
    TooManyKeys,
    /// A ratchet step counter cannot advance further.
    #[error("SFrame ratchet step overflow")]
    RatchetExhausted,
    /// The crypto provider failed, or does not implement what the cipher suite needs.
    #[error("crypto provider: {0}")]
    Crypto(CryptoError),
}

/// The three kinds of decryption failure the W3C Encoded Transform API reports
/// (`SFrameTransformErrorEventType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The data does not follow the SFrame format (`"syntax"`).
    Syntax,
    /// The key identifier parsed from the header has no key (`"keyID"`).
    KeyId,
    /// The authentication tag did not validate (`"authentication"`).
    Authentication,
}

impl Error {
    /// The W3C error kind of a decryption failure, if the failure is one of the three the
    /// Encoded Transform API names. A replay, a key-management error and a provider failure are
    /// none of them.
    #[must_use]
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            Self::TruncatedHeader | Self::NonMinimalHeader | Self::TruncatedCiphertext => {
                Some(ErrorKind::Syntax)
            }
            Self::UnknownKeyId(_) | Self::KeyRoleConflict(_) => Some(ErrorKind::KeyId),
            Self::AuthenticationFailed => Some(ErrorKind::Authentication),
            _ => None,
        }
    }

    /// The KID a decryption failure is about, when it has one (the `keyID` attribute of the
    /// W3C error event).
    #[must_use]
    pub fn key_id(&self) -> Option<u64> {
        match self {
            Self::UnknownKeyId(kid)
            | Self::KeyRoleConflict(kid)
            | Self::CounterExhausted(kid)
            | Self::KeyReuse(kid)
            | Self::Replayed { kid, .. } => Some(*kid),
            _ => None,
        }
    }
}

/// Maps a provider failure: a failed tag check is the protocol's authentication failure,
/// anything else stays a provider error.
pub(crate) fn crypto_error(error: CryptoError) -> Error {
    match error {
        CryptoError::AuthenticationFailed => Error::AuthenticationFailed,
        other => Error::Crypto(other),
    }
}
