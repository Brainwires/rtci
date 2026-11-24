//! `MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256` (RFC 8489 sections 14.5 and 14.6), and
//! the keys of the two credential mechanisms (sections 9.1.1, 9.2.2 and 18.5.1).
//!
//! Both attributes carry an HMAC over the message up to the attribute, computed with the
//! header's length field set as if the message ended at the attribute. They differ in the
//! hash (SHA-1, SHA-256) and in that the SHA-256 one may be truncated where a usage allows it.
//!
//! A receiver does not read attributes directly off a message it has only run
//! [`MessageIntegrity::check`](crate::integrity::MessageIntegrity::check) on: whatever follows the integrity attribute is not covered by
//! it. Use [`Validator`](crate::validated::Validator), whose result exposes only what was
//! authenticated.

#[cfg(test)]
mod integrity_test;

use crate::attributes::*;
use crate::message::*;
use crate::opaque::opaque_string;
use crate::password_algorithm::{PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256};
use crypto::{CryptoError, HashAlgorithm, HmacAlgorithm, RTCCrypto, SecretVec, constant_time_eq};
use shared::error::*;
use std::fmt;

// separator for credentials.
pub(crate) const CREDENTIALS_SEP: &str = ":";

/// Which of the two integrity attributes protects a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityAlgorithm {
    /// `MESSAGE-INTEGRITY`: HMAC-SHA1, 20 bytes.
    Sha1,
    /// `MESSAGE-INTEGRITY-SHA256`: HMAC-SHA256, 32 bytes unless a usage allows truncation.
    Sha256,
}

impl IntegrityAlgorithm {
    /// The attribute that carries this algorithm's HMAC.
    #[must_use]
    pub const fn attr_type(self) -> AttrType {
        match self {
            Self::Sha1 => ATTR_MESSAGE_INTEGRITY,
            Self::Sha256 => ATTR_MESSAGE_INTEGRITY_SHA256,
        }
    }

    /// The length of the untruncated HMAC in bytes.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::Sha1 => MESSAGE_INTEGRITY_SIZE,
            Self::Sha256 => MESSAGE_INTEGRITY_SHA256_SIZE,
        }
    }

    const fn hmac(self) -> HmacAlgorithm {
        match self {
            Self::Sha1 => HmacAlgorithm::Sha1,
            Self::Sha256 => HmacAlgorithm::Sha256,
        }
    }
}

/// The length of a `MESSAGE-INTEGRITY` value in bytes.
pub const MESSAGE_INTEGRITY_SIZE: usize = 20;
/// The length of an untruncated `MESSAGE-INTEGRITY-SHA256` value in bytes.
pub const MESSAGE_INTEGRITY_SHA256_SIZE: usize = 32;
/// The shortest `MESSAGE-INTEGRITY-SHA256` value RFC 8489 section 14.6 allows, in bytes.
pub const MESSAGE_INTEGRITY_SHA256_MIN_SIZE: usize = 16;

fn crypto_error(error: CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

/// The HMAC input of an integrity attribute that starts at `start` in `m.raw` and whose value
/// takes `value_len` bytes: the message up to the attribute, with the header's length field
/// pointing to the end of the attribute (RFC 8489 sections 14.5 and 14.6).
///
/// Returned as the adjusted length field, the two bytes ahead of it and the bytes after it.
fn hmac_input(m: &Message, start: usize, value_len: usize) -> Result<([u8; 2], &[u8], &[u8])> {
    if start < MESSAGE_HEADER_SIZE || m.raw.len() < start {
        return Err(Error::ErrUnexpectedHeaderEof);
    }
    let length = start - MESSAGE_HEADER_SIZE
        + ATTRIBUTE_HEADER_SIZE
        + nearest_padded_value_length(value_len);
    let length = u16::try_from(length).map_err(|_| Error::ErrPacketTooBig)?;
    Ok((length.to_be_bytes(), &m.raw[..2], &m.raw[4..start]))
}

/// Appends the integrity attribute of `algorithm` to `m`, its HMAC cut to `tag_len` bytes.
fn add_integrity(
    m: &mut Message,
    algorithm: IntegrityAlgorithm,
    tag_len: usize,
    key: &[u8],
    crypto: &dyn RTCCrypto,
) -> Result<()> {
    for a in &m.attributes.0 {
        // FINGERPRINT is the last attribute of a message (RFC 8489 section 14.7), so no
        // integrity attribute is added after it.
        if a.typ == ATTR_FINGERPRINT {
            return Err(Error::ErrFingerprintBeforeIntegrity);
        }
    }
    let start = MESSAGE_HEADER_SIZE + m.length as usize;
    let mut tag = vec![0_u8; algorithm.tag_len()];
    {
        let (length, type_field, rest) = hmac_input(m, start, tag_len)?;
        // A STUN message is authenticated once, so the MAC is keyed here rather than held. On
        // a per-packet path the keyed object belongs in the surrounding state instead.
        crypto
            .new_hmac(algorithm.hmac(), key)
            .and_then(|mut mac| mac.sign(&[type_field, &length, rest], &mut tag))
            .map_err(crypto_error)?;
    }
    m.add(algorithm.attr_type(), &tag[..tag_len]);
    Ok(())
}

/// Checks the first integrity attribute of `algorithm` in `m`, whose value must be at least
/// `min_tag_len` bytes.
pub(crate) fn check_integrity(
    m: &Message,
    algorithm: IntegrityAlgorithm,
    min_tag_len: usize,
    key: &[u8],
    crypto: &dyn RTCCrypto,
) -> Result<()> {
    let index = m
        .position(algorithm.attr_type())
        .ok_or(Error::ErrAttributeNotFound)?;
    let value = &m.attributes.0[index].value;
    let full = algorithm.tag_len();
    // RFC 8489 section 14.6: at most the whole HMAC, at least the usage's minimum, a multiple
    // of 4. MESSAGE-INTEGRITY is never truncated, so its minimum is its whole length.
    if value.len() > full || value.len() < min_tag_len || !value.len().is_multiple_of(PADDING) {
        return Err(Error::ErrIntegrityMismatch);
    }
    let (length, type_field, rest) = hmac_input(m, m.attribute_offset(index), value.len())?;
    let input: [&[u8]; 3] = [type_field, &length, rest];
    let mut mac = crypto
        .new_hmac(algorithm.hmac(), key)
        .map_err(crypto_error)?;
    let result = if value.len() == full {
        mac.verify(&input, value)
    } else {
        let mut tag = vec![0_u8; full];
        mac.sign(&input, &mut tag).and_then(|()| {
            if constant_time_eq(&tag[..value.len()], value) {
                Ok(())
            } else {
                Err(CryptoError::AuthenticationFailed)
            }
        })
    };
    match result {
        Ok(()) => Ok(()),
        Err(CryptoError::AuthenticationFailed | CryptoError::InvalidTagLength { .. }) => {
            Err(Error::ErrIntegrityMismatch)
        }
        Err(error) => Err(crypto_error(error)),
    }
}

/// The key of the long-term credential mechanism for a password algorithm of the STUN
/// Password Algorithms registry (RFC 8489 sections 9.2.2 and 18.5.1):
///
/// ```text
/// key = H(username ":" OpaqueString(realm) ":" OpaqueString(password))
/// ```
///
/// with H = MD5 ([`PASSWORD_ALGORITHM_MD5`], 16 bytes; for legacy systems only, section
/// 18.5.1.1) or SHA-256 ([`PASSWORD_ALGORITHM_SHA256`], 32 bytes). The username is
/// OpaqueString-processed as well, as the USERNAME attribute requires (section 14.3); an empty
/// part is used as it is.
///
/// # Errors
///
/// Fails for an algorithm other than those two, for a username, realm or password that
/// OpaqueString does not allow, and when the provider fails.
pub fn long_term_key(
    algorithm: u16,
    username: &str,
    realm: &str,
    password: &str,
    crypto: &dyn RTCCrypto,
) -> Result<Vec<u8>> {
    let (hash, key_len) = match algorithm {
        PASSWORD_ALGORITHM_MD5 => (HashAlgorithm::Md5, 16),
        PASSWORD_ALGORITHM_SHA256 => (HashAlgorithm::Sha256, 32),
        other => {
            return Err(Error::Other(format!(
                "password algorithm {other:#06x} is not supported"
            )));
        }
    };
    let credentials = SecretVec::new(
        [
            opaque_or_empty(username)?,
            opaque_or_empty(realm)?,
            opaque_or_empty(password)?,
        ]
        .join(CREDENTIALS_SEP)
        .into_bytes(),
    );
    let key = crypto
        .hash(hash, credentials.as_ref())
        .map_err(crypto_error)?;
    if key.len() != key_len {
        return Err(Error::Crypto(format!(
            "provider returned an invalid digest length: {}",
            key.len()
        )));
    }
    Ok(key)
}

fn opaque_or_empty(s: &str) -> Result<String> {
    if s.is_empty() {
        Ok(String::new())
    } else {
        opaque_string(s).map(|s| s.into_owned())
    }
}

// MessageIntegrity represents MESSAGE-INTEGRITY attribute.
//
// RFC 8489 Section 14.5
#[derive(Clone)]
/// The `MESSAGE-INTEGRITY` key: an HMAC-SHA1 is computed over the message with it.
///
/// Built from a short-term password, or from a long-term username/realm/password triple.
pub struct MessageIntegrity<'a> {
    key: SecretVec,
    crypto: &'a dyn RTCCrypto,
}

impl<'a> fmt::Display for MessageIntegrity<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSAGE-INTEGRITY key: [REDACTED; {} bytes]",
            self.key.len()
        )
    }
}

impl<'a> Setter for MessageIntegrity<'a> {
    // add_to adds MESSAGE-INTEGRITY attribute to message.
    //
    // CPU costly, see BenchmarkMessageIntegrity_AddTo.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        add_integrity(
            m,
            IntegrityAlgorithm::Sha1,
            MESSAGE_INTEGRITY_SIZE,
            self.key.as_ref(),
            self.crypto,
        )
    }
}

impl<'a> MessageIntegrity<'a> {
    /// Creates a raw-key integrity attribute with an explicit crypto provider.
    #[must_use]
    pub fn new_raw_integrity_with_provider(
        key: impl Into<Vec<u8>>,
        crypto: &'a dyn RTCCrypto,
    ) -> Self {
        Self {
            key: SecretVec::new(key.into()),
            crypto,
        }
    }

    /// Creates a short-term integrity attribute with an explicit crypto provider.
    ///
    /// The password's bytes are the key as they are: it must already be OpaqueString-processed
    /// (RFC 8489 section 9.1.1). That holds for every ICE password, which is ASCII by its
    /// grammar; for a password of any other origin use [`short_term`](Self::short_term).
    #[must_use]
    pub fn new_short_term_integrity_with_provider(
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Self {
        Self::new_raw_integrity_with_provider(password.into_bytes(), crypto)
    }

    /// Creates a short-term integrity attribute: `key = OpaqueString(password)` (RFC 8489
    /// section 9.1.1).
    ///
    /// # Errors
    ///
    /// Fails for a password OpaqueString does not allow (RFC 8265 section 4.2).
    pub fn short_term(password: &str, crypto: &'a dyn RTCCrypto) -> Result<Self> {
        let key = opaque_string(password)?.into_owned().into_bytes();
        Ok(Self::new_raw_integrity_with_provider(key, crypto))
    }

    /// Creates a long-term integrity attribute with an explicit crypto provider, with the MD5
    /// key of RFC 8489 section 9.2.2 (realm and password OpaqueString-processed).
    pub fn new_long_term_integrity_with_provider(
        username: String,
        realm: String,
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Result<Self> {
        let key = MessageIntegrity::long_term_integrity_key(username, realm, password, crypto)?;
        Ok(Self::new_raw_integrity_with_provider(key, crypto))
    }

    /// Creates a long-term integrity key with an explicit crypto provider: the MD5 key of RFC
    /// 8489 section 9.2.2. [`long_term_key`] takes the password algorithm.
    pub fn long_term_integrity_key(
        username: String,
        realm: String,
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Result<Vec<u8>> {
        let password = SecretVec::new(password.into_bytes());
        let password = std::str::from_utf8(password.as_ref())
            .map_err(|_| Error::Other("the password is not UTF-8".to_owned()))?;
        long_term_key(PASSWORD_ALGORITHM_MD5, &username, &realm, password, crypto)
    }

    /// Check checks MESSAGE-INTEGRITY attribute: the first one in `m`, over the message up to
    /// it. Attributes after it are not covered, whatever they are.
    ///
    /// A receiver that goes on to read the message uses
    /// [`Validator`](crate::validated::Validator) instead, which runs this check and then
    /// exposes only the attributes it covers (RFC 8489 section 9).
    ///
    /// CPU costly, see BenchmarkMessageIntegrity_Check.
    pub fn check(m: &mut Message, key: &[u8], crypto: &dyn RTCCrypto) -> Result<()> {
        check_integrity(
            m,
            IntegrityAlgorithm::Sha1,
            MESSAGE_INTEGRITY_SIZE,
            key,
            crypto,
        )
    }
}

/// The `MESSAGE-INTEGRITY-SHA256` key: an HMAC-SHA256 is computed over the message with it
/// (RFC 8489 section 14.6).
///
/// The value is the whole 32-byte HMAC unless the usage allows truncation
/// ([`with_tag_len`](Self::with_tag_len)).
#[derive(Clone)]
pub struct MessageIntegritySha256<'a> {
    key: SecretVec,
    tag_len: usize,
    crypto: &'a dyn RTCCrypto,
}

impl<'a> fmt::Display for MessageIntegritySha256<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSAGE-INTEGRITY-SHA256 key: [REDACTED; {} bytes]",
            self.key.len()
        )
    }
}

impl<'a> Setter for MessageIntegritySha256<'a> {
    /// Adds MESSAGE-INTEGRITY-SHA256 to `m`. It goes after MESSAGE-INTEGRITY when both are
    /// sent, and ahead of FINGERPRINT.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        add_integrity(
            m,
            IntegrityAlgorithm::Sha256,
            self.tag_len,
            self.key.as_ref(),
            self.crypto,
        )
    }
}

impl<'a> MessageIntegritySha256<'a> {
    /// An integrity attribute with `key` as the HMAC key.
    #[must_use]
    pub fn new_raw(key: impl Into<Vec<u8>>, crypto: &'a dyn RTCCrypto) -> Self {
        Self {
            key: SecretVec::new(key.into()),
            tag_len: MESSAGE_INTEGRITY_SHA256_SIZE,
            crypto,
        }
    }

    /// The short-term credential form: `key = OpaqueString(password)` (RFC 8489 section
    /// 9.1.1).
    ///
    /// # Errors
    ///
    /// Fails for a password OpaqueString does not allow.
    pub fn short_term(password: &str, crypto: &'a dyn RTCCrypto) -> Result<Self> {
        let key = opaque_string(password)?.into_owned().into_bytes();
        Ok(Self::new_raw(key, crypto))
    }

    /// The long-term credential form, with the key of `password_algorithm`
    /// ([`long_term_key`]).
    ///
    /// # Errors
    ///
    /// As [`long_term_key`].
    pub fn long_term(
        password_algorithm: u16,
        username: &str,
        realm: &str,
        password: &str,
        crypto: &'a dyn RTCCrypto,
    ) -> Result<Self> {
        let key = long_term_key(password_algorithm, username, realm, password, crypto)?;
        Ok(Self::new_raw(key, crypto))
    }

    /// Sends the first `tag_len` bytes of the HMAC instead of all 32, for a usage that allows
    /// truncation.
    ///
    /// # Errors
    ///
    /// RFC 8489 section 14.6: the value is 16 to 32 bytes and a multiple of 4.
    pub fn with_tag_len(mut self, tag_len: usize) -> Result<Self> {
        if !(MESSAGE_INTEGRITY_SHA256_MIN_SIZE..=MESSAGE_INTEGRITY_SHA256_SIZE).contains(&tag_len)
            || !tag_len.is_multiple_of(PADDING)
        {
            return Err(Error::ErrAttributeSizeInvalid);
        }
        self.tag_len = tag_len;
        Ok(self)
    }

    /// Checks the first MESSAGE-INTEGRITY-SHA256 of `m`, which must be the whole 32-byte HMAC.
    ///
    /// As with [`MessageIntegrity::check`], a receiver that goes on to read the message uses
    /// [`Validator`](crate::validated::Validator).
    ///
    /// # Errors
    ///
    /// `ErrAttributeNotFound` without the attribute, `ErrIntegrityMismatch` when it does not
    /// match or is truncated.
    pub fn check(m: &Message, key: &[u8], crypto: &dyn RTCCrypto) -> Result<()> {
        Self::check_truncated(m, MESSAGE_INTEGRITY_SHA256_SIZE, key, crypto)
    }

    /// Checks the first MESSAGE-INTEGRITY-SHA256 of `m` for a usage that allows truncation
    /// down to `min_tag_len` bytes (never fewer than 16).
    ///
    /// # Errors
    ///
    /// As [`check`](Self::check); a value shorter than `min_tag_len` is a mismatch.
    pub fn check_truncated(
        m: &Message,
        min_tag_len: usize,
        key: &[u8],
        crypto: &dyn RTCCrypto,
    ) -> Result<()> {
        check_integrity(
            m,
            IntegrityAlgorithm::Sha256,
            min_tag_len.max(MESSAGE_INTEGRITY_SHA256_MIN_SIZE),
            key,
            crypto,
        )
    }
}
