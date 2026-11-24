//! Receiving a STUN message safely: the checks of RFC 8489 sections 6.3, 9 and 14.7 in one
//! place, with a result that only shows what the checks cover.
//!
//! # Why
//!
//! `MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256` authenticate the message *up to* the
//! attribute. Anything after it can be appended by anyone on the path without breaking the
//! HMAC, which is why RFC 8489 section 9 says attributes that follow an integrity attribute
//! MUST be ignored (FINGERPRINT, and MESSAGE-INTEGRITY-SHA256 after MESSAGE-INTEGRITY,
//! excepted). A receiver that checks the HMAC and then reads attributes with
//! [`Message::get`](crate::message::Message::get),
//! [`Message::contains`](crate::message::Message::contains) or a
//! [`Getter`](crate::message::Getter) on the original
//! message does not ignore them: an ICE-CONTROLLED appended after the integrity attribute of
//! a genuine Binding request would be obeyed.
//!
//! # How
//!
//! Run every received message through a [`Validator`](crate::validated::Validator) and read attributes only from the
//! [`ValidatedMessage`](crate::validated::ValidatedMessage) it returns. That message holds the attributes ahead of the first
//! integrity attribute and nothing else, so an appended attribute cannot be read by mistake.
//!
//! ```
//! use rtci_stun::attributes::*;
//! use rtci_stun::fingerprint::FINGERPRINT;
//! use rtci_stun::integrity::MessageIntegrity;
//! use rtci_stun::message::*;
//! use rtci_stun::textattrs::TextAttribute;
//! use rtci_stun::validated::{Rejection, Validator};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = rtci_stun::crypto::default_provider()?;
//! let crypto = provider.crypto();
//!
//! // The peer's request: USERNAME inside the integrity, then FINGERPRINT.
//! let mut request = Message::new();
//! request.build(&[
//!     Box::new(BINDING_REQUEST),
//!     Box::new(TransactionId::new()),
//!     Box::new(TextAttribute::new(ATTR_USERNAME, "local:remote".to_owned())),
//!     Box::new(MessageIntegrity::short_term("password", crypto)?),
//!     Box::new(FINGERPRINT),
//! ])?;
//!
//! // What this usage understands: STUN's own attributes plus ICE's.
//! let known = [&STUN_ATTRIBUTES[..], &[ATTR_PRIORITY, ATTR_USE_CANDIDATE]].concat();
//! let validator = Validator::new().require_fingerprint().known_attributes(&known);
//!
//! let mut received = Message::new();
//! received.unmarshal_binary(&request.raw)?;
//! match validator.authenticate(&received, b"password", crypto) {
//!     Ok(valid) => {
//!         // `valid` derefs to a `Message` with the covered attributes only.
//!         assert!(valid.contains(ATTR_USERNAME));
//!     }
//!     Err(Rejection::UnknownAttributes(unknown)) => {
//!         // A request: answer 420 (`unknown_attributes_response`). Anything else: drop it.
//!         # let _ = unknown;
//!     }
//!     Err(_) => { /* drop it */ }
//! }
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
//!
//! A message that carries no integrity by design (a Binding indication, the response of a
//! public STUN server, a 401 challenge) goes through
//! [`Validator::unauthenticated`](crate::validated::Validator::unauthenticated), which
//! applies the same rule: if someone put an integrity attribute in it, what follows is still
//! not shown.

#[cfg(test)]
mod validated_test;

use crate::attributes::*;
use crate::error_code::CODE_UNKNOWN_ATTRIBUTE;
use crate::fingerprint::FINGERPRINT;
use crate::integrity::{
    IntegrityAlgorithm, MESSAGE_INTEGRITY_SHA256_MIN_SIZE, MESSAGE_INTEGRITY_SHA256_SIZE,
    check_integrity,
};
use crate::message::*;
use crate::uattrs::UnknownAttributes;
use crypto::RTCCrypto;
use shared::error::*;

use std::fmt;
use std::ops::Deref;

/// Why a received message was not accepted.
///
/// RFC 8489 section 6.3: a message that fails the basic checks is silently discarded. The one
/// case that has an answer is [`UnknownAttributes`](Self::UnknownAttributes) in a *request*,
/// which is answered 420 ([`unknown_attributes_response`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// FINGERPRINT is required by the usage and the message has none.
    FingerprintMissing,
    /// FINGERPRINT has the wrong value or length, or is not the last attribute.
    FingerprintMismatch,
    /// The message has no integrity attribute, or not the one that was asked for.
    IntegrityMissing,
    /// The integrity attribute does not match the message and key, or is shorter than the
    /// usage allows.
    IntegrityMismatch,
    /// The message has comprehension-required attributes the usage does not know, ahead of
    /// its integrity attribute. They are listed in the order they appear.
    UnknownAttributes(Vec<AttrType>),
    /// The crypto provider failed.
    Crypto(String),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FingerprintMissing => write!(f, "FINGERPRINT is missing"),
            Self::FingerprintMismatch => write!(f, "FINGERPRINT does not match"),
            Self::IntegrityMissing => write!(f, "the integrity attribute is missing"),
            Self::IntegrityMismatch => write!(f, "the integrity attribute does not match"),
            Self::UnknownAttributes(unknown) => write!(
                f,
                "unknown comprehension-required attributes: {}",
                UnknownAttributes(unknown.clone())
            ),
            Self::Crypto(error) => write!(f, "crypto provider: {error}"),
        }
    }
}

impl std::error::Error for Rejection {}

/// The checks a usage applies to every message it receives.
///
/// The default checks a FINGERPRINT that is present and knows no usage attributes; a usage
/// states its own rules once and keeps the value:
///
/// * [`require_fingerprint`](Self::require_fingerprint): the usage sends FINGERPRINT in every
///   message (ICE does, RFC 8445 section 7.1), so a message without one is not for it;
/// * [`known_attributes`](Self::known_attributes): the comprehension-required attributes the
///   usage understands; any other fails the message (RFC 8489 sections 6.3.1 to 6.3.4);
/// * [`allow_truncated_sha256`](Self::allow_truncated_sha256): the usage allows a truncated
///   MESSAGE-INTEGRITY-SHA256 (RFC 8489 section 14.6).
#[derive(Debug, Clone, Copy)]
pub struct Validator<'a> {
    known: Option<&'a [AttrType]>,
    fingerprint_required: bool,
    min_sha256_len: usize,
}

impl Default for Validator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Validator<'a> {
    /// A validator that checks FINGERPRINT when it is present, takes
    /// MESSAGE-INTEGRITY-SHA256 only whole, and does not look for unknown attributes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            known: None,
            fingerprint_required: false,
            min_sha256_len: MESSAGE_INTEGRITY_SHA256_SIZE,
        }
    }

    /// Refuses a message without FINGERPRINT ([`Rejection::FingerprintMissing`]).
    #[must_use]
    pub const fn require_fingerprint(mut self) -> Self {
        self.fingerprint_required = true;
        self
    }

    /// Refuses a message that carries a comprehension-required attribute outside `known`
    /// ([`Rejection::UnknownAttributes`]). `known` is
    /// [`STUN_ATTRIBUTES`] plus the usage's own.
    #[must_use]
    pub const fn known_attributes(mut self, known: &'a [AttrType]) -> Self {
        self.known = Some(known);
        self
    }

    /// Accepts a MESSAGE-INTEGRITY-SHA256 truncated to `min_len` bytes or more (never fewer
    /// than 16, RFC 8489 section 14.6).
    #[must_use]
    pub const fn allow_truncated_sha256(mut self, min_len: usize) -> Self {
        self.min_sha256_len = if min_len < MESSAGE_INTEGRITY_SHA256_MIN_SIZE {
            MESSAGE_INTEGRITY_SHA256_MIN_SIZE
        } else {
            min_len
        };
        self
    }

    /// Checks a message that must be authenticated with `key`.
    ///
    /// RFC 8489 sections 9.1.3 and 9.2.4: MESSAGE-INTEGRITY-SHA256 is verified when the
    /// message has it, MESSAGE-INTEGRITY otherwise.
    /// [`ValidatedMessage::integrity`] says which, so a response can be sent with the same
    /// one (section 9.1.3).
    ///
    /// # Errors
    ///
    /// The [`Rejection`] that says which check failed. In order: FINGERPRINT, integrity,
    /// unknown attributes (RFC 8489 section 6.3).
    pub fn authenticate(
        &self,
        m: &Message,
        key: &[u8],
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<ValidatedMessage, Rejection> {
        let algorithm = if m.contains(ATTR_MESSAGE_INTEGRITY_SHA256) {
            IntegrityAlgorithm::Sha256
        } else {
            IntegrityAlgorithm::Sha1
        };
        self.authenticate_with(m, algorithm, key, crypto)
    }

    /// Checks a message that must be authenticated with `key` by the integrity attribute of
    /// `algorithm`, whatever else it carries.
    ///
    /// This is the check for a response when the request carried one integrity attribute
    /// (RFC 8489 section 9.1.4: "the algorithm in the response has to match") and for
    /// everything after the first response (section 9.1.5).
    ///
    /// # Errors
    ///
    /// As [`authenticate`](Self::authenticate); a message without that attribute is
    /// [`Rejection::IntegrityMissing`].
    pub fn authenticate_with(
        &self,
        m: &Message,
        algorithm: IntegrityAlgorithm,
        key: &[u8],
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<ValidatedMessage, Rejection> {
        let fingerprint = self.check_fingerprint(m)?;
        if !m.contains(algorithm.attr_type()) {
            return Err(Rejection::IntegrityMissing);
        }
        let min_len = match algorithm {
            IntegrityAlgorithm::Sha1 => algorithm.tag_len(),
            IntegrityAlgorithm::Sha256 => self.min_sha256_len,
        };
        match check_integrity(m, algorithm, min_len, key, crypto) {
            Ok(()) => {}
            Err(Error::ErrIntegrityMismatch) => return Err(Rejection::IntegrityMismatch),
            Err(Error::ErrAttributeNotFound) => return Err(Rejection::IntegrityMissing),
            Err(error) => return Err(Rejection::Crypto(error.to_string())),
        }
        self.finish(m, Some(algorithm), fingerprint)
    }

    /// Checks a message that is not authenticated: FINGERPRINT and unknown attributes only.
    ///
    /// For a usage or a message without credentials: a Binding indication, the response of a
    /// public STUN server, the 401 that starts the long-term mechanism. If the message does
    /// carry an integrity attribute, it is not verified and
    /// [`ValidatedMessage::integrity`] is `None`, but the attributes after it are still left
    /// out, as RFC 8489 section 9 requires of every agent.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] that says which check failed.
    pub fn unauthenticated(&self, m: &Message) -> std::result::Result<ValidatedMessage, Rejection> {
        let fingerprint = self.check_fingerprint(m)?;
        self.finish(m, None, fingerprint)
    }

    /// RFC 8489 sections 7 and 14.7: a FINGERPRINT has the right value and is the last
    /// attribute; whether one must be there is the usage's rule.
    fn check_fingerprint(&self, m: &Message) -> std::result::Result<bool, Rejection> {
        if !m.contains(ATTR_FINGERPRINT) {
            return if self.fingerprint_required {
                Err(Rejection::FingerprintMissing)
            } else {
                Ok(false)
            };
        }
        FINGERPRINT
            .check(m)
            .map(|()| true)
            .map_err(|_| Rejection::FingerprintMismatch)
    }

    fn finish(
        &self,
        m: &Message,
        integrity: Option<IntegrityAlgorithm>,
        fingerprint: bool,
    ) -> std::result::Result<ValidatedMessage, Rejection> {
        let covered = covered_message(m);
        if let Some(known) = self.known {
            let unknown = covered.unknown_required_attributes(known);
            if !unknown.is_empty() {
                return Err(Rejection::UnknownAttributes(unknown));
            }
        }
        Ok(ValidatedMessage {
            covered,
            integrity,
            fingerprint,
        })
    }
}

/// The part of `m` an agent may read: its header and the attributes ahead of its first
/// integrity attribute, or all of them when it has none (RFC 8489 section 9). FINGERPRINT,
/// which only says the message is STUN, is left out with the rest.
fn covered_message(m: &Message) -> Message {
    let cut = m
        .attributes
        .0
        .iter()
        .position(|a| {
            a.typ == ATTR_MESSAGE_INTEGRITY
                || a.typ == ATTR_MESSAGE_INTEGRITY_SHA256
                || a.typ == ATTR_FINGERPRINT
        })
        .unwrap_or(m.attributes.0.len());
    let end = m.attribute_offset(cut).min(m.raw.len());
    let mut covered = Message {
        typ: m.typ,
        length: (end.saturating_sub(MESSAGE_HEADER_SIZE)) as u32,
        transaction_id: m.transaction_id,
        attributes: Attributes(m.attributes.0[..cut].to_vec()),
        raw: m.raw[..end].to_vec(),
    };
    if covered.raw.len() >= MESSAGE_HEADER_SIZE {
        covered.write_length();
    }
    covered
}

/// A received message that passed a [`Validator`], reduced to what its checks cover.
///
/// It dereferences to a [`Message`] that holds the header and the attributes ahead of the
/// first integrity attribute: [`get`](Message::get), [`contains`](Message::contains) and every
/// [`Getter`] work on it and cannot see an attribute that was appended after the integrity
/// attribute. The integrity attributes and FINGERPRINT are not in it either; ask
/// [`integrity`](Self::integrity) and [`has_fingerprint`](Self::has_fingerprint).
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedMessage {
    covered: Message,
    integrity: Option<IntegrityAlgorithm>,
    fingerprint: bool,
}

impl ValidatedMessage {
    /// The message, with the covered attributes only.
    #[must_use]
    pub fn message(&self) -> &Message {
        &self.covered
    }

    /// Gives up the wrapper and returns the message with the covered attributes only.
    #[must_use]
    pub fn into_message(self) -> Message {
        self.covered
    }

    /// The integrity attribute that was verified, or `None` for a message accepted through
    /// [`Validator::unauthenticated`].
    ///
    /// A response to this message carries the same one and no other (RFC 8489 section
    /// 9.1.3).
    #[must_use]
    pub fn integrity(&self) -> Option<IntegrityAlgorithm> {
        self.integrity
    }

    /// Whether the message was authenticated.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.integrity.is_some()
    }

    /// Whether the message carried a (correct) FINGERPRINT.
    #[must_use]
    pub fn has_fingerprint(&self) -> bool {
        self.fingerprint
    }
}

impl Deref for ValidatedMessage {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.covered
    }
}

impl AsRef<Message> for ValidatedMessage {
    fn as_ref(&self) -> &Message {
        &self.covered
    }
}

/// Builds the answer to a request that failed with [`Rejection::UnknownAttributes`]: an error
/// response of the request's method and transaction id with ERROR-CODE 420 (Unknown
/// Attribute) and the attributes in UNKNOWN-ATTRIBUTES (RFC 8489 sections 6.3.1 and 14.8).
///
/// `then` is applied after them: the integrity attribute when the request was authenticated
/// (section 6.3.1.1), then FINGERPRINT where the usage sends it.
///
/// # Errors
///
/// Fails when `request` is not a request, or a setter fails.
pub fn unknown_attributes_response(
    request: &Message,
    unknown: &[AttrType],
    then: &[Box<dyn Setter + '_>],
) -> Result<Message> {
    if request.typ.class != CLASS_REQUEST {
        return Err(Error::ErrUnexpectedClass);
    }
    let mut response = Message::new();
    response.write_header();
    response.set_type(MessageType::new(request.typ.method, CLASS_ERROR_RESPONSE));
    request.transaction_id.add_to(&mut response)?;
    CODE_UNKNOWN_ATTRIBUTE.add_to(&mut response)?;
    UnknownAttributes(unknown.to_vec()).add_to(&mut response)?;
    for setter in then {
        setter.add_to(&mut response)?;
        if response.length > u32::from(u16::MAX) {
            return Err(Error::ErrPacketTooBig);
        }
    }
    Ok(response)
}
