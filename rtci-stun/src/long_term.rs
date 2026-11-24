//! The client side of the long-term credential mechanism (RFC 8489 section 9.2), as data and
//! rules without I/O.
//!
//! [`LongTermCredentials`](crate::long_term::LongTermCredentials) holds what a client keeps for one server: the user name and
//! password, and, once the server has challenged a request, the realm, the nonce, the password
//! algorithm and whether the user name is sent hashed. It does three things:
//!
//! * [`challenge`](crate::long_term::LongTermCredentials::challenge) takes a 401 (Unauthenticated) or 438
//!   (Stale Nonce) error response and decides whether the request may be retried, applying
//!   the bid-down protection of the nonce cookie (section 9.2.5);
//! * [`setter`](crate::long_term::LongTermCredentials::setter) adds the authentication attributes to a request:
//!   none before the first challenge (section 9.2.3.1), then USERNAME or USERHASH, REALM,
//!   NONCE, PASSWORD-ALGORITHMS and PASSWORD-ALGORITHM when the server offered algorithms, and
//!   the integrity attribute (sections 9.2.3.2 and 9.2.5);
//! * [`check_response`](crate::long_term::LongTermCredentials::check_response) authenticates a response and
//!   says whether it is one to act on, a challenge, or one to discard (section 9.2.5).
//!
//! The transaction layer stays with the caller: a retry is a new transaction, a discarded
//! response leaves the request's retransmissions running.

#[cfg(test)]
mod long_term_test;

use crate::attributes::*;
use crate::error_code::{CODE_STALE_NONCE, CODE_UNAUTHORIZED, ErrorCode, ErrorCodeAttribute};
use crate::integrity::{
    IntegrityAlgorithm, MessageIntegrity, MessageIntegritySha256, long_term_key,
};
use crate::message::*;
use crate::nonce_cookie::SecurityFeatures;
use crate::opaque::opaque_string;
use crate::password_algorithm::{
    PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256, PasswordAlgorithm, PasswordAlgorithms,
};
use crate::textattrs::TextAttribute;
use crate::userhash::Userhash;
use crate::validated::{Rejection, ValidatedMessage, Validator};
use crypto::{RTCCrypto, SecretVec};
use shared::error::*;

use std::fmt;

/// Why a 401 or 438 error response does not lead to a retry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChallengeError {
    /// The response is not an error response with code 401 or 438.
    NotAChallenge,
    /// The response has no REALM or no NONCE, or one of them is not text.
    Incomplete,
    /// The nonce cookie has the "Password algorithms" bit set but the response carries no
    /// PASSWORD-ALGORITHMS: the attribute was removed on the way (a bid-down attack). RFC
    /// 8489 section 9.2.5: the client MUST NOT retry.
    BidDown,
    /// PASSWORD-ALGORITHMS lists no algorithm this client supports. RFC 8489 section 9.2.5:
    /// the client MUST NOT retry.
    NoSupportedAlgorithm,
    /// A 401 to a request that was already authenticated with the same user name, realm and
    /// password algorithm: the credentials are wrong, and retrying without changing them is
    /// what RFC 8489 section 9.2.5 forbids.
    CredentialsRejected,
    /// The realm, the user name or the password cannot be used (not an OpaqueString), or the
    /// crypto provider failed.
    Unusable(String),
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAChallenge => write!(f, "not a 401 or 438 error response"),
            Self::Incomplete => write!(f, "the challenge has no REALM or no NONCE"),
            Self::BidDown => write!(
                f,
                "the nonce cookie announces PASSWORD-ALGORITHMS and the response has none"
            ),
            Self::NoSupportedAlgorithm => {
                write!(f, "the server offers no supported password algorithm")
            }
            Self::CredentialsRejected => write!(f, "the credentials were rejected"),
            Self::Unusable(reason) => write!(f, "the credentials cannot be used: {reason}"),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// What a response to a request of this client is, once checked.
#[derive(Debug, Clone, PartialEq)]
pub enum LongTermResponse {
    /// A success or error response authenticated with the client's key: act on it.
    Authenticated(ValidatedMessage),
    /// A 401 or 438 error response. It is not authenticated (the server cannot sign for
    /// credentials it rejects); hand the original response to
    /// [`LongTermCredentials::challenge`].
    Challenge(ValidatedMessage),
}

/// What a server's challenge fixed: everything that is derived from the realm, the nonce and
/// the offered algorithms.
struct Session {
    realm: String,
    nonce: String,
    /// PASSWORD-ALGORITHMS as the server sent it, echoed in every request.
    algorithms: Option<PasswordAlgorithms>,
    /// The algorithm chosen from it; `None` is RFC 5389's MD5 without PASSWORD-ALGORITHM.
    algorithm: Option<PasswordAlgorithm>,
    /// USERHASH in place of USERNAME.
    userhash: Option<Userhash>,
    key: SecretVec,
}

/// A client's long-term credentials for one server, and what the server's challenges added
/// to them. See the [module documentation](self).
pub struct LongTermCredentials {
    username: String,
    password: SecretVec,
    supported: Vec<u16>,
    session: Option<Session>,
}

impl fmt::Debug for LongTermCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LongTermCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("realm", &self.realm())
            .field("nonce", &self.nonce())
            .field("password_algorithm", &self.password_algorithm())
            .field("uses_userhash", &self.uses_userhash())
            .finish()
    }
}

impl LongTermCredentials {
    /// Credentials that support the SHA-256 and MD5 password algorithms.
    ///
    /// # Errors
    ///
    /// RFC 8489 section 14.3: the user name is OpaqueString-processed; one the profile does
    /// not allow is refused, as is such a password (section 9.2.2).
    pub fn new(username: &str, password: &str) -> Result<Self> {
        Ok(Self {
            username: opaque_string(username)?.into_owned(),
            password: SecretVec::new(opaque_string(password)?.into_owned().into_bytes()),
            supported: vec![PASSWORD_ALGORITHM_SHA256, PASSWORD_ALGORITHM_MD5],
            session: None,
        })
    }

    /// Restricts the password algorithms this client accepts from a server's
    /// PASSWORD-ALGORITHMS, for instance to SHA-256 alone (RFC 8489 section 18.5.1.1 keeps
    /// MD5 for legacy systems). Numbers other than
    /// [`PASSWORD_ALGORITHM_SHA256`] and [`PASSWORD_ALGORITHM_MD5`] are dropped: there is no
    /// key derivation for them.
    ///
    /// A server that sends no PASSWORD-ALGORITHMS is an RFC 5389 server, which has MD5 only;
    /// a client that left MD5 out refuses its challenge
    /// ([`ChallengeError::NoSupportedAlgorithm`]).
    #[must_use]
    pub fn with_password_algorithms(mut self, supported: &[u16]) -> Self {
        self.supported = supported
            .iter()
            .copied()
            .filter(|a| [PASSWORD_ALGORITHM_SHA256, PASSWORD_ALGORITHM_MD5].contains(a))
            .collect();
        self
    }

    /// The user name, OpaqueString-processed.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The realm of the last challenge.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.session.as_ref().map(|s| s.realm.as_str())
    }

    /// The nonce of the last challenge.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.session.as_ref().map(|s| s.nonce.as_str())
    }

    /// The password algorithm sent in PASSWORD-ALGORITHM, when the server offered a list.
    #[must_use]
    pub fn password_algorithm(&self) -> Option<&PasswordAlgorithm> {
        self.session.as_ref().and_then(|s| s.algorithm.as_ref())
    }

    /// Whether requests carry USERHASH in place of USERNAME.
    #[must_use]
    pub fn uses_userhash(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.userhash.is_some())
    }

    /// The integrity attribute requests carry and responses must carry, once challenged:
    /// MESSAGE-INTEGRITY-SHA256 alone after a challenge with PASSWORD-ALGORITHMS (RFC 8489
    /// section 9.2.5), MESSAGE-INTEGRITY otherwise.
    #[must_use]
    pub fn integrity(&self) -> Option<IntegrityAlgorithm> {
        self.session.as_ref().map(|s| {
            if s.algorithms.is_some() {
                IntegrityAlgorithm::Sha256
            } else {
                IntegrityAlgorithm::Sha1
            }
        })
    }

    /// Forgets the server's challenge: the next request is a first request again.
    pub fn reset(&mut self) {
        self.session = None;
    }

    /// Takes the 401 (Unauthenticated) or 438 (Stale Nonce) error `response` to `request` and
    /// prepares the retry (RFC 8489 section 9.2.5).
    ///
    /// On `Ok`, the realm, nonce, algorithm and key are replaced by the response's, and the
    /// request is to be sent again in a new transaction with [`setter`](Self::setter).
    ///
    /// # Errors
    ///
    /// The [`ChallengeError`] that says why there is no retry. The state is unchanged then.
    pub fn challenge(
        &mut self,
        request: &Message,
        response: &Message,
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<(), ChallengeError> {
        // Whatever follows an integrity attribute is not read (section 9), signed or not.
        let response = Validator::new()
            .unauthenticated(response)
            .map_err(|_| ChallengeError::NotAChallenge)?;
        let code = error_code_of(&response).ok_or(ChallengeError::NotAChallenge)?;
        if code != CODE_UNAUTHORIZED && code != CODE_STALE_NONCE {
            return Err(ChallengeError::NotAChallenge);
        }
        let realm = TextAttribute::get_from_as(&response, ATTR_REALM)
            .map_err(|_| ChallengeError::Incomplete)?
            .text;
        let nonce = TextAttribute::get_from_as(&response, ATTR_NONCE)
            .map_err(|_| ChallengeError::Incomplete)?
            .text;
        if realm.is_empty() || nonce.is_empty() {
            return Err(ChallengeError::Incomplete);
        }
        let realm = opaque_string(&realm)
            .map_err(|e| ChallengeError::Unusable(e.to_string()))?
            .into_owned();

        // The nonce cookie says which features the server uses; the attributes have to agree.
        let features = SecurityFeatures::from_nonce(&nonce).unwrap_or(SecurityFeatures::NONE);
        let mut algorithms = PasswordAlgorithms::default();
        let algorithms = match algorithms.get_from(&response) {
            Ok(()) => Some(algorithms),
            Err(Error::ErrAttributeNotFound) => None,
            Err(_) => return Err(ChallengeError::Incomplete),
        };
        if features.password_algorithms() && algorithms.is_none() {
            return Err(ChallengeError::BidDown);
        }
        let algorithm = match &algorithms {
            Some(list) => Some(
                list.first_supported(&self.supported)
                    .cloned()
                    .ok_or(ChallengeError::NoSupportedAlgorithm)?,
            ),
            // An RFC 5389 server: the MD5 key, without PASSWORD-ALGORITHM.
            None if self.supported.contains(&PASSWORD_ALGORITHM_MD5) => None,
            None => return Err(ChallengeError::NoSupportedAlgorithm),
        };

        // A 401 to a request that carried these very credentials: they are wrong.
        if code == CODE_UNAUTHORIZED
            && let Some(session) = &self.session
            && request_was_authenticated(request)
            && session.realm == realm
            && session.algorithm == algorithm
            && session.userhash.is_some() == features.username_anonymity()
        {
            return Err(ChallengeError::CredentialsRejected);
        }

        let userhash = if features.username_anonymity() {
            Some(
                Userhash::new(&self.username, &realm, crypto)
                    .map_err(|e| ChallengeError::Unusable(e.to_string()))?,
            )
        } else {
            None
        };
        let password = std::str::from_utf8(self.password.as_ref())
            .map_err(|e| ChallengeError::Unusable(e.to_string()))?;
        let key = long_term_key(
            algorithm
                .as_ref()
                .map_or(PASSWORD_ALGORITHM_MD5, |a| a.algorithm),
            &self.username,
            &realm,
            password,
            crypto,
        )
        .map_err(|e| ChallengeError::Unusable(e.to_string()))?;

        self.session = Some(Session {
            realm,
            nonce,
            algorithms,
            algorithm,
            userhash,
            key: SecretVec::new(key),
        });
        Ok(())
    }

    /// A [`Setter`] that adds the authentication attributes to a request. It goes after the
    /// request's own attributes and ahead of FINGERPRINT.
    ///
    /// Before the first challenge it adds nothing: the first request carries no USERNAME,
    /// USERHASH, REALM, NONCE, PASSWORD-ALGORITHMS, PASSWORD-ALGORITHM or integrity attribute
    /// (RFC 8489 section 9.2.3.1).
    #[must_use]
    pub fn setter<'a>(&'a self, crypto: &'a dyn RTCCrypto) -> LongTermAuthentication<'a> {
        LongTermAuthentication {
            credentials: self,
            crypto,
        }
    }

    /// Checks a response to a request that was sent with [`setter`](Self::setter) after a
    /// challenge, by the rules of RFC 8489 section 9.2.5. `validator` carries the usage's own
    /// checks (FINGERPRINT, known attributes).
    ///
    /// * A 401 or 438 error response is a [`LongTermResponse::Challenge`]: such a response
    ///   need not be signed.
    /// * Any other response must carry the integrity attribute the request carried, valid
    ///   under the client's key; then it is [`LongTermResponse::Authenticated`].
    ///
    /// # Errors
    ///
    /// The response is to be discarded as if it had never been received, so that the
    /// request's retransmissions continue: [`Rejection::IntegrityMissing`] (which is what a
    /// 400 without integrity attribute gets) or [`Rejection::IntegrityMismatch`], and, for a
    /// response whose NONCE has a cookie with the "Password algorithms" bit but which has no
    /// PASSWORD-ALGORITHMS, [`Rejection::IntegrityMissing`] as well: it is to be ignored.
    /// When every response to a request was discarded this way, the transaction's failure is
    /// an integrity violation, not a timeout; over a reliable transport it fails at once.
    pub fn check_response(
        &self,
        response: &Message,
        validator: &Validator<'_>,
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<LongTermResponse, Rejection> {
        let unauthenticated = validator.unauthenticated(response);
        if let Ok(view) = &unauthenticated
            && response.typ.class == CLASS_ERROR_RESPONSE
            && let Some(code) = error_code_of(view)
            && (code == CODE_UNAUTHORIZED || code == CODE_STALE_NONCE)
        {
            return unauthenticated.map(LongTermResponse::Challenge);
        }
        // Before any challenge the client has no key: nothing can be authenticated.
        let (Some(session), Some(algorithm)) = (&self.session, self.integrity()) else {
            return Err(unauthenticated.err().unwrap_or(Rejection::IntegrityMissing));
        };
        let valid =
            validator.authenticate_with(response, algorithm, session.key.as_ref(), crypto)?;
        // "For all other responses": a cookie that announces PASSWORD-ALGORITHMS on a
        // response without the attribute means the response was tampered with.
        if let Ok(nonce) = TextAttribute::get_from_as(&valid, ATTR_NONCE)
            && SecurityFeatures::from_nonce(&nonce.text).is_some_and(|f| f.password_algorithms())
            && !valid.contains(ATTR_PASSWORD_ALGORITHMS)
        {
            return Err(Rejection::IntegrityMissing);
        }
        Ok(LongTermResponse::Authenticated(valid))
    }
}

/// The code of the ERROR-CODE attribute of `m`, when it is an error response that has one.
fn error_code_of(m: &Message) -> Option<ErrorCode> {
    if m.typ.class != CLASS_ERROR_RESPONSE {
        return None;
    }
    let mut code = ErrorCodeAttribute::default();
    code.get_from(m).ok()?;
    Some(code.code)
}

/// Whether `request` carried credentials: an integrity attribute (RFC 8489 section 9.2.4).
fn request_was_authenticated(request: &Message) -> bool {
    request.contains(ATTR_MESSAGE_INTEGRITY) || request.contains(ATTR_MESSAGE_INTEGRITY_SHA256)
}

/// The authentication attributes of a request, as a [`Setter`]: see
/// [`LongTermCredentials::setter`].
pub struct LongTermAuthentication<'a> {
    credentials: &'a LongTermCredentials,
    crypto: &'a dyn RTCCrypto,
}

impl Setter for LongTermAuthentication<'_> {
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let Some(session) = &self.credentials.session else {
            return Ok(());
        };
        match &session.userhash {
            Some(userhash) => userhash.add_to(m)?,
            None => {
                TextAttribute::new(ATTR_USERNAME, self.credentials.username.clone()).add_to(m)?
            }
        }
        TextAttribute::new(ATTR_REALM, session.realm.clone()).add_to(m)?;
        TextAttribute::new(ATTR_NONCE, session.nonce.clone()).add_to(m)?;
        if let Some(algorithms) = &session.algorithms {
            algorithms.add_to(m)?;
        }
        if let Some(algorithm) = &session.algorithm {
            algorithm.add_to(m)?;
        }
        if session.algorithms.is_some() {
            MessageIntegritySha256::new_raw(session.key.as_ref().to_vec(), self.crypto).add_to(m)
        } else {
            MessageIntegrity::new_raw_integrity_with_provider(
                session.key.as_ref().to_vec(),
                self.crypto,
            )
            .add_to(m)
        }
    }
}
