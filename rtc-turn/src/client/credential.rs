//! The long-term credential of one allocation (RFC 8489 §9.2), as snapshots.
//!
//! [`LongTermCredentials`] holds the rules: what a 401 or 438 turns into, which attributes a
//! request carries, which responses are authentic. A [`Credential`] is one state of it and is
//! never changed: a challenge, or a new password, makes a new one. A transaction keeps the
//! snapshot its request was made with, so its response is checked against the key that
//! request was signed with, whatever the server has asked for since.
use std::sync::Arc;

use crypto::{RTCCrypto, SecretVec};
use shared::error::Result;
use stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_MESSAGE_INTEGRITY_SHA256, ATTR_REALM};
use stun::error_code::{CODE_STALE_NONCE, ErrorCodeAttribute};
use stun::integrity::long_term_key;
use stun::long_term::{ChallengeError, LongTermCredentials, LongTermResponse};
use stun::message::{CLASS_ERROR_RESPONSE, Getter, Message, Setter};
use stun::password_algorithm::{
    PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256, PasswordAlgorithms,
};
use stun::validated::{Rejection, ValidatedMessage, Validator};

/// What the application gave the client to authenticate with.
pub(crate) struct Login {
    pub(crate) username: String,
    pub(crate) password: String,
    /// The password algorithms the client accepts from a server's PASSWORD-ALGORITHMS; empty
    /// for all it implements (SHA-256 and MD5).
    pub(crate) password_algorithms: Vec<u16>,
}

/// What a server's challenge added to the login.
struct Session {
    credentials: LongTermCredentials,
    /// The 401 or 438 the session was made from (its covered attributes), from which it is
    /// made again for a new password.
    challenge: Message,
    /// The long-term key, for the one check [`LongTermCredentials`] leaves out: a 401 or 438
    /// that carries an integrity attribute.
    key: SecretVec,
}

/// The credential requests are made with: none until the server asked for one.
pub(crate) struct Credential {
    login: Arc<Login>,
    session: Option<Session>,
}

impl Credential {
    /// The credential of a first request: nothing (RFC 8489 §9.2.3.1).
    pub(crate) fn new(login: Arc<Login>) -> Self {
        Self {
            login,
            session: None,
        }
    }

    /// Whether the server has asked for the credential, so that requests carry it.
    pub(crate) fn is_established(&self) -> bool {
        self.session.is_some()
    }

    /// The nonce requests carry.
    #[cfg(test)]
    pub(crate) fn nonce(&self) -> Option<&str> {
        self.session.as_ref()?.credentials.nonce()
    }

    fn build(
        login: &Arc<Login>,
        earlier: Option<&Message>,
        new: Option<(&Message, &Message)>,
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<Self, ChallengeError> {
        let unusable = |err: shared::error::Error| ChallengeError::Unusable(err.to_string());

        // What the new challenge says, less whatever follows an integrity attribute
        // (RFC 8489 §9).
        let new = match new {
            Some((request, response)) => Some((
                request,
                Validator::new()
                    .unauthenticated(response)
                    .map_err(|_| ChallengeError::NotAChallenge)?
                    .into_message(),
            )),
            None => None,
        };
        let Some(latest) = new.as_ref().map(|(_, response)| response).or(earlier) else {
            return Ok(Self::new(login.clone()));
        };

        let mut credentials = LongTermCredentials::new(&login.username, &login.password)
            .map_err(unusable)?
            .with_password_algorithms(&accepted_algorithms(login, latest));
        let mut challenge = None;
        if let Some((request, mut response)) = new {
            // The state the earlier challenge left, against which the new one is judged: a
            // 401 to a request that carried these very credentials is not answered again.
            // (An earlier challenge the algorithms of this one rule out left no such state.)
            if let Some(earlier) = earlier {
                let _ = credentials.challenge(&Message::new(), earlier, crypto);
            }
            // RFC 8489 §9.2.4 has a 438 (Stale Nonce) carry the REALM. A server that leaves
            // it out of the response to a request that carried one means the realm it
            // already gave: the nonce is what a 438 is about.
            if !response.contains(ATTR_REALM)
                && is_stale_nonce(&response)
                && let Some(realm) = credentials.realm()
            {
                let realm = realm.to_owned();
                response.add(ATTR_REALM, realm.as_bytes());
            }
            credentials.challenge(request, &response, crypto)?;
            challenge = Some(response);
        } else if let Some(earlier) = earlier {
            credentials.challenge(&Message::new(), earlier, crypto)?;
            challenge = Some(earlier.clone());
        }
        let Some(challenge) = challenge else {
            return Ok(Self::new(login.clone()));
        };
        let key = long_term_key(
            credentials
                .password_algorithm()
                .map_or(PASSWORD_ALGORITHM_MD5, |a| a.algorithm),
            credentials.username(),
            credentials.realm().unwrap_or_default(),
            &login.password,
            crypto,
        )
        .map_err(unusable)?;
        Ok(Self {
            login: login.clone(),
            session: Some(Session {
                credentials,
                challenge,
                key: SecretVec::new(key),
            }),
        })
    }

    /// The credential after the 401 (Unauthenticated) or 438 (Stale Nonce) `response` to
    /// `request`, by the rules of RFC 8489 §9.2.5: the realm, nonce, password algorithm and
    /// user name form the server asked for.
    ///
    /// # Errors
    ///
    /// The request is not to be made again: the nonce cookie announces PASSWORD-ALGORITHMS
    /// and the response has none (a bid-down), no offered algorithm is supported, the same
    /// credentials were just refused, or the response has no realm or nonce.
    pub(crate) fn challenged(
        &self,
        request: &Message,
        response: &Message,
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<Self, ChallengeError> {
        Self::build(
            &self.login,
            self.session.as_ref().map(|s| &s.challenge),
            Some((request, response)),
            crypto,
        )
    }

    /// The same session (realm, nonce, algorithm) for another user name or password.
    ///
    /// # Errors
    ///
    /// Fails when the user name or the password cannot be used (RFC 8489 §9.2.2: they are
    /// OpaqueStrings).
    pub(crate) fn with_login(&self, login: Arc<Login>, crypto: &dyn RTCCrypto) -> Result<Self> {
        Self::build(
            &login,
            self.session.as_ref().map(|s| &s.challenge),
            None,
            crypto,
        )
        .map_err(|err| shared::error::Error::Other(err.to_string()))
    }

    /// The authentication attributes of a request made with this credential; `None` before
    /// the server asked for it.
    pub(crate) fn setter<'a>(&'a self, crypto: &'a dyn RTCCrypto) -> Option<Box<dyn Setter + 'a>> {
        let session = self.session.as_ref()?;
        Some(Box::new(session.credentials.setter(crypto)))
    }

    /// Checks the response to a request made with this credential (RFC 8489 §9.2.5).
    ///
    /// A request that carried no credential takes any response, less what follows an
    /// integrity attribute. One that carried it takes a response signed with the same key and
    /// attribute, or a 401 or 438, which a server cannot always sign; a 401 or 438 that is
    /// signed all the same must verify.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] the response is discarded for.
    pub(crate) fn check_response(
        &self,
        response: &Message,
        validator: &Validator<'_>,
        crypto: &dyn RTCCrypto,
    ) -> std::result::Result<ValidatedMessage, Rejection> {
        let Some(session) = &self.session else {
            return validator.unauthenticated(response);
        };
        match session
            .credentials
            .check_response(response, validator, crypto)?
        {
            LongTermResponse::Authenticated(valid) => Ok(valid),
            LongTermResponse::Challenge(unsigned) => {
                if response.contains(ATTR_MESSAGE_INTEGRITY)
                    || response.contains(ATTR_MESSAGE_INTEGRITY_SHA256)
                {
                    validator.authenticate(response, session.key.as_ref(), crypto)
                } else {
                    Ok(unsigned)
                }
            }
        }
    }
}

/// The password algorithms the client takes from the PASSWORD-ALGORITHMS of `challenge`.
///
/// RFC 8489 §9.2.5 has a client use the first algorithm of the server's list it supports.
/// TURN narrows that (RFC 8656 §6): when the list holds both MD5 and SHA-256 and the client
/// supports both, the request carries SHA-256, wherever the server put it. So with SHA-256 on
/// offer and allowed, it is the only one taken.
fn accepted_algorithms(login: &Login, challenge: &Message) -> Vec<u16> {
    let allowed = if login.password_algorithms.is_empty() {
        vec![PASSWORD_ALGORITHM_SHA256, PASSWORD_ALGORITHM_MD5]
    } else {
        login.password_algorithms.clone()
    };
    let mut offered = PasswordAlgorithms::default();
    if allowed.contains(&PASSWORD_ALGORITHM_SHA256)
        && offered.get_from(challenge).is_ok()
        && offered
            .0
            .iter()
            .any(|a| a.algorithm == PASSWORD_ALGORITHM_SHA256)
    {
        vec![PASSWORD_ALGORITHM_SHA256]
    } else {
        allowed
    }
}

/// Whether `m` is a 438 (Stale Nonce) error response.
fn is_stale_nonce(m: &Message) -> bool {
    let mut code = ErrorCodeAttribute::default();
    m.typ.class == CLASS_ERROR_RESPONSE && code.get_from(m).is_ok() && code.code == CODE_STALE_NONCE
}

#[cfg(test)]
impl Credential {
    /// The credential of the scripted server's user ("user", "pass") after its 401 with the
    /// realm "realm" and the nonce "nonce", for tests that start from a granted allocation.
    pub(crate) fn established() -> Arc<Self> {
        use stun::error_code::CODE_UNAUTHORIZED;
        use stun::message::{METHOD_ALLOCATE, MessageType, TransactionId};
        use stun::textattrs::TextAttribute;

        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let mut challenge = Message::new();
        challenge
            .build(&[
                Box::new(TransactionId::new()),
                Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
                Box::new(ErrorCodeAttribute {
                    code: CODE_UNAUTHORIZED,
                    reason: b"Unauthorized".to_vec(),
                }),
                Box::new(TextAttribute::new(
                    stun::attributes::ATTR_NONCE,
                    "nonce".to_owned(),
                )),
                Box::new(TextAttribute::new(ATTR_REALM, "realm".to_owned())),
            ])
            .expect("the challenge builds");
        let login = Arc::new(Login {
            username: "user".to_owned(),
            password: "pass".to_owned(),
            password_algorithms: vec![],
        });
        Arc::new(
            Self::new(login)
                .challenged(&Message::new(), &challenge, provider.crypto())
                .expect("the challenge is taken"),
        )
    }
}
