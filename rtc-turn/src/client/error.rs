use std::fmt;
use std::net::SocketAddr;

use shared::error::Error;
use stun::addr::MappedAddress;
use stun::alternate::TryAlternate;
use stun::attributes::{ATTR_ALTERNATE_SERVER, AttrType};
use stun::error_code::{ErrorCode, ErrorCodeAttribute};
use stun::message::Getter;
use stun::uattrs::UnknownAttributes;
use stun::validated::ValidatedMessage;

/// An error response from the server: its code and what a client acts on with it.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorResponse {
    /// The STUN error code, for example 437 (`stun::error_code::CODE_ALLOC_MISMATCH`).
    pub code: ErrorCode,
    /// The reason phrase the server sent. For people; nothing depends on its text.
    pub reason: String,
    /// The ALTERNATE-SERVER of a 300 (Try Alternate): the server to use instead
    /// (RFC 8489 §10, RFC 8656 §7.4). It is reported whether or not the response was
    /// authenticated; see `try_alternate`.
    pub alternate_server: Option<SocketAddr>,
    /// The redirection of a 300 (Try Alternate) that was authenticated with the request's
    /// credential: every ALTERNATE-SERVER and the ALTERNATE-DOMAIN. RFC 8489 §14.8 has a
    /// client validate the response before it redirects itself, so this is `None` for a 300
    /// that was not signed, such as one to the first Allocate, which carries no credential.
    /// [`Client::follow_alternate`](super::Client::follow_alternate) takes it.
    pub try_alternate: Option<TryAlternate>,
    /// The attributes a 420 (Unknown Attribute) says the server did not understand.
    pub unknown_attributes: Vec<AttrType>,
}

impl fmt::Debug for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorResponse")
            .field("code", &self.code.0)
            .field("reason", &self.reason)
            .field("alternate_server", &self.alternate_server)
            .field("try_alternate", &self.try_alternate)
            .field("unknown_attributes", &self.unknown_attributes)
            .finish()
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error {}: {}", self.code.0, self.reason)
    }
}

/// Why a TURN request did not do what it asked.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum RequestError {
    /// The server answered with this error response.
    Rejected(ErrorResponse),
    /// There is no usable answer: the response was malformed, the request timed out or could
    /// not be made, or the state it was about is gone.
    Failed(Error),
}

impl RequestError {
    /// The server's error code, when the server answered with one.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Rejected(response) => Some(response.code),
            Self::Failed(_) => None,
        }
    }

    /// Whether the server answered with `code`.
    #[must_use]
    pub fn is(&self, code: ErrorCode) -> bool {
        self.code() == Some(code)
    }

    /// The error of the error response `res`, from the attributes its checks cover.
    pub(crate) fn of(res: &ValidatedMessage) -> Self {
        let mut code = ErrorCodeAttribute::default();
        if let Err(err) = code.get_from(res) {
            return Self::Failed(Error::Other(format!(
                "{} without ERROR-CODE: {err}",
                res.typ
            )));
        }
        let mut alternate = MappedAddress::default();
        let alternate_server = alternate
            .get_from_as(res, ATTR_ALTERNATE_SERVER)
            .ok()
            .map(|()| SocketAddr::new(alternate.ip, alternate.port));
        let mut unknown = UnknownAttributes(vec![]);
        let unknown_attributes = if unknown.get_from(res).is_ok() {
            unknown.0
        } else {
            vec![]
        };
        Self::Rejected(ErrorResponse {
            code: code.code,
            reason: String::from_utf8_lossy(&code.reason).into_owned(),
            alternate_server,
            try_alternate: TryAlternate::from_response(res).ok().flatten(),
            unknown_attributes,
        })
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(response) => response.fmt(f),
            Self::Failed(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RequestError {}

impl From<RequestError> for Error {
    /// The error itself when there is one, the server's code and reason as text otherwise.
    fn from(err: RequestError) -> Self {
        match err {
            RequestError::Failed(err) => err,
            RequestError::Rejected(response) => Error::Other(response.to_string()),
        }
    }
}

impl From<Error> for RequestError {
    fn from(err: Error) -> Self {
        Self::Failed(err)
    }
}
