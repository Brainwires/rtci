use std::fmt;

use sdp::description::session::SessionDescription;
use sdp::util::ConnectionRole;
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};

/// Indicates the role of the DTLS transport in the handshake.
///
/// `RTCDtlsRole` determines whether the peer acts as a DTLS client or server
/// during the DTLS handshake. This role is typically determined automatically
/// based on the ICE role, but can be explicitly set in certain scenarios.
///
/// # Role Selection
///
/// - **Offerer**: Should use [`Auto`](Self::Auto) (actpass in SDP), allowing the answerer to choose
/// - **Answerer**: Should use [`Client`](Self::Client) (active in SDP) for lower latency
///
/// The answerer using `Client` allows the DTLS handshake to start immediately
/// without waiting for the answer to be received by the offerer.
///
/// # Relationship with ICE Role
///
/// When `Auto` is used, the DTLS role is derived from the ICE role:
///
/// - **ICE Controlled** → DTLS Client
/// - **ICE Controlling** → DTLS Server
///
/// # Examples
///
/// ## Standard Offer/Answer
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// // Offerer uses Auto (actpass)
/// let offerer_role = RTCDtlsRole::Auto;
/// println!("Offerer SDP: a=setup:actpass");
///
/// // Answerer uses Client (active) - recommended
/// let answerer_role = RTCDtlsRole::Client;
/// println!("Answerer SDP: a=setup:active");
///
/// // This allows DTLS handshake to begin in parallel with signaling
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// let role = RTCDtlsRole::Client;
/// assert_eq!(role.to_string(), "client");
///
/// let role = RTCDtlsRole::Server;
/// assert_eq!(role.to_string(), "server");
/// ```
///
/// ## Checking Role
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsRole;
///
/// fn will_initiate_handshake(role: RTCDtlsRole) -> bool {
///     matches!(role, RTCDtlsRole::Client)
/// }
///
/// assert!(will_initiate_handshake(RTCDtlsRole::Client));
/// assert!(!will_initiate_handshake(RTCDtlsRole::Server));
/// ```
///
/// # Specification
///
/// - [RFC 5763] - DTLS-SRTP Setup Attribute
/// - [RFC 8122] - Connection-Oriented Media Transport over TLS
///
/// [RFC 5763]: https://datatracker.ietf.org/doc/html/rfc5763
/// [RFC 8122]: https://datatracker.ietf.org/doc/html/rfc8122
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCDtlsRole {
    /// Role not specified. This should not occur in normal operation.
    #[default]
    Unspecified = 0,

    /// DTLS role is determined automatically based on ICE role.
    ///
    /// The ICE controlled role acts as the DTLS client, and the ICE controlling
    /// role acts as the DTLS server. This maps to `setup:actpass` in SDP.
    ///
    /// The offerer MUST use `Auto` and be prepared to receive a client_hello
    /// before receiving the answer.
    #[serde(rename = "auto")]
    Auto = 1,

    /// DTLS client role - initiates the handshake.
    ///
    /// The client sends the first DTLS ClientHello message to begin the
    /// handshake. This maps to `setup:active` in SDP.
    ///
    /// The answerer SHOULD use `Client` to allow the answer and DTLS handshake
    /// to occur in parallel, reducing latency.
    #[serde(rename = "client")]
    Client = 2,

    /// DTLS server role - waits for the handshake to be initiated.
    ///
    /// The server waits to receive a DTLS ClientHello message before responding.
    /// This maps to `setup:passive` in SDP.
    ///
    /// Note: Using `Server` as the answerer adds latency since the DTLS
    /// handshake cannot begin until the answerer receives the offer.
    #[serde(rename = "server")]
    Server = 3,
}

/// <https://datatracker.ietf.org/doc/html/rfc5763>
/// The answerer MUST use either a
/// setup attribute value of setup:active or setup:passive.  Note that
/// if the answerer uses setup:passive, then the DTLS handshake will
/// not begin until the answerer is received, which adds additional
/// latency. setup:active allows the answer and the DTLS handshake to
/// occur in parallel.  Thus, setup:active is RECOMMENDED.
pub(crate) const DEFAULT_DTLS_ROLE_ANSWER: RTCDtlsRole = RTCDtlsRole::Client;

/// The endpoint that is the offerer MUST use the setup attribute
/// value of setup:actpass and be prepared to receive a client_hello
/// before it receives the answer.
pub(crate) const DEFAULT_DTLS_ROLE_OFFER: RTCDtlsRole = RTCDtlsRole::Auto;

impl fmt::Display for RTCDtlsRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCDtlsRole::Auto => write!(f, "auto"),
            RTCDtlsRole::Client => write!(f, "client"),
            RTCDtlsRole::Server => write!(f, "server"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

/// The DTLS role a remote description states with `a=setup` (RFC 4145 section 4, RFC 8842
/// section 5): the first media-level value, else the session-level one (the attribute may sit
/// at either level, and a media-level one overrides it). `active` is the DTLS client, `passive`
/// the server; `actpass`, no attribute or anything else is [`RTCDtlsRole::Auto`], "no role
/// taken". `set_remote_description` refuses the values RFC 8842 does not allow before this is
/// used (`validate_setup_attributes`).
impl From<&SessionDescription> for RTCDtlsRole {
    fn from(session_description: &SessionDescription) -> Self {
        let media_level = session_description
            .media_descriptions
            .iter()
            .flat_map(|media_section| media_section.attributes.iter())
            .find(|attribute| attribute.key == "setup");
        let session_level = session_description
            .attributes
            .iter()
            .find(|attribute| attribute.key == "setup");
        match media_level
            .or(session_level)
            .and_then(|attribute| attribute.value.as_deref())
        {
            Some("active") => RTCDtlsRole::Client,
            Some("passive") => RTCDtlsRole::Server,
            _ => RTCDtlsRole::Auto,
        }
    }
}

/// Checks every `a=setup` of a remote description (RFC 4145 section 4, RFC 8842 section 5.1).
///
/// The value is `active`, `passive` or `actpass`. `holdconn` is refused: RFC 8842 section 5.1
/// bars it from a DTLS association, and taking it for "no preference" would start a handshake
/// the peer said not to start. A level states one value. Sections may differ from each other:
/// with BUNDLE the transport takes the first one's (the attribute's multiplexing category is
/// TRANSPORT, RFC 8859 section 5.9), which is the one [`RTCDtlsRole::from`] reads.
pub(crate) fn validate_setup_attributes(session_description: &SessionDescription) -> Result<()> {
    let check = |attributes: &[sdp::description::common::Attribute]| -> Result<()> {
        let mut stated = None;
        for attribute in attributes.iter().filter(|a| a.key == "setup") {
            let value = attribute.value.as_deref();
            if !matches!(value, Some("active" | "passive" | "actpass"))
                || stated.is_some_and(|stated| stated != value)
            {
                return Err(Error::ErrSessionDescriptionInvalidSetup);
            }
            stated = Some(value);
        }
        Ok(())
    };
    check(&session_description.attributes)?;
    session_description
        .media_descriptions
        .iter()
        .try_for_each(|media_section| check(&media_section.attributes))
}

impl RTCDtlsRole {
    pub(crate) fn to_connection_role(self) -> ConnectionRole {
        match self {
            RTCDtlsRole::Client => ConnectionRole::Active,
            RTCDtlsRole::Server => ConnectionRole::Passive,
            RTCDtlsRole::Auto => ConnectionRole::Actpass,
            _ => ConnectionRole::Unspecified,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_dtls_role_string() {
        let tests = vec![
            (RTCDtlsRole::Unspecified, "Unspecified"),
            (RTCDtlsRole::Auto, "auto"),
            (RTCDtlsRole::Client, "client"),
            (RTCDtlsRole::Server, "server"),
        ];

        for (role, expected_string) in tests {
            assert_eq!(role.to_string(), expected_string)
        }
    }

    #[test]
    fn test_dtls_role_from_remote_sdp() -> Result<()> {
        const NO_MEDIA: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
";

        const MEDIA_NO_SETUP: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
m=application 47299 DTLS/SCTP 5000
c=IN IP4 192.168.20.129
";

        const MEDIA_SETUP_DECLARED: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
m=application 47299 DTLS/SCTP 5000
c=IN IP4 192.168.20.129
a=setup:";

        const SESSION_SETUP_PASSIVE: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
a=setup:passive
m=application 47299 DTLS/SCTP 5000
c=IN IP4 192.168.20.129
";

        let tests = vec![
            (
                "No MediaDescriptions",
                NO_MEDIA.to_owned(),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, no setup",
                MEDIA_NO_SETUP.to_owned(),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, setup:actpass",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "actpass"),
                RTCDtlsRole::Auto,
            ),
            (
                "MediaDescription, setup:passive",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "passive"),
                RTCDtlsRole::Server,
            ),
            (
                "MediaDescription, setup:active",
                format!("{}{}\n", MEDIA_SETUP_DECLARED, "active"),
                RTCDtlsRole::Client,
            ),
            // RFC 4145 section 4: the attribute may be given at session level.
            (
                "Session-level setup:passive",
                SESSION_SETUP_PASSIVE.to_owned(),
                RTCDtlsRole::Server,
            ),
            (
                "Session-level setup:passive, no MediaDescriptions",
                format!("{NO_MEDIA}a=setup:passive\n"),
                RTCDtlsRole::Server,
            ),
            // A media-level value overrides the session-level one.
            (
                "Session-level setup:passive, MediaDescription setup:active",
                format!("{SESSION_SETUP_PASSIVE}a=setup:active\n"),
                RTCDtlsRole::Client,
            ),
        ];

        for (name, session_description_str, expected_role) in tests {
            let mut reader = Cursor::new(session_description_str.as_bytes());
            let session_description = SessionDescription::unmarshal(&mut reader)?;
            assert_eq!(
                RTCDtlsRole::from(&session_description),
                expected_role,
                "{name} failed"
            );
        }

        Ok(())
    }

    fn parse(sdp: &str) -> SessionDescription {
        SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes())).unwrap()
    }

    const TWO_SECTIONS: &str = "v=0
o=- 4596489990601351948 2 IN IP4 127.0.0.1
s=-
t=0 0
SESSION
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
FIRST
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
SECOND
";

    /// The two-section description with the given lines (each empty, or `\n`-terminated) at
    /// session level, in the first section and in the second.
    fn with_lines(session: &str, first: &str, second: &str) -> SessionDescription {
        parse(
            &TWO_SECTIONS
                .replace("SESSION\n", session)
                .replace("FIRST\n", first)
                .replace("SECOND\n", second),
        )
    }

    fn two_sections(session: &str, first: &str, second: &str) -> SessionDescription {
        let line = |value: &str| {
            if value.is_empty() {
                String::new()
            } else {
                format!("a=setup:{value}\n")
            }
        };
        with_lines(&line(session), &line(first), &line(second))
    }

    /// RFC 8842 section 5.1: `holdconn` is never used for a DTLS association; RFC 4145 section
    /// 4 defines no other value than the four.
    #[test]
    fn setup_holdconn_and_unknown_values_are_refused() {
        for (session, first, second) in [
            ("", "holdconn", ""),
            ("holdconn", "", ""),
            ("holdconn", "active", "active"),
            ("", "active", "holdconn"),
            ("", "both", ""),
            ("", "ACTIVE", ""),
        ] {
            assert_eq!(
                validate_setup_attributes(&two_sections(session, first, second)),
                Err(Error::ErrSessionDescriptionInvalidSetup),
                "session {session:?}, sections {first:?} / {second:?}"
            );
        }
        let valueless = with_lines("a=setup\n", "", "");
        assert_eq!(
            validate_setup_attributes(&valueless),
            Err(Error::ErrSessionDescriptionInvalidSetup)
        );
    }

    /// Valid values pass, at either level; a level that states two different values does not.
    #[test]
    fn valid_setup_values_are_accepted() {
        for (session, first, second) in [
            ("", "", ""),
            ("", "actpass", "actpass"),
            ("", "active", "active"),
            ("", "passive", ""),
            ("passive", "", ""),
            ("passive", "active", "active"),
            ("actpass", "", "passive"),
        ] {
            assert_eq!(
                validate_setup_attributes(&two_sections(session, first, second)),
                Ok(()),
                "session {session:?}, sections {first:?} / {second:?}"
            );
        }
        let twice = with_lines("", "a=setup:active\na=setup:passive\n", "");
        assert_eq!(
            validate_setup_attributes(&twice),
            Err(Error::ErrSessionDescriptionInvalidSetup)
        );
    }
}
