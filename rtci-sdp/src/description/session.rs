//! The session description — a whole SDP document.
//!
//! A [`SessionDescription`](crate::description::session::SessionDescription) is the session-level fields (`v=`, `o=`, `s=`, `t=`, …) followed by
//! any number of [`MediaDescription`](crate::description::media::MediaDescription)s. `unmarshal` parses one
//! from a string and `marshal` prints it back; the round trip is faithful, including attributes
//! this crate does not interpret.
//!
//! The `ATTR_KEY_*` constants name the `a=` attributes WebRTC relies on — `mid`, `msid`,
//! `setup`, `rtcp-mux`, `extmap` and the direction flags — and the `SEMANTIC_TOKEN_*` constants
//! name the grouping semantics used with `a=group` and `a=msid-semantic`.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Read;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, io};

use url::Url;

use crate::grammar::{self, invalid, syntax};
use crate::lexer::*;
use crate::util::*;
use shared::error::{Error, Result};

use super::common::*;
use super::media::*;

/// Constants for SDP attributes used in JSEP
pub const ATTR_KEY_CANDIDATE: &str = "candidate";
/// `a=end-of-candidates`: ICE gathering for this section is complete.
pub const ATTR_KEY_END_OF_CANDIDATES: &str = "end-of-candidates";
/// `a=identity`: an identity assertion for the session.
pub const ATTR_KEY_IDENTITY: &str = "identity";
/// `a=group`: groups m-lines, as BUNDLE does.
pub const ATTR_KEY_GROUP: &str = "group";
/// `a=ssrc`: declares an SSRC and its attributes.
pub const ATTR_KEY_SSRC: &str = "ssrc";
/// `a=ssrc-group`: relates SSRCs, such as an RTX stream to its primary.
pub const ATTR_KEY_SSRC_GROUP: &str = "ssrc-group";
/// `a=msid`: associates a track with a media stream.
pub const ATTR_KEY_MSID: &str = "msid";
/// `a=msid-semantic`: declares the semantics used by `a=msid`.
pub const ATTR_KEY_MSID_SEMANTIC: &str = "msid-semantic";
/// `a=setup`: the DTLS role — `active`, `passive` or `actpass`.
pub const ATTR_KEY_CONNECTION_SETUP: &str = "setup";
/// `a=mid`: the media identification tag that names this m-line.
pub const ATTR_KEY_MID: &str = "mid";
/// `a=ice-lite`: the endpoint is an ICE-lite implementation.
pub const ATTR_KEY_ICELITE: &str = "ice-lite";
/// `a=rtcp-mux`: RTP and RTCP share one port.
pub const ATTR_KEY_RTCPMUX: &str = "rtcp-mux";
/// `a=rtcp-rsize`: reduced-size RTCP is supported.
pub const ATTR_KEY_RTCPRSIZE: &str = "rtcp-rsize";
/// `a=inactive`: neither send nor receive.
pub const ATTR_KEY_INACTIVE: &str = "inactive";
/// `a=recvonly`: receive only.
pub const ATTR_KEY_RECV_ONLY: &str = "recvonly";
/// `a=sendonly`: send only.
pub const ATTR_KEY_SEND_ONLY: &str = "sendonly";
/// `a=sendrecv`: send and receive.
pub const ATTR_KEY_SEND_RECV: &str = "sendrecv";
/// `a=extmap`: maps an RTP header-extension URI to an id.
pub const ATTR_KEY_EXT_MAP: &str = "extmap";
/// `a=extmap-allow-mixed`: one- and two-byte header extensions may be mixed.
pub const ATTR_KEY_EXTMAP_ALLOW_MIXED: &str = "extmap-allow-mixed";
/// `a=max-message-size`: the largest SCTP message this endpoint accepts.
pub const ATTR_KEY_MAX_MESSAGE_SIZE: &str = "max-message-size";
/// `a=rtcp-mux-only`: RTP and RTCP share one port and nothing else is supported (RFC 8858).
pub const ATTR_KEY_RTCPMUX_ONLY: &str = "rtcp-mux-only";
/// `a=rtcp`: the RTCP port and address (RFC 3605).
pub const ATTR_KEY_RTCP: &str = "rtcp";
/// `a=rtcp-fb`: an RTCP feedback capability (RFC 4585).
pub const ATTR_KEY_RTCP_FB: &str = "rtcp-fb";
/// `a=rtcp-xr`: RTCP extended reports (RFC 3611).
pub const ATTR_KEY_RTCP_XR: &str = "rtcp-xr";
/// `a=rtpmap`: the codec of a payload type.
pub const ATTR_KEY_RTPMAP: &str = "rtpmap";
/// `a=fmtp`: format-specific parameters.
pub const ATTR_KEY_FMTP: &str = "fmtp";
/// `a=ptime`: the preferred packet duration, in milliseconds.
pub const ATTR_KEY_PTIME: &str = "ptime";
/// `a=maxptime`: the longest packet duration, in milliseconds.
pub const ATTR_KEY_MAXPTIME: &str = "maxptime";
/// `a=framerate`: the maximum video frame rate.
pub const ATTR_KEY_FRAMERATE: &str = "framerate";
/// `a=imageattr`: image sizes a payload type sends or receives (RFC 6236).
pub const ATTR_KEY_IMAGEATTR: &str = "imageattr";
/// `a=content`: what a media stream shows (RFC 4796).
pub const ATTR_KEY_CONTENT: &str = "content";
/// `a=rid`: an RTP stream identifier and its restrictions (RFC 8851).
pub const ATTR_KEY_RID: &str = "rid";
/// `a=simulcast`: the simulcast streams of a media section (RFC 8853).
pub const ATTR_KEY_SIMULCAST: &str = "simulcast";
/// `a=ice-ufrag`: the ICE user name fragment.
pub const ATTR_KEY_ICE_UFRAG: &str = "ice-ufrag";
/// `a=ice-pwd`: the ICE password.
pub const ATTR_KEY_ICE_PWD: &str = "ice-pwd";
/// `a=ice-options`: the ICE options the agent supports.
pub const ATTR_KEY_ICE_OPTIONS: &str = "ice-options";
/// `a=ice-pacing`: the ICE pacing interval, in milliseconds.
pub const ATTR_KEY_ICE_PACING: &str = "ice-pacing";
/// `a=remote-candidates`: the remote candidates the controlling agent selected.
pub const ATTR_KEY_REMOTE_CANDIDATES: &str = "remote-candidates";
/// `a=fingerprint`: a certificate fingerprint (RFC 8122).
pub const ATTR_KEY_FINGERPRINT: &str = "fingerprint";
/// `a=tls-id`: the DTLS association identifier (RFC 8842).
pub const ATTR_KEY_TLS_ID: &str = "tls-id";
/// `a=sctp-port`: the SCTP port (RFC 8841).
pub const ATTR_KEY_SCTP_PORT: &str = "sctp-port";
/// `a=sctpmap`: the SCTP association of an old-style data section
/// (draft-ietf-mmusic-sctp-sdp-05; replaced by `a=sctp-port`).
pub const ATTR_KEY_SCTPMAP: &str = "sctpmap";
/// `a=bundle-only`: the section is used only inside its BUNDLE group (RFC 9143).
pub const ATTR_KEY_BUNDLE_ONLY: &str = "bundle-only";
/// `a=cryptex`: RTP header extensions and CSRCs are encrypted (RFC 9335).
pub const ATTR_KEY_CRYPTEX: &str = "cryptex";
/// `BUNDLE`: the m= sections share one transport (RFC 9143).
pub const SEMANTIC_TOKEN_BUNDLE: &str = "BUNDLE";

/// Constants for semantic tokens used in JSEP
pub const SEMANTIC_TOKEN_LIP_SYNCHRONIZATION: &str = "LS";
/// `FID`: flow identification — the SSRCs carry the same content, as RTX does.
pub const SEMANTIC_TOKEN_FLOW_IDENTIFICATION: &str = "FID";
/// `FEC`: one SSRC carries error-correction data for another.
pub const SEMANTIC_TOKEN_FORWARD_ERROR_CORRECTION: &str = "FEC";
// https://datatracker.ietf.org/doc/html/rfc5956#section-4.1
/// `FEC-FR`: the FEC framework grouping semantic.
pub const SEMANTIC_TOKEN_FORWARD_ERROR_CORRECTION_FRAMEWORK: &str = "FEC-FR";
/// `WMS`: WebRTC media streams, used with `a=msid-semantic`.
pub const SEMANTIC_TOKEN_WEBRTC_MEDIA_STREAMS: &str = "WMS";

/// The largest session description, in bytes, [`SessionDescription::unmarshal`] accepts. Real
/// offers and answers are a few to a few hundred kilobytes.
pub const MAX_SDP_SIZE: usize = 1 << 20;
/// The most lines [`SessionDescription::unmarshal`] accepts in one session description.
pub const MAX_SDP_LINES: usize = 65_536;
/// The most `m=` sections [`SessionDescription::unmarshal`] accepts in one session description.
pub const MAX_MEDIA_DESCRIPTIONS: usize = 1024;
/// The most `a=` lines [`SessionDescription::unmarshal`] accepts at the session level, and in
/// each `m=` section.
pub const MAX_ATTRIBUTES_PER_SECTION: usize = 4096;
/// The most formats [`SessionDescription::unmarshal`] accepts on one `m=` line. RTP payload
/// types are 7 bits, so 128 distinct values exist.
pub const MAX_FORMATS_PER_MEDIA: usize = 256;

fn over_limit(what: &str, limit: usize) -> Error {
    Error::SdpInvalidValue(format!("session description has more than {limit} {what}"))
}

/// Version describes the value provided by the "v=" field which gives
/// the version of the Session Description Protocol.
pub type Version = isize;

/// A decimal number of any length, `1*DIGIT`: the `<sess-id>` and `<sess-version>` of an
/// `o=` line (RFC 8866 section 9). The grammar sets no upper bound, so a compliant
/// description may carry values beyond 64 bits (RFC 9429 section 5.2.1 has a JSEP endpoint
/// generate them within 64 bits, and section 5.8 has it accept compliant SDP that does not
/// follow its generation rules).
///
/// It keeps the digits as written, leading zeros included, so a description is written back
/// as it was read; equality and order are those of the numbers.
#[derive(Debug, Clone)]
pub struct SdpDecimal(String);

impl SdpDecimal {
    /// `value` when it is `1*DIGIT`.
    pub fn parse(value: &str) -> Option<Self> {
        (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| SdpDecimal(value.to_owned()))
    }

    /// The digits as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The number, when it fits 64 bits.
    pub fn to_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }

    /// The digits without leading zeros ("0" for zero).
    fn significant(&self) -> &str {
        let trimmed = self.0.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }
    }

    /// The number plus one (RFC 3264 section 8: the version "MUST increment by one"), with
    /// no upper bound.
    pub fn incremented(&self) -> Self {
        let mut digits: Vec<u8> = self.significant().bytes().collect();
        let mut i = digits.len();
        loop {
            if i == 0 {
                digits.insert(0, b'1');
                break;
            }
            i -= 1;
            if digits[i] == b'9' {
                digits[i] = b'0';
            } else {
                digits[i] += 1;
                break;
            }
        }
        SdpDecimal(String::from_utf8(digits).unwrap_or_default())
    }
}

impl Default for SdpDecimal {
    fn default() -> Self {
        SdpDecimal("0".to_owned())
    }
}

impl From<u64> for SdpDecimal {
    fn from(value: u64) -> Self {
        SdpDecimal(value.to_string())
    }
}

impl FromStr for SdpDecimal {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        SdpDecimal::parse(value).ok_or_else(|| syntax("1*DIGIT", value))
    }
}

impl fmt::Display for SdpDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for SdpDecimal {
    fn eq(&self, other: &Self) -> bool {
        self.significant() == other.significant()
    }
}

impl Eq for SdpDecimal {}

impl std::hash::Hash for SdpDecimal {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.significant().hash(state);
    }
}

impl PartialOrd for SdpDecimal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SdpDecimal {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let (a, b) = (self.significant(), other.significant());
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }
}

impl PartialEq<u64> for SdpDecimal {
    fn eq(&self, other: &u64) -> bool {
        self.to_u64() == Some(*other)
    }
}

/// Origin defines the structure for the "o=" field which provides the
/// originator of the session plus a session identifier and version number.
#[derive(Debug, Default, Clone)]
pub struct Origin {
    /// The originator's user name, or `-` when withheld.
    pub username: String,
    /// A globally unique session identifier, `1*DIGIT` of any length.
    pub session_id: SdpDecimal,
    /// Incremented on each modification of the session description; `1*DIGIT` of any
    /// length.
    pub session_version: SdpDecimal,
    /// The network type, always `IN` in practice.
    pub network_type: String,
    /// The address type, `IP4` or `IP6`.
    pub address_type: String,
    /// The originator's address. WebRTC does not use it and sends a placeholder.
    pub unicast_address: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.username,
            self.session_id,
            self.session_version,
            self.network_type,
            self.address_type,
            self.unicast_address,
        )
    }
}

/// The seconds from the NTP epoch (1900-01-01 UTC) to the Unix epoch: RFC 8866 section 5.2
/// recommends "a timestamp, in seconds since January 1, 1900 UTC" for `<sess-id>` and, "as
/// with <sess-id>", for `<sess-version>`.
pub const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;

impl Origin {
    /// The `o=` line RFC 9429 section 5.2.1 gives an offer: `<username>` `-`, the given
    /// session id and version, and the non-meaningful address `IN IP4 0.0.0.0`.
    pub fn jsep(session_id: u64, session_version: u64) -> Self {
        Origin {
            username: "-".to_owned(),
            session_id: session_id.into(),
            session_version: session_version.into(),
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "0.0.0.0".to_owned(),
        }
    }

    /// An empty session description with SDP version 0.
    pub fn new() -> Self {
        Origin {
            username: "".to_owned(),
            session_id: SdpDecimal::default(),
            session_version: SdpDecimal::default(),
            network_type: "".to_owned(),
            address_type: "".to_owned(),
            unicast_address: "".to_owned(),
        }
    }
}

/// SessionName describes a structured representations for the "s=" field
/// and is the textual session name.
pub type SessionName = String;

/// EmailAddress describes a structured representations for the "e=" line
/// which specifies email contact information for the person responsible for
/// the conference.
pub type EmailAddress = String;

/// PhoneNumber describes a structured representations for the "p=" line
/// specify phone contact information for the person responsible for the
/// conference.
pub type PhoneNumber = String;

/// TimeZone is one `<adjustment time> <offset>` pair of a "z=" line, which describes
/// repeated sessions scheduling.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TimeZone {
    /// The time at which the offset takes effect.
    pub adjustment_time: u64,
    /// The offset from the session's base time, in seconds.
    pub offset: i64,
}

impl fmt::Display for TimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.adjustment_time, self.offset)
    }
}

/// TimeDescription describes the "t=", "r=" and "z=" fields of the session description,
/// which specify the start and stop times of a session, its repeat intervals and durations,
/// and the time zone adjustments of those repetitions.
///
/// RFC 8866 section 9: `time-description = time-field [repeat-description]`,
/// `repeat-description = 1*repeat-field [zone-field]`.
#[derive(Debug, Default, Clone)]
pub struct TimeDescription {
    /// `t=<start-time> <stop-time>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.9>
    pub timing: Timing,

    /// `r=<repeat interval> <active duration> <offsets from start-time>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.10>
    pub repeat_times: Vec<RepeatTime>,

    /// `z=<adjustment time> <offset> <adjustment time> <offset> ...`
    ///
    /// The zone adjustments of this time description's repetitions. Written after the `r=`
    /// lines.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.11>
    pub time_zones: Vec<TimeZone>,
}

/// Timing defines the "t=" field's structured representation for the start and
/// stop times.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Timing {
    /// Session start time in NTP seconds; `0` means unbounded.
    pub start_time: u64,
    /// Session stop time in NTP seconds; `0` means unbounded.
    pub stop_time: u64,
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.start_time, self.stop_time)
    }
}

/// RepeatTime describes the "r=" fields of the session description which
/// represents the intervals and durations for repeated scheduled sessions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepeatTime {
    /// How often the session repeats, in seconds.
    pub interval: i64,
    /// How long each repetition lasts, in seconds.
    pub duration: i64,
    /// Offsets from the start time at which the session repeats.
    pub offsets: Vec<i64>,
}

impl fmt::Display for RepeatTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.interval, self.duration)?;

        for value in &self.offsets {
            write!(f, " {value}")?;
        }
        Ok(())
    }
}

/// SessionDescription is a a well-defined format for conveying sufficient
/// information to discover and participate in a multimedia session.
#[derive(Debug, Default, Clone)]
pub struct SessionDescription {
    /// `v=0`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.1>
    pub version: Version,

    /// `o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.2>
    pub origin: Origin,

    /// `s=<session name>`
    ///
    /// Never empty in SDP: an empty name is written as `-`.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.3>
    pub session_name: SessionName,

    /// `i=<session description>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.4>
    pub session_information: Option<Information>,

    /// `u=<uri>`: an RFC 3986 `URI-reference`, absolute or relative (RFC 8866 section 9:
    /// `uri-field = %x75 "=" uri CRLF`, `uri = URI-reference`).
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.5>
    pub uri: Option<String>,

    /// `e=<email-address>`, any number of lines.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.6>
    pub email_addresses: Vec<EmailAddress>,

    /// `p=<phone-number>`, any number of lines.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.6>
    pub phone_numbers: Vec<PhoneNumber>,

    /// `c=<nettype> <addrtype> <connection-address>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.7>
    pub connection_information: Option<ConnectionInformation>,

    /// `b=<bwtype>:<bandwidth>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.8>
    pub bandwidth: Vec<Bandwidth>,

    /// The time descriptions: `t=`, each with its `r=` and `z=` lines. SDP needs at least
    /// one: an empty list is written as `t=0 0`.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.9>
    pub time_descriptions: Vec<TimeDescription>,

    /// Obsolete. RFC 8866 section 5.12: a `k=` line "MUST NOT be included in an SDP
    /// description and MUST be discarded if received". The parser never sets this field
    /// and nothing writes it; it is kept so that code naming it still builds.
    pub encryption_key: Option<EncryptionKey>,

    /// `a=<attribute>`
    ///
    /// `a=<attribute>:<value>`
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.13>
    pub attributes: Vec<Attribute>,

    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.14>
    pub media_descriptions: Vec<MediaDescription>,
}

/// Writes the description in the order RFC 8866 section 9 requires, whatever order its
/// parts were set in: `v o s i u e* p* c b* (t r* z)+ a*`, then for each media description
/// `m i c b* a*`.
impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_key_value(f, "v=", Some(&self.version))?;
        write_key_value(f, "o=", Some(&self.origin))?;
        if self.session_name.is_empty() {
            // Section 5.3: "The 's=' line MUST NOT be empty"; `s=-` names a nameless session.
            write_key_value(f, "s=", Some("-"))?;
        } else {
            write_key_value(f, "s=", Some(&self.session_name))?;
        }

        write_key_value(f, "i=", self.session_information.as_ref())?;

        if let Some(uri) = &self.uri {
            write_key_value(f, "u=", Some(uri))?;
        }
        for email_address in &self.email_addresses {
            write_key_value(f, "e=", Some(email_address))?;
        }
        for phone_number in &self.phone_numbers {
            write_key_value(f, "p=", Some(phone_number))?;
        }
        if let Some(connection_information) = &self.connection_information {
            write_key_value(f, "c=", Some(&connection_information))?;
        }

        for bandwidth in &self.bandwidth {
            write_key_value(f, "b=", Some(&bandwidth))?;
        }
        if self.time_descriptions.is_empty() {
            // Section 9: `1*time-description`.
            write_key_value(f, "t=", Some("0 0"))?;
        }
        for time_description in &self.time_descriptions {
            write_key_value(f, "t=", Some(&time_description.timing))?;
            for repeat_time in &time_description.repeat_times {
                write_key_value(f, "r=", Some(&repeat_time))?;
            }
            write_key_slice_of_values(f, "z=", &time_description.time_zones)?;
        }

        for attribute in &self.attributes {
            write_key_value(f, "a=", Some(&attribute))?;
        }

        for media_description in &self.media_descriptions {
            write_key_value(f, "m=", Some(&media_description.media_name))?;
            write_key_value(f, "i=", media_description.media_title.as_ref())?;
            if let Some(connection_information) = &media_description.connection_information {
                write_key_value(f, "c=", Some(&connection_information))?;
            }
            for bandwidth in &media_description.bandwidth {
                write_key_value(f, "b=", Some(&bandwidth))?;
            }
            for attribute in &media_description.attributes {
                write_key_value(f, "a=", Some(&attribute))?;
            }
        }

        Ok(())
    }
}

/// What [`SessionDescription::unmarshal_with_options`] accepts beyond the RFC 8866 grammar.
///
/// [`SessionDescription::unmarshal`] parses with [`ParseOptions::strict`]: RFC 9429 section
/// 5.8 has a description that is not well formed rejected, so the engine's own parsing is
/// the grammar and nothing else. An application that has to read what other software calls
/// SDP can ask for each leniency by name, or for all of them with
/// [`ParseOptions::lenient`].
///
/// # What is accepted in every mode
///
/// These are the places where the parser is deliberately wider than the grammar, each for
/// a reason:
///
/// * A line may end in a bare LF instead of CRLF. RFC 8866 section 5: "parsers SHOULD be
///   tolerant and also accept lines terminated with a single newline character".
/// * The last line may have no line ending, and empty lines may follow it. Descriptions
///   that went through a text field or a `trim()` look like this.
/// * `z=` may follow a `t=` line that has no `r=` line. RFC 4566 allowed it, and RFC 8866
///   moved `z=` into the repeat description; a description written to RFC 4566 still parses.
/// * `k=` lines are checked for syntax and dropped (RFC 8866 section 5.12: "MUST be
///   discarded if received").
/// * `a=name:` with an empty value is kept as an attribute whose value is the empty string.
///   RFC 3611 defines one (`a=rtcp-xr:`), although the RFC 8866 `byte-string` is never empty.
/// * An attribute this crate does not know is kept as it is, at either level (RFC 8866
///   section 5.13: "an attribute that is not understood MUST be ignored"). The typed
///   accessors are where the value of a known attribute is checked.
/// * Several `c=` lines in one media description are accepted; the last one is kept.
///
/// # What is always refused
///
/// A type letter RFC 8866 does not define (section 5: such a description is ignored or
/// rejected whole), a line that is not `<type>=<value>`, NUL, a bare CR, text that is not
/// UTF-8 when the description names no other set with `a=charset` (`unmarshal`, from bytes),
/// session-level lines out of order, and a
/// description without `v=`, `o=`, `s=` or `t=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseOptions {
    /// Skip empty lines before and between lines, as some media players accept.
    pub blank_lines: bool,
    /// Accept `i=`, `c=`, `b=` and `k=` after `a=` lines inside a media description. Some
    /// gateways write them so; RFC 8866 section 5 has them "in exactly the order given".
    pub unordered_media_lines: bool,
    /// Do not check what the fields of a line contain beyond what the parser needs:
    /// fields may be separated and surrounded by any run of spaces and tabs; `t=` times may
    /// be any number; addresses in `o=` and `c=` need only be free of white space (and `c=`
    /// may lack one); `i=`, `e=` and `p=` text is kept unchecked; `s=` may be empty; extra
    /// fields after the stop time of `t=` are ignored.
    pub loose_fields: bool,
}

impl ParseOptions {
    /// The RFC 8866 grammar, with only the tolerance every mode has. The default.
    pub const fn strict() -> Self {
        ParseOptions {
            blank_lines: false,
            unordered_media_lines: false,
            loose_fields: false,
        }
    }

    /// Every leniency.
    pub const fn lenient() -> Self {
        ParseOptions {
            blank_lines: true,
            unordered_media_lines: true,
            loose_fields: true,
        }
    }
}

/// Reset cleans the SessionDescription, and sets all fields back to their default values
impl SessionDescription {
    /// A session description with the session-level lines RFC 9429 section 5.2.1 gives an
    /// offer: `v=0`, `o=- <sess-id> <sess-version> IN IP4 0.0.0.0` with a random 63-bit
    /// session id and, for the session version, the system clock's seconds since 1900 (RFC
    /// 8866 section 5.2: "it is RECOMMENDED that a timestamp be used"), `s=-` and `t=0 0`.
    ///
    /// `_identity` is ignored. It used to add a bare `a=identity`, which is not SDP: the
    /// attribute carries an assertion (RFC 8827 section 5). An application that has one
    /// adds it with `with_typed(&Identity)`.
    pub fn new_jsep_session_description(_identity: bool) -> Self {
        let since_unix_epoch = SystemTime::now() // Exemption: wall-clock is correct here: RFC 8866 section 5.2 recommends a timestamp for the session version
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        Self::new_jsep_session_description_with_origin(Origin::jsep(
            new_session_id(),
            since_unix_epoch.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS,
        ))
    }

    /// [`new_jsep_session_description`](Self::new_jsep_session_description) with the `o=`
    /// line the caller gives, for a session whose origin is kept across descriptions (RFC
    /// 9429 section 5.2.2: "The fields of the "o=" line MUST stay the same except for the
    /// <session-version> field") or drawn from sources the caller controls.
    pub fn new_jsep_session_description_with_origin(origin: Origin) -> Self {
        SessionDescription {
            version: 0,
            origin,
            session_name: "-".to_string(),
            session_information: None,
            uri: None,
            email_addresses: vec![],
            phone_numbers: vec![],
            connection_information: None,
            bandwidth: vec![],
            time_descriptions: vec![TimeDescription {
                timing: Timing {
                    start_time: 0,
                    stop_time: 0,
                },
                repeat_times: vec![],
                time_zones: vec![],
            }],
            encryption_key: None,
            attributes: vec![],
            media_descriptions: vec![],
        }
    }

    /// WithPropertyAttribute adds a property attribute 'a=key' to the session description
    pub fn with_property_attribute(mut self, key: String) -> Self {
        self.attributes.push(Attribute::new(key, None));
        self
    }

    /// WithValueAttribute adds a value attribute 'a=key:value' to the session description
    pub fn with_value_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.push(Attribute::new(key, Some(value)));
        self
    }

    /// WithFingerprint adds a fingerprint to the session description
    pub fn with_fingerprint(self, algorithm: String, value: String) -> Self {
        self.with_value_attribute("fingerprint".to_string(), algorithm + " " + value.as_str())
    }

    /// WithMedia adds a media description to the session description
    pub fn with_media(mut self, md: MediaDescription) -> Self {
        self.media_descriptions.push(md);
        self
    }

    fn build_codec_map(&self) -> HashMap<u8, Codec> {
        let mut codecs: HashMap<u8, Codec> = HashMap::new();

        for m in &self.media_descriptions {
            codecs.extend(m.codecs());
        }

        codecs
    }

    /// get_codec_for_payload_type scans the SessionDescription for the given payload type and returns the codec
    pub fn get_codec_for_payload_type(&self, payload_type: u8) -> Result<Codec> {
        let codecs = self.build_codec_map();

        if let Some(codec) = codecs.get(&payload_type) {
            Ok(codec.clone())
        } else {
            Err(Error::PayloadTypeNotFound)
        }
    }

    /// get_payload_type_for_codec scans the SessionDescription for a codec that matches the provided codec
    /// as closely as possible and returns its payload type
    pub fn get_payload_type_for_codec(&self, wanted: &Codec) -> Result<u8> {
        let codecs = self.build_codec_map();

        for (payload_type, codec) in codecs.iter() {
            if codecs_match(wanted, codec) {
                return Ok(*payload_type);
            }
        }

        Err(Error::CodecNotFound)
    }

    /// Returns whether an attribute exists
    pub fn has_attribute(&self, key: &str) -> bool {
        self.attributes.iter().any(|a| a.key == key)
    }

    /// Attribute returns the value of an attribute and if it exists
    pub fn attribute(&self, key: &str) -> Option<&String> {
        for a in &self.attributes {
            if a.key == key {
                return a.value.as_ref();
            }
        }
        None
    }

    /// The value of the first session-level `b=` line of `kind`, in the unit of that
    /// modifier.
    pub fn bandwidth_of(&self, kind: BandwidthKind) -> Option<u64> {
        find_bandwidth(&self.bandwidth, kind)
    }

    crate::attribute::common_accessors!();
    crate::attribute::session_accessors!();

    /// Marshal takes a SDP struct to text, in the order RFC 8866 section 9 gives:
    ///
    /// ```text
    /// Session description
    ///    v=  (protocol version)
    ///    o=  (originator and session identifier)
    ///    s=  (session name)
    ///    i=* (session information)
    ///    u=* (URI of description)
    ///    e=* (zero or more email address lines)
    ///    p=* (zero or more phone number lines)
    ///    c=* (connection information -- not required if included in all media)
    ///    b=* (zero or more bandwidth information lines)
    ///    One or more time descriptions:
    ///       t=  (time the session is active)
    ///       r=* (zero or more repeat times)
    ///       z=* (time zone adjustments of those repeat times)
    ///    a=* (zero or more session attribute lines)
    ///    Zero or more media descriptions:
    ///       m=  (media name and transport address)
    ///       i=* (media title)
    ///       c=* (connection information -- optional if included at session level)
    ///       b=* (zero or more bandwidth information lines)
    ///       a=* (zero or more media attribute lines)
    /// ```
    ///
    /// `k=` is never written (section 5.12). An empty session name is written as `s=-` and
    /// an empty list of time descriptions as `t=0 0`, so that what comes out has the
    /// required lines. Field values are written as they are: build them from parsed or
    /// checked input.
    pub fn marshal(&self) -> String {
        self.to_string()
    }

    /// Unmarshal deserializes a session description, with [`ParseOptions::strict`]: the
    /// RFC 8866 section 9 grammar, line by line and in its order.
    ///
    /// See [`ParseOptions`] for what is accepted beyond the grammar, and for what is
    /// refused. Attribute values are kept as text: use the typed accessors
    /// (`mid()`, `rtpmaps()`, `candidates()`, ...) or [`SessionDescription::validate`] to
    /// check them.
    ///
    /// The input is bounded: [`MAX_SDP_SIZE`] bytes, [`MAX_SDP_LINES`] lines,
    /// [`MAX_MEDIA_DESCRIPTIONS`] media descriptions, [`MAX_ATTRIBUTES_PER_SECTION`]
    /// attributes at each level and [`MAX_FORMATS_PER_MEDIA`] formats on an `m=` line.
    pub fn unmarshal<R: io::BufRead + io::Seek>(reader: &mut R) -> Result<Self> {
        Self::unmarshal_with_options(reader, &ParseOptions::strict())
    }

    /// [`SessionDescription::unmarshal`] with the leniencies `options` names.
    pub fn unmarshal_with_options<R: io::BufRead + io::Seek>(
        reader: &mut R,
        options: &ParseOptions,
    ) -> Result<Self> {
        let start = reader.stream_position()?;
        let end = reader.seek(io::SeekFrom::End(0))?;
        reader.seek(io::SeekFrom::Start(start))?;
        if end.saturating_sub(start) > MAX_SDP_SIZE as u64 {
            return Err(over_limit("bytes", MAX_SDP_SIZE));
        }

        let mut bytes = Vec::with_capacity(end.saturating_sub(start) as usize);
        io::Read::take(&mut *reader, MAX_SDP_SIZE as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SDP_SIZE {
            return Err(over_limit("bytes", MAX_SDP_SIZE));
        }
        let text = decode(&bytes)?;
        Self::parse_with_options(&text, options)
    }

    /// The character set the session name and information are in (RFC 8866 section 6.10,
    /// `a=charset`): UTF-8 when the description names none.
    pub fn charset(&self) -> Charset {
        self.attribute(ATTR_KEY_CHARSET)
            .map_or(Charset::Utf8, |name| Charset::named(name))
    }

    /// Parses a session description from text, with the leniencies `options` names.
    pub fn parse_with_options(text: &str, options: &ParseOptions) -> Result<Self> {
        Self::parse_located(text, options).map_err(|err| err.error)
    }

    /// [`Self::parse_with_options`], saying which line a syntax error is on (W3C webrtc-pc
    /// section 11.1: an `sdp-syntax-error` carries its `sdpLineNumber`).
    ///
    /// # Errors
    ///
    /// The error [`Self::parse_with_options`] returns, with the number (from 1, blank lines
    /// counted) of the line it is about; `None` for an error about the description as a whole
    /// (its size, or a missing `t=` line at its end).
    pub fn parse_located(
        text: &str,
        options: &ParseOptions,
    ) -> std::result::Result<Self, SdpParseError> {
        let unlocated = |error| SdpParseError {
            line_number: None,
            error,
        };
        if text.len() > MAX_SDP_SIZE {
            return Err(unlocated(over_limit("bytes", MAX_SDP_SIZE)));
        }
        let mut parser = Parser::new(*options);
        let lines = lines_located(text, options.blank_lines, MAX_SDP_LINES).map_err(
            |(number, error)| SdpParseError {
                line_number: Some(number),
                error,
            },
        )?;
        for line in lines {
            let number = line.number;
            parser.line(line).map_err(|error| SdpParseError {
                line_number: Some(number),
                error,
            })?;
        }
        parser.finish().map_err(unlocated)
    }
}

/// RFC 3986 section 4.1 `URI-reference`: a URI, or a relative reference (RFC 8866 section
/// 9 has `uri = URI-reference`). An absolute one is what the `url` crate parses; a relative
/// one has only the characters of the grammar (unreserved, sub-delims, `:` `@` `/` `?` `#`
/// `[` `]`, and `%` with two hex digits) and no `:` in its first segment (`path-noscheme`).
fn is_uri_reference(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let ok = b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?#[]".contains(&b);
        if b == b'%' {
            if !bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            i += 3;
            continue;
        }
        if !ok {
            return false;
        }
        i += 1;
    }
    let first_segment = value.split(['/', '?', '#']).next().unwrap_or_default();
    match first_segment.split_once(':') {
        // A scheme: the reference is a URI.
        Some((scheme, _)) => {
            scheme
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic())
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
                && Url::parse(value).is_ok()
        }
        None => true,
    }
}

/// The `a=charset` attribute (RFC 8866 section 6.10).
pub const ATTR_KEY_CHARSET: &str = "charset";

/// The character set of a description's charset-dependent fields (`s=`, `i=`), from its
/// `a=charset` (RFC 8866 section 6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Charset {
    /// ISO-10646 in UTF-8, the default.
    Utf8,
    /// ISO-8859-1.
    Latin1,
    /// US-ASCII.
    Ascii,
    /// A character set this crate does not support (or not a registered one): its strings
    /// are octet strings (RFC 8866 section 6.10: "If the identifier is not recognized or not
    /// supported, all strings that are affected by it SHOULD be regarded as octet strings"),
    /// each octet read as the character of that code point.
    Other(String),
}

impl Charset {
    /// The character set `name` identifies. RFC 8866 section 6.10: the identifier "MUST be
    /// compared against identifiers from the 'Name' or 'Preferred MIME Name' field of the
    /// registry using a case-insensitive comparison"; the aliases of the IANA Character Sets
    /// registry for the three sets are recognised too.
    pub fn named(name: &str) -> Self {
        const UTF8: [&str; 2] = ["UTF-8", "csUTF8"];
        const LATIN1: [&str; 10] = [
            "ISO-8859-1",
            "ISO_8859-1:1987",
            "ISO_8859-1",
            "iso-ir-100",
            "latin1",
            "l1",
            "IBM819",
            "CP819",
            "csISOLatin1",
            "ISO-8859-1:1987",
        ];
        const ASCII: [&str; 11] = [
            "US-ASCII",
            "ANSI_X3.4-1968",
            "iso-ir-6",
            "ANSI_X3.4-1986",
            "ISO_646.irv:1991",
            "ISO646-US",
            "us",
            "IBM367",
            "cp367",
            "csASCII",
            "ASCII",
        ];
        let name = name.trim();
        let is = |names: &[&str]| names.iter().any(|n| n.eq_ignore_ascii_case(name));
        if is(&UTF8) {
            Charset::Utf8
        } else if is(&LATIN1) {
            Charset::Latin1
        } else if is(&ASCII) {
            Charset::Ascii
        } else {
            Charset::Other(name.to_owned())
        }
    }
}

/// The `a=charset` value of a description's session part, read from its bytes (the
/// attribute is ASCII, whatever set it names).
fn declared_charset(bytes: &[u8]) -> Option<Charset> {
    for line in bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"m=") {
            return None;
        }
        if let Some(value) = line.strip_prefix(b"a=charset:") {
            return core::str::from_utf8(value).ok().map(Charset::named);
        }
    }
    None
}

/// The text of a description given as bytes. RFC 8866 section 5: "the 'a=charset' attribute
/// ... is used to specify the character set"; without one, or with UTF-8, the text is UTF-8
/// and other bytes refuse it. ISO-8859-1 is decoded as such, US-ASCII must be 7-bit, and an
/// unsupported set's text is kept as octets (each byte the character of its code point; RFC
/// 8866 section 6.10). Every other field is ASCII in all of these.
fn decode(bytes: &[u8]) -> Result<std::borrow::Cow<'_, str>> {
    match declared_charset(bytes) {
        None | Some(Charset::Utf8) => core::str::from_utf8(bytes)
            .map(std::borrow::Cow::Borrowed)
            .map_err(|_| Error::SdpInvalidSyntax("the description is not UTF-8".to_owned())),
        Some(Charset::Ascii) => {
            if bytes.is_ascii() {
                Ok(std::borrow::Cow::Owned(
                    bytes.iter().map(|&b| char::from(b)).collect(),
                ))
            } else {
                Err(Error::SdpInvalidSyntax(
                    "a=charset:US-ASCII and a byte above 127 (RFC 8866 section 6.10)".to_owned(),
                ))
            }
        }
        Some(Charset::Latin1 | Charset::Other(_)) => Ok(std::borrow::Cow::Owned(
            bytes.iter().map(|&b| char::from(b)).collect(),
        )),
    }
}

/// A description that does not parse, and where: what
/// [`SessionDescription::parse_located`] returns.
#[derive(Debug, PartialEq)]
pub struct SdpParseError {
    /// The line the error is about, from 1 (blank lines counted); `None` when it is about the
    /// description as a whole.
    pub line_number: Option<usize>,
    /// What is wrong.
    pub error: Error,
}

impl From<SessionDescription> for String {
    fn from(sdp: SessionDescription) -> String {
        sdp.marshal()
    }
}

impl TryFrom<String> for SessionDescription {
    type Error = Error;
    fn try_from(sdp_string: String) -> Result<Self> {
        SessionDescription::parse_with_options(&sdp_string, &ParseOptions::strict())
    }
}

impl FromStr for SessionDescription {
    type Err = Error;
    fn from_str(sdp: &str) -> Result<Self> {
        SessionDescription::parse_with_options(sdp, &ParseOptions::strict())
    }
}

/// Where the parser is in `v o s i u e* p* c b* (t r* z)+ k a* m*`: the rank of the
/// earliest line type that may still come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SessionRank {
    Version,
    Origin,
    Name,
    Information,
    Uri,
    Email,
    Phone,
    Connection,
    Bandwidth,
    Time,
    Key,
    Attribute,
}

/// Where the parser is inside a time description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeState {
    /// No `t=` line yet, or a line that is not part of a time description came since.
    Outside,
    /// The last line was `t=`.
    Timing,
    /// The last line was `r=`.
    Repeat,
    /// The last line was `z=`.
    Zone,
}

/// Where the parser is in `m i c* b* k a*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MediaRank {
    Information,
    Connection,
    Bandwidth,
    Key,
    Attribute,
}

struct Parser {
    options: ParseOptions,
    desc: SessionDescription,
    rank: SessionRank,
    time: TimeState,
    /// `Some` once the first `m=` line was read.
    media: Option<MediaState>,
}

struct MediaState {
    rank: MediaRank,
    has_title: bool,
    has_key: bool,
}

fn out_of_order(kind: u8) -> Error {
    Error::SdpInvalidSyntax(format!(
        "a `{}=` line where the grammar has none",
        kind as char
    ))
}

impl Parser {
    fn new(options: ParseOptions) -> Self {
        Parser {
            options,
            desc: SessionDescription::default(),
            rank: SessionRank::Version,
            time: TimeState::Outside,
            media: None,
        }
    }

    fn finish(self) -> Result<SessionDescription> {
        // v=, o=, s= and one t= are required, in that order: a t= line means all four.
        if self.desc.time_descriptions.is_empty() {
            return Err(Error::SdpInvalidSyntax(
                "the description ends before its `t=` line".to_owned(),
            ));
        }
        Ok(self.desc)
    }

    /// The fields of a structured line: separated by one space, or by any white space when
    /// `loose_fields` is set.
    fn fields<'a>(&self, what: &str, value: &'a str) -> Result<Vec<&'a str>> {
        if self.options.loose_fields {
            let fields: Vec<&str> = value.split_whitespace().collect();
            if fields.is_empty() {
                return Err(syntax(what, value));
            }
            Ok(fields)
        } else {
            grammar::fields(what, value)
        }
    }

    fn line(&mut self, line: Line<'_>) -> Result<()> {
        if !matches!(
            line.kind,
            b'v' | b'o'
                | b's'
                | b'i'
                | b'u'
                | b'e'
                | b'p'
                | b'c'
                | b'b'
                | b't'
                | b'r'
                | b'z'
                | b'k'
                | b'a'
                | b'm'
        ) {
            // RFC 8866 section 5: a parser "MUST completely ignore or reject any session
            // description that contains a type letter that it does not understand".
            return Err(Error::SdpInvalidSyntax(format!(
                "unknown line type `{}=`",
                line.kind.escape_ascii()
            )));
        }

        if line.kind == b'm' {
            // A media description may only start once the session level is complete.
            if self.desc.time_descriptions.is_empty() {
                return Err(out_of_order(line.kind));
            }
            self.media_line(line.value)?;
            self.media = Some(MediaState {
                rank: MediaRank::Information,
                has_title: false,
                has_key: false,
            });
            return Ok(());
        }

        if self.media.is_some() {
            self.media_level(line)
        } else {
            self.session_level(line)
        }
    }

    fn session_level(&mut self, line: Line<'_>) -> Result<()> {
        use SessionRank as R;

        let value = line.value;
        let was_time = self.time;
        if !matches!(line.kind, b'r' | b'z') {
            self.time = TimeState::Outside;
        }

        // (rank of this line, rank of the earliest line that may follow it)
        let (rank, next) = match line.kind {
            b'v' => (R::Version, R::Origin),
            b'o' => (R::Origin, R::Name),
            b's' => (R::Name, R::Information),
            b'i' => (R::Information, R::Uri),
            b'u' => (R::Uri, R::Email),
            b'e' => (R::Email, R::Email),
            b'p' => (R::Phone, R::Phone),
            b'c' => (R::Connection, R::Bandwidth),
            b'b' => (R::Bandwidth, R::Bandwidth),
            b't' | b'r' | b'z' => (R::Time, R::Time),
            b'k' => (R::Key, R::Attribute),
            b'a' => (R::Attribute, R::Attribute),
            _ => return Err(out_of_order(line.kind)),
        };

        // v=, o= and s= are required and come first, in that order; a t= line is required
        // before anything that follows the time descriptions.
        let allowed = match self.rank {
            R::Version | R::Origin | R::Name => rank == self.rank,
            earliest => {
                rank >= earliest && (rank <= R::Time || !self.desc.time_descriptions.is_empty())
            }
        };
        if !allowed {
            return Err(out_of_order(line.kind));
        }

        match line.kind {
            b'v' => {
                // `1*DIGIT`, and RFC 9429 section 5.8.1: the version is 0.
                if grammar::digits::<u32>("v=", value)? != 0 {
                    return Err(syntax("v=", value));
                }
                self.desc.version = 0;
            }
            b'o' => self.desc.origin = self.origin(value)?,
            b's' => {
                if !(grammar::is_byte_string(value)
                    || (value.is_empty() && self.options.loose_fields))
                {
                    return Err(syntax("s=", value));
                }
                self.desc.session_name = value.to_owned();
            }
            b'i' => self.desc.session_information = Some(self.text("i=", value)?),
            b'u' => {
                if !is_uri_reference(value) {
                    return Err(syntax("u=", value));
                }
                self.desc.uri = Some(value.to_owned());
            }
            b'e' => {
                if !self.options.loose_fields && !is_email_address(value) {
                    return Err(syntax("e=", value));
                }
                self.desc.email_addresses.push(value.to_owned());
            }
            b'p' => {
                if !self.options.loose_fields && !is_phone_number(value) {
                    return Err(syntax("p=", value));
                }
                self.desc.phone_numbers.push(value.to_owned());
            }
            b'c' => self.desc.connection_information = Some(self.connection(value)?),
            b'b' => self.desc.bandwidth.push(self.bandwidth(value)?),
            b't' => {
                let timing = self.timing(value)?;
                self.desc.time_descriptions.push(TimeDescription {
                    timing,
                    repeat_times: vec![],
                    time_zones: vec![],
                });
                self.time = TimeState::Timing;
            }
            b'r' => {
                if !matches!(was_time, TimeState::Timing | TimeState::Repeat) {
                    return Err(out_of_order(line.kind));
                }
                let repeat = self.repeat(value)?;
                // `was_time` is not `Outside`, so a time description exists.
                if let Some(last) = self.desc.time_descriptions.last_mut() {
                    last.repeat_times.push(repeat);
                }
                self.time = TimeState::Repeat;
            }
            b'z' => {
                if !matches!(was_time, TimeState::Timing | TimeState::Repeat) {
                    return Err(out_of_order(line.kind));
                }
                let zones = self.zones(value)?;
                if let Some(last) = self.desc.time_descriptions.last_mut() {
                    last.time_zones = zones;
                }
                self.time = TimeState::Zone;
            }
            b'k' => check_key(value)?,
            _ => {
                if self.desc.attributes.len() >= MAX_ATTRIBUTES_PER_SECTION {
                    return Err(over_limit("session attributes", MAX_ATTRIBUTES_PER_SECTION));
                }
                self.desc.attributes.push(parse_attribute(value)?);
            }
        }

        self.rank = next;
        Ok(())
    }

    fn media_level(&mut self, line: Line<'_>) -> Result<()> {
        use MediaRank as M;

        let value = line.value;
        let (rank, next) = match line.kind {
            b'i' => (M::Information, M::Connection),
            b'c' => (M::Connection, M::Connection),
            b'b' => (M::Bandwidth, M::Bandwidth),
            b'k' => (M::Key, M::Attribute),
            b'a' => (M::Attribute, M::Attribute),
            _ => return Err(out_of_order(line.kind)),
        };

        let unordered = self.options.unordered_media_lines;
        let Some(state) = self.media.as_mut() else {
            return Err(out_of_order(line.kind));
        };
        if !unordered && rank < state.rank {
            return Err(out_of_order(line.kind));
        }
        // One i= and one k= at most, in any mode.
        match line.kind {
            b'i' if std::mem::replace(&mut state.has_title, true) => {
                return Err(out_of_order(line.kind));
            }
            b'k' if std::mem::replace(&mut state.has_key, true) => {
                return Err(out_of_order(line.kind));
            }
            _ => {}
        }
        state.rank = state.rank.max(next);

        match line.kind {
            b'i' => {
                let title = self.text("i=", value)?;
                self.last_media()?.media_title = Some(title);
            }
            b'c' => {
                let connection = self.connection(value)?;
                self.last_media()?.connection_information = Some(connection);
            }
            b'b' => {
                let bandwidth = self.bandwidth(value)?;
                self.last_media()?.bandwidth.push(bandwidth);
            }
            b'k' => check_key(value)?,
            _ => {
                let attribute = parse_attribute(value)?;
                let media = self.last_media()?;
                if media.attributes.len() >= MAX_ATTRIBUTES_PER_SECTION {
                    return Err(over_limit(
                        "attributes in one media section",
                        MAX_ATTRIBUTES_PER_SECTION,
                    ));
                }
                media.attributes.push(attribute);
            }
        }
        Ok(())
    }

    fn last_media(&mut self) -> Result<&mut MediaDescription> {
        self.desc
            .media_descriptions
            .last_mut()
            .ok_or(Error::SdpEmptyTimeDescription)
    }

    /// `text = byte-string`.
    fn text(&self, what: &str, value: &str) -> Result<String> {
        if !(grammar::is_byte_string(value) || self.options.loose_fields) {
            return Err(syntax(what, value));
        }
        Ok(value.to_owned())
    }

    /// `username SP sess-id SP sess-version SP nettype SP addrtype SP unicast-address`.
    fn origin(&self, value: &str) -> Result<Origin> {
        let fields = self.fields("o=", value)?;
        let [
            username,
            session_id,
            session_version,
            network_type,
            address_type,
            address,
        ] = fields[..]
        else {
            return Err(syntax("o=", value));
        };
        if !grammar::is_non_ws_string(username)
            || !grammar::is_token(network_type)
            || !grammar::is_token(address_type)
        {
            return Err(syntax("o=", value));
        }
        let address_ok = if self.options.loose_fields {
            grammar::is_non_ws_string(address)
        } else {
            grammar::is_unicast_address(address_type, address)
        };
        if !address_ok {
            return Err(syntax("o= unicast-address", value));
        }
        Ok(Origin {
            username: username.to_owned(),
            // The grammar has no upper bound (RFC 8866 section 9: `1*DIGIT`), and nor has
            // this type: RFC 9429 section 5.8 accepts compliant SDP beyond the 64 bits
            // section 5.2.1 generates.
            session_id: SdpDecimal::parse(session_id)
                .ok_or_else(|| syntax("o= sess-id", session_id))?,
            session_version: SdpDecimal::parse(session_version)
                .ok_or_else(|| syntax("o= sess-version", session_version))?,
            network_type: network_type.to_owned(),
            address_type: address_type.to_owned(),
            unicast_address: address.to_owned(),
        })
    }

    fn connection(&self, value: &str) -> Result<ConnectionInformation> {
        let fields = self.fields("c=", value)?;
        if !self.options.loose_fields {
            return ConnectionInformation::parse_fields(&fields, value);
        }
        if !(2..=3).contains(&fields.len())
            || !grammar::is_token(fields[0])
            || !grammar::is_token(fields[1])
        {
            return Err(syntax("c=", value));
        }
        Ok(ConnectionInformation {
            network_type: fields[0].to_owned(),
            address_type: fields[1].to_owned(),
            address: fields.get(2).map(|address| {
                // Kept whole when it is not an address the grammar knows.
                Address::parse(fields[1], address).unwrap_or_else(|_| Address {
                    address: (*address).to_owned(),
                    ttl: None,
                    range: None,
                })
            }),
        })
    }

    fn bandwidth(&self, value: &str) -> Result<Bandwidth> {
        if self.options.loose_fields {
            Bandwidth::parse(value.trim())
        } else {
            Bandwidth::parse(value)
        }
    }

    /// `start-time SP stop-time`, each `time / "0"`, `time = POS-DIGIT 9*DIGIT`.
    fn timing(&self, value: &str) -> Result<Timing> {
        let fields = self.fields("t=", value)?;
        let loose = self.options.loose_fields;
        if fields.len() < 2 || (fields.len() > 2 && !loose) {
            return Err(syntax("t=", value));
        }
        let time = |field: &str| -> Result<u64> {
            if !(loose || field == "0" || (grammar::is_integer(field) && field.len() >= 10)) {
                return Err(syntax("t=", value));
            }
            grammar::digits("t=", field)
        };
        Ok(Timing {
            start_time: time(fields[0])?,
            stop_time: time(fields[1])?,
        })
    }

    /// `repeat-interval SP typed-time 1*(SP typed-time)`.
    fn repeat(&self, value: &str) -> Result<RepeatTime> {
        let fields = self.fields("r=", value)?;
        if fields.len() < 3 {
            return Err(syntax("r=", value));
        }
        // repeat-interval = POS-DIGIT *DIGIT [fixed-len-time-unit]
        if fields[0].starts_with('0') {
            return Err(syntax("r= repeat-interval", value));
        }
        let interval = parse_typed_time(fields[0])?;
        let duration = parse_typed_time(fields[1])?;
        let mut offsets = Vec::with_capacity(fields.len() - 2);
        for field in &fields[2..] {
            offsets.push(parse_typed_time(field)?);
        }
        Ok(RepeatTime {
            interval,
            duration,
            offsets,
        })
    }

    /// `time SP ["-"] typed-time *(SP time SP ["-"] typed-time)`.
    fn zones(&self, value: &str) -> Result<Vec<TimeZone>> {
        let fields = self.fields("z=", value)?;
        if !fields.len().is_multiple_of(2) {
            return Err(syntax("z=", value));
        }
        let mut zones = Vec::with_capacity(fields.len() / 2);
        for pair in fields.chunks(2) {
            let time = pair[0];
            if !(self.options.loose_fields || (grammar::is_integer(time) && time.len() >= 10)) {
                return Err(syntax("z= adjustment time", value));
            }
            let adjustment_time = grammar::digits("z= adjustment time", time)?;
            let offset = match pair[1].strip_prefix('-') {
                Some(positive) => parse_typed_time(positive)?
                    .checked_neg()
                    .ok_or_else(|| invalid("z= offset", value))?,
                None => parse_typed_time(pair[1])?,
            };
            zones.push(TimeZone {
                adjustment_time,
                offset,
            });
        }
        Ok(zones)
    }

    /// `media SP port ["/" integer] SP proto 1*(SP fmt)`.
    fn media_line(&mut self, value: &str) -> Result<()> {
        if self.desc.media_descriptions.len() >= MAX_MEDIA_DESCRIPTIONS {
            return Err(over_limit("media sections", MAX_MEDIA_DESCRIPTIONS));
        }

        let fields = self.fields("m=", value)?;
        if fields.len() < 4 {
            return Err(syntax("m=", value));
        }
        if fields.len() - 3 > MAX_FORMATS_PER_MEDIA {
            return Err(over_limit("formats on one m= line", MAX_FORMATS_PER_MEDIA));
        }

        // <media>
        // RFC 8866 section 5.14: <media> is a token ("audio", "video", "text",
        // "application", "message", "image" are registered, and new media types
        // may be), so an unknown one is parsed: it is the offer/answer layer that
        // rejects a media type it doesn't know (RFC 9429 section 5.3.1 answers
        // it with port 0), not the parser.
        if !grammar::is_token(fields[0]) {
            return Err(Error::SdpInvalidValue(fields[0].to_owned()));
        }

        // <port> ["/" integer]
        let (port, count) = match fields[1].split_once('/') {
            Some((port, count)) => (port, Some(count)),
            None => (fields[1], None),
        };
        let port_value = grammar::port(port)? as isize;
        let port_range = match count {
            Some(count) => {
                if !grammar::is_integer(count) {
                    return Err(syntax("m= number of ports", value));
                }
                Some(
                    count
                        .parse::<u16>()
                        .map_err(|_| invalid("m= number of ports", value))?
                        as isize,
                )
            }
            None => None,
        };

        // <proto>
        // RFC 8866 section 5.14: <proto> is the media transport protocol and is
        // extensible -- "New transport protocols MAY be defined, and MUST be
        // registered with IANA." Any `token *("/" token)` is accepted instead of a fixed
        // list, so IANA-registered transports beyond the RTP/SAVPF set interoperate, e.g.
        // UDP/BFCP (RFC 8856), TCP/DTLS/SCTP (RFC 8841) or TCP/MRCPv2.
        let mut protos = vec![];
        for proto in fields[2].split('/') {
            if !grammar::is_token(proto) {
                return Err(Error::SdpInvalidValue(fields[2].to_owned()));
            }
            protos.push(proto.to_owned());
        }

        // <fmt>...
        let mut formats = Vec::with_capacity(fields.len() - 3);
        for field in &fields[3..] {
            if !grammar::is_token(field) {
                return Err(syntax("m= fmt", value));
            }
            formats.push((*field).to_owned());
        }

        self.desc.media_descriptions.push(MediaDescription {
            media_name: MediaName {
                media: fields[0].to_owned(),
                port: RangedPort {
                    value: port_value,
                    range: port_range,
                },
                protos,
                formats,
            },
            media_title: None,
            connection_information: None,
            bandwidth: vec![],
            encryption_key: None,
            attributes: vec![],
        });
        Ok(())
    }
}

/// `attribute = (attribute-name ":" attribute-value) / attribute-name`, the name a token.
///
/// The value starts after the first colon and is kept whole.
pub(crate) fn parse_attribute(value: &str) -> Result<Attribute> {
    let (key, value) = match value.split_once(':') {
        Some((key, value)) => (key, Some(value)),
        None => (value, None),
    };
    if !grammar::is_token(key) {
        return Err(syntax("attribute name", key));
    }
    Ok(Attribute {
        key: key.to_owned(),
        value: value.map(str::to_owned),
    })
}

/// `key-type = "prompt" / "clear:" text / "base64:" base64 / "uri:" uri`. The line is
/// obsolete and its content is not kept (RFC 8866 section 5.12).
fn check_key(value: &str) -> Result<()> {
    let ok = if value == "prompt" {
        true
    } else if let Some(text) = value.strip_prefix("clear:") {
        grammar::is_byte_string(text)
    } else if let Some(key) = value.strip_prefix("base64:") {
        grammar::is_base64(key)
    } else if let Some(uri) = value.strip_prefix("uri:") {
        grammar::is_non_ws_string(uri)
    } else {
        false
    };
    if ok {
        Ok(())
    } else {
        // The key is not quoted in the error: it may be one.
        Err(Error::SdpInvalidSyntax("k= line".to_owned()))
    }
}

/// `email-safe`: any byte except NUL, CR, LF and the quoting characters `()<>`.
fn is_email_safe(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|b| matches!(b, 0 | b'\r' | b'\n' | b'(' | b')' | b'<' | b'>'))
}

/// RFC 5322 `atext`.
fn is_atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
}

/// RFC 5322 `dot-atom-text = 1*atext *("." 1*atext)`.
fn is_dot_atom(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|atom| !atom.is_empty() && atom.bytes().all(is_atext))
}

/// RFC 5322 `addr-spec = local-part "@" domain`, without comments, folding white space or
/// the obsolete forms: the local part is a dot-atom or a quoted string, the domain a
/// dot-atom or a domain literal.
fn is_addr_spec(value: &str) -> bool {
    let bytes = value.as_bytes();
    let at = if bytes.first() == Some(&b'"') {
        // quoted-string: DQUOTE *(qtext / quoted-pair / WSP) DQUOTE
        let mut i = 1;
        loop {
            match bytes.get(i) {
                Some(b'"') => break i + 1,
                Some(b'\\') if matches!(bytes.get(i + 1), Some(0x20..=0x7e | b'\t')) => i += 2,
                Some(b' ' | b'\t' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e) => i += 1,
                _ => return false,
            }
        }
    } else {
        match value.find('@') {
            Some(at) if is_dot_atom(&value[..at]) => at,
            _ => return false,
        }
    };
    if bytes.get(at) != Some(&b'@') {
        return false;
    }
    let domain = &value[at + 1..];
    match domain.strip_prefix('[').and_then(|d| d.strip_suffix(']')) {
        // domain-literal: "[" *dtext "]"
        Some(literal) => literal
            .bytes()
            .all(|b| matches!(b, 0x21..=0x5a | 0x5e..=0x7e)),
        None => is_dot_atom(domain),
    }
}

/// `email-address = address-and-comment / dispname-and-address / addr-spec`.
fn is_email_address(value: &str) -> bool {
    if let Some(rest) = value.strip_suffix(')') {
        // addr-spec 1*SP "(" 1*email-safe ")"
        let Some((address, comment)) = rest.split_once('(') else {
            return false;
        };
        let spec = address.trim_end_matches(' ');
        return spec.len() < address.len() && is_addr_spec(spec) && is_email_safe(comment);
    }
    if let Some(rest) = value.strip_suffix('>') {
        // 1*email-safe 1*SP "<" addr-spec ">"
        let Some((name, address)) = rest.split_once('<') else {
            return false;
        };
        return name.ends_with(' ')
            && is_email_safe(name.trim_end_matches(' '))
            && is_addr_spec(address);
    }
    is_addr_spec(value)
}

/// `phone = ["+"] DIGIT 1*(SP / "-" / DIGIT)`.
fn is_phone(value: &str) -> bool {
    let digits = value.strip_prefix('+').unwrap_or(value).as_bytes();
    digits.len() >= 2
        && digits[0].is_ascii_digit()
        && digits[1..]
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b' ' || *b == b'-')
}

/// `phone-number = phone *SP "(" 1*email-safe ")" / 1*email-safe "<" phone ">" / phone`.
fn is_phone_number(value: &str) -> bool {
    if let Some(rest) = value.strip_suffix(')') {
        let Some((phone, comment)) = rest.split_once('(') else {
            return false;
        };
        // `phone` itself may end in spaces: `*SP` adds nothing to check.
        return is_phone(phone) && is_email_safe(comment);
    }
    if let Some(rest) = value.strip_suffix('>') {
        let Some((name, phone)) = rest.split_once('<') else {
            return false;
        };
        return is_email_safe(name) && is_phone(phone);
    }
    is_phone(value)
}

/// `typed-time = 1*DIGIT [fixed-len-time-unit]`, in seconds.
///
/// The units are `d`, `h`, `m` and `s`, case-sensitive.
fn parse_typed_time(value: &str) -> Result<i64> {
    let (number, factor) = match value.as_bytes().last() {
        Some(b'd') => (&value[..value.len() - 1], 86400),
        Some(b'h') => (&value[..value.len() - 1], 3600),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b's') => (&value[..value.len() - 1], 1),
        _ => (value, 1),
    };
    grammar::digits::<i64>("typed-time", number)?
        .checked_mul(factor)
        .ok_or_else(|| invalid("typed-time", value))
}
