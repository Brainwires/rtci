#[cfg(test)]
mod util_test;

use shared::error::{Error, Result};

use crate::attribute::{Fmtp, RtpMap, TypedAttribute};
use std::collections::HashMap;
use std::fmt;

/// The `a=` line prefix.
pub const ATTRIBUTE_KEY: &str = "a=";

/// ConnectionRole indicates which of the end points should initiate the connection establishment
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionRole {
    #[default]
    /// No `a=setup` attribute was present.
    Unspecified,

    /// ConnectionRoleActive indicates the endpoint will initiate an outgoing connection.
    Active,

    /// ConnectionRolePassive indicates the endpoint will accept an incoming connection.
    Passive,

    /// ConnectionRoleActpass indicates the endpoint is willing to accept an incoming connection or to initiate an outgoing connection.
    Actpass,

    /// ConnectionRoleHoldconn indicates the endpoint does not want the connection to be established for the time being.
    Holdconn,
}

const CONNECTION_ROLE_ACTIVE_STR: &str = "active";
const CONNECTION_ROLE_PASSIVE_STR: &str = "passive";
const CONNECTION_ROLE_ACTPASS_STR: &str = "actpass";
const CONNECTION_ROLE_HOLDCONN_STR: &str = "holdconn";

impl fmt::Display for ConnectionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectionRole::Active => CONNECTION_ROLE_ACTIVE_STR,
            ConnectionRole::Passive => CONNECTION_ROLE_PASSIVE_STR,
            ConnectionRole::Actpass => CONNECTION_ROLE_ACTPASS_STR,
            ConnectionRole::Holdconn => CONNECTION_ROLE_HOLDCONN_STR,
            _ => "Unspecified",
        };
        write!(f, "{s}")
    }
}

impl From<u8> for ConnectionRole {
    fn from(v: u8) -> Self {
        match v {
            1 => ConnectionRole::Active,
            2 => ConnectionRole::Passive,
            3 => ConnectionRole::Actpass,
            4 => ConnectionRole::Holdconn,
            _ => ConnectionRole::Unspecified,
        }
    }
}

impl From<&str> for ConnectionRole {
    fn from(raw: &str) -> Self {
        match raw {
            CONNECTION_ROLE_ACTIVE_STR => ConnectionRole::Active,
            CONNECTION_ROLE_PASSIVE_STR => ConnectionRole::Passive,
            CONNECTION_ROLE_ACTPASS_STR => ConnectionRole::Actpass,
            CONNECTION_ROLE_HOLDCONN_STR => ConnectionRole::Holdconn,
            _ => ConnectionRole::Unspecified,
        }
    }
}

/// https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-26#section-5.2.1
/// Session ID is recommended to be constructed by generating a 64-bit
/// quantity with the highest bit set to zero and the remaining 63-bits
/// being cryptographically random.
pub(crate) fn new_session_id() -> u64 {
    let c = u64::MAX ^ (1u64 << 63);
    rand::random::<u64>() & c
}

// Codec represents a codec
#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// One codec offered by a media section, assembled from its `a=rtpmap`, `a=fmtp` and
/// `a=rtcp-fb` attributes.
pub struct Codec {
    /// The RTP payload type that identifies this codec in the stream.
    pub payload_type: u8,
    /// The encoding name, such as `VP8` or `opus`.
    pub name: String,
    /// The RTP clock rate in Hz.
    pub clock_rate: u32,
    /// Codec-specific encoding parameters — the channel count, for audio.
    pub encoding_parameters: String,
    /// The `a=fmtp` format parameters, verbatim.
    pub fmtp: String,
    /// The `a=rtcp-fb` feedback types negotiated for this codec, such as `nack` or `goog-remb`.
    pub rtcp_feedback: Vec<String>,
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}/{}/{} ({}) [",
            self.payload_type, self.name, self.clock_rate, self.encoding_parameters, self.fmtp,
        )?;

        let mut first = true;
        for part in &self.rtcp_feedback {
            if first {
                first = false;
                write!(f, "{part}")?;
            } else {
                write!(f, ", {part}")?;
            }
        }

        write!(f, "]")
    }
}

/// The codec an `a=rtpmap` value describes: `<payload type> <encoding name>/<clock
/// rate>[/<encoding parameters>]` (RFC 8866 section 6.6).
pub(crate) fn parse_rtpmap(value: &str) -> Result<Codec> {
    let rtpmap = RtpMap::parse(value)?;
    Ok(Codec {
        payload_type: rtpmap.payload_type,
        name: rtpmap.encoding_name,
        clock_rate: rtpmap.clock_rate,
        encoding_parameters: rtpmap.channels.map(|c| c.to_string()).unwrap_or_default(),
        ..Default::default()
    })
}

/// The format parameters an `a=fmtp` value carries for an RTP payload type:
/// `<format> <format specific parameters>` (RFC 8866 section 6.15). The parameters are
/// everything after the first space.
pub(crate) fn parse_fmtp(value: &str) -> Result<Codec> {
    let fmtp = Fmtp::parse(value)?;
    let payload_type = fmtp
        .payload_type()
        .ok_or_else(|| Error::SdpInvalidValue(format!("fmtp format `{}`", fmtp.format)))?;
    Ok(Codec {
        payload_type,
        fmtp: fmtp.parameters,
        ..Default::default()
    })
}

/// The most `a=rtcp-fb` values one payload type keeps. Browsers declare well under a dozen per
/// codec; further lines (and repeats of a value already kept) are dropped, so a description
/// can't grow a codec's feedback list without bound.
pub(crate) const MAX_RTCP_FEEDBACK_PER_CODEC: usize = 64;

pub(crate) fn merge_codecs(mut codec: Codec, codecs: &mut HashMap<u8, Codec>) {
    if let Some(saved_codec) = codecs.get_mut(&codec.payload_type) {
        if saved_codec.payload_type == 0 {
            saved_codec.payload_type = codec.payload_type
        }
        if saved_codec.name.is_empty() {
            saved_codec.name = codec.name
        }
        if saved_codec.clock_rate == 0 {
            saved_codec.clock_rate = codec.clock_rate
        }
        if saved_codec.encoding_parameters.is_empty() {
            saved_codec.encoding_parameters = codec.encoding_parameters
        }
        if saved_codec.fmtp.is_empty() {
            saved_codec.fmtp = codec.fmtp
        }
        for feedback in codec.rtcp_feedback.drain(..) {
            if saved_codec.rtcp_feedback.len() >= MAX_RTCP_FEEDBACK_PER_CODEC {
                break;
            }
            if !saved_codec.rtcp_feedback.contains(&feedback) {
                saved_codec.rtcp_feedback.push(feedback);
            }
        }
    } else {
        codec.rtcp_feedback.truncate(MAX_RTCP_FEEDBACK_PER_CODEC);
        codecs.insert(codec.payload_type, codec);
    }
}

fn equivalent_fmtp(want: &str, got: &str) -> bool {
    let mut want_split: Vec<&str> = want.split(';').collect();
    let mut got_split: Vec<&str> = got.split(';').collect();

    if want_split.len() != got_split.len() {
        return false;
    }

    want_split.sort_unstable();
    got_split.sort_unstable();

    for (i, &want_part) in want_split.iter().enumerate() {
        let want_part = want_part.trim();
        let got_part = got_split[i].trim();
        if got_part != want_part {
            return false;
        }
    }

    true
}

pub(crate) fn codecs_match(wanted: &Codec, got: &Codec) -> bool {
    if !wanted.name.is_empty() && wanted.name.to_lowercase() != got.name.to_lowercase() {
        return false;
    }
    if wanted.clock_rate != 0 && wanted.clock_rate != got.clock_rate {
        return false;
    }
    if !wanted.encoding_parameters.is_empty()
        && wanted.encoding_parameters != got.encoding_parameters
    {
        return false;
    }
    if !wanted.fmtp.is_empty() && !equivalent_fmtp(&wanted.fmtp, &got.fmtp) {
        return false;
    }

    true
}
