//! `a=extmap` RTP header-extension declarations.
//!
//! An [`ExtMap`](crate::extmap::ExtMap) binds a header-extension URI to the small integer id that will appear in RTP
//! packets. Both sides must agree, which is the whole point of negotiating it in SDP: the id is
//! per-session, while the URI is the stable name.
//!
//! The `*_URI` constants are the extensions this stack uses — audio level, video orientation,
//! absolute send time, transport-wide CC, and the SDES ids that make simulcast demultiplexing
//! possible.
#[cfg(test)]
mod extmap_test;

use super::direction::*;
use crate::attribute::TypedAttribute;
use crate::description::common::*;
use crate::grammar;
use shared::error::{Error, Result};

use std::fmt;
use std::io;
use url::Url;

/// Default ext values
pub const DEF_EXT_MAP_VALUE_ABS_SEND_TIME: usize = 1;
/// The default id this crate assigns to the transport-wide CC extension.
pub const DEF_EXT_MAP_VALUE_TRANSPORT_CC: usize = 2;
/// The default id assigned to the SDES `mid` extension.
pub const DEF_EXT_MAP_VALUE_SDES_MID: usize = 3;
/// The default id assigned to the SDES RTP stream id extension.
pub const DEF_EXT_MAP_VALUE_SDES_RTP_STREAM_ID: usize = 4;

/// The absolute-send-time extension URI, used for bandwidth estimation.
pub const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
/// The transport-wide congestion control extension URI.
pub const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
/// The SDES `mid` extension URI, which tags each packet with its m-line.
pub const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
/// The SDES RTP stream id (RID) extension URI, which identifies a simulcast layer.
pub const SDES_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
/// The SDES repaired RTP stream id extension URI, which identifies an RTX layer's target.
pub const SDES_REPAIR_RTP_STREAM_ID_URI: &str =
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

/// The audio-level extension URI, carrying per-packet loudness.
pub const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
/// The video-orientation (CVO) extension URI, carrying rotation flags.
pub const VIDEO_ORIENTATION_URI: &str = "urn:3gpp:video-orientation";

/// The first of the ids an offerer uses for an extension it leaves the answerer to number
/// (RFC 8285 section 6).
pub const EXT_MAP_ANSWERER_ASSIGNED_MIN: u16 = 4096;
/// The last of those ids.
pub const EXT_MAP_ANSWERER_ASSIGNED_MAX: u16 = 4351;

/// ExtMap represents the activation of a single RTP header extension:
/// `a=extmap:<value>["/"<direction>] <URI> [<extensionattributes>]` (RFC 8285 section 5).
///
/// ```text
/// extmap-value        = mapentry SP extensionname [SP extensionattributes]
/// mapentry            = "extmap:" 1*5DIGIT ["/" direction]
/// extensionname       = URI
/// extensionattributes = byte-string
/// direction           = "sendonly" / "recvonly" / "sendrecv" / "inactive"
/// ```
#[derive(Debug, Clone, Default)]
pub struct ExtMap {
    /// The id this extension is negotiated under.
    ///
    /// RFC 8285 section 4.3 calls 1 to 256 the valid range: 1 to 255 is the local identifier
    /// that appears in RTP packets (1 to 14 fit the one-byte header form; 15 and above need
    /// the two-byte form), and 256 names the four `appbits` of the two-byte header. 4096 to
    /// 4351 is not an identifier: an offerer with more extensions than identifiers, or with
    /// alternatives, uses that range, and the answerer that wants the extension remaps it
    /// to a free valid id (RFC 8285 section 6). See [`ExtMap::is_answerer_assigned`].
    pub value: u16,
    /// The direction the extension applies in, if the attribute restricted it.
    pub direction: Direction,
    /// The extension's canonical URI.
    pub uri: Option<Url>,
    /// Extension-specific attributes trailing the URI: a byte-string, spaces included.
    pub ext_attr: Option<String>,
}

impl fmt::Display for ExtMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)?;

        if self.direction != Direction::Unspecified {
            write!(f, "/{}", self.direction)?;
        }

        if let Some(uri) = &self.uri {
            write!(f, " {uri}")?;
        }

        if let Some(ext_attr) = &self.ext_attr {
            write!(f, " {ext_attr}")?;
        }

        Ok(())
    }
}

impl TypedAttribute for ExtMap {
    const NAME: &'static str = "extmap";

    /// Parses the value of an `a=extmap` line: what follows `extmap:`.
    ///
    /// The id must be one RFC 8285 gives a meaning: 1 to 256 (the valid range), or 4096 to
    /// 4351 (the range an answerer remaps). 0 is padding, and nothing else is defined.
    fn parse(value: &str) -> Result<Self> {
        let error = || Error::ParseExtMap(value.to_owned());

        let (entry, rest) = value.split_once(' ').ok_or_else(error)?;
        let (uri, ext_attr) = match rest.split_once(' ') {
            Some((uri, ext_attr)) => (uri, Some(ext_attr)),
            None => (rest, None),
        };
        if uri.is_empty() || ext_attr.is_some_and(|a| !grammar::is_byte_string(a)) {
            return Err(error());
        }

        let (id, direction) = match entry.split_once('/') {
            Some((id, direction)) => (id, Some(direction)),
            None => (entry, None),
        };
        // mapentry = "extmap:" 1*5DIGIT
        if !grammar::is_digits(id) || id.len() > 5 {
            return Err(error());
        }
        let value_id = id.parse::<u32>().map_err(|_| error())?;
        let in_range = (1..=256).contains(&value_id)
            || (EXT_MAP_ANSWERER_ASSIGNED_MIN as u32..=EXT_MAP_ANSWERER_ASSIGNED_MAX as u32)
                .contains(&value_id);
        if !in_range {
            return Err(Error::ParseExtMap(format!(
                "{id} -- extmap key must be in the range 1-256 or 4096-4351"
            )));
        }

        let direction = match direction {
            None => Direction::Unspecified,
            Some(direction) => match Direction::new(direction) {
                Direction::Unspecified => {
                    return Err(Error::ParseExtMap(format!(
                        "unknown direction from {direction}"
                    )));
                }
                direction => direction,
            },
        };

        Ok(ExtMap {
            value: value_id as u16,
            direction,
            uri: Some(Url::parse(uri)?),
            ext_attr: ext_attr.map(str::to_owned),
        })
    }
}

impl ExtMap {
    /// converts this object to an Attribute
    pub fn convert(&self) -> Attribute {
        Attribute {
            key: "extmap".to_string(),
            value: Some(self.to_string()),
        }
    }

    /// Whether the id is in the 4096 to 4351 range: the offerer did not number the
    /// extension, and an answerer that accepts it remaps it to a free id in the valid range
    /// (RFC 8285 section 6). Such an id never appears in a packet.
    pub fn is_answerer_assigned(&self) -> bool {
        (EXT_MAP_ANSWERER_ASSIGNED_MIN..=EXT_MAP_ANSWERER_ASSIGNED_MAX).contains(&self.value)
    }

    /// Whether the id fits the one-byte header form (1 to 14). An id of 15 to 255 needs the
    /// two-byte form (RFC 8285 section 4.3).
    pub fn fits_one_byte_header(&self) -> bool {
        (1..=14).contains(&self.value)
    }

    /// Whether the id identifies an extension element in a packet: 1 to 255. 256 (the
    /// `appbits`) and the 4096 to 4351 range do not.
    pub fn is_element_id(&self) -> bool {
        (1..=255).contains(&self.value)
    }

    /// unmarshal creates an Extmap from a line of the form `extmap:<value>...` (the
    /// attribute, with or without its `a=`), for a caller that will use the id in packets.
    ///
    /// It accepts what [`TypedAttribute::parse`] accepts, minus the ids that do not
    /// identify an extension element: 256 (the `appbits`) and 4096 to 4351 (extensions the
    /// offerer left for the answerer to number) are refused here, because every caller of
    /// this function takes [`ExtMap::value`] as the identifier to put in, or look for in,
    /// an RTP header. A caller that handles those ids (RFC 8285 section 6: skip the
    /// extension, or remap it to a free id) parses with [`TypedAttribute::parse`], or
    /// reads a description's `extmaps()`, and asks [`ExtMap::is_element_id`].
    pub fn unmarshal<R: io::BufRead>(reader: &mut R) -> Result<Self> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.strip_suffix('\n').unwrap_or(&line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let parsed = match line.split_once(':') {
            Some(("extmap" | "a=extmap", value)) => <Self as TypedAttribute>::parse(value)?,
            _ => return Err(Error::ParseExtMap(line.to_owned())),
        };
        if !parsed.is_element_id() {
            return Err(Error::ParseExtMap(format!(
                "{} -- extmap key is not a local identifier (1-255)",
                parsed.value
            )));
        }
        Ok(parsed)
    }

    /// marshal creates a string from an ExtMap
    pub fn marshal(&self) -> String {
        "extmap:".to_string() + self.to_string().as_str()
    }
}
