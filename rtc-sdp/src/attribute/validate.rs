//! Checking a whole description: [`SessionDescription::validate`].

use shared::error::{Error, Result};

use super::mux::{self, AttributeLevel};
use super::*;
use crate::description::common::Attribute;
use crate::description::media::MediaDescription;
use crate::description::session::*;
use crate::extmap::ExtMap;
use crate::grammar;

/// Property attributes: the ones that take no value.
const FLAGS: [&str; 12] = [
    ATTR_KEY_SEND_RECV,
    ATTR_KEY_SEND_ONLY,
    ATTR_KEY_RECV_ONLY,
    ATTR_KEY_INACTIVE,
    ATTR_KEY_RTCPMUX,
    ATTR_KEY_RTCPMUX_ONLY,
    ATTR_KEY_RTCPRSIZE,
    ATTR_KEY_ICELITE,
    ATTR_KEY_END_OF_CANDIDATES,
    ATTR_KEY_BUNDLE_ONLY,
    ATTR_KEY_EXTMAP_ALLOW_MIXED,
    ATTR_KEY_CRYPTEX,
];

/// Parses `value` when the grammar of the attribute `name` is known; an unknown attribute
/// is fine as it is.
fn check_value(name: &str, value: Option<&str>) -> Result<()> {
    fn check<T: TypedAttribute>(value: Option<&str>) -> Result<()> {
        let value = value
            .ok_or_else(|| Error::SdpInvalidSyntax(format!("`a={}` has no value", T::NAME)))?;
        T::parse(value).map(|_| ())
    }

    if FLAGS.contains(&name) {
        return match value {
            None => Ok(()),
            Some(_) => Err(Error::SdpInvalidSyntax(format!(
                "`a={name}` takes no value"
            ))),
        };
    }
    match name {
        "group" => check::<Group>(value),
        "mid" => check::<Mid>(value),
        "msid" => check::<Msid>(value),
        "msid-semantic" => check::<MsidSemantic>(value),
        "ssrc" => check::<Ssrc>(value),
        "ssrc-group" => check::<SsrcGroup>(value),
        "rid" => check::<Rid>(value),
        "simulcast" => check::<Simulcast>(value),
        "extmap" => check::<ExtMap>(value),
        "rtcp" => check::<Rtcp>(value),
        "rtcp-fb" => check::<RtcpFb>(value),
        "rtcp-xr" => check::<RtcpXr>(value),
        "rtpmap" => check::<RtpMap>(value),
        "fmtp" => check::<Fmtp>(value),
        "ptime" => check::<Ptime>(value),
        "maxptime" => check::<MaxPtime>(value),
        "framerate" => check::<FrameRate>(value),
        "imageattr" => check::<ImageAttr>(value),
        "content" => check::<Content>(value),
        "candidate" => check::<Candidate>(value),
        "remote-candidates" => check::<RemoteCandidates>(value),
        "ice-ufrag" => check::<IceUfrag>(value),
        "ice-pwd" => check::<IcePwd>(value),
        "ice-options" => check::<IceOptions>(value),
        "ice-pacing" => check::<IcePacing>(value),
        "fingerprint" => check::<Fingerprint>(value),
        "setup" => check::<Setup>(value),
        "tls-id" => check::<TlsId>(value),
        "identity" => check::<Identity>(value),
        "sctp-port" => check::<SctpPort>(value),
        "max-message-size" => check::<MaxMessageSize>(value),
        "sctpmap" => check::<SctpMap>(value),
        // RFC 8866 section 5.13: an attribute that is not understood is ignored. What is
        // left to check is that its name is a token and its value has no NUL, CR or LF,
        // which matters for a description that was built and not parsed.
        _ => {
            if grammar::is_token(name)
                && value.is_none_or(|v| v.is_empty() || grammar::is_byte_string(v))
            {
                Ok(())
            } else {
                Err(Error::SdpInvalidSyntax(format!(
                    "attribute `{}`",
                    name.escape_debug()
                )))
            }
        }
    }
}

fn check_level(name: &str, media: bool) -> Result<()> {
    let Some(level) = mux::attribute(name).and_then(|row| row.level) else {
        return Ok(());
    };
    let allowed = match (level, media) {
        (AttributeLevel::Source, _) => false,
        (level, true) => level.allows_media(),
        (level, false) => level.allows_session(),
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::SdpInvalidValue(format!(
            "`a={name}` at the {} level",
            if media { "media" } else { "session" }
        )))
    }
}

/// The attributes a level holds at most once (RFC 8866 section 6.7 for the direction,
/// RFC 5888 section 4 for `mid`, and so on): a second one makes the level ambiguous.
const SINGLE: [&str; 15] = [
    "mid",
    "setup",
    "ice-ufrag",
    "ice-pwd",
    "ice-options",
    "ice-pacing",
    "tls-id",
    "simulcast",
    "sctp-port",
    "max-message-size",
    "rtcp",
    "ptime",
    "maxptime",
    "framerate",
    "remote-candidates",
];

fn check_attributes(attributes: &[Attribute], media: bool) -> Result<()> {
    let mut directions = 0usize;
    for (index, attribute) in attributes.iter().enumerate() {
        let (name, value) = attribute.parts();
        check_value(name, value)?;
        check_level(name, media)?;
        if matches!(
            name,
            ATTR_KEY_SEND_RECV | ATTR_KEY_SEND_ONLY | ATTR_KEY_RECV_ONLY | ATTR_KEY_INACTIVE
        ) {
            directions += 1;
        }
        if SINGLE.contains(&name) && attributes[..index].iter().any(|a| a.parts().0 == name) {
            return Err(Error::SdpInvalidValue(format!(
                "more than one `a={name}` at one level"
            )));
        }
    }
    if directions > 1 {
        return Err(Error::SdpInvalidValue(
            "more than one direction attribute at one level".to_owned(),
        ));
    }
    Ok(())
}

fn check_media(media: &MediaDescription, session_has_connection: bool) -> Result<()> {
    // RFC 8866 section 5.7: "A session description MUST contain either at least one 'c='
    // line in each media description or a single 'c=' line at the session level."
    if media.connection_information.is_none() && !session_has_connection {
        return Err(Error::SdpInvalidSyntax(format!(
            "the `m={}` section has no `c=` line and the session has none",
            media.media_name.media
        )));
    }
    check_attributes(&media.attributes, true)?;

    // Every rid an a=simulcast line names is one of the section's a=rid lines, and a rid-id
    // names one a=rid line (RFC 8853 section 5.2, RFC 8851 section 4).
    let rids = media.rids()?;
    for (index, rid) in rids.iter().enumerate() {
        if rids[..index].iter().any(|other| other.id == rid.id) {
            return Err(Error::SdpInvalidValue(format!(
                "`a=rid:{}` occurs twice in one media section",
                rid.id
            )));
        }
    }
    if let Some(simulcast) = media.simulcast()? {
        for id in simulcast.rids() {
            if !rids.iter().any(|rid| rid.id == id) {
                return Err(Error::SdpInvalidValue(format!(
                    "`a=simulcast` names the rid `{id}`, which has no `a=rid` line"
                )));
            }
        }
    }

    // RFC 8866 section 5.14: with an RTP profile, the formats are RTP payload type numbers.
    if media.media_name.protos.iter().any(|p| p == "RTP") {
        for format in &media.media_name.formats {
            if !grammar::is_digits(format) || !format.parse::<u8>().is_ok_and(|pt| pt <= 127) {
                return Err(Error::SdpInvalidValue(format!(
                    "`{format}` is not an RTP payload type"
                )));
            }
        }
    }
    Ok(())
}

impl SessionDescription {
    /// Checks what [`SessionDescription::unmarshal`] leaves unchecked: everything that
    /// takes more than one line to judge, and the value of every attribute this crate has a
    /// type for.
    ///
    /// RFC 9429 section 5.8 has a description rejected when a line is not well formed "even
    /// if its value is discarded"; this is that check for the `a=` lines. It returns the
    /// first problem found:
    ///
    /// * a media description without `c=` when the session has none (RFC 8866 section 5.7);
    /// * a known attribute whose value does not match its grammar, or a property attribute
    ///   (`rtcp-mux`, `sendrecv`, ...) that carries a value;
    /// * an attribute at a level it is not defined for (`a=group` in a media description,
    ///   `a=rtcp-mux` at the session level, ...), per the levels of [`mux`];
    /// * more than one direction attribute at one level (RFC 8866 section 6.7), or more
    ///   than one of an attribute that a level holds once (`mid`, `setup`, `ice-ufrag`,
    ///   `ice-pwd`, `simulcast`, ...);
    /// * two `a=mid` with the same tag (RFC 5888 section 4);
    /// * two `a=rid` with one id in a section, an `a=simulcast` naming a rid without an
    ///   `a=rid` line;
    /// * in a section with an RTP profile, a format that is not a payload type (RFC 8866
    ///   section 5.14).
    ///
    /// An attribute this crate does not know is not an error (RFC 8866 section 5.13).
    /// Negotiation rules (what an answer may contain given an offer, which tags a group may
    /// name, BUNDLE consistency across sections) are not checked here: they belong to the
    /// layer that negotiates.
    pub fn validate(&self) -> Result<()> {
        check_attributes(&self.attributes, false)?;

        let mut mids: Vec<String> = Vec::with_capacity(self.media_descriptions.len());
        for media in &self.media_descriptions {
            check_media(media, self.connection_information.is_some())?;
            if let Some(mid) = media.mid()? {
                if mids.iter().any(|m| m == mid.as_str()) {
                    return Err(Error::SdpInvalidValue(format!(
                        "`a=mid:{mid}` occurs twice"
                    )));
                }
                mids.push(mid.as_str().to_owned());
            }
        }

        Ok(())
    }
}
