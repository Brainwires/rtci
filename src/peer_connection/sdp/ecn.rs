//! `a=ecn-capable-rtp` (RFC 6679 section 6.1): ECN for RTP negotiated in the offer/answer.
//!
//! RFC 8888 section 7: "When congestion control feedback is to be used with RTP and ECN, the
//! SDP offer generated MUST include an "a=ecn-capable-rtp:" attribute to negotiate ECN
//! support, along with an "a=rtcp-fb:" attribute with the "ack" parameter "ccfb"". With ECN on
//! (`SettingEngineBuilder::with_ecn`) every RTP section of an offer that uses an AVPF profile
//! carries the attribute; an answer carries it, with one initiation method, only where the
//! offer had one this endpoint implements (section 6.1.1). A stream sends ECT only when both
//! sides' sections carry it (section 6.1.1: "If the attribute is removed in the answer, then ECN
//! MUST NOT be used in any direction for that media flow") and the peer can read the marks
//! (its `mode` is not `setonly`).
//!
//! The initiation methods this endpoint implements are `rtp` (section 7.2.1, the RTP/RTCP
//! probes of `interceptor::EcnValidation`) and `leap` (section 7.2.3); `ice` (section 7.2.2,
//! STUN probes) is not, so it is never offered or answered and the `rtp+ecn` ICE option
//! (section 6.4) is never written.

use sdp::description::media::MediaDescription;
use sdp::description::session::SessionDescription;

/// `a=ecn-capable-rtp` (RFC 6679 section 6.1).
pub(crate) const ATTR_KEY_ECN_CAPABLE_RTP: &str = "ecn-capable-rtp";

/// The initiation method of RFC 6679 section 7.2.1 (RTP and RTCP).
const METHOD_RTP: &str = "rtp";
/// The leap-of-faith initiation of RFC 6679 section 7.2.3.
const METHOD_LEAP: &str = "leap";

/// The `mode=` parameter (RFC 6679 section 6.1): what the endpoint can do with the ECN field
/// of UDP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcnMode {
    /// It sets and reads it (the default when the parameter is left out).
    SetRead,
    /// It sets it but cannot read it.
    SetOnly,
    /// It reads it but cannot set it.
    ReadOnly,
}

/// A parsed `a=ecn-capable-rtp` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EcnCapability {
    /// The initiation methods, in decreasing preference, unknown ones included (they are
    /// ignored where the list is used: "unknown methods MUST be ignored upon reception").
    pub(crate) methods: Vec<String>,
    /// `mode=`; "An offer that does not include a "mode=" parameter MUST be treated as if a
    /// "mode=setread" parameter had been included".
    pub(crate) mode: EcnMode,
}

impl EcnCapability {
    /// Parses `ecn-attribute = "a=ecn-capable-rtp:" SP init-list [SP parm-list]` (RFC 6679
    /// Figure 5). Unknown parameters are ignored ("Unknown optional parameters MUST be ignored
    /// on reception"); a value without an initiation method is `None`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (init_list, parm_list) = match value.split_once(' ') {
            Some((init, parms)) => (init, parms),
            None => (value, ""),
        };
        let methods: Vec<String> = init_list
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(|m| m.to_ascii_lowercase())
            .collect();
        if methods.is_empty() {
            return None;
        }
        let mut mode = EcnMode::SetRead;
        for parm in parm_list.split(';') {
            if let Some((name, val)) = parm.trim().split_once('=')
                && name.trim().eq_ignore_ascii_case("mode")
            {
                match val.trim().to_ascii_lowercase().as_str() {
                    "setonly" => mode = EcnMode::SetOnly,
                    "readonly" => mode = EcnMode::ReadOnly,
                    "setread" => mode = EcnMode::SetRead,
                    _ => {}
                }
            }
        }
        Some(Self { methods, mode })
    }

    /// The first method of the list this endpoint implements.
    fn first_known(&self) -> Option<interceptor::EcnInitiation> {
        self.methods.iter().find_map(|m| method_initiation(m))
    }
}

fn method_initiation(method: &str) -> Option<interceptor::EcnInitiation> {
    match method {
        METHOD_RTP => Some(interceptor::EcnInitiation::RtpAndRtcp),
        METHOD_LEAP => Some(interceptor::EcnInitiation::LeapOfFaith),
        _ => None,
    }
}

fn initiation_method(initiation: interceptor::EcnInitiation) -> &'static str {
    match initiation {
        interceptor::EcnInitiation::RtpAndRtcp => METHOD_RTP,
        interceptor::EcnInitiation::LeapOfFaith => METHOD_LEAP,
    }
}

/// The section's `a=ecn-capable-rtp`, parsed, if it has one.
pub(crate) fn media_ecn_capability(media: &MediaDescription) -> Option<EcnCapability> {
    media
        .attribute(ATTR_KEY_ECN_CAPABLE_RTP)
        .flatten()
        .and_then(EcnCapability::parse)
}

/// The `a=ecn-capable-rtp` that applies to `media` of `desc`: its own, or the tagged
/// section's of its BUNDLE group, where RFC 9143 section 7.1.3 puts the IDENTICAL attributes
/// (RFC 8859 section 7.4 places this one there) of an answer or a subsequent offer.
pub(crate) fn section_ecn_capability(
    desc: &SessionDescription,
    media: &MediaDescription,
) -> Option<EcnCapability> {
    media_ecn_capability(media)
        .or_else(|| super::tagged_section(desc, media).and_then(media_ecn_capability))
}

/// The value of an offer's `a=ecn-capable-rtp` (RFC 6679 section 6.1.1: "one or more ECN
/// initiation methods in a comma-separated list in decreasing order of preference"): the
/// configured initiation first, then the other method this endpoint implements. No `mode=`
/// (this endpoint sets and reads the field: `with_ecn` says the socket layer does both) and no
/// `ect=` (ECT(0) implied: this endpoint takes either marking).
pub(crate) fn offer_value(preferred: interceptor::EcnInitiation) -> String {
    let other = match preferred {
        interceptor::EcnInitiation::RtpAndRtcp => interceptor::EcnInitiation::LeapOfFaith,
        interceptor::EcnInitiation::LeapOfFaith => interceptor::EcnInitiation::RtpAndRtcp,
    };
    format!(
        " {},{}",
        initiation_method(preferred),
        initiation_method(other)
    )
}

/// The value of an answer's `a=ecn-capable-rtp` to an offered one: "its single preferred
/// choice of initiation method" (RFC 6679 section 6.1.1), the offer's first that this endpoint
/// implements, unknown ones "MUST NOT be included in an answer". `None` when there is none.
/// This endpoint sets and reads the field, so every offered `mode=` has a common capability.
pub(crate) fn answer_value(offered: &EcnCapability) -> Option<String> {
    offered
        .first_known()
        .map(|initiation| format!(" {}", initiation_method(initiation)))
}

/// Whether ECN was negotiated for a section, and how its streams initiate it: both the
/// offered and the answered section carry the attribute (RFC 6679 section 6.1.1), the answer's
/// method is one this endpoint implements, and the remote side can read the marks this
/// endpoint would send (its `mode` is not `setonly`).
pub(crate) fn negotiated_initiation(
    local: (&SessionDescription, &MediaDescription),
    remote: (&SessionDescription, &MediaDescription),
    local_is_answer: bool,
) -> Option<interceptor::EcnInitiation> {
    let local_capability = section_ecn_capability(local.0, local.1)?;
    let remote_capability = section_ecn_capability(remote.0, remote.1)?;
    if remote_capability.mode == EcnMode::SetOnly {
        return None;
    }
    let answered = if local_is_answer {
        &local_capability
    } else {
        &remote_capability
    };
    answered.first_known()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attribute_parses_methods_and_mode_and_ignores_unknown_parameters() {
        let parsed = EcnCapability::parse(" leap,rtp mode=readonly; ect=1; foo=\"x y\"");
        assert_eq!(
            parsed,
            Some(EcnCapability {
                methods: vec!["leap".to_owned(), "rtp".to_owned()],
                mode: EcnMode::ReadOnly,
            })
        );
        assert_eq!(
            EcnCapability::parse(" rtp").map(|c| c.mode),
            Some(EcnMode::SetRead)
        );
        assert_eq!(EcnCapability::parse(" "), None);
    }

    #[test]
    fn an_answer_takes_the_first_offered_method_it_implements() {
        let offered = EcnCapability::parse(" ice,leap,rtp").expect("parses");
        assert_eq!(answer_value(&offered).as_deref(), Some(" leap"));
        let only_ice = EcnCapability::parse(" ice,future").expect("parses");
        assert_eq!(answer_value(&only_ice), None);
    }
}
