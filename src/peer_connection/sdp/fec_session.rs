//! A FEC session of its own in SDP (RFC 5109 sections 14.1 and 14.3): an m= section that
//! lists only `ulpfec`, grouped with the media section it protects by `a=group:FEC-FR`
//! (RFC 5956 section 4.1) or `a=group:FEC` (RFC 4756), and carried outside the BUNDLE group,
//! on a transport of its own: "the FEC and the payload MUST NOT be multiplexed by SSRC into
//! one single RTP session since they always have the same SSRC" (section 14.1).

use super::{
    add_candidates_to_media_descriptions, get_mid_value, is_rejected_media, is_rtp_profile,
};
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::rtp_transceiver::RTCFecGroupSemantics;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::internal::{FecSessionFeedback, FecSessionFormat};
use sdp::description::media::MediaDescription;
use sdp::description::session::{ATTR_KEY_CONNECTION_SETUP, ATTR_KEY_GROUP, ATTR_KEY_MID};
use sdp::description::session::{ATTR_KEY_RTCPMUX, SessionDescription};
use sdp::util::ConnectionRole;
use shared::error::Result;

/// The encoding name of RFC 5109 (section 14.1: "The name used in this binding is "ulpfec"").
const ULPFEC: &str = "ulpfec";

/// A FEC session a description sets up: the media section, the FEC section that protects it,
/// and how the two are grouped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FecSessionSections {
    /// The mid of the protected media section.
    pub(crate) protected_mid: String,
    /// The mid of the FEC section.
    pub(crate) fec_mid: String,
    pub(crate) semantics: RTCFecGroupSemantics,
    /// The FEC section's `ulpfec` format.
    pub(crate) format: FecSessionFormat,
}

/// What generating a FEC session's m= section needs beside the transport's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FecSection {
    /// The mid of the section it protects.
    pub(crate) protected_mid: String,
    pub(crate) semantics: RTCFecGroupSemantics,
    pub(crate) format: FecSessionFormat,
    /// The direction the section states.
    pub(crate) direction: RTCRtpTransceiverDirection,
}

/// The `ulpfec` format of `media` when the section is a FEC session's: audio or video over an
/// RTP profile, not rejected, and every format it lists is `ulpfec` (RFC 5109 section 14.1:
/// "the payload type number for the FEC stream [is] conveyed in their m line", with "an rtpmap
/// attribute"). The first format is the one used; its rate has to be above 1000 Hz (section
/// 13: "When this media format is used as a separate stream ... the rate SHALL be larger than
/// 1000 Hz").
pub(crate) fn fec_section_format(media: &MediaDescription) -> Option<FecSessionFormat> {
    if !matches!(media.media_name.media.as_str(), "audio" | "video")
        || is_rejected_media(media)
        || !is_rtp_profile(media)
        || media.media_name.formats.is_empty()
    {
        return None;
    }
    let mut formats = vec![];
    for format in &media.media_name.formats {
        let payload_type: u8 = format.parse().ok()?;
        let rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.key == "rtpmap")
            .filter_map(|a| a.value.as_deref())
            .find_map(|value| {
                let (pt, encoding) = value.trim().split_once(' ')?;
                (pt.parse::<u8>().ok()? == payload_type).then_some(encoding.trim())
            })?;
        let mut parts = rtpmap.split('/');
        if !parts.next()?.eq_ignore_ascii_case(ULPFEC) {
            return None;
        }
        let clock_rate: u32 = parts.next()?.parse().ok()?;
        let one_level_only = media
            .attributes
            .iter()
            .filter(|a| a.key == "fmtp")
            .filter_map(|a| a.value.as_deref())
            .filter_map(|value| value.trim().split_once(' '))
            .any(|(pt, parameters)| {
                pt.parse::<u8>().ok() == Some(payload_type)
                    && interceptor::ulpfec_one_level_only_from_fmtp(parameters)
            });
        formats.push(FecSessionFormat {
            payload_type,
            clock_rate,
            one_level_only,
            feedback: section_feedback(media, payload_type),
        });
    }
    // RFC 5109 section 14.1: "dynamic payload type numbers MUST be used".
    formats
        .into_iter()
        .next()
        .filter(|format| format.clock_rate > 1000 && format.payload_type >= 96)
}

/// The per-packet congestion feedback `media` states for its format `payload_type`: the
/// transport-wide sequence number extension with `a=rtcp-fb:<pt> transport-cc` (both needed:
/// the extension numbers the packets, the feedback type is what the reports are), and
/// `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 6). `a=rtcp-fb:*` applies to every format
/// (RFC 4585 section 4.2).
fn section_feedback(media: &MediaDescription, payload_type: u8) -> FecSessionFeedback {
    let feedback: Vec<&str> = media
        .attributes
        .iter()
        .filter(|a| a.key == "rtcp-fb")
        .filter_map(|a| a.value.as_deref())
        .filter_map(|value| {
            let (pt, rest) = value.trim().split_once(' ')?;
            (pt == "*" || pt.parse::<u8>().ok() == Some(payload_type)).then_some(rest.trim())
        })
        .collect();
    let has = |wanted: &str| {
        feedback
            .iter()
            .any(|f| f.split_whitespace().eq(wanted.split_whitespace()))
    };
    let extension = media
        .attributes
        .iter()
        .filter(|a| a.key == "extmap")
        .filter_map(|a| a.value.as_deref())
        .find_map(|value| {
            let mut parts = value.split_whitespace();
            let id = parts.next()?;
            let uri = parts.next()?;
            // An extension restricted to `inactive` is not in use (RFC 8285 section 7).
            let (id, direction) = id.split_once('/').unwrap_or((id, ""));
            (uri == ::sdp::extmap::TRANSPORT_CC_URI && direction != "inactive")
                .then(|| id.parse::<u8>().ok())
                .flatten()
                .filter(|id| (1..=14).contains(id))
        });
    FecSessionFeedback {
        transport_cc_extension: extension.filter(|_| has("transport-cc")),
        ccfb: has("ack ccfb"),
    }
}

/// The FEC sessions of a description: each `a=group:FEC-FR` / `a=group:FEC` line that names
/// exactly one media section and one FEC section ([`fec_section_format`]), both present and
/// neither rejected, with the FEC section outside every BUNDLE group (it is a second RTP
/// session, RFC 5109 section 14.1). A group of any other shape sets up none: its FEC section
/// is then an ordinary section with nothing to decode, which an answer rejects.
pub(crate) fn fec_sessions(desc: &SessionDescription) -> Vec<FecSessionSections> {
    let bundled: Vec<&str> = super::bundle_groups(desc).into_iter().flatten().collect();
    let section = |mid: &str| {
        desc.media_descriptions
            .iter()
            .find(|media| get_mid_value(media).is_some_and(|m| m == mid))
    };
    let mut sessions: Vec<FecSessionSections> = vec![];
    for value in desc
        .attributes
        .iter()
        .filter(|a| a.key == ATTR_KEY_GROUP)
        .filter_map(|a| a.value.as_deref())
    {
        let mut tokens = value.split_whitespace();
        let Some(semantics) = tokens.next().and_then(RTCFecGroupSemantics::from_token) else {
            continue;
        };
        let mids: Vec<&str> = tokens.collect();
        let [first, second] = mids.as_slice() else {
            continue;
        };
        let (Some(a), Some(b)) = (section(first), section(second)) else {
            continue;
        };
        let (protected_mid, fec_mid, protected, format) =
            match (fec_section_format(a), fec_section_format(b)) {
                (None, Some(format)) => (*first, *second, a, format),
                (Some(format), None) => (*second, *first, b, format),
                _ => continue,
            };
        if is_rejected_media(protected)
            || bundled.contains(&fec_mid)
            || sessions
                .iter()
                .any(|s| s.fec_mid == fec_mid || s.protected_mid == protected_mid)
        {
            continue;
        }
        sessions.push(FecSessionSections {
            protected_mid: protected_mid.to_owned(),
            fec_mid: fec_mid.to_owned(),
            semantics,
            format,
        });
    }
    sessions
}

/// What [`add_fec_media_section`] needs.
pub(crate) struct AddFecMediaSectionParams<'a> {
    pub(crate) should_add_candidates: bool,
    pub(crate) mid_value: String,
    /// The media type of the protected section (`video/ulpfec`, `audio/ulpfec`: RFC 5109
    /// sections 13.1 and 13.2).
    pub(crate) kind: String,
    pub(crate) ice_params: &'a RTCIceParameters,
    pub(crate) dtls_role: ConnectionRole,
    pub(crate) ice_gathering_state: RTCIceGatheringState,
    pub(crate) section: &'a FecSection,
}

/// Adds the m= section of a FEC session (RFC 5109 section 14.1): one `ulpfec` format with a
/// dynamic payload type, its own mid and transport parameters, RTP and RTCP multiplexed. It
/// describes no source: the FEC stream has the SSRC of the media stream it protects (section
/// 7.2), which the media section describes.
pub(crate) fn add_fec_media_section(
    d: SessionDescription,
    dtls_fingerprints: &[RTCDtlsFingerprint],
    candidates: &[RTCIceCandidate],
    params: AddFecMediaSectionParams<'_>,
) -> Result<SessionDescription> {
    let format = params.section.format;
    let mut media = MediaDescription::new_jsep_media_description(params.kind, vec![])
        .with_value_attribute(
            ATTR_KEY_CONNECTION_SETUP.to_owned(),
            params.dtls_role.to_string(),
        )
        .with_value_attribute(ATTR_KEY_MID.to_owned(), params.mid_value)
        .with_ice_credentials(
            params.ice_params.username_fragment.clone(),
            params.ice_params.password.clone(),
        )
        .with_property_attribute(ATTR_KEY_RTCPMUX.to_owned())
        .with_codec(
            format.payload_type,
            ULPFEC.to_owned(),
            format.clock_rate,
            0,
            if format.one_level_only {
                "onelevelonly=1".to_owned()
            } else {
                String::new()
            },
        )
        .with_property_attribute(params.section.direction.to_string());
    // The FEC session is an RTP session on a transport of its own, with a congestion
    // controller of its own: its packets carry the transport-wide sequence number and are
    // reported on, as the media's are.
    let feedback = format.feedback;
    if let Some(id) = feedback.transport_cc_extension {
        media = media
            .with_extmap(sdp::extmap::ExtMap {
                value: u16::from(id),
                uri: url::Url::parse(::sdp::extmap::TRANSPORT_CC_URI).ok(),
                ..Default::default()
            })
            .with_value_attribute(
                "rtcp-fb".to_owned(),
                format!("{} transport-cc", format.payload_type),
            );
    }
    if feedback.ccfb {
        media = media.with_value_attribute(
            "rtcp-fb".to_owned(),
            format!("{} ack ccfb", format.payload_type),
        );
    }
    for fingerprint in dtls_fingerprints {
        media = media.with_fingerprint(
            fingerprint.algorithm.clone(),
            fingerprint.value.to_uppercase(),
        );
    }
    if params.should_add_candidates {
        media =
            add_candidates_to_media_descriptions(candidates, media, params.ice_gathering_state)?;
    }
    Ok(d.with_media(media))
}

/// The `a=group` line of a FEC session: the media section first, then the FEC section, as
/// the examples of RFC 5109 section 14.1 and RFC 5956 section 4.2 write it.
pub(crate) fn fec_group_value(
    semantics: RTCFecGroupSemantics,
    protected_mid: &str,
    fec_mid: &str,
) -> String {
    format!("{} {protected_mid} {fec_mid}", semantics.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(sdp: &str) -> SessionDescription {
        let sdp = sdp.replace('\n', "\r\n");
        SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes())).unwrap()
    }

    const HEAD: &str = "v=0\no=- 1 1 IN IP4 127.0.0.1\ns=-\nt=0 0\n";

    fn media(mid: &str, port: u16, formats: &str, rtpmaps: &str) -> String {
        format!(
            "m=video {port} UDP/TLS/RTP/SAVPF {formats}\nc=IN IP4 0.0.0.0\na=mid:{mid}\n{rtpmaps}"
        )
    }

    fn offer(groups: &str, fec: &str) -> SessionDescription {
        parse(&format!(
            "{HEAD}{groups}{}{fec}",
            media("0", 9, "96", "a=rtpmap:96 VP8/90000\n")
        ))
    }

    /// The SDP of RFC 5109 section 14.1, in its WebRTC transport form: `a=group:FEC 0 1`
    /// with a FEC section of one dynamic `ulpfec` format.
    #[test]
    fn a_group_of_a_media_section_and_a_ulpfec_only_section_is_a_fec_session() {
        for (token, semantics) in [
            ("FEC", RTCFecGroupSemantics::Fec),
            ("FEC-FR", RTCFecGroupSemantics::FecFr),
        ] {
            let desc = offer(
                &format!("a=group:BUNDLE 0\na=group:{token} 0 1\n"),
                &media(
                    "1",
                    9,
                    "100",
                    "a=rtpmap:100 ulpfec/90000\na=fmtp:100 onelevelonly=1\n",
                ),
            );
            assert_eq!(
                fec_sessions(&desc),
                vec![FecSessionSections {
                    protected_mid: "0".to_owned(),
                    fec_mid: "1".to_owned(),
                    semantics,
                    format: FecSessionFormat {
                        payload_type: 100,
                        clock_rate: 90_000,
                        one_level_only: true,
                        feedback: FecSessionFeedback::default(),
                    },
                }]
            );
        }
    }

    /// The per-packet feedback a FEC section states: the transport-wide sequence number
    /// extension counts only with `transport-cc` feedback for the format (or for `*`), an
    /// `inactive` one not at all, and `ack ccfb` on its own.
    #[test]
    fn the_congestion_feedback_of_a_fec_section_is_read() {
        let twcc = ::sdp::extmap::TRANSPORT_CC_URI;
        for (lines, expected) in [
            (String::new(), FecSessionFeedback::default()),
            (
                format!("a=extmap:3 {twcc}\na=rtcp-fb:100 transport-cc\n"),
                FecSessionFeedback {
                    transport_cc_extension: Some(3),
                    ccfb: false,
                },
            ),
            (
                format!("a=extmap:3 {twcc}\na=rtcp-fb:* transport-cc\na=rtcp-fb:100 ack ccfb\n"),
                FecSessionFeedback {
                    transport_cc_extension: Some(3),
                    ccfb: true,
                },
            ),
            (
                format!("a=extmap:3 {twcc}\n"),
                FecSessionFeedback::default(),
            ),
            (
                format!("a=extmap:3/inactive {twcc}\na=rtcp-fb:100 transport-cc\n"),
                FecSessionFeedback::default(),
            ),
            (
                format!("a=extmap:3 {twcc}\na=rtcp-fb:101 transport-cc\n"),
                FecSessionFeedback::default(),
            ),
            (
                "a=rtcp-fb:100 ack ccfb\n".to_owned(),
                FecSessionFeedback {
                    transport_cc_extension: None,
                    ccfb: true,
                },
            ),
        ] {
            let desc = offer(
                "a=group:FEC-FR 0 1\n",
                &media(
                    "1",
                    9,
                    "100",
                    &format!("a=rtpmap:100 ulpfec/90000\n{lines}"),
                ),
            );
            let sessions = fec_sessions(&desc);
            assert_eq!(sessions.len(), 1, "{lines}");
            assert_eq!(sessions[0].format.feedback, expected, "{lines}");
        }
    }

    #[test]
    fn the_order_of_the_tags_does_not_decide_which_section_is_fec() {
        let desc = offer(
            "a=group:FEC-FR 1 0\n",
            &media("1", 9, "100", "a=rtpmap:100 ulpfec/90000\n"),
        );
        let sessions = fec_sessions(&desc);
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            (
                sessions[0].protected_mid.as_str(),
                sessions[0].fec_mid.as_str()
            ),
            ("0", "1")
        );
    }

    /// RFC 5109 section 14.1: dynamic payload types; section 13: a rate above 1000 Hz; and a
    /// FEC section is a second RTP session, so it is not in the media's BUNDLE group.
    #[test]
    fn what_is_not_a_fec_session() {
        let fec = |formats: &str, rtpmaps: &str| media("1", 9, formats, rtpmaps);
        let cases = [
            // No group.
            ("", fec("100", "a=rtpmap:100 ulpfec/90000\n")),
            // Another semantics.
            (
                "a=group:LS 0 1\n",
                fec("100", "a=rtpmap:100 ulpfec/90000\n"),
            ),
            // A media format beside ulpfec: an ordinary section.
            (
                "a=group:FEC 0 1\n",
                fec(
                    "96 100",
                    "a=rtpmap:96 VP8/90000\na=rtpmap:100 ulpfec/90000\n",
                ),
            ),
            // A static payload type.
            ("a=group:FEC 0 1\n", fec("34", "a=rtpmap:34 ulpfec/90000\n")),
            // A rate of 1000 Hz.
            (
                "a=group:FEC 0 1\n",
                fec("100", "a=rtpmap:100 ulpfec/1000\n"),
            ),
            // No rtpmap.
            ("a=group:FEC 0 1\n", fec("100", "")),
            // Rejected.
            (
                "a=group:FEC 0 1\n",
                media("1", 0, "100", "a=rtpmap:100 ulpfec/90000\n"),
            ),
            // In the BUNDLE group: one RTP session, where the two cannot share an SSRC.
            (
                "a=group:BUNDLE 0 1\na=group:FEC 0 1\n",
                fec("100", "a=rtpmap:100 ulpfec/90000\n"),
            ),
            // Three tags.
            (
                "a=group:FEC 0 1 2\n",
                fec("100", "a=rtpmap:100 ulpfec/90000\n"),
            ),
            // A tag no section has.
            (
                "a=group:FEC 0 7\n",
                fec("100", "a=rtpmap:100 ulpfec/90000\n"),
            ),
        ];
        for (groups, fec) in cases {
            let desc = offer(groups, &fec);
            assert_eq!(fec_sessions(&desc), vec![], "{groups}{fec}");
        }
    }

    #[test]
    fn the_group_line_names_the_media_section_first() {
        assert_eq!(
            fec_group_value(RTCFecGroupSemantics::Fec, "0", "1"),
            "FEC 0 1"
        );
        assert_eq!(
            fec_group_value(RTCFecGroupSemantics::FecFr, "a", "b"),
            "FEC-FR a b"
        );
    }
}
