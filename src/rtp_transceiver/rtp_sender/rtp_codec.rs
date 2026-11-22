use crate::peer_connection::configuration::UNSPECIFIED_STR;
use crate::peer_connection::configuration::media_engine::*;
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::{
    RTCP_FB_ACK_CCFB, RTCPFeedback, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_TRANSPORT_CC,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::{PayloadType, fmtp};
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};
use std::fmt;

/// Codec kind identifying the media type.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RtpCodecKind {
    /// Unspecified or unknown codec type
    #[default]
    Unspecified = 0,

    /// Audio codec
    #[serde(rename = "audio")]
    Audio = 1,

    /// Video codec
    #[serde(rename = "video")]
    Video = 2,

    /// Non-audio/video RTP-carried application data
    #[serde(rename = "application")]
    Application = 3,
}

impl From<&str> for RtpCodecKind {
    fn from(raw: &str) -> Self {
        match raw {
            "audio" => RtpCodecKind::Audio,
            "video" => RtpCodecKind::Video,
            "application" => RtpCodecKind::Application,
            _ => RtpCodecKind::Unspecified,
        }
    }
}

impl From<u8> for RtpCodecKind {
    fn from(v: u8) -> Self {
        match v {
            1 => RtpCodecKind::Audio,
            2 => RtpCodecKind::Video,
            3 => RtpCodecKind::Application,
            _ => RtpCodecKind::Unspecified,
        }
    }
}

impl fmt::Display for RtpCodecKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RtpCodecKind::Audio => "audio",
            RtpCodecKind::Video => "video",
            RtpCodecKind::Application => "application",
            RtpCodecKind::Unspecified => UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

/// RTP codec capability providing information about supported codecs.
///
/// ## Specifications
///
/// * [W3C](https://www.w3.org/TR/webrtc/#dictionary-rtcrtpcodec-members)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpCodec {
    /// MIME type of the codec (e.g., "video/VP8", "audio/opus")
    pub mime_type: String,
    /// Codec clock rate in Hz
    pub clock_rate: u32,
    /// Number of audio channels (0 for video codecs)
    pub channels: u16,
    /// Format-specific parameters as SDP fmtp line
    pub sdp_fmtp_line: String,
    /// RTCP feedback mechanisms supported by this codec (deprecated, will be removed)
    pub rtcp_feedback: Vec<RTCPFeedback>, //TODO: to be removed
}

impl RTCRtpCodec {
    /// Creates an RTP payloader for this codec.
    ///
    /// Returns a boxed trait object implementing the Payloader interface
    /// for packetizing media frames into RTP packets.
    ///
    /// # Errors
    ///
    /// Returns `Error::ErrNoPayloaderForCodec` if the codec is not supported.
    pub fn payloader(&self) -> Result<Box<dyn rtp::packetizer::Payloader>> {
        let mime_type = self.mime_type.to_lowercase();
        if mime_type == MIME_TYPE_H264.to_lowercase() {
            // RFC 6184 6.2: the negotiated packetization mode decides whether STAP-A and FU-A
            // may be sent at all; an absent parameter means mode 0.
            Ok(Box::new(
                rtp::codec::h264::H264Payloader::with_packetization_mode(h264_packetization_mode(
                    &self.sdp_fmtp_line,
                )),
            ))
        } else if mime_type == MIME_TYPE_HEVC.to_lowercase() {
            Ok(Box::<rtp::codec::h265::HevcPayloader>::default())
        } else if mime_type == MIME_TYPE_VP8.to_lowercase() {
            let mut vp8_payloader = rtp::codec::vp8::Vp8Payloader::default();
            vp8_payloader.enable_picture_id = true;
            Ok(Box::new(vp8_payloader))
        } else if mime_type == MIME_TYPE_VP9.to_lowercase() {
            Ok(Box::<rtp::codec::vp9::Vp9Payloader>::default())
        } else if mime_type == MIME_TYPE_OPUS.to_lowercase() {
            Ok(Box::<rtp::codec::opus::OpusPayloader>::default())
        } else if mime_type == MIME_TYPE_G722.to_lowercase()
            || mime_type == MIME_TYPE_PCMU.to_lowercase()
            || mime_type == MIME_TYPE_PCMA.to_lowercase()
            || mime_type == MIME_TYPE_TELEPHONE_EVENT.to_lowercase()
        {
            Ok(Box::<rtp::codec::g7xx::G7xxPayloader>::default())
        } else if mime_type == MIME_TYPE_AV1.to_lowercase() {
            Ok(Box::<rtp::codec::av1::Av1Payloader>::default())
        } else if mime_type == MIME_TYPE_SMPTE336M.to_lowercase() {
            Ok(Box::<rtp::codec::smpte336m::Smpte336mPayloader>::default())
        } else {
            Err(Error::ErrNoPayloaderForCodec)
        }
    }
}

/// The `packetization-mode` an H.264 fmtp line names, 0 when it names none (RFC 6184 8.1).
pub(crate) fn h264_packetization_mode(sdp_fmtp_line: &str) -> u8 {
    sdp_fmtp_line
        .split(';')
        .filter_map(|parameter| parameter.trim().split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("packetization-mode"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// Codec match quality result from fuzzy search.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum CodecMatch {
    /// No match found
    #[default]
    None = 0,
    /// Partial match (MIME type matches)
    Partial = 1,
    /// Exact match (MIME type and format parameters match)
    Exact = 2,
}

/// Performs fuzzy search for a codec in a list of available codecs.
///
/// First attempts an exact match on both MIME type and format parameters,
/// then falls back to matching only the MIME type.
///
/// # Parameters
///
/// * `needle_rtp_codec` - The codec to search for
/// * `haystack` - List of available codecs to search in
///
/// # Returns
///
/// A tuple of (matched codec parameters, match quality)
pub(crate) fn codec_parameters_fuzzy_search(
    needle_rtp_codec: &RTCRtpCodec,
    haystack: &[RTCRtpCodecParameters],
) -> (RTCRtpCodecParameters, CodecMatch) {
    let needle_fmtp = fmtp::parse(&needle_rtp_codec.mime_type, &needle_rtp_codec.sdp_fmtp_line);

    // First attempt to match on mime_type + sdpfmtp_line
    for c in haystack {
        let cfmpt = fmtp::parse(&c.rtp_codec.mime_type, &c.rtp_codec.sdp_fmtp_line);
        if needle_fmtp.match_fmtp(&*cfmpt) {
            return (c.clone(), CodecMatch::Exact);
        }
    }

    // Fallback to just mime_type
    for c in haystack {
        // MIME types are ASCII-only; eq_ignore_ascii_case is sufficient and allocation-free.
        if c.rtp_codec
            .mime_type
            .eq_ignore_ascii_case(&needle_rtp_codec.mime_type)
        {
            return (c.clone(), CodecMatch::Partial);
        }
    }

    (RTCRtpCodecParameters::default(), CodecMatch::None)
}

/// The negotiated codec an encoding is sent with.
///
/// An encoding that names a codec is sent with the negotiated codec matching it
/// ([`codec_parameters_fuzzy_search`]). One that names none (an empty `codec`, the
/// `RTCRtpCodec` default: W3C `addTransceiver` lets `sendEncodings` leave the codec to
/// negotiation) is sent with the first media codec of the negotiated list, the codec the
/// sender's parameters prefer; repair formats (RTX, RED, ULPFEC, FlexFEC) only accompany
/// a media codec and are never it.
///
/// # Returns
///
/// `None` when the encoding names a codec that was not negotiated, or names none and the
/// negotiated list has no media codec.
pub(crate) fn encoding_send_codec(
    codec: &RTCRtpCodec,
    negotiated: &[RTCRtpCodecParameters],
) -> Option<RTCRtpCodecParameters> {
    if codec.mime_type.is_empty() {
        return negotiated
            .iter()
            .find(|c| !c.rtp_codec.mime_type.is_empty() && !is_repair_codec(&c.rtp_codec))
            .cloned();
    }
    match codec_parameters_fuzzy_search(codec, negotiated) {
        (_, CodecMatch::None) => None,
        (matched, _) => Some(matched),
    }
}

/// Searches for a matching encoding in available codecs.
///
/// Iterates through encodings looking for the best codec match, preferring exact matches.
///
/// # Parameters
///
/// * `encodings` - List of encoding parameters to search through
/// * `haystack` - List of available codec parameters
///
/// # Returns
///
/// A tuple of (matched encoding, match quality)
pub(crate) fn encoding_parameters_fuzzy_search(
    encodings: &[RTCRtpEncodingParameters],
    haystack: &[RTCRtpCodecParameters],
) -> (RTCRtpEncodingParameters, CodecMatch) {
    let mut result = None;
    for encoding in encodings {
        let (_, codec_match_type) = codec_parameters_fuzzy_search(&encoding.codec, haystack);
        if codec_match_type == CodecMatch::Exact {
            return (encoding.clone(), codec_match_type);
        } else if result.is_none() {
            result = Some((encoding.clone(), CodecMatch::Partial));
        }
    }

    if let Some((encoding, code_match_type)) = result {
        (encoding, code_match_type)
    } else {
        (RTCRtpEncodingParameters::default(), CodecMatch::None)
    }
}

/// Finds the RTX payload type associated with a given payload type.
///
/// Searches for an RTX codec with the matching APT (Associated Payload Type) parameter.
///
/// # Parameters
///
/// * `needle` - The primary payload type to find RTX for
/// * `haystack` - List of codec parameters to search
///
/// # Returns
///
/// The RTX payload type if found, None otherwise
pub(crate) fn find_rtx_payload_type(
    needle: PayloadType,
    haystack: &[RTCRtpCodecParameters],
) -> Option<PayloadType> {
    for c in haystack {
        // Match on the parsed `apt` value rather than the whole fmtp line, so an
        // RTX codec carrying extra parameters (e.g. `apt=96;rtx-time=3000`, RFC
        // 4588 §8.1) is still associated with its primary.
        if parse_rtx_apt(&c.rtp_codec.sdp_fmtp_line) == Some(needle) {
            return Some(c.payload_type);
        }
    }

    None
}

/// Parses the associated payload type (`apt`) from an RTX codec's fmtp line.
///
/// RFC 4588 §8.1 defines the `apt` parameter, which maps a retransmission
/// payload type to the payload type of the stream it repairs. The fmtp line may
/// carry additional parameters (e.g. `apt=96;rtx-time=3000`), so the value is
/// extracted from the `apt=` token rather than compared against the whole line.
///
/// # Parameters
///
/// * `sdp_fmtp_line` - The RTX codec's fmtp line, e.g. `"apt=96"`
///
/// # Returns
///
/// The associated (primary) payload type if an `apt=` token is present, else None.
pub(crate) fn parse_rtx_apt(sdp_fmtp_line: &str) -> Option<PayloadType> {
    sdp_fmtp_line
        .split(';')
        .filter_map(|param| param.trim().strip_prefix("apt="))
        .find_map(|value| value.trim().parse::<PayloadType>().ok())
}

/// The `rtx-time` of a retransmission format's fmtp line (RFC 4588 section 8.1: "the time in
/// milliseconds (measured from the time a packet was first sent) that the sender keeps an RTP
/// packet in its buffers available for retransmission"), e.g. of `"apt=96;rtx-time=3000"`.
pub(crate) fn parse_rtx_time(sdp_fmtp_line: &str) -> Option<std::time::Duration> {
    sdp_fmtp_line
        .split(';')
        .filter_map(|param| param.trim().strip_prefix("rtx-time="))
        .find_map(|value| value.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
}

/// Whether `mime_type` is a retransmission format (`audio/rtx`, `video/rtx`; RFC 4588
/// section 8).
pub(crate) fn is_rtx_mime_type(mime_type: &str) -> bool {
    mime_type
        .split_once('/')
        .is_some_and(|(_, subtype)| subtype.eq_ignore_ascii_case("rtx"))
}

/// Whether `codec` repairs another stream rather than carrying media of its own.
///
/// Covers retransmission (RTX, RFC 4588) and forward error correction (FlexFEC, ULPFEC, RED).
/// These are not alternative media formats a peer chooses between — they accompany whichever
/// primary codec was chosen — which is why codec preferences leave them in place. See
/// [setCodecPreferences](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-setcodecpreferences):
///
/// > Codecs of type RTX, RED and FEC are always supported […] and are not affected by this method.
pub(crate) fn is_repair_codec(codec: &RTCRtpCodec) -> bool {
    let mime_type = codec.mime_type.to_lowercase();
    let subtype = mime_type
        .split_once('/')
        .map_or(mime_type.as_str(), |(_, subtype)| subtype);

    matches!(subtype, "rtx" | "ulpfec" | "red") || subtype.starts_with("flexfec")
}

/// The kind of a repair format: `"rtx"`, `"ulpfec"`, `"red"` or `"flexfec"` (any FlexFEC
/// draft); `""` for a media codec.
pub(crate) fn repair_family(codec: &RTCRtpCodec) -> &'static str {
    let mime_type = codec.mime_type.to_lowercase();
    let subtype = mime_type
        .split_once('/')
        .map_or(mime_type.as_str(), |(_, subtype)| subtype);
    match subtype {
        "rtx" => "rtx",
        "ulpfec" => "ulpfec",
        "red" => "red",
        s if s.starts_with("flexfec") => "flexfec",
        _ => "",
    }
}

/// Whether `mime_type` names FlexFEC draft-ietf-payload-flexible-fec-scheme-03
/// (`video/flexfec-03`), matched exactly.
///
/// RFC 8627's `video/flexfec` is a different wire format (its own header layout and masks), so a
/// substring match, which also took `video/flexfec`, handed RFC 8627 packets to the draft-03
/// coder.
pub(crate) fn is_flexfec03_mime_type(mime_type: &str) -> bool {
    mime_type.eq_ignore_ascii_case(MIME_TYPE_FLEX_FEC03)
}

/// Whether `mime_type` names RFC 8627 FlexFEC (`video/flexfec`), matched exactly: never
/// `video/flexfec-03`, which is the draft-03 coder's.
pub(crate) fn is_flexfec_mime_type(mime_type: &str) -> bool {
    mime_type.eq_ignore_ascii_case(MIME_TYPE_FLEX_FEC)
}

/// Whether `mime_type` names a FEC format the engine has a coder for: FlexFEC draft-03
/// (`video/flexfec-03`) or RFC 8627 (`video/flexfec`).
pub(crate) fn is_fec_mime_type(mime_type: &str) -> bool {
    is_flexfec03_mime_type(mime_type) || is_flexfec_mime_type(mime_type)
}

/// The FEC format a stream's repair flow uses: its payload type and what selects and
/// configures the coder (the interceptors read the MIME type and the `a=fmtp` line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FecFormat {
    pub(crate) payload_type: PayloadType,
    pub(crate) mime_type: String,
    pub(crate) sdp_fmtp_line: String,
}

/// The FEC format of `haystack`: FlexFEC draft-03 when it is there (what browsers send), else
/// RFC 8627 FlexFEC.
pub(crate) fn find_fec_format(haystack: &[RTCRtpCodecParameters]) -> Option<FecFormat> {
    haystack
        .iter()
        .find(|c| is_flexfec03_mime_type(&c.rtp_codec.mime_type))
        .or_else(|| {
            haystack
                .iter()
                .find(|c| is_flexfec_mime_type(&c.rtp_codec.mime_type))
        })
        .map(|c| FecFormat {
            payload_type: c.payload_type,
            mime_type: c.rtp_codec.mime_type.clone(),
            sdp_fmtp_line: c.rtp_codec.sdp_fmtp_line.clone(),
        })
}

/// The payload type of the FEC format in `haystack` ([`find_fec_format`]).
#[cfg(test)]
pub(crate) fn find_fec_payload_type(haystack: &[RTCRtpCodecParameters]) -> Option<PayloadType> {
    find_fec_format(haystack).map(|format| format.payload_type)
}

/// Computes the intersection of two RTCP feedback lists.
///
/// Returns feedback mechanisms that are supported by both lists,
/// matching on both type and parameter fields.
///
/// `trr-int` matches on the type alone and keeps the parameter of `a`: its number is each
/// endpoint's own minimum interval between regular RTCP packets (RFC 4585 section 4.2), not
/// a capability the two have to agree on, so an answer states its own.
///
/// # Parameters
///
/// * `a` - First feedback list
/// * `b` - Second feedback list
///
/// # Returns
///
/// Vector of common feedback mechanisms
pub(crate) fn rtcp_feedback_intersection(
    a: &[RTCPFeedback],
    b: &[RTCPFeedback],
) -> Vec<RTCPFeedback> {
    let mut out = vec![];
    for a_feedback in a {
        for b_feeback in b {
            if a_feedback.typ == b_feeback.typ
                && (a_feedback.parameter == b_feeback.parameter || a_feedback.typ == "trr-int")
            {
                out.push(a_feedback.clone());
                break;
            }
        }
    }

    // RFC 8888 section 6: of several congestion control feedback mechanisms "that offer
    // substantially the same semantics", the answer SHOULD include only one, and the same one
    // in a later answer to the same offer. RFC 8888 is kept and transport-wide congestion
    // control dropped, which is also what the interceptors run a stream on when a peer
    // answered both (`interceptor::negotiated_congestion_feedback`).
    let is_ccfb = |f: &RTCPFeedback| f.typ == TYPE_RTCP_FB_ACK && f.parameter == RTCP_FB_ACK_CCFB;
    if out.iter().any(is_ccfb) {
        out.retain(|f| f.typ != TYPE_RTCP_FB_TRANSPORT_CC);
    }

    out
}

#[cfg(test)]
mod congestion_feedback_answer_test {
    use super::*;

    fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
        RTCPFeedback {
            typ: typ.to_owned(),
            parameter: parameter.to_owned(),
        }
    }

    /// RFC 8888 section 6: offered RFC 8888 and transport-wide congestion control together,
    /// the answer keeps one of them, RFC 8888, and the same one every time.
    #[test]
    fn an_answer_keeps_one_congestion_feedback_mechanism() {
        let ours = [
            feedback("nack", ""),
            feedback("transport-cc", ""),
            feedback("ack", "ccfb"),
        ];
        let offered_both = [
            feedback("ack", "ccfb"),
            feedback("transport-cc", ""),
            feedback("nack", ""),
        ];
        let expected = vec![feedback("nack", ""), feedback("ack", "ccfb")];
        assert_eq!(expected, rtcp_feedback_intersection(&ours, &offered_both));
        assert_eq!(
            expected,
            rtcp_feedback_intersection(&ours, &offered_both),
            "a later answer to the same offer chooses the same mechanism"
        );
    }

    /// A peer that offers transport-wide congestion control alone, as browsers do, gets it.
    #[test]
    fn transport_cc_is_answered_when_rfc8888_was_not_offered() {
        let ours = [feedback("transport-cc", ""), feedback("ack", "ccfb")];
        let offered = [feedback("transport-cc", ""), feedback("nack", "")];
        assert_eq!(
            vec![feedback("transport-cc", "")],
            rtcp_feedback_intersection(&ours, &offered)
        );
    }
}

#[cfg(test)]
#[path = "rtp_codec_packetization_test.rs"]
mod rtp_codec_packetization_test;

#[cfg(test)]
#[path = "rtp_codec_flexfec_test.rs"]
mod rtp_codec_flexfec_test;

#[cfg(test)]
mod rtx_apt_test {
    use super::{
        RTCRtpCodec, RTCRtpCodecParameters, encoding_send_codec, find_rtx_payload_type,
        is_rtx_mime_type, parse_rtx_apt, parse_rtx_time,
    };

    fn media(mime_type: &str, payload_type: u8) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90000,
                ..Default::default()
            },
            payload_type,
        }
    }

    #[test]
    fn an_encoding_without_a_codec_is_sent_with_the_first_media_codec() {
        // Repair formats only accompany a media codec: one listed first is passed over.
        let negotiated = vec![
            rtx(97, "apt=96"),
            media("video/red", 63),
            media("video/ulpfec", 116),
            media("video/flexfec-03", 118),
            media("video/VP8", 96),
            media("video/H264", 102),
        ];
        let chosen = encoding_send_codec(&RTCRtpCodec::default(), &negotiated);
        assert_eq!(chosen.map(|c| c.payload_type), Some(96));
        assert_eq!(
            encoding_send_codec(&RTCRtpCodec::default(), &[rtx(97, "apt=96")]),
            None,
            "nothing to send with"
        );
    }

    #[test]
    fn an_encoding_naming_a_codec_is_sent_with_that_codec_or_not_at_all() {
        let negotiated = vec![media("video/VP8", 96), media("video/H264", 102)];
        let h264 = RTCRtpCodec {
            mime_type: "video/H264".to_owned(),
            clock_rate: 90000,
            ..Default::default()
        };
        assert_eq!(
            encoding_send_codec(&h264, &negotiated).map(|c| c.payload_type),
            Some(102)
        );
        let vp9 = RTCRtpCodec {
            mime_type: "video/VP9".to_owned(),
            clock_rate: 90000,
            ..Default::default()
        };
        assert_eq!(
            encoding_send_codec(&vp9, &negotiated),
            None,
            "a codec that was not negotiated is not replaced by another"
        );
    }

    fn rtx(payload_type: u8, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: "video/rtx".to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    #[test]
    fn find_rtx_payload_type_tolerates_extra_apt_params() {
        // A remote may append rtx-time to the apt fmtp (RFC 4588 §8.1); the
        // association must still succeed rather than dropping RTX from the answer.
        let haystack = vec![rtx(97, "apt=96;rtx-time=3000"), rtx(99, "apt=98")];
        assert_eq!(find_rtx_payload_type(96, &haystack), Some(97));
        assert_eq!(find_rtx_payload_type(98, &haystack), Some(99));
        assert_eq!(find_rtx_payload_type(100, &haystack), None);
    }

    #[test]
    fn parses_plain_apt() {
        assert_eq!(parse_rtx_apt("apt=96"), Some(96));
        assert_eq!(parse_rtx_apt("apt=127"), Some(127));
        assert_eq!(parse_rtx_apt("apt=0"), Some(0));
    }

    #[test]
    fn parses_apt_with_extra_params() {
        // RFC 4588 §8.1 allows an optional rtx-time parameter alongside apt.
        assert_eq!(parse_rtx_apt("apt=96;rtx-time=3000"), Some(96));
        assert_eq!(parse_rtx_apt("rtx-time=3000;apt=102"), Some(102));
        assert_eq!(parse_rtx_apt("apt=98 ; rtx-time=1000"), Some(98));
        let ms = std::time::Duration::from_millis;
        assert_eq!(parse_rtx_time("apt=96;rtx-time=3000"), Some(ms(3000)));
        assert_eq!(parse_rtx_time("rtx-time=250; apt=102"), Some(ms(250)));
        assert_eq!(parse_rtx_time("apt=96"), None);
        assert_eq!(parse_rtx_time("apt=96;rtx-time=soon"), None);
        assert!(is_rtx_mime_type("video/rtx") && is_rtx_mime_type("audio/RTX"));
        assert!(!is_rtx_mime_type("video/VP8"));
    }

    #[test]
    fn returns_none_without_apt() {
        assert_eq!(parse_rtx_apt(""), None);
        assert_eq!(parse_rtx_apt("profile-id=0"), None);
        assert_eq!(parse_rtx_apt("apt="), None);
        assert_eq!(parse_rtx_apt("apt=notanumber"), None);
        // Out of the u8 payload-type range.
        assert_eq!(parse_rtx_apt("apt=300"), None);
    }
}
