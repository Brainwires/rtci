use crate::peer_connection::configuration::UNSPECIFIED_STR;
use crate::peer_connection::configuration::media_engine::*;
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::{
    RTCP_FB_ACK_CCFB, RTCPFeedback, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_CCM, TYPE_RTCP_FB_TRANSPORT_CC,
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
            // may be sent at all; an absent parameter means mode 0, mode 2 is interleaved
            // (section 6.4), and a value above 2 is no mode (section 8.1).
            Ok(Box::new(
                rtp::codec::h264::H264Payloader::try_with_packetization_mode(
                    h264_packetization_mode(&self.sdp_fmtp_line),
                )?,
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
        } else if mime_type == MIME_TYPE_CN.to_lowercase() {
            Ok(Box::<rtp::codec::comfort_noise::ComfortNoisePayloader>::default())
        } else if mime_type == MIME_TYPE_AV1.to_lowercase() {
            Ok(Box::<rtp::codec::av1::Av1Payloader>::default())
        } else if mime_type == MIME_TYPE_SMPTE336M.to_lowercase() {
            Ok(Box::<rtp::codec::smpte336m::Smpte336mPayloader>::default())
        } else {
            Err(Error::ErrNoPayloaderForCodec)
        }
    }

    /// Creates an H.264 depacketizer for a stream received with this codec, configured from
    /// the sender's stream properties in its fmtp line: with `packetization-mode=2` NAL units
    /// leave in decoding order through a de-interleaving buffer sized by
    /// `sprop-interleaving-depth` and `sprop-max-don-diff` (RFC 6184 sections 7.2.2, 8.1).
    ///
    /// Use it on a remote track's codec: its fmtp line is the one the sender described.
    ///
    /// # Errors
    ///
    /// `Error::ErrNoPayloaderForCodec` for a codec other than H.264; an error for a
    /// `packetization-mode` other than 0, 1 or 2.
    pub fn h264_depacketizer(&self) -> Result<rtp::codec::h264::H264Packet> {
        if !self.mime_type.eq_ignore_ascii_case(MIME_TYPE_H264) {
            return Err(Error::ErrNoPayloaderForCodec);
        }
        let packet = rtp::codec::h264::H264Packet::default();
        match h264_packetization_mode(&self.sdp_fmtp_line) {
            0 | 1 => Ok(packet),
            2 => Ok(
                packet.with_deinterleaving(rtp::codec::h264::H264DeinterleavingBuffer::new(
                    fmtp_number(&self.sdp_fmtp_line, "sprop-interleaving-depth").unwrap_or(0),
                    fmtp_number(&self.sdp_fmtp_line, "sprop-max-don-diff"),
                )),
            ),
            other => Err(Error::Other(format!(
                "H.264 packetization-mode is 0, 1 or 2, not {other}"
            ))),
        }
    }

    /// Creates an H.265 depacketizer for a stream received with this codec, configured from
    /// the sender's stream properties in its fmtp line: with `sprop-max-don-diff` above 0
    /// the DONL and DOND fields are read and NAL units leave in decoding order through a
    /// de-packetization buffer of `sprop-depack-buf-nalus` (RFC 7798 sections 6, 7.1).
    ///
    /// # Errors
    ///
    /// `Error::ErrNoPayloaderForCodec` for a codec other than H.265; an error for a `tx-mode`
    /// other than SRST, which the depacketizer does not do (RFC 7798 section 7.1: "If the
    /// value is equal to "MRST", MRST MUST be in use").
    pub fn h265_depacketizer(&self) -> Result<rtp::codec::h265::H265Packet> {
        if !self.mime_type.eq_ignore_ascii_case(MIME_TYPE_HEVC) {
            return Err(Error::ErrNoPayloaderForCodec);
        }
        let tx_mode = fmtp_value(&self.sdp_fmtp_line, "tx-mode");
        if tx_mode.is_some_and(|mode| !mode.eq_ignore_ascii_case("SRST")) {
            return Err(Error::Other(format!(
                "H.265 tx-mode {} is not supported, only SRST",
                tx_mode.unwrap_or_default()
            )));
        }
        let mut packet = rtp::codec::h265::H265Packet::default();
        let max_don_diff = fmtp_number(&self.sdp_fmtp_line, "sprop-max-don-diff").unwrap_or(0);
        if max_don_diff > 0 {
            packet.with_depacketization_buffer(rtp::codec::h265::H265DepacketizationBuffer::new(
                max_don_diff,
                fmtp_number(&self.sdp_fmtp_line, "sprop-depack-buf-nalus").unwrap_or(0),
            ));
        }
        Ok(packet)
    }

    /// The out-of-band parameter sets of the sender's stream, in the order the fmtp line
    /// gives them: H.264 `sprop-parameter-sets` (RFC 6184 section 8.1, base64 NAL units
    /// separated by commas), H.265 `sprop-vps`, `sprop-sps`, `sprop-pps` and `sprop-sei`
    /// (RFC 7798 section 7.1). A decoder takes them before the first NAL unit of the stream
    /// (RFC 6184 section 8.2.2, RFC 7798 section 7.2.2). Empty for another codec or a line
    /// without them.
    ///
    /// # Errors
    ///
    /// A value that is not base64.
    pub fn sprop_parameter_sets(&self) -> Result<Vec<bytes::Bytes>> {
        use base64::Engine as _;
        let keys: &[&str] = if self.mime_type.eq_ignore_ascii_case(MIME_TYPE_H264) {
            &["sprop-parameter-sets"]
        } else if self.mime_type.eq_ignore_ascii_case(MIME_TYPE_HEVC) {
            &["sprop-vps", "sprop-sps", "sprop-pps", "sprop-sei"]
        } else {
            &[]
        };
        let mut sets = vec![];
        for key in keys {
            let Some(value) = fmtp_value(&self.sdp_fmtp_line, key) else {
                continue;
            };
            for set in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let nal_unit = base64::engine::general_purpose::STANDARD
                    .decode(set)
                    .map_err(|e| Error::Other(format!("{key}: {e}")))?;
                sets.push(bytes::Bytes::from(nal_unit));
            }
        }
        Ok(sets)
    }
}

/// The value of an fmtp parameter, trimmed; parameter names compare without regard to case.
fn fmtp_value<'a>(sdp_fmtp_line: &'a str, key: &str) -> Option<&'a str> {
    sdp_fmtp_line
        .split(';')
        .filter_map(|parameter| parameter.trim().split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        .map(|(_, value)| value.trim())
}

fn fmtp_number<T: std::str::FromStr>(sdp_fmtp_line: &str, key: &str) -> Option<T> {
    fmtp_value(sdp_fmtp_line, key)?.parse().ok()
}

/// The `packetization-mode` an H.264 fmtp line names, 0 when it names none (RFC 6184 8.1).
pub(crate) fn h264_packetization_mode(sdp_fmtp_line: &str) -> u8 {
    fmtp_number::<u32>(sdp_fmtp_line, "packetization-mode")
        .map_or(0, |mode| u8::try_from(mode).unwrap_or(u8::MAX))
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
    // A format is its encoding name and its clock rate (RFC 8866 section 6.6, `a=rtpmap`):
    // `telephone-event/8000` and `telephone-event/48000` are two formats. A needle that
    // states no clock rate (an encoding that leaves its codec to negotiation) matches any.
    // So are its encoding parameters, the channel count of an audio format (`opus/48000/2`;
    // RFC 7587 section 7: Opus "MUST" be `opus/48000/2`): two formats that state different
    // counts are different formats. One that states none matches any.
    let same_clock_rate = |c: &RTCRtpCodecParameters| {
        (needle_rtp_codec.clock_rate == 0
            || c.rtp_codec.clock_rate == 0
            || c.rtp_codec.clock_rate == needle_rtp_codec.clock_rate)
            && (needle_rtp_codec.channels == 0
                || c.rtp_codec.channels == 0
                || c.rtp_codec.channels == needle_rtp_codec.channels)
    };

    // First attempt to match on mime_type + sdpfmtp_line
    for c in haystack.iter().filter(|c| same_clock_rate(c)) {
        let cfmpt = fmtp::parse(&c.rtp_codec.mime_type, &c.rtp_codec.sdp_fmtp_line);
        if needle_fmtp.match_fmtp(&*cfmpt) {
            return (c.clone(), CodecMatch::Exact);
        }
    }

    // Fallback to just mime_type
    for c in haystack.iter().filter(|c| same_clock_rate(c)) {
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

/// W3C webrtc 5.4 "codec dictionary match": whether two codec dictionaries name the same
/// codec. The MIME types are equal without regard to case, the clock rates equal, the
/// channels both absent (0) or equal, and the `sdpFmtpLine`s both absent (empty) or
/// matching: compared by the format's own rules where it has key-value parameters
/// (`fmtp::match_fmtp`: H.264 profile and packetization mode, and so on) and as strings
/// otherwise.
pub(crate) fn codec_dictionary_match(first: &RTCRtpCodec, second: &RTCRtpCodec) -> bool {
    if !first.mime_type.eq_ignore_ascii_case(&second.mime_type)
        || first.clock_rate != second.clock_rate
        || first.channels != second.channels
    {
        return false;
    }
    let (first_fmtp, second_fmtp) = (first.sdp_fmtp_line.trim(), second.sdp_fmtp_line.trim());
    if first_fmtp.is_empty() != second_fmtp.is_empty() {
        return false;
    }
    if first_fmtp.is_empty() {
        return true;
    }
    if !first_fmtp.contains('=') || !second_fmtp.contains('=') {
        return first_fmtp == second_fmtp;
    }
    fmtp::parse(&first.mime_type, first_fmtp)
        .match_fmtp(&*fmtp::parse(&second.mime_type, second_fmtp))
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
/// `ccm tmmbr` of both lists, whatever their `smaxpr` (RFC 5104 section 7.1: "tmmbr
/// smaxpr=<n>", the session maximum packet rate). Section 7.2: "the highest value from offer
/// and answer SHALL be used. If the session maximum packet rate parameter is not present in an
/// offer, it SHALL NOT be included by the answerer": `b` is the remote side's list, and
/// without its `smaxpr` the result has none. `None` when the two are not both `ccm tmmbr`.
fn tmmbr_intersection(a: &RTCPFeedback, b: &RTCPFeedback) -> Option<RTCPFeedback> {
    let smaxpr = |f: &RTCPFeedback| -> Option<Option<u64>> {
        if f.typ != TYPE_RTCP_FB_CCM {
            return None;
        }
        let mut tokens = f.parameter.split_whitespace();
        if tokens.next() != Some("tmmbr") {
            return None;
        }
        Some(tokens.find_map(|t| t.strip_prefix("smaxpr=")?.parse().ok()))
    };
    let (ours, theirs) = (smaxpr(a)?, smaxpr(b)?);
    Some(RTCPFeedback {
        typ: TYPE_RTCP_FB_CCM.to_owned(),
        parameter: match theirs {
            Some(theirs) => format!("tmmbr smaxpr={}", ours.unwrap_or(0).max(theirs)),
            None => "tmmbr".to_owned(),
        },
    })
}

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
            // Receiver reference times, from an `a=rtcp-fb ... rrtr` line or from
            // `a=rtcp-xr:rcvr-rtt` (RFC 3611 section 5.1): the remote side's form is kept, so
            // that an answer repeats the form the offer used.
            if a_feedback.typ == interceptor::RTCP_FB_RRTR && b_feeback.typ == a_feedback.typ {
                out.push(b_feeback.clone());
                break;
            }
            if let Some(tmmbr) = tmmbr_intersection(a_feedback, b_feeback) {
                out.push(tmmbr);
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
