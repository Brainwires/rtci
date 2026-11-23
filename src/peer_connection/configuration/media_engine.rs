//! Media engine configuration for codecs and RTP extensions.
//!
//! The media engine manages codec registration, RTP header extensions, and media
//! capabilities negotiation for peer connections. It defines what codecs and features
//! are available for encoding/decoding media streams.
//!
//! # Overview
//!
//! - **Codec Registration** - Define supported audio/video codecs
//! - **Header Extensions** - Configure RTP header extensions
//! - **Feedback Mechanisms** - Register RTCP feedback types
//! - **Negotiation** - Codec and extension negotiation with remote peers
//!
//! # Examples
//!
//! ## Using Default Codecs
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register standard WebRTC codecs
//! media_engine.register_default_codecs()?;
//! // Now supports: Opus, G722, PCMU, PCMA, VP8, VP9, H264, AV1
//! # Ok(())
//! # }
//! ```
//!
//! ## Registering Custom Codec
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS};
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register Opus with custom parameters
//! let opus_codec = RTCRtpCodecParameters {
//!     rtp_codec: RTCRtpCodec {
//!         mime_type: MIME_TYPE_OPUS.to_owned(),
//!         clock_rate: 48000,
//!         channels: 2,
//!         sdp_fmtp_line: "minptime=10;useinbandfec=1;stereo=1".to_owned(),
//!         rtcp_feedback: vec![],
//!     },
//!     payload_type: 111,
//!     ..Default::default()
//! };
//!
//! media_engine.register_codec(opus_codec, RtpCodecKind::Audio)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Registering RTP Header Extension
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//! use rtc::rtp_transceiver::rtp_sender::{RtpCodecKind, RTCRtpHeaderExtensionCapability};
//! use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register audio level extension
//! media_engine.register_header_extension(
//!     RTCRtpHeaderExtensionCapability {
//!         uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
//!     },
//!     RtpCodecKind::Audio,
//!     Some(RTCRtpTransceiverDirection::Sendrecv),
//! )?;
//! # Ok(())
//! # }
//! ```

/// Whether a codec's fmtp parameters are part of what the format is, so that a format with
/// other parameters is another format, not a variant to fall back to: H.264
/// (`profile-level-id`, `packetization-mode`; RFC 6184 section 8.2.2), VP9 (`profile-id`;
/// RFC 9628 section 6), AV1 (`profile`; AV1 RTP section 7.2) and H.265 (`profile-space`,
/// `profile-id`, `tier-flag`, `interop-constraints`, `profile-compatibility-indicator`,
/// `tx-mode`; RFC 7798 section 7.2.2).
pub(crate) fn has_symmetric_configuration(codec: &RTCRtpCodec) -> bool {
    [MIME_TYPE_H264, MIME_TYPE_VP9, MIME_TYPE_AV1, MIME_TYPE_HEVC]
        .iter()
        .any(|mime_type| codec.mime_type.eq_ignore_ascii_case(mime_type))
}

/// The fmtp line of an H.264 answer: this endpoint's parameters (`local`), with the offer's
/// profile and the level RFC 6184 section 8.2.2 allows: this endpoint's own when both sides
/// say `level-asymmetry-allowed=1`, else the lower of the two.
fn h264_answer_fmtp(local: &str, offered: &str) -> String {
    let parameter = |line: &str, key: &str| -> Option<String> {
        line.split(';').find_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case(key)
                .then(|| v.trim().to_owned())
        })
    };
    let asymmetric =
        |line: &str| parameter(line, "level-asymmetry-allowed").as_deref() == Some("1");
    let (Some(local_id), Some(offered_id)) = (
        parameter(local, "profile-level-id").filter(|id| id.len() == 6 && id.is_ascii()),
        parameter(offered, "profile-level-id").filter(|id| id.len() == 6 && id.is_ascii()),
    ) else {
        return local.to_owned();
    };
    let level = |id: &str| u8::from_str_radix(&id[4..], 16).ok();
    let (Some(local_level), Some(offered_level)) = (level(&local_id), level(&offered_id)) else {
        return local.to_owned();
    };
    let answered_level = if asymmetric(local) && asymmetric(offered) {
        local_level
    } else {
        local_level.min(offered_level)
    };
    let answered_id = format!("{}{answered_level:02x}", &offered_id[..4]);
    local
        .split(';')
        .map(|p| match p.trim().split_once('=') {
            Some((k, _)) if k.trim().eq_ignore_ascii_case("profile-level-id") => {
                format!("{}={answered_id}", k.trim())
            }
            _ => p.trim().to_owned(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// The fmtp line of an H.265 answer: this endpoint's parameters (`local`) with a `level-id`
/// no higher than the offer's (RFC 7798 section 7.2.2: "the value of level-id is changeable
/// as long as the highest level indicated by the answer is not higher than that indicated by
/// the offer"); an absent `level-id` is 93 (section 7.1).
fn h265_answer_fmtp(local: &str, offered: &str) -> String {
    let level = |line: &str| -> Option<u8> {
        let fmtp = crate::rtp_transceiver::fmtp::parse(MIME_TYPE_HEVC, line);
        fmtp.as_any()
            .downcast_ref::<crate::rtp_transceiver::fmtp::h265::H265Fmtp>()?
            .level_id()
    };
    let (Some(local_level), Some(offered_level)) = (level(local), level(offered)) else {
        return local.to_owned();
    };
    if local_level <= offered_level {
        return local.to_owned();
    }
    let mut written = false;
    let mut parameters: Vec<String> = local
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, _)) if k.trim().eq_ignore_ascii_case("level-id") => {
                written = true;
                format!("{}={offered_level}", k.trim())
            }
            _ => p.to_owned(),
        })
        .collect();
    if !written {
        parameters.insert(0, format!("level-id={offered_level}"));
    }
    parameters.join(";")
}

#[cfg(test)]
mod h264_high_profile_test;
#[cfg(test)]
mod media_engine_test;
#[cfg(test)]
mod multi_codec_test;

use crate::peer_connection::sdp::{
    ATTR_KEY_SFRAME, ENCRYPT_URI, MediaDescriptionExt, SectionExtension,
    codecs_from_media_description, is_unknown_application_media,
    rtp_extensions_from_media_description,
};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::fmtp;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RTCRtpCodec, RtpCodecKind, codec_parameters_fuzzy_search, is_flexfec_mime_type,
    is_repair_codec, parse_rtx_apt, repair_family, rtcp_feedback_intersection,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::{
    RTCRtpHeaderExtensionCapability, RTCRtpHeaderExtensionEncryption,
};
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;
use crate::rtp_transceiver::{
    PayloadType,
    rtp_sender::rtcp_parameters::{RTCPFeedback, RTCRtcpParameters},
};
use sdp::MediaDescription;
use sdp::description::session::SessionDescription;
use shared::error::{Error, Result};
use std::collections::HashMap;
use unicase::UniCase;

/// H.264 video codec MIME type.
///
/// Used for baseline, main, and high profile H.264 video encoding.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_H264: &str = "video/H264";

/// H.265/HEVC video codec MIME type.
///
/// Used for High Efficiency Video Coding (HEVC/H.265) video encoding.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_HEVC: &str = "video/H265";

/// Opus audio codec MIME type.
///
/// Modern, versatile audio codec with excellent quality and low latency.
/// Recommended for most WebRTC applications.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_OPUS: &str = "audio/opus";

/// VP8 video codec MIME type.
///
/// Open-source video codec, widely supported across all browsers.
/// Good fallback option for video conferencing.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_VP8: &str = "video/VP8";

/// VP9 video codec MIME type.
///
/// Successor to VP8 with better compression efficiency.
/// Supported by modern browsers.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_VP9: &str = "video/VP9";

/// AV1 video codec MIME type.
///
/// Next-generation open video codec with excellent compression.
/// Increasing browser support.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_AV1: &str = "video/AV1";

/// G.722 audio codec MIME type.
///
/// Wideband audio codec (50-7000 Hz).
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_G722: &str = "audio/G722";

/// PCMU (G.711 μ-law) audio codec MIME type.
///
/// Standard telephony codec, primarily used in North America.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_PCMU: &str = "audio/PCMU";

/// PCMA (G.711 A-law) audio codec MIME type.
///
/// Standard telephony codec, primarily used in Europe.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_PCMA: &str = "audio/PCMA";

/// RTX (Retransmission) MIME type.
///
/// Used for RTP retransmission to improve reliability.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_RTX: &str = "video/rtx";

/// FlexFEC forward error correction MIME type, as published: RFC 8627.
///
/// Its coder is `interceptor::FlexFecSendBuilder` / `interceptor::FlexFecReceiveBuilder`
/// (opt-in). The payload format is not compatible with [`MIME_TYPE_FLEX_FEC03`], and each name
/// selects its own coder. Register it with its required `repair-window` parameter
/// (`interceptor::FlexFecParameters::to_fmtp`).
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_FLEX_FEC: &str = "video/flexfec";

/// FlexFEC-03 forward error correction MIME type: draft-ietf-payload-flexible-fec-scheme-03,
/// the FlexFEC browsers send. Its coder is `interceptor::FlexFec03SendBuilder` /
/// `interceptor::FlexFec03ReceiveBuilder` (opt-in).
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_FLEX_FEC03: &str = "video/flexfec-03";

/// ULP FEC (Uneven Level Protection Forward Error Correction) MIME type.
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_ULP_FEC: &str = "video/ulpfec";

/// Telephone-event MIME type for DTMF tones.
///
/// Used for transmitting DTMF (touch-tone) signals.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_TELEPHONE_EVENT: &str = "audio/telephone-event";

/// Comfort noise MIME type (RFC 3389).
///
/// Used for the noise parameters a sender of G.711 (or another codec without comfort noise of
/// its own) sends during silence; static payload type 13 at 8000 Hz.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_CN: &str = "audio/CN";

/// SMPTE ST 336 (KLV) metadata MIME type
///
/// Used for transmitting KLV (key-length-value) metadata.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_SMPTE336M: &str = "application/smpte336m";

/// The ids this endpoint gives the header extensions it offers, in the order it takes them:
/// the one-byte ids 1 to 14 first (RFC 8285 section 4.1.2: "the one-byte header form is
/// preferred"), then 16 to 255, which need the two-byte form (section 4.3; 15 is reserved in
/// the one-byte form and not used, section 5). An offer only takes an id above 14 when the
/// one-byte ids are all taken, so a stream is two-byte only when it has to be.
pub(crate) fn local_extension_ids() -> impl Iterator<Item = u16> {
    (1..=14).chain(16..=255)
}

/// The most header extensions that can be registered: one per id of
/// [`local_extension_ids`].
const MAX_HEADER_EXTENSIONS: usize = 254;

#[derive(Default, Clone)]
pub(crate) struct MediaEngineHeaderExtension {
    pub(crate) uri: String,
    pub(crate) is_audio: bool,
    pub(crate) is_video: bool,
    pub(crate) allowed_direction: Option<RTCRtpTransceiverDirection>,
    /// A registered extension: how offers signal it (RFC 6904).
    pub(crate) encryption: RTCRtpHeaderExtensionEncryption,
    /// A negotiated mapping: whether it is the encrypted form (`a=extmap:<id>
    /// urn:ietf:params:rtp-hdrext:encrypt <uri>`, RFC 6904 section 4).
    pub(crate) encrypted: bool,
    /// A negotiated mapping: the extension attributes the peer's description gave it (for
    /// the client-to-mixer audio level, `vad=on` or `vad=off`, RFC 6464 section 4).
    pub(crate) attributes: Option<String>,
}

impl MediaEngineHeaderExtension {
    pub fn is_matching_direction(&self, dir: RTCRtpTransceiverDirection) -> bool {
        if let Some(allowed_direction) = self.allowed_direction {
            use RTCRtpTransceiverDirection::*;
            allowed_direction == Inactive && dir == Inactive
                || allowed_direction.has_send() && dir.has_send()
                || allowed_direction.has_recv() && dir.has_recv()
        } else {
            // None means all directions matches.
            true
        }
    }
}

/// Media engine managing codecs and RTP capabilities for peer connections.
///
/// MediaEngine defines which audio/video codecs are supported and how they're
/// configured. Each peer connection should have its own MediaEngine instance
/// as codec negotiation state is tracked per-connection.
///
/// # Thread Safety
///
/// ⚠️ MediaEngine is **not** safe for concurrent use during configuration.
/// Configure it completely before using in a peer connection.
///
/// # Examples
///
/// ## Default Configuration
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// media_engine.register_default_codecs()?;
///
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## Custom Codec Configuration
///
/// ```
/// use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8};
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
///
/// // Register only specific codecs for minimal overhead
/// media_engine.register_codec(
///     RTCRtpCodecParameters {
///         rtp_codec: RTCRtpCodec {
///             mime_type: MIME_TYPE_OPUS.to_owned(),
///             clock_rate: 48000,
///             channels: 2,
///             sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
///             rtcp_feedback: vec![],
///         },
///         payload_type: 111,
///         ..Default::default()
///     },
///     RtpCodecKind::Audio,
/// )?;
///
/// media_engine.register_codec(
///     RTCRtpCodecParameters {
///         rtp_codec: RTCRtpCodec {
///             mime_type: MIME_TYPE_VP8.to_owned(),
///             clock_rate: 90000,
///             channels: 0,
///             sdp_fmtp_line: "".to_owned(),
///             rtcp_feedback: vec![],
///         },
///         payload_type: 96,
///         ..Default::default()
///     },
///     RtpCodecKind::Video,
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Default, Clone)]
pub struct MediaEngine {
    // If we have attempted to negotiate a codec type yet.
    pub(crate) negotiated_video: bool,
    pub(crate) negotiated_audio: bool,
    pub(crate) negotiated_application: bool,
    pub(crate) negotiate_multi_codecs: bool,

    pub(crate) video_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) audio_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) application_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) negotiated_video_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) negotiated_audio_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) negotiated_application_codecs: Vec<RTCRtpCodecParameters>,
    /// The payload types of the negotiated lists that number an SFrame section's formats
    /// (`a=sframe`, draft-ietf-avtcore-rtp-sframe-03 section 6): the SFrame sections of a
    /// connection number their formats apart from the plain ones ("payload types for media
    /// encodings that are relevant for SFrame MUST NOT be reused between the two media
    /// sections" of one BUNDLE group), so the lists hold a format once per numbering.
    pub(crate) sframe_payload_types: Vec<PayloadType>,

    pub(crate) header_extensions: Vec<MediaEngineHeaderExtension>,
    pub(crate) negotiated_header_extensions: HashMap<u16, MediaEngineHeaderExtension>,

    /// Whether RTP retransmission (RFC 4588) is negotiated beside RFC 8627 FlexFEC.
    /// See [`MediaEngine::set_flexfec_with_retransmission`].
    pub(crate) flexfec_with_retransmission: bool,
    /// See [`MediaEngine::set_vp9_receiver_limits`].
    pub(crate) vp9_receiver_limits: bool,

    /// The RTCP CNAME of the connection this media engine belongs to (RFC 7022), set when the
    /// connection is built: what `a=ssrc:<ssrc> cname:` lines and `RTCRtcpParameters::cname`
    /// say. Empty in a media engine no connection has taken yet.
    pub(crate) rtcp_cname: String,

    /// The packet times this endpoint states in its audio sections; see
    /// [`MediaEngine::set_audio_packet_time`].
    pub(crate) audio_packet_time: RTCPacketTime,
}

/// The packet times of a media section, in milliseconds: `a=ptime`, the length of media one
/// packet should carry, and `a=maxptime`, the most it may carry (RFC 8866 sections 6.4, 6.5).
/// They are what the endpoint that states them would like to receive (RFC 3264 section 5);
/// for Opus they are its `ptime` and `maxptime` parameters (RFC 7587 section 7).
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct RTCPacketTime {
    /// `a=ptime`; `None` when not stated.
    pub ptime: Option<u32>,
    /// `a=maxptime`; `None` when not stated.
    pub maxptime: Option<u32>,
}

/// Whether an RTP payload type cannot be told from an RTCP packet type once RTP and RTCP share
/// a port (RFC 5761 section 4): with the marker bit set, payload types 64 to 95 give the second
/// octet the values 192 to 223, the RTCP packet types.
pub(crate) fn is_rtcp_conflicting_payload_type(payload_type: PayloadType) -> bool {
    (64..=95).contains(&payload_type)
}

/// The receiver capabilities the default VP9 formats state with
/// [`MediaEngine::set_vp9_receiver_limits`] (RFC 9628 section 6: max-fr in frames per second,
/// max-fs in macroblocks). The engine does not decode, so these are what a typical decoder
/// takes, the values Firefox offers: 60 frames a second, 12,288 macroblocks (up to 4096 x
/// 3072). An application whose decoder takes less registers its own VP9 codecs.
pub const VP9_RECEIVER_LIMITS: &str = "max-fr=60;max-fs=12288";

/// The fmtp line of a default VP9 format of `profile_id`, with or without
/// [`VP9_RECEIVER_LIMITS`].
fn default_vp9_fmtp(profile_id: u8, receiver_limits: bool) -> String {
    if receiver_limits {
        format!("{VP9_RECEIVER_LIMITS};profile-id={profile_id}")
    } else {
        format!("profile-id={profile_id}")
    }
}

impl MediaEngine {
    /// Registers standard WebRTC codecs for audio and video.
    ///
    /// This convenience method registers all codecs commonly supported by WebRTC implementations:
    ///
    /// **Audio Codecs:**
    /// - Opus (48kHz, stereo, with FEC)
    /// - G.722 (8kHz wideband)
    /// - PCMU/G.711 μ-law (8kHz)
    /// - PCMA/G.711 A-law (8kHz)
    /// - telephone-event at 48 kHz and 8 kHz, events 0-15 (DTMF, RFC 4733)
    ///
    /// **Video Codecs:**
    /// - VP8 with RTCP feedback
    /// - VP9 (multiple profiles) with RTCP feedback
    /// - H.264 (multiple profiles/packetization modes) with RTCP feedback
    /// - AV1 with RTCP feedback  
    /// - H.265/HEVC with RTCP feedback
    /// - ULP FEC (forward error correction)
    ///
    /// # Thread Safety
    ///
    /// ⚠️ Not safe for concurrent use. Call before using MediaEngine in a peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// media_engine.register_default_codecs()?;
    /// // Media engine now supports all standard WebRTC codecs
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    ///
    /// Returns an error if one of the default codecs cannot be registered; with an unmodified
    /// `MediaEngine` this does not happen.
    pub fn register_default_codecs(&mut self) -> Result<()> {
        // Default Audio Codecs
        for codec in [
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_G722.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 9,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_PCMU.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 0,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_PCMA.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 8,
            },
            // Comfort noise (RFC 3389), which RFC 7874 section 3 has every WebRTC endpoint
            // support "for streams encoded with G.711 or any other supported codec that does
            // not provide its own CN": at 8000 Hz, the clock of G.711 and of G.722's RTP
            // timestamps, on its static payload type (RFC 3389 section 4: "Other clock rates
            // MUST use dynamic payload types", RFC 3551 table 4). None for Opus, which has its
            // own (RFC 7874: RFC 3389 CN with Opus is "NOT RECOMMENDED").
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_CN.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 13,
            },
            // DTMF as named telephone events (RFC 4733), which RFC 7874 section 3 has every
            // WebRTC endpoint implement, with events 0 to 15, the DTMF digits. One format per
            // clock rate of the audio codecs above (the event stream runs on the clock of the
            // audio it goes with), each stating the events it takes (RFC 4733 section 2.4.1:
            // `a=fmtp:<pt> 0-15`). The application sends and reads the event packets
            // (`rtp::codec::telephone_event`).
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_TELEPHONE_EVENT.to_owned(),
                    clock_rate: 48000,
                    channels: 0,
                    sdp_fmtp_line: "0-15".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 112,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_TELEPHONE_EVENT.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "0-15".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 115,
            },
        ] {
            self.register_codec(codec, RtpCodecKind::Audio)?;
        }

        let video_rtcp_feedback = vec![
            RTCPFeedback {
                typ: "goog-remb".to_owned(),
                parameter: "".to_owned(),
            },
            RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "fir".to_owned(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "".to_owned(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            },
        ];

        // RFC 4588 retransmission (RTX) codec. The `apt` (associated payload
        // type) fmtp parameter points at the primary codec this RTX stream
        // repairs. Browsers offer an RTX codec for every video codec by default
        // and drop RTX negotiation for any primary we do not pair one with, so
        // register one RTX codec per primary video codec. A FEC codec (an application may
        // register ULPFEC or FlexFEC itself) is not a media codec and gets no RTX pairing.
        let rtx_codec = |payload_type: PayloadType, apt: PayloadType| RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_RTX.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: format!("apt={apt}"),
                rtcp_feedback: vec![],
            },
            payload_type,
        };

        for codec in vec![
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 96,
            },
            rtx_codec(97, 96),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP9.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    // RFC 9628 section 6 has a receiver state max-fr and max-fs; by default
                    // they are left out for WebKit's sake (see `set_vp9_receiver_limits`).
                    sdp_fmtp_line: default_vp9_fmtp(0, self.vp9_receiver_limits),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 98,
            },
            rtx_codec(99, 98),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP9.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: default_vp9_fmtp(1, self.vp9_receiver_limits),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 100,
            },
            rtx_codec(101, 100),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 102,
            },
            rtx_codec(103, 102),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 127,
            },
            rtx_codec(104, 127),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 125,
            },
            rtx_codec(105, 125),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 108,
            },
            rtx_codec(109, 108),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 123,
            },
            rtx_codec(124, 123),
            // H.264 High Profile, Level 4.0 (720p60 / 1080p30), as webrtc-rs 0.17 registers it.
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640028"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 118,
            },
            rtx_codec(110, 118),
            // H.264 High Profile, Level 4.1 (1080p60), as webrtc-rs 0.17 registers it.
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640029"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 119,
            },
            rtx_codec(113, 119),
            // H.264 High Profile, Level 4.2 (1080p64), as webrtc-rs 0.17 registers it.
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64002a"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 120,
            },
            rtx_codec(114, 120),
            // H.264 High Profile, Level 5.1 (4K30), as webrtc-rs 0.17 registers it.
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640033"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 121,
            },
            rtx_codec(122, 121),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_AV1.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    // The AV1 RTP payload format's SDP parameter is `profile` (AV1 RTP spec,
                    // section 7.2); `profile-id` is VP9's.
                    sdp_fmtp_line: "profile=0".to_owned(),
                    // Layer Refresh Request (`ccm lrr`), which the AV1 RTP payload format names
                    // for its scalable streams, besides the video feedback of every codec.
                    rtcp_feedback: video_rtcp_feedback
                        .iter()
                        .cloned()
                        .chain([RTCPFeedback {
                            typ: "ccm".to_owned(),
                            parameter: "lrr".to_owned(),
                        }])
                        .collect(),
                },
                payload_type: 41,
            },
            rtx_codec(106, 41),
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_HEVC.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    // Main profile, main tier, level 3.1, one RTP stream (RFC 7798 section
                    // 7.1): stated, so that another configuration is not matched by name
                    // (section 7.2.2), in the form browsers offer it.
                    sdp_fmtp_line: "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST".to_owned(),
                    rtcp_feedback: video_rtcp_feedback,
                },
                payload_type: 126,
            },
            rtx_codec(107, 126),
            // No ULPFEC (RFC 5109): nothing in this engine encodes or decodes it, so offering
            // it invited a peer to send repair packets that would be dropped. An application
            // with its own ULPFEC coder registers `MIME_TYPE_ULP_FEC` itself. See FORK.md.
        ] {
            self.register_codec(codec, RtpCodecKind::Video)?;
        }

        Ok(())
    }

    /// add_codec will append codec if it not exists
    fn add_codec(codecs: &mut Vec<RTCRtpCodecParameters>, codec: RTCRtpCodecParameters) {
        for c in codecs.iter() {
            if c.rtp_codec.mime_type == codec.rtp_codec.mime_type
                && c.payload_type == codec.payload_type
            {
                return;
            }
        }
        codecs.push(codec);
    }

    /// Registers a custom codec for use in this peer connection.
    ///
    /// Adds a codec to the list of supported codecs. During SDP negotiation, only
    /// codecs registered here will be offered/accepted.
    ///
    /// # Parameters
    ///
    /// * `codec` - The codec parameters including MIME type, clock rate, and payload type
    /// * `typ` - Whether this is an audio or video codec
    ///
    /// # Thread Safety
    ///
    /// ⚠️ Not safe for concurrent use. Register all codecs before using in a peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS};
    /// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    ///
    /// // Register Opus with custom fmtp parameters
    /// media_engine.register_codec(
    ///     RTCRtpCodecParameters {
    ///         rtp_codec: RTCRtpCodec {
    ///             mime_type: MIME_TYPE_OPUS.to_owned(),
    ///             clock_rate: 48000,
    ///             channels: 2,
    ///             sdp_fmtp_line: "minptime=10;useinbandfec=1;stereo=1".to_owned(),
    ///             rtcp_feedback: vec![],
    ///         },
    ///         payload_type: 111,
    ///         ..Default::default()
    ///     },
    ///     RtpCodecKind::Audio,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    ///
    /// Returns [`Error::ErrUnknownType`] if `typ` is not `Audio`, `Video` or `Application`,
    /// and [`Error::SdpInvalidValue`] for a payload type of 64 to 95: RFC 5761 section 4,
    /// "RTP payload types in the range 64-95 MUST NOT be used". With the marker bit set such
    /// a packet has the second octet of an RTCP packet (types 192 to 223), and this endpoint
    /// always multiplexes RTP and RTCP on one port.
    pub fn register_codec(
        &mut self,
        codec: RTCRtpCodecParameters,
        typ: RtpCodecKind,
    ) -> Result<()> {
        if is_rtcp_conflicting_payload_type(codec.payload_type) {
            return Err(Error::SdpInvalidValue(format!(
                "payload type {} of {}: 64 to 95 cannot be used with RTP/RTCP multiplexing \
                 (RFC 5761 section 4)",
                codec.payload_type, codec.rtp_codec.mime_type
            )));
        }
        // RFC 8627 section 5.1 (draft-03 section 5.1): `repair-window` is required. A FlexFEC
        // format registered without one is offered with the window its receiver uses when a
        // line has none (`interceptor::FLEXFEC_DEFAULT_REPAIR_WINDOW`, 10 s).
        let mut codec = codec;
        if crate::rtp_transceiver::rtp_sender::rtp_codec::is_fec_mime_type(
            &codec.rtp_codec.mime_type,
        ) && interceptor::FlexFecParameters::parse(&codec.rtp_codec.sdp_fmtp_line)
            .repair_window
            .is_none()
        {
            let window = interceptor::FlexFecParameters::with_repair_window(
                interceptor::FLEXFEC_DEFAULT_REPAIR_WINDOW,
            )
            .to_fmtp();
            let line = codec.rtp_codec.sdp_fmtp_line.trim();
            codec.rtp_codec.sdp_fmtp_line = if line.is_empty() {
                window
            } else {
                format!("{line};{window}")
            };
        }
        match typ {
            RtpCodecKind::Audio => {
                MediaEngine::add_codec(&mut self.audio_codecs, codec);
                Ok(())
            }
            RtpCodecKind::Video => {
                MediaEngine::add_codec(&mut self.video_codecs, codec);
                Ok(())
            }
            RtpCodecKind::Application => {
                MediaEngine::add_codec(&mut self.application_codecs, codec);
                Ok(())
            }
            _ => Err(Error::ErrUnknownType),
        }
    }

    /// Adds a header extension to the MediaEngine
    /// To determine the negotiated value use [`MediaEngine::get_header_extension_id`] after signaling is complete.
    ///
    /// The `allowed_direction` controls for which transceiver directions the extension matches. If
    /// set to `None` it matches all directions. The `SendRecv` direction would match all transceiver
    /// directions apart from `Inactive`. Inactive only matches inactive.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrRegisterHeaderExtensionInvalidDirection`] if `allowed_direction` is
    ///   `Unspecified`.
    /// - [`Error::ErrRegisterHeaderExtensionNoFreeID`] if 254 extensions are registered
    ///   already: one for each id RFC 8285 lets an RTP header carry (1 to 14 in the one-byte
    ///   form, 16 to 255 in the two-byte form). Offers take the one-byte ids first.
    /// - [`Error::TypeError`] for an audio level extension (RFC 6464, RFC 6465) registered for
    ///   a kind other than audio (RFC 6465 section 5: "They MUST NOT be advertised with other
    ///   media types"), and for `urn:ietf:params:rtp-hdrext:encrypt`, which is not an
    ///   extension of its own (RFC 6904 section 4; see
    ///   [`set_header_extension_encryption`](Self::set_header_extension_encryption)).
    pub fn register_header_extension(
        &mut self,
        extension: RTCRtpHeaderExtensionCapability,
        typ: RtpCodecKind,
        allowed_direction: Option<RTCRtpTransceiverDirection>,
    ) -> Result<()> {
        if let Some(direction) = &allowed_direction
            && (direction == &RTCRtpTransceiverDirection::Unspecified
                || direction == &RTCRtpTransceiverDirection::Inactive)
        {
            return Err(Error::ErrRegisterHeaderExtensionInvalidDirection);
        }
        if typ != RtpCodecKind::Audio
            && matches!(
                extension.uri.as_str(),
                ::sdp::extmap::AUDIO_LEVEL_URI | rtp::extension::CSRC_AUDIO_LEVEL_URI
            )
        {
            return Err(Error::TypeError(format!(
                "{} is defined for audio only (RFC 6464 section 4, RFC 6465 section 5)",
                extension.uri
            )));
        }
        if extension.uri == ENCRYPT_URI {
            return Err(Error::TypeError(format!(
                "{ENCRYPT_URI} encrypts another extension (RFC 6904 section 4): use \
                 MediaEngine::set_header_extension_encryption"
            )));
        }

        let ext = {
            match self
                .header_extensions
                .iter_mut()
                .find(|ext| ext.uri == extension.uri)
            {
                Some(ext) => ext,
                None => {
                    // We have registered too many extensions
                    if self.header_extensions.len() >= MAX_HEADER_EXTENSIONS {
                        return Err(Error::ErrRegisterHeaderExtensionNoFreeID);
                    }
                    self.header_extensions
                        .push(MediaEngineHeaderExtension::default());

                    // Unwrap is fine because we just pushed
                    self.header_extensions.last_mut().unwrap()
                }
            }
        };

        if typ == RtpCodecKind::Audio {
            ext.is_audio = true;
        } else if typ == RtpCodecKind::Video {
            ext.is_video = true;
        }

        ext.uri = extension.uri;
        ext.allowed_direction = allowed_direction;

        Ok(())
    }

    /// Sets how offers signal a registered header extension with respect to RFC 6904
    /// header extension encryption: in the clear (the default for an extension the
    /// application registers), encrypted, or both, with the peer choosing (RFC 6904 section
    /// 4.1 "best-effort encryption").
    ///
    /// The encrypted form is `a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`; once
    /// negotiated, the SRTP contexts encrypt and decrypt that element's payload (RFC 6904
    /// section 3) and its [`RTCRtpHeaderExtensionParameters::encrypted`] is true. Answering,
    /// the engine takes the encrypted form whenever the offer has it, whatever this says
    /// (section 4.1: answerers "SHOULD choose the encrypted form ... and mark the
    /// unencrypted form 'inactive'"). The default interceptors set
    /// [`BestEffort`](RTCRtpHeaderExtensionEncryption::BestEffort) for the audio level
    /// extensions (RFC 8834 sections 5.2.2 and 5.2.3: their encryption is RECOMMENDED);
    /// [`Clear`](RTCRtpHeaderExtensionEncryption::Clear) turns that off.
    ///
    /// # Errors
    ///
    /// [`Error::ErrUnknownType`] when `uri` is not a registered header extension.
    pub fn set_header_extension_encryption(
        &mut self,
        uri: &str,
        encryption: RTCRtpHeaderExtensionEncryption,
    ) -> Result<()> {
        let ext = self
            .header_extensions
            .iter_mut()
            .find(|ext| ext.uri == uri)
            .ok_or(Error::ErrUnknownType)?;
        ext.encryption = encryption;
        Ok(())
    }

    /// Adds a feedback mechanism to all already-registered codecs.
    ///
    /// Registering the same mechanism twice is a no-op the second time.
    pub fn register_feedback(&mut self, feedback: RTCPFeedback, typ: RtpCodecKind) {
        let codecs = match typ {
            RtpCodecKind::Video => &mut self.video_codecs,
            RtpCodecKind::Audio => &mut self.audio_codecs,
            _ => return,
        };

        for codec in codecs {
            // Matched on both fields: `nack` and `nack pli` are distinct mechanisms that share a
            // type, so comparing types alone would drop the second one.
            if !codec.rtp_codec.rtcp_feedback.contains(&feedback) {
                codec.rtp_codec.rtcp_feedback.push(feedback.clone());
            }
        }
    }

    /// Returns the negotiated id for a header extension.
    /// If the Header Extension isn't enabled ok will be false
    pub fn get_header_extension_id(
        &self,
        extension: RTCRtpHeaderExtensionCapability,
    ) -> (u16, bool, bool) {
        if self.negotiated_header_extensions.is_empty() {
            return (0, false, false);
        }

        for (id, h) in &self.negotiated_header_extensions {
            if extension.uri == h.uri {
                return (*id, h.is_audio, h.is_video);
            }
        }

        (0, false, false)
    }

    /// clone_to copies any user modifiable state of the MediaEngine
    /// all internal state is reset
    pub(crate) fn clone_to(&self) -> Self {
        MediaEngine {
            video_codecs: self.video_codecs.clone(),
            audio_codecs: self.audio_codecs.clone(),
            application_codecs: self.application_codecs.clone(),
            header_extensions: self.header_extensions.clone(),
            flexfec_with_retransmission: self.flexfec_with_retransmission,
            vp9_receiver_limits: self.vp9_receiver_limits,
            ..Default::default()
        }
    }

    /// Whether RTP retransmission (`rtx`, RFC 4588) stays negotiated in a video section that
    /// also negotiates RFC 8627 FlexFEC ([`MIME_TYPE_FLEX_FEC`]). `false` by default.
    ///
    /// RFC 8627 section 1.1.7: "If a peer supporting both FLEX FEC and other RTP
    /// retransmission methods (see RFC 4588) receives an Offer including both FLEX FEC and
    /// another RTP retransmission method, it MUST respond with an Answer containing only FLEX
    /// FEC." So when a remote description carries both and this engine has both registered,
    /// the retransmission formats are not negotiated and the answer has none; FlexFEC's own
    /// retransmission form (section 4.2.2.1, a repair packet with `R` set) replaces them.
    ///
    /// The rule is for the `flexfec` format of the RFC. [`MIME_TYPE_FLEX_FEC03`], the format
    /// browsers negotiate, comes from a draft that has no such rule and is always answered
    /// together with `rtx`, as libwebrtc does. `true` gives the RFC format the same lenient
    /// treatment.
    pub fn set_flexfec_with_retransmission(&mut self, allowed: bool) {
        self.flexfec_with_retransmission = allowed;
    }

    /// Whether the default VP9 formats state this endpoint's receiver limits,
    /// [`VP9_RECEIVER_LIMITS`] (`max-fr=60;max-fs=12288`), in their fmtp. `false` by default.
    ///
    /// RFC 9628 section 6: "If the implementation is willing to receive media, both
    /// parameters MUST be provided." That is the form with `true`. It is not the default
    /// because WebKit does not interoperate with it: in the repository's browser matrix
    /// (conformance train 5, round 1) a WebKit sender answered with the limits sent no VP9 at
    /// all ("reflect video VP9": no packet reached the engine), where the same answer without
    /// them works; Chromium and Firefox take either. Browsers themselves leave the
    /// parameters out (libwebrtc) or state them (Firefox).
    ///
    /// Applies to the default VP9 formats registered after it and to those already
    /// registered by [`register_default_codecs`](Self::register_default_codecs).
    pub fn set_vp9_receiver_limits(&mut self, stated: bool) {
        self.vp9_receiver_limits = stated;
        for codec in self.video_codecs.iter_mut() {
            if !codec
                .rtp_codec
                .mime_type
                .eq_ignore_ascii_case(MIME_TYPE_VP9)
            {
                continue;
            }
            for profile_id in [0, 1] {
                if codec.rtp_codec.sdp_fmtp_line == default_vp9_fmtp(profile_id, !stated) {
                    codec.rtp_codec.sdp_fmtp_line = default_vp9_fmtp(profile_id, stated);
                }
            }
        }
    }

    /// The packet times this endpoint states in each audio section it offers or answers, as
    /// `a=ptime` and `a=maxptime` (RFC 8866 sections 6.4, 6.5; RFC 7587 section 7 maps Opus's
    /// `ptime` and `maxptime` to them, and section 7.1 handles `maxptime` "in the same way as
    /// ptime": each side states what it wants to receive, RFC 3264 section 5). Neither is
    /// stated by default. What the remote side states is
    /// [`RTCRtpTransceiver::remote_packet_time`](crate::rtp_transceiver::RTCRtpTransceiver::remote_packet_time),
    /// which an application that packetizes audio follows.
    pub fn set_audio_packet_time(&mut self, packet_time: RTCPacketTime) {
        self.audio_packet_time = packet_time;
    }

    /// set_multi_codec_negotiation enables or disables the negotiation of multiple codecs.
    pub(crate) fn set_multi_codec_negotiation(&mut self, negotiate_multi_codecs: bool) {
        self.negotiate_multi_codecs = negotiate_multi_codecs;
    }

    /// multi_codec_negotiation returns the current state of the negotiation of multiple codecs.
    pub(crate) fn multi_codec_negotiation(&self) -> bool {
        self.negotiate_multi_codecs
    }

    pub(crate) fn get_codec_by_payload(
        &self,
        payload_type: PayloadType,
    ) -> Result<(RTCRtpCodecParameters, RtpCodecKind)> {
        if self.negotiated_video {
            for codec in &self.negotiated_video_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Video));
                }
            }
        }
        if self.negotiated_audio {
            for codec in &self.negotiated_audio_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Audio));
                }
            }
        }
        if self.negotiated_application {
            for codec in &self.negotiated_application_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Application));
                }
            }
        }
        if !self.negotiated_video {
            for codec in &self.video_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Video));
                }
            }
        }
        if !self.negotiated_audio {
            for codec in &self.audio_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Audio));
                }
            }
        }
        if !self.negotiated_application {
            for codec in &self.application_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Application));
                }
            }
        }

        Err(Error::ErrCodecNotFound)
    }

    /// Look up a codec and enable if it exists
    pub(crate) fn match_remote_codec(
        &self,
        remote_codec: &RTCRtpCodecParameters,
        typ: RtpCodecKind,
        exact_matches: &[RTCRtpCodecParameters],
        partial_matches: &[RTCRtpCodecParameters],
    ) -> Result<(RTCRtpCodecParameters, CodecMatch)> {
        let codecs = match typ {
            RtpCodecKind::Audio => &self.audio_codecs,
            RtpCodecKind::Video => &self.video_codecs,
            RtpCodecKind::Application => &self.application_codecs,
            // A media section of a kind this engine does not know has no codec to match; its
            // callers already skip such sections, so this is an error, not a panic.
            RtpCodecKind::Unspecified => return Err(Error::ErrCodecNotFound),
        };

        let remote_fmtp = fmtp::parse(
            &remote_codec.rtp_codec.mime_type,
            remote_codec.rtp_codec.sdp_fmtp_line.as_str(),
        );
        if let Some(apt) = remote_fmtp.parameter("apt") {
            let payload_type = apt.parse::<u8>()?;

            let mut apt_match = CodecMatch::None;
            let mut apt_codec = None;
            for codec in exact_matches {
                if codec.payload_type == payload_type {
                    apt_match = CodecMatch::Exact;
                    apt_codec = Some(codec);
                    break;
                }
            }

            if apt_match == CodecMatch::None {
                for codec in partial_matches {
                    if codec.payload_type == payload_type {
                        apt_match = CodecMatch::Partial;
                        apt_codec = Some(codec);
                        break;
                    }
                }
            }

            if apt_match == CodecMatch::None {
                return Ok((RTCRtpCodecParameters::default(), CodecMatch::None));
                // not an error, we just ignore this codec we don't support
            }

            // replace the apt value with the original codec's payload type
            let mut to_match_codec = remote_codec.clone();
            if let Some(apt_codec) = apt_codec {
                let (apt_matched, mt) = codec_parameters_fuzzy_search(&apt_codec.rtp_codec, codecs);
                if mt == apt_match {
                    to_match_codec.rtp_codec.sdp_fmtp_line =
                        to_match_codec.rtp_codec.sdp_fmtp_line.replacen(
                            &format!("apt={payload_type}"),
                            &format!("apt={}", apt_matched.payload_type),
                            1,
                        );
                }
            }

            // if apt's media codec is partial match, then apt codec must be partial match too
            let (local_codec, mut match_type) =
                codec_parameters_fuzzy_search(&to_match_codec.rtp_codec, codecs);
            if match_type == CodecMatch::Exact && apt_match == CodecMatch::Partial {
                match_type = CodecMatch::Partial;
            }
            return Ok((local_codec, match_type));
        }

        let (local_codec, match_type) =
            codec_parameters_fuzzy_search(&remote_codec.rtp_codec, codecs);
        Ok((local_codec, match_type))
    }

    // Update header extensions from a remote media section.
    fn update_header_extension_from_media_section(
        &mut self,
        media: &MediaDescription,
    ) -> Result<()> {
        if media.media_name.port.value == 0
            && !media
                .attributes
                .iter()
                .any(|attribute| attribute.key == "bundle-only")
        {
            return Ok(());
        }
        let typ = if media.media_name.media.to_lowercase() == "audio" {
            RtpCodecKind::Audio
        } else if media.media_name.media.to_lowercase() == "video" {
            RtpCodecKind::Video
        } else {
            return Ok(());
        };

        let extensions = rtp_extensions_from_media_description(media)?;

        for (extension, mapping) in extensions {
            self.update_header_extension_mapping(extension.as_str(), typ, &mapping);
        }

        Ok(())
    }

    /// Look up a header extension and enable if it exists: a clear mapping of `id`.
    pub(crate) fn update_header_extension(
        &mut self,
        id: u16,
        extension: &str,
        typ: RtpCodecKind,
    ) -> Result<()> {
        self.update_header_extension_mapping(
            extension,
            typ,
            &SectionExtension {
                id,
                ..Default::default()
            },
        );
        Ok(())
    }

    /// Look up a header extension and enable it, as a section of a description maps it.
    pub(crate) fn update_header_extension_mapping(
        &mut self,
        extension: &str,
        typ: RtpCodecKind,
        mapping: &SectionExtension,
    ) {
        let id = mapping.id;
        for local_extension in &self.header_extensions {
            if local_extension.uri == extension {
                let mut negotiated = self
                    .negotiated_header_extensions
                    .get(&id)
                    .filter(|current| current.uri == extension)
                    .cloned()
                    .unwrap_or_else(|| MediaEngineHeaderExtension {
                        uri: extension.to_owned(),
                        allowed_direction: local_extension.allowed_direction,
                        ..Default::default()
                    });
                // One form of an extension is negotiated (RFC 6904 section 4.1: "answerers
                // MUST NOT negotiate the use of ... both encrypted and unencrypted forms").
                negotiated.encrypted = mapping.encrypted;
                negotiated.attributes.clone_from(&mapping.attributes);
                // A retired section cannot retain a conflicting ID or duplicate
                // this URI at its previous ID. RTP and SDP use the same mapping.
                self.negotiated_header_extensions
                    .retain(|old_id, current| *old_id == id || current.uri != extension);
                if local_extension.is_audio && typ == RtpCodecKind::Audio {
                    negotiated.is_audio = true;
                }
                if local_extension.is_video && typ == RtpCodecKind::Video {
                    negotiated.is_video = true;
                }
                self.negotiated_header_extensions.insert(id, negotiated);
            }
        }
    }

    pub(crate) fn push_codecs(&mut self, codecs: Vec<RTCRtpCodecParameters>, typ: RtpCodecKind) {
        self.push_section_codecs(codecs, typ, false);
    }

    /// [`Self::push_codecs`] for one remote section, `sframe` when it carries `a=sframe`: its
    /// formats are merged with the entries of the same numbering (SFrame or plain) only, so a
    /// format an SFrame section numbers apart from a plain section keeps both numbers.
    pub(crate) fn push_section_codecs(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        typ: RtpCodecKind,
        sframe: bool,
    ) {
        let sframe_payload_types = self.sframe_payload_types.clone();
        let negotiated = match typ {
            RtpCodecKind::Audio => &mut self.negotiated_audio_codecs,
            RtpCodecKind::Video => &mut self.negotiated_video_codecs,
            RtpCodecKind::Application => &mut self.negotiated_application_codecs,
            RtpCodecKind::Unspecified => return,
        };
        let before = negotiated.len();
        MediaEngine::merge_negotiated_codecs(negotiated, codecs, |payload_type| {
            sframe_payload_types.contains(&payload_type) == sframe
        });
        if sframe {
            let added: Vec<PayloadType> = negotiated[before..]
                .iter()
                .map(|c| c.payload_type)
                .collect();
            self.sframe_payload_types.extend(added);
        }
    }

    /// The formats a section of `kind` offers and matches against: those of the negotiated
    /// list (the registered ones before any negotiation) in the section's numbering, SFrame
    /// (`sframe`) or plain. An SFrame section of a connection that has negotiated none yet
    /// numbers the registered formats with payload types no registered or negotiated format
    /// uses ([`Self::sframe_numbering`]).
    pub(crate) fn codecs_for_section(
        &self,
        kind: RtpCodecKind,
        sframe: bool,
    ) -> Vec<RTCRtpCodecParameters> {
        let numbered: Vec<RTCRtpCodecParameters> = self
            .get_codecs_by_kind(kind)
            .into_iter()
            .filter(|codec| self.sframe_payload_types.contains(&codec.payload_type) == sframe)
            .collect();
        if sframe && numbered.is_empty() {
            return self.sframe_numbering(kind);
        }
        numbered
    }

    /// The registered formats of `kind` renumbered for an SFrame section: each registered
    /// format (audio first, then video, so that the kinds do not share a number either) takes
    /// the next dynamic payload type (96 to 127, then 35 to 63; never 64 to 95, RFC 5761
    /// section 4) that no registered or negotiated format uses. RTX `apt` and RED's
    /// redundancy list follow the renumbering. The numbering is the same every time while
    /// the registration and the negotiated lists are.
    pub(crate) fn sframe_numbering(&self, kind: RtpCodecKind) -> Vec<RTCRtpCodecParameters> {
        let taken: std::collections::HashSet<PayloadType> = [
            &self.audio_codecs,
            &self.video_codecs,
            &self.negotiated_audio_codecs,
            &self.negotiated_video_codecs,
        ]
        .into_iter()
        .flatten()
        .map(|codec| codec.payload_type)
        .collect();
        let mut free = (96..=127u8)
            .chain(35..=63u8)
            .filter(|pt| !taken.contains(pt));
        let mut map: Vec<(RtpCodecKind, PayloadType, PayloadType)> = vec![];
        for k in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            for codec in self.registered_codecs_by_kind(k) {
                if let Some(pt) = free.next() {
                    map.push((k, codec.payload_type, pt));
                }
            }
        }
        let renumber = |pt: PayloadType| {
            map.iter()
                .find(|(k, old, _)| *k == kind && *old == pt)
                .map(|(_, _, new)| *new)
        };
        self.registered_codecs_by_kind(kind)
            .iter()
            .filter_map(|codec| {
                let mut codec = codec.clone();
                codec.payload_type = renumber(codec.payload_type)?;
                match repair_family(&codec.rtp_codec) {
                    "rtx" => {
                        let apt = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)?;
                        let apt = renumber(apt)?;
                        let rest: Vec<String> = codec
                            .rtp_codec
                            .sdp_fmtp_line
                            .split(';')
                            .map(str::trim)
                            .filter(|p| {
                                !p.is_empty() && !p.to_ascii_lowercase().starts_with("apt=")
                            })
                            .map(str::to_owned)
                            .collect();
                        codec.rtp_codec.sdp_fmtp_line = std::iter::once(format!("apt={apt}"))
                            .chain(rest)
                            .collect::<Vec<_>>()
                            .join(";");
                    }
                    "red" if !codec.rtp_codec.sdp_fmtp_line.trim().is_empty() => {
                        let list: Option<Vec<String>> = codec
                            .rtp_codec
                            .sdp_fmtp_line
                            .trim()
                            .split('/')
                            .map(|pt| pt.trim().parse().ok().and_then(renumber))
                            .map(|pt| pt.map(|pt: PayloadType| pt.to_string()))
                            .collect();
                        codec.rtp_codec.sdp_fmtp_line = list?.join("/");
                    }
                    _ => {}
                }
                Some(codec)
            })
            .collect()
    }

    /// Adds the formats of one remote media section to the negotiated list of its kind.
    ///
    /// With several media sections of one kind negotiated (the default, see
    /// `SettingEngineBuilder::with_disable_media_engine_multiple_codecs`), every remote
    /// description adds each section's formats here, so the list must keep one entry per
    /// format and one format per payload type. A peer that renumbers a format it already
    /// negotiated (which RFC 3264 section 8.3.2 forbids) or numbers it differently in another
    /// section would otherwise put the same format here twice, and every answer would then
    /// describe it twice under two payload types:
    ///
    /// - a payload type already in the list keeps the format it names (first mapping wins;
    ///   RFC 8843 section 7.5 gives one payload type one format across a BUNDLE group);
    /// - a media or FEC format already in the list under another number is not added again.
    ///   Identity is the encoding name, clock rate, channels and fmtp parameters (RFC 8866
    ///   section 6.6), not the payload type: FEC has no `apt` to tie it to a primary, so
    ///   matching by payload type alone let a renumbered FlexFEC in twice;
    /// - an RTX format (RFC 4588 section 8.6) is added only when its `apt` still names, in the
    ///   list, the very format the remote section gives that number, and that primary has no
    ///   RTX entry yet. One whose primary was kept under its earlier number is stale.
    ///
    /// The entries that are added keep the remote section's order.
    fn merge_negotiated_codecs(
        negotiated: &mut Vec<RTCRtpCodecParameters>,
        incoming: Vec<RTCRtpCodecParameters>,
        same_numbering: impl Fn(PayloadType) -> bool,
    ) {
        let is_rtx = |codec: &RTCRtpCodecParameters| repair_family(&codec.rtp_codec) == "rtx";

        // What the list holds once this section's formats are in, built primaries (and FEC)
        // first so that an RTX entry is judged against the primaries this section adds.
        let mut merged = negotiated.clone();
        let mut take = vec![false; incoming.len()];

        for (i, codec) in incoming.iter().enumerate() {
            if is_rtx(codec) {
                continue;
            }
            let known = merged.iter().any(|existing| {
                existing.payload_type == codec.payload_type
                    || (same_numbering(existing.payload_type)
                        && same_format(&existing.rtp_codec, &codec.rtp_codec))
            });
            if !known {
                take[i] = true;
                merged.push(codec.clone());
            }
        }

        for (i, codec) in incoming.iter().enumerate() {
            if !is_rtx(codec)
                || merged
                    .iter()
                    .any(|existing| existing.payload_type == codec.payload_type)
            {
                continue;
            }
            let Some(apt) = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line) else {
                continue;
            };
            // The primary this entry repairs, as the remote section numbers it.
            let Some(remote_primary) = incoming
                .iter()
                .find(|primary| primary.payload_type == apt && !is_rtx(primary))
            else {
                continue;
            };
            let same_primary = merged.iter().any(|existing| {
                existing.payload_type == apt
                    && same_format(&existing.rtp_codec, &remote_primary.rtp_codec)
            });
            let already_repaired = merged.iter().any(|existing| {
                is_rtx(existing) && parse_rtx_apt(&existing.rtp_codec.sdp_fmtp_line) == Some(apt)
            });
            if same_primary && !already_repaired {
                take[i] = true;
                merged.push(codec.clone());
            }
        }

        negotiated.extend(
            incoming
                .into_iter()
                .zip(take)
                .filter_map(|(codec, take)| take.then_some(codec)),
        );
    }

    /// Update the MediaEngine from a remote description
    pub(crate) fn update_from_remote_description(
        &mut self,
        desc: &SessionDescription,
    ) -> Result<()> {
        for media in &desc.media_descriptions {
            // A data channel section, or an `m=application` line that is not RTP (the pre-RFC
            // 8841 `DTLS/SCTP` data section): no codecs to read.
            if media.is_webrtc_datachannel() || is_unknown_application_media(media) {
                continue;
            }

            let typ = if media.media_name.media.to_lowercase() == "audio" {
                RtpCodecKind::Audio
            } else if media.media_name.media.to_lowercase() == "video" {
                RtpCodecKind::Video
            } else if media.media_name.media.to_lowercase() == "application" {
                RtpCodecKind::Application
            } else {
                RtpCodecKind::Unspecified
            };

            if !self.negotiated_audio && typ == RtpCodecKind::Audio {
                self.negotiated_audio = true;
            } else if !self.negotiated_video && typ == RtpCodecKind::Video {
                self.negotiated_video = true;
            } else if !self.negotiated_application && typ == RtpCodecKind::Application {
                self.negotiated_application = true;
            } else {
                // update header extesions from remote sdp if codec is negotiated, Firefox
                // would send updated header extension in renegotiation.
                // e.g. publish first track without simucalst ->negotiated-> publish second track with simucalst
                // then the two media secontions have different rtp header extensions in offer
                self.update_header_extension_from_media_section(media)?;

                if !self.negotiate_multi_codecs || typ == RtpCodecKind::Unspecified {
                    continue;
                }
            }

            let mut codecs = codecs_from_media_description(media)?;
            // RFC 4585 section 4.1: no feedback outside an AVPF-based profile.
            if !crate::peer_connection::sdp::is_avpf_section(media) {
                for codec in &mut codecs {
                    codec.rtp_codec.rtcp_feedback.clear();
                }
            }

            let add_if_new = |existing_codecs: &mut Vec<RTCRtpCodecParameters>,
                              codec: &RTCRtpCodecParameters| {
                let mut found = false;
                for existing_codec in existing_codecs.iter() {
                    if existing_codec.payload_type == codec.payload_type {
                        found = true;
                        break;
                    }
                }

                if !found {
                    existing_codecs.push(codec.clone());
                }
            };

            let mut exact_matches = vec![];
            let mut partial_matches = vec![];

            for remote_codec in &mut codecs {
                let (local_codec, match_type) =
                    self.match_remote_codec(remote_codec, typ, &exact_matches, &partial_matches)?;

                remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                    &local_codec.rtp_codec.rtcp_feedback,
                    &remote_codec.rtp_codec.rtcp_feedback,
                );

                if match_type == CodecMatch::Exact {
                    add_if_new(&mut exact_matches, remote_codec);
                } else if match_type == CodecMatch::Partial {
                    add_if_new(&mut partial_matches, remote_codec);
                }
            }
            // second pass in case there were missed RTX codecs
            for remote_codec in &mut codecs {
                let (local_codec, match_type) =
                    self.match_remote_codec(remote_codec, typ, &exact_matches, &partial_matches)?;

                remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                    &local_codec.rtp_codec.rtcp_feedback,
                    &remote_codec.rtp_codec.rtcp_feedback,
                );

                if match_type == CodecMatch::Exact {
                    add_if_new(&mut exact_matches, remote_codec);
                } else if match_type == CodecMatch::Partial {
                    add_if_new(&mut partial_matches, remote_codec);
                }
            }

            // A format matched by its name alone has parameters this endpoint did not register.
            // For H.264, VP9 and AV1 those parameters say what the bitstream is (profile,
            // packetization mode), and "the answerer MUST either maintain all configuration
            // parameters or remove the media format (payload type) completely" (RFC 6184
            // section 8.2.2; RFC 9628 section 6; AV1 RTP section 7.2): such a format is not
            // negotiated, nor is its RTX.
            // A codec registered with no parameters at all states no configuration, and
            // keeps matching by name.
            let removed: Vec<PayloadType> =
                partial_matches
                    .iter()
                    .filter(|codec| {
                        has_symmetric_configuration(&codec.rtp_codec)
                            && self.match_remote_codec(codec, typ, &[], &[]).is_ok_and(
                                |(local, _)| !local.rtp_codec.sdp_fmtp_line.trim().is_empty(),
                            )
                    })
                    .map(|codec| codec.payload_type)
                    .collect();
            partial_matches.retain(|codec| {
                !removed.contains(&codec.payload_type)
                    && !(is_repair_codec(&codec.rtp_codec)
                        && parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                            .is_some_and(|apt| removed.contains(&apt)))
            });

            // RFC 8627 section 5.1 (and draft-ietf-payload-flexible-fec-scheme-03 section 5.1):
            // `repair-window` is a required parameter, so a FlexFEC format without one is not
            // negotiated. Section 5.2.1: "the receiver ... MUST reject" a repair window it
            // cannot support: one longer than the window this endpoint registered.
            for matches in [&mut exact_matches, &mut partial_matches] {
                matches.retain(|codec| self.repair_window_supported(codec, typ));
            }

            // RFC 8627 section 1.1.7: offered FlexFEC and another RTP retransmission method,
            // the answer contains only FlexFEC.
            if !self.flexfec_with_retransmission {
                for matches in [&mut exact_matches, &mut partial_matches] {
                    if matches
                        .iter()
                        .any(|codec| is_flexfec_mime_type(&codec.rtp_codec.mime_type))
                    {
                        matches.retain(|codec| repair_family(&codec.rtp_codec) != "rtx");
                    }
                }
            }

            // RFC 2198 section 5: the encodings a RED format names in its fmtp
            // (`<primary>/<redundant>...`) "MUST" be formats of the m= line too, and section
            // 3: of RED's own clock rate. A RED format naming one that is not, or one this
            // endpoint did not negotiate, carries blocks that cannot be decoded, and is not
            // negotiated. A RED format without an fmtp line (libwebrtc's `video/red`) names
            // none.
            for matches in [&mut exact_matches, &mut partial_matches] {
                let negotiated = matches.clone();
                matches.retain(|codec| red_encodings_negotiated(codec, &negotiated));
            }

            // use exact matches when they exist, otherwise fall back to partial
            // An SFrame section's formats are numbered apart from the plain ones
            // (draft-ietf-avtcore-rtp-sframe-03 section 6).
            let sframe = media.has_attribute(ATTR_KEY_SFRAME);
            if !exact_matches.is_empty() {
                self.push_section_codecs(exact_matches, typ, sframe);
            } else if !partial_matches.is_empty() {
                self.push_section_codecs(partial_matches, typ, sframe);
            } else {
                // no match, not negotiated
                continue;
            }

            self.update_header_extension_from_media_section(media)?;
        }

        Ok(())
    }

    /// Whether a remote FlexFEC format (`codec`, RFC 8627 or draft-03) has the required
    /// `repair-window` (section 5.1) and it is no longer than the one this endpoint registered
    /// for the format (section 5.2.1). Any other format passes.
    fn repair_window_supported(&self, codec: &RTCRtpCodecParameters, typ: RtpCodecKind) -> bool {
        let mime_type = &codec.rtp_codec.mime_type;
        if !crate::rtp_transceiver::rtp_sender::rtp_codec::is_fec_mime_type(mime_type) {
            return true;
        }
        let Some(remote) =
            interceptor::FlexFecParameters::parse(&codec.rtp_codec.sdp_fmtp_line).repair_window
        else {
            log::debug!(
                "{mime_type} payload type {} without repair-window: not negotiated (RFC 8627 \
                 section 5.1)",
                codec.payload_type
            );
            return false;
        };
        let registered = match typ {
            RtpCodecKind::Audio => &self.audio_codecs,
            RtpCodecKind::Video => &self.video_codecs,
            _ => &self.application_codecs,
        };
        let supported = registered
            .iter()
            .filter(|local| local.rtp_codec.mime_type.eq_ignore_ascii_case(mime_type))
            .filter_map(|local| {
                interceptor::FlexFecParameters::parse(&local.rtp_codec.sdp_fmtp_line).repair_window
            })
            .max()
            .unwrap_or(interceptor::FLEXFEC_MAX_REPAIR_WINDOW);
        if remote > supported {
            log::debug!(
                "{mime_type} payload type {}: repair window {remote:?} longer than the \
                 {supported:?} this endpoint supports: not negotiated (RFC 8627 section 5.2.1)",
                codec.payload_type
            );
            return false;
        }
        true
    }

    /// The `a=fmtp` parameters this endpoint states for `codec`, a format of a media section it
    /// is describing. `codec` may be a negotiated format, whose fmtp line is the remote
    /// side's; a description states this endpoint's own parameters, not the peer's (RFC 3264
    /// section 6.1: the answerer's "own" parameters; RFC 7587 section 7.1: Opus parameters
    /// are "declarative" and each side's own; AV1 RTP section 7.2.3; RFC 9628 section 6.1.2).
    ///
    /// - A repair format (RTX, its `apt`) keeps its line.
    /// - A format one of the registered codecs matches is described with that codec's line.
    /// - H.264 (RFC 6184 section 8.2.2): the profile and `packetization-mode` are symmetric,
    ///   so an answer keeps the offer's profile; the level is this endpoint's own when both
    ///   sides say `level-asymmetry-allowed=1`, else the lower of the two ("the level ... in
    ///   the answer MUST NOT be higher than the level in the offer").
    /// - A format no registered codec matches keeps its line.
    pub(crate) fn local_fmtp_line(
        &self,
        typ: RtpCodecKind,
        codec: &RTCRtpCodecParameters,
        answering: bool,
    ) -> String {
        let registered = match typ {
            RtpCodecKind::Audio => &self.audio_codecs,
            RtpCodecKind::Video => &self.video_codecs,
            RtpCodecKind::Application => &self.application_codecs,
            RtpCodecKind::Unspecified => return codec.rtp_codec.sdp_fmtp_line.clone(),
        };
        // RFC 8627 section 5.2.1 (and draft-ietf-payload-flexible-fec-scheme-03 5.2.1): "Any
        // unknown option in the offer must be ignored and deleted from the answer". A FlexFEC
        // answer states this endpoint's own parameters (its `repair-window`), as a media
        // codec's does. RTX and RED keep theirs: they name payload types of the description.
        if answering
            && crate::rtp_transceiver::rtp_sender::rtp_codec::is_fec_mime_type(
                &codec.rtp_codec.mime_type,
            )
            && let Some(local) = registered.iter().find(|registered| {
                registered
                    .rtp_codec
                    .mime_type
                    .eq_ignore_ascii_case(&codec.rtp_codec.mime_type)
            })
        {
            return local.rtp_codec.sdp_fmtp_line.clone();
        }
        if is_repair_codec(&codec.rtp_codec) {
            return codec.rtp_codec.sdp_fmtp_line.clone();
        }
        let (local, matched) = codec_parameters_fuzzy_search(&codec.rtp_codec, registered);
        if matched == CodecMatch::None
            || (matched == CodecMatch::Partial && has_symmetric_configuration(&codec.rtp_codec))
        {
            return codec.rtp_codec.sdp_fmtp_line.clone();
        }
        let local_line = local.rtp_codec.sdp_fmtp_line;
        if !answering {
            return local_line;
        }
        if codec
            .rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_H264)
        {
            h264_answer_fmtp(&local_line, &codec.rtp_codec.sdp_fmtp_line)
        } else if codec
            .rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_HEVC)
        {
            h265_answer_fmtp(&local_line, &codec.rtp_codec.sdp_fmtp_line)
        } else {
            local_line
        }
    }

    /// The codecs registered for `typ`, whatever negotiation made of them.
    pub(crate) fn registered_codecs_by_kind(&self, typ: RtpCodecKind) -> &[RTCRtpCodecParameters] {
        match typ {
            RtpCodecKind::Audio => &self.audio_codecs,
            RtpCodecKind::Video => &self.video_codecs,
            RtpCodecKind::Application => &self.application_codecs,
            RtpCodecKind::Unspecified => &[],
        }
    }

    pub(crate) fn get_codecs_by_kind(&self, typ: RtpCodecKind) -> Vec<RTCRtpCodecParameters> {
        if typ == RtpCodecKind::Video {
            if self.negotiated_video {
                self.negotiated_video_codecs.clone()
            } else {
                self.video_codecs.clone()
            }
        } else if typ == RtpCodecKind::Audio {
            if self.negotiated_audio {
                self.negotiated_audio_codecs.clone()
            } else {
                self.audio_codecs.clone()
            }
        } else if typ == RtpCodecKind::Application {
            if self.negotiated_application {
                self.negotiated_application_codecs.clone()
            } else {
                self.application_codecs.clone()
            }
        } else {
            vec![]
        }
    }

    pub(crate) fn get_rtp_parameters_by_kind(
        &self,
        typ: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> RTCRtpParameters {
        let mut header_extensions = vec![];

        let found_codecs = self.get_codecs_by_kind(typ);

        if self.negotiated_video && typ == RtpCodecKind::Video
            || self.negotiated_audio && typ == RtpCodecKind::Audio
        {
            for (id, e) in &self.negotiated_header_extensions {
                if e.is_matching_direction(direction)
                    && (e.is_audio && typ == RtpCodecKind::Audio
                        || e.is_video && typ == RtpCodecKind::Video)
                {
                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id: *id,
                        uri: e.uri.clone(),
                        encrypted: e.encrypted,
                        attributes: e.attributes.clone(),
                    });
                }
            }
        } else {
            // Each registered extension in each form its encryption setting offers (RFC 6904
            // section 4.1), with the id it was negotiated with or the first free one.
            let mut assigned: Vec<(u16, &MediaEngineHeaderExtension, bool)> = vec![];
            for ext in &self.header_extensions {
                let forms: &[bool] = match ext.encryption {
                    RTCRtpHeaderExtensionEncryption::Clear => &[false],
                    RTCRtpHeaderExtensionEncryption::BestEffort => &[false, true],
                    RTCRtpHeaderExtensionEncryption::Encrypted => &[true],
                };
                for &encrypted in forms {
                    let negotiated_id = self
                        .negotiated_header_extensions
                        .iter()
                        .find(|(_, n)| n.uri == ext.uri && n.encrypted == encrypted)
                        .map(|(id, _)| *id);
                    let id = negotiated_id.or_else(|| {
                        local_extension_ids().find(|id| {
                            !assigned.iter().any(|(taken, _, _)| taken == id)
                                && !self.negotiated_header_extensions.contains_key(id)
                        })
                    });
                    if let Some(id) = id {
                        assigned.push((id, ext, encrypted));
                    }
                }
            }
            assigned.sort_by_key(|(id, _, _)| *id);

            for (id, e, encrypted) in assigned {
                if e.is_matching_direction(direction)
                    && (e.is_audio && typ == RtpCodecKind::Audio
                        || e.is_video && typ == RtpCodecKind::Video)
                {
                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id,
                        uri: e.uri.clone(),
                        encrypted,
                        attributes: None,
                    })
                }
            }
        }

        RTCRtpParameters {
            header_extensions,
            codecs: found_codecs,
            rtcp: RTCRtcpParameters {
                cname: self.rtcp_cname.clone(),
                reduced_size: false,
            },
        }
    }

    pub(crate) fn get_rtp_parameters_by_payload_type(
        &self,
        payload_type: PayloadType,
    ) -> Result<RTCRtpParameters> {
        let (codec, typ) = self.get_codec_by_payload(payload_type)?;

        let mut header_extensions = vec![];
        for (id, e) in &self.negotiated_header_extensions {
            if e.is_audio && typ == RtpCodecKind::Audio || e.is_video && typ == RtpCodecKind::Video
            {
                header_extensions.push(RTCRtpHeaderExtensionParameters {
                    uri: e.uri.clone(),
                    id: *id,
                    encrypted: e.encrypted,
                    attributes: e.attributes.clone(),
                });
            }
        }

        Ok(RTCRtpParameters {
            header_extensions,
            codecs: vec![codec],
            ..Default::default()
        })
    }

    pub(crate) fn is_rtx_enabled(
        &self,
        kind: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> bool {
        for codec in &self.get_rtp_parameters_by_kind(kind, direction).codecs {
            if UniCase::new(codec.rtp_codec.mime_type.as_str()) == UniCase::new(MIME_TYPE_RTX) {
                return true;
            }
        }

        false
    }

    pub(crate) fn is_fec_enabled(
        &self,
        kind: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> bool {
        // The FEC formats the engine has a coder for, each matched exactly: FlexFEC draft-03
        // (`video/flexfec-03`) and RFC 8627 (`video/flexfec`).
        self.get_rtp_parameters_by_kind(kind, direction)
            .codecs
            .iter()
            .any(|codec| {
                crate::rtp_transceiver::rtp_sender::rtp_codec::is_fec_mime_type(
                    &codec.rtp_codec.mime_type,
                )
            })
    }
}

/// The parameters of an `a=fmtp` line as a set: keys and values compared without case, and
/// parameter order, spacing and repeats ignored.
fn fmtp_parameter_set(line: &str) -> Vec<(String, String)> {
    let mut set: Vec<(String, String)> = line
        .split(';')
        .map(str::trim)
        .filter(|parameter| !parameter.is_empty())
        .map(|parameter| match parameter.split_once('=') {
            Some((key, value)) => (
                key.trim().to_ascii_lowercase(),
                value.trim().to_ascii_lowercase(),
            ),
            None => (parameter.to_ascii_lowercase(), String::new()),
        })
        .collect();
    set.sort();
    set.dedup();
    set
}

/// Whether `a` and `b` describe one format (RFC 8866 section 6.6, `a=rtpmap` and `a=fmtp`):
/// the same encoding name, clock rate, channels and fmtp parameters. The payload type that
/// numbers it is not part of the format.
///
/// A VP9 format without `profile-id` is profile 0 (RFC 9628 section 6: "If no profile-id is
/// present, Profile 0 MUST be inferred"), so it is the format that says `profile-id=0`.
fn same_format(a: &RTCRtpCodec, b: &RTCRtpCodec) -> bool {
    let parameters = |codec: &RTCRtpCodec| {
        let mut set = fmtp_parameter_set(&codec.sdp_fmtp_line);
        if codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP9)
            && !set.iter().any(|(key, _)| key == "profile-id")
        {
            set.push(("profile-id".to_owned(), "0".to_owned()));
            set.sort();
        }
        set
    };
    a.mime_type.eq_ignore_ascii_case(&b.mime_type)
        && a.clock_rate == b.clock_rate
        && a.channels == b.channels
        && parameters(a) == parameters(b)
}

/// RFC 8834 section 4.3: where payload types associate RTP streams with m= lines (the
/// sections of one BUNDLE group share an RTP session), "the payload type numbers MUST be
/// unique across the signalling contexts"; RFC 9143 section 9.1 says the same of a BUNDLE
/// group. Given the sections of one group (their mid and the formats their m= line lists),
/// the payload types that two sections use for different formats, each with the mids that
/// use it. Empty when the group's payload types are consistent. For the SDP layer, which
/// refuses such a remote offer (or reads the packets by MID, not by payload type).
pub(crate) fn payload_types_reused_across_sections(
    sections: &[(&str, &[RTCRtpCodecParameters])],
) -> Vec<(PayloadType, Vec<String>)> {
    let mut conflicts: Vec<(PayloadType, Vec<String>)> = vec![];
    for (i, (mid, codecs)) in sections.iter().enumerate() {
        for codec in codecs.iter() {
            for (other_mid, other_codecs) in &sections[i + 1..] {
                let clash = other_codecs.iter().any(|other| {
                    other.payload_type == codec.payload_type
                        && !same_format(&other.rtp_codec, &codec.rtp_codec)
                });
                if !clash {
                    continue;
                }
                let entry = match conflicts
                    .iter_mut()
                    .find(|(pt, _)| *pt == codec.payload_type)
                {
                    Some(entry) => entry,
                    None => {
                        conflicts.push((codec.payload_type, vec![]));
                        conflicts.last_mut().expect("just pushed")
                    }
                };
                for m in [*mid, *other_mid] {
                    if !entry.1.iter().any(|known| known == m) {
                        entry.1.push(m.to_owned());
                    }
                }
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod payload_type_reuse_test {
    use super::*;

    fn codec(payload_type: PayloadType, mime_type: &str, clock_rate: u32) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    /// RFC 8834 section 4.3: one payload type names one format across the m= lines of an
    /// RTP session; the same format under one number in two sections is fine.
    #[test]
    fn a_payload_type_naming_two_formats_in_one_group_is_found() {
        let audio = [
            codec(111, MIME_TYPE_OPUS, 48000),
            codec(96, MIME_TYPE_PCMU, 8000),
        ];
        let video = [
            codec(96, MIME_TYPE_VP8, 90000),
            codec(97, MIME_TYPE_VP9, 90000),
        ];
        let more_video = [codec(97, MIME_TYPE_VP9, 90000)];
        let conflicts = payload_types_reused_across_sections(&[
            ("0", &audio),
            ("1", &video),
            ("2", &more_video),
        ]);
        assert_eq!(conflicts, vec![(96, vec!["0".to_owned(), "1".to_owned()])]);
        assert!(
            payload_types_reused_across_sections(&[("1", &video), ("2", &more_video)]).is_empty()
        );
    }
}

#[cfg(test)]
mod same_format_test {
    use super::*;

    fn vp9(fmtp: &str) -> RTCRtpCodec {
        RTCRtpCodec {
            mime_type: MIME_TYPE_VP9.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        }
    }

    #[test]
    fn a_vp9_format_without_a_profile_id_is_profile_0() {
        assert!(same_format(&vp9(""), &vp9("profile-id=0")));
        assert!(same_format(&vp9("profile-id=0"), &vp9("")));
        assert!(!same_format(&vp9(""), &vp9("profile-id=2")));
        assert!(!same_format(&vp9("profile-id=0"), &vp9("profile-id=2")));
        // Only VP9 has that default.
        let other = |fmtp: &str| RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            ..vp9(fmtp)
        };
        assert!(!same_format(&other(""), &other("profile-id=0")));
    }
}

#[cfg(test)]
#[path = "media_engine_unspecified_test.rs"]
mod media_engine_unspecified_test;

#[cfg(test)]
mod default_fec_codec_test {
    use super::*;

    // ULPFEC (RFC 5109) is not in the default codecs: the engine neither encodes nor decodes
    // it, so it must not be offered (upstream #837 made the same change). See FORK.md.
    #[test]
    fn default_codecs_do_not_offer_ulpfec() {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();

        let ulpfec: Vec<_> = me
            .video_codecs
            .iter()
            .filter(|c| {
                UniCase::new(c.rtp_codec.mime_type.as_str()) == UniCase::new(MIME_TYPE_ULP_FEC)
            })
            .map(|c| c.payload_type)
            .collect();

        assert!(
            ulpfec.is_empty(),
            "default codecs must not offer ULPFEC: {ulpfec:?}"
        );
    }

    // The constant remains part of the public API so an application can opt in.
    #[test]
    fn ulpfec_remains_registerable_explicitly() {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_ULP_FEC.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 116,
            },
            RtpCodecKind::Video,
        )
        .expect("an application may still register ULPFEC itself");

        assert!(me.video_codecs.iter().any(|c| {
            UniCase::new(c.rtp_codec.mime_type.as_str()) == UniCase::new(MIME_TYPE_ULP_FEC)
        }));
    }
}

#[cfg(test)]
mod default_rtx_codec_test {
    use super::*;
    use crate::rtp_transceiver::rtp_sender::rtp_codec::{find_rtx_payload_type, parse_rtx_apt};

    // RFC 4588 / issue #119: register_default_codecs must register a video/rtx
    // codec (apt=<primary>) for every primary video codec, otherwise browser
    // RTX offers get dropped during negotiation.
    #[test]
    fn default_codecs_register_rtx_for_every_primary() {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();

        let mut primary_payload_types = vec![];
        let mut rtx_apts = vec![];
        for codec in &me.video_codecs {
            if UniCase::new(codec.rtp_codec.mime_type.as_str()) == UniCase::new(MIME_TYPE_RTX) {
                let apt = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                    .expect("rtx codec must carry an apt= parameter");
                rtx_apts.push(apt);
            } else if UniCase::new(codec.rtp_codec.mime_type.as_str())
                != UniCase::new(MIME_TYPE_ULP_FEC)
            {
                // A FEC codec is not a media codec and gets no RTX pairing (none is a
                // default today; this keeps the check right if one is added).
                primary_payload_types.push(codec.payload_type);
            }
        }

        assert!(!rtx_apts.is_empty(), "no RTX codecs were registered");

        for pt in &primary_payload_types {
            assert!(
                rtx_apts.contains(pt),
                "primary payload type {pt} has no associated RTX codec (apt={pt})"
            );
            // find_rtx_payload_type must locate our RTX pt by its apt.
            assert!(
                find_rtx_payload_type(*pt, &me.video_codecs).is_some(),
                "find_rtx_payload_type failed for primary payload type {pt}"
            );
        }
    }

    #[test]
    fn default_video_codec_payload_types_are_unique() {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();

        let mut seen = std::collections::HashSet::new();
        for codec in &me.video_codecs {
            assert!(
                seen.insert(codec.payload_type),
                "duplicate video payload type {} ({})",
                codec.payload_type,
                codec.rtp_codec.mime_type
            );
        }
    }
}

#[cfg(test)]
mod register_feedback_test {
    use super::*;

    fn video_codec(payload_type: PayloadType) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
        RTCPFeedback {
            typ: typ.to_owned(),
            parameter: parameter.to_owned(),
        }
    }

    fn count(me: &MediaEngine, typ: &str, parameter: &str) -> usize {
        me.video_codecs[0]
            .rtp_codec
            .rtcp_feedback
            .iter()
            .filter(|fb| fb.typ == typ && fb.parameter == parameter)
            .count()
    }

    // `configure_congestion_control` and `configure_twcc_receiver_only` both need transport-cc,
    // and an application that calls one alongside `register_default_interceptors` calls both.
    // Without dedupe the codec accumulates one `a=rtcp-fb:<pt> transport-cc` per caller, and the
    // answer goes out with the line repeated.
    #[test]
    fn registering_the_same_feedback_twice_adds_it_once() {
        let mut me = MediaEngine::default();
        me.register_codec(video_codec(96), RtpCodecKind::Video)
            .unwrap();

        me.register_feedback(feedback("transport-cc", ""), RtpCodecKind::Video);
        me.register_feedback(feedback("transport-cc", ""), RtpCodecKind::Video);

        assert_eq!(1, count(&me, "transport-cc", ""));
    }

    // The dedupe matches on type *and* parameter. `nack` and `nack pli` share a type but are
    // different mechanisms, and comparing types alone would silently drop the second.
    #[test]
    fn feedback_of_the_same_type_with_different_parameters_both_register() {
        let mut me = MediaEngine::default();
        me.register_codec(video_codec(96), RtpCodecKind::Video)
            .unwrap();

        me.register_feedback(feedback("nack", ""), RtpCodecKind::Video);
        me.register_feedback(feedback("nack", "pli"), RtpCodecKind::Video);

        assert_eq!(1, count(&me, "nack", ""));
        assert_eq!(1, count(&me, "nack", "pli"));
    }

    // A codec registered *after* the feedback does not have it — `register_feedback` only touches
    // codecs already present. Pinning this so the dedupe is not mistaken for a guarantee that
    // every codec ends up with every mechanism.
    #[test]
    fn feedback_applies_only_to_codecs_already_registered() {
        let mut me = MediaEngine::default();
        me.register_codec(video_codec(96), RtpCodecKind::Video)
            .unwrap();
        me.register_feedback(feedback("transport-cc", ""), RtpCodecKind::Video);
        me.register_codec(video_codec(98), RtpCodecKind::Video)
            .unwrap();

        assert_eq!(1, count(&me, "transport-cc", ""));
        assert!(me.video_codecs[1].rtp_codec.rtcp_feedback.is_empty());
    }

    // Audio and video are separate lists; registering for one must not reach the other.
    #[test]
    fn feedback_does_not_cross_between_audio_and_video() {
        let mut me = MediaEngine::default();
        me.register_codec(video_codec(96), RtpCodecKind::Video)
            .unwrap();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            },
            RtpCodecKind::Audio,
        )
        .unwrap();

        me.register_feedback(feedback("transport-cc", ""), RtpCodecKind::Video);

        assert_eq!(1, count(&me, "transport-cc", ""));
        assert!(me.audio_codecs[0].rtp_codec.rtcp_feedback.is_empty());
    }
}

/// Whether `codec`, when it is a RED format (RFC 2198), names in its fmtp only formats of
/// `negotiated` with its own clock rate. Any other format, and a RED format without an fmtp
/// line, passes.
pub(crate) fn red_encodings_negotiated(
    codec: &RTCRtpCodecParameters,
    negotiated: &[RTCRtpCodecParameters],
) -> bool {
    let red = &codec.rtp_codec;
    if !red.mime_type.to_ascii_lowercase().ends_with("/red") {
        return true;
    }
    let fmtp = red.sdp_fmtp_line.trim();
    if fmtp.is_empty() {
        return true;
    }
    rtp::codec::red::parse_red_fmtp(fmtp).is_ok_and(|payload_types| {
        payload_types.iter().all(|pt| {
            negotiated.iter().any(|named| {
                named.payload_type == *pt && named.rtp_codec.clock_rate == red.clock_rate
            })
        })
    })
}

#[cfg(test)]
mod payload_type_numbering_test {
    use super::*;

    /// RFC 3551 section 3 and RFC 5761 section 4: where more than the 32 dynamic payload
    /// types are needed, the unassigned numbers below 64 are used next and 64 to 95 never
    /// (they would collide with RTCP packet types under rtcp-mux). The engine's own numbering
    /// (an SFrame section's formats): 34 formats registered on 0 to 33 take 96 to 127, then
    /// 35 and 36.
    #[test]
    fn numbering_past_the_dynamic_range_uses_35_to_63_and_never_64_to_95() {
        let mut media_engine = MediaEngine::default();
        for i in 0..34u8 {
            media_engine
                .register_codec(
                    RTCRtpCodecParameters {
                        rtp_codec: RTCRtpCodec {
                            mime_type: format!("video/X{i}"),
                            clock_rate: 90000,
                            channels: 0,
                            sdp_fmtp_line: String::new(),
                            rtcp_feedback: vec![],
                        },
                        payload_type: i,
                    },
                    RtpCodecKind::Video,
                )
                .expect("registered");
        }
        let numbered: Vec<PayloadType> = media_engine
            .sframe_numbering(RtpCodecKind::Video)
            .iter()
            .map(|codec| codec.payload_type)
            .collect();
        let expected: Vec<PayloadType> = (96..=127).chain([35, 36]).collect();
        assert_eq!(numbered, expected);
    }
}
