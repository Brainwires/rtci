use std::borrow::Cow;
use std::fmt;

use shared::{
    error::Result,
    marshal::{Marshal, MarshalSize},
};

/// Absolute capture time: when a frame was captured, on the capturer's NTP clock.
pub mod abs_capture_time_extension;
/// Absolute send time, for one-way-delay based bandwidth estimation.
pub mod abs_send_time_extension;
/// Per-packet audio loudness and voice activity ([RFC 6464]).
pub mod audio_level_extension;
/// Corruption detection samples (a libwebrtc experiment, W3C webrtc-stats
/// `corruptionMeasurements`).
pub mod corruption_detection_extension;
/// The audio level of each contributing source of a mixed packet ([RFC 6465]).
///
/// [RFC 6465]: https://datatracker.ietf.org/doc/html/rfc6465
pub mod csrc_audio_level_extension;
/// In-band NTP-format timestamps for rapid synchronisation ([RFC 6051] section 3.3).
///
/// [RFC 6051]: https://datatracker.ietf.org/doc/html/rfc6051
pub mod ntp_timestamp_extension;
/// A requested playout-delay range, for latency/smoothness trade-offs.
pub mod playout_delay_extension;
/// SDES items in header extensions: MID, RtpStreamId, RepairedRtpStreamId ([RFC 7941],
/// [RFC 8852]).
///
/// [RFC 7941]: https://datatracker.ietf.org/doc/html/rfc7941
/// [RFC 8852]: https://datatracker.ietf.org/doc/html/rfc8852
pub mod sdes_extension;
/// Transmission time offset ([RFC 5450]).
///
/// [RFC 5450]: https://datatracker.ietf.org/doc/html/rfc5450
pub mod transmission_offset_extension;
/// The transport-wide sequence number that TWCC feedback refers to.
pub mod transport_cc_extension;
/// Camera direction and rotation (CVO), so a receiver can display video upright.
pub mod video_orientation_extension;

/// The URI of the absolute-send-time extension.
pub const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
/// The URI of the absolute-capture-time extension.
pub const ABS_CAPTURE_TIME_URI: &str =
    "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time";
/// The URI of the corruption detection extension (W3C webrtc-stats 8.5).
pub const CORRUPTION_DETECTION_URI: &str =
    "http://www.webrtc.org/experiments/rtp-hdrext/corruption-detection";
/// The URI of the client-to-mixer audio level extension (RFC 6464).
pub const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
/// The URI of the mixer-to-client audio level extension (RFC 6465).
pub const CSRC_AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:csrc-audio-level";
/// The URI of the 64-bit NTP timestamp extension (RFC 6051 section 3.3).
pub const NTP_64_URI: &str = ntp_timestamp_extension::NTP_64_URI;
/// The URI of the 56-bit NTP timestamp extension (RFC 6051 section 3.3).
pub const NTP_56_URI: &str = ntp_timestamp_extension::NTP_56_URI;
/// The URI of the playout-delay extension.
pub const PLAYOUT_DELAY_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";
/// The URI of the transport-wide sequence number extension.
pub const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
/// The URI of the video orientation extension (3GPP TS 26.114).
pub const VIDEO_ORIENTATION_URI: &str = "urn:3gpp:video-orientation";
/// The URI of the MID extension (RFC 8843).
pub const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
/// The URI of the RtpStreamId extension (RFC 8852).
pub const SDES_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
/// The URI of the RepairedRtpStreamId extension (RFC 8852).
pub const SDES_REPAIRED_RTP_STREAM_ID_URI: &str =
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
/// The URI of the transmission time offset extension (RFC 5450).
pub const TRANSMISSION_OFFSET_URI: &str = "urn:ietf:params:rtp-hdrext:toffset";

/// A generic RTP header extension.
#[non_exhaustive]
pub enum HeaderExtension {
    /// The absolute-send-time extension.
    AbsSendTime(abs_send_time_extension::AbsSendTimeExtension),
    /// The audio-level extension.
    AudioLevel(audio_level_extension::AudioLevelExtension),
    /// The playout-delay extension.
    PlayoutDelay(playout_delay_extension::PlayoutDelayExtension),
    /// The transport-wide CC extension.
    TransportCc(transport_cc_extension::TransportCcExtension),
    /// The video-orientation extension.
    VideoOrientation(video_orientation_extension::VideoOrientationExtension),
    /// The absolute-capture-time extension.
    AbsCaptureTime(abs_capture_time_extension::AbsCaptureTimeExtension),
    /// The mixer-to-client audio level extension.
    CsrcAudioLevel(csrc_audio_level_extension::CsrcAudioLevelExtension),
    /// The MID extension.
    Mid(sdes_extension::Mid),
    /// The RtpStreamId extension.
    RtpStreamId(sdes_extension::RtpStreamId),
    /// The RepairedRtpStreamId extension.
    RepairedRtpStreamId(sdes_extension::RepairedRtpStreamId),
    /// The transmission time offset extension.
    TransmissionOffset(transmission_offset_extension::TransmissionOffsetExtension),

    /// A custom extension
    Custom {
        /// The extension's canonical URI, which is what SDP negotiates ids against.
        uri: Cow<'static, str>,
        /// The extension value, erased so extensions of different types can be held together.
        extension: Box<dyn Marshal + 'static>,
    },
}

impl HeaderExtension {
    /// The extension's URI.
    pub fn uri(&self) -> Cow<'static, str> {
        use HeaderExtension::*;

        match self {
            AbsSendTime(_) => ABS_SEND_TIME_URI.into(),
            AudioLevel(_) => AUDIO_LEVEL_URI.into(),
            PlayoutDelay(_) => PLAYOUT_DELAY_URI.into(),
            TransportCc(_) => TRANSPORT_CC_URI.into(),
            VideoOrientation(_) => VIDEO_ORIENTATION_URI.into(),
            AbsCaptureTime(_) => ABS_CAPTURE_TIME_URI.into(),
            CsrcAudioLevel(_) => CSRC_AUDIO_LEVEL_URI.into(),
            Mid(_) => SDES_MID_URI.into(),
            RtpStreamId(_) => SDES_RTP_STREAM_ID_URI.into(),
            RepairedRtpStreamId(_) => SDES_REPAIRED_RTP_STREAM_ID_URI.into(),
            TransmissionOffset(_) => TRANSMISSION_OFFSET_URI.into(),
            Custom { uri, .. } => uri.clone(),
        }
    }

    /// Whether both refer to the same extension, comparing URIs rather than values.
    pub fn is_same(&self, other: &Self) -> bool {
        // One URI is one extension, whatever its value.
        self.uri() == other.uri()
    }
}

impl MarshalSize for HeaderExtension {
    fn marshal_size(&self) -> usize {
        use HeaderExtension::*;
        match self {
            AbsSendTime(ext) => ext.marshal_size(),
            AudioLevel(ext) => ext.marshal_size(),
            PlayoutDelay(ext) => ext.marshal_size(),
            TransportCc(ext) => ext.marshal_size(),
            VideoOrientation(ext) => ext.marshal_size(),
            AbsCaptureTime(ext) => ext.marshal_size(),
            CsrcAudioLevel(ext) => ext.marshal_size(),
            Mid(ext) => ext.marshal_size(),
            RtpStreamId(ext) => ext.marshal_size(),
            RepairedRtpStreamId(ext) => ext.marshal_size(),
            TransmissionOffset(ext) => ext.marshal_size(),
            Custom { extension: ext, .. } => ext.marshal_size(),
        }
    }
}

impl Marshal for HeaderExtension {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        use HeaderExtension::*;
        match self {
            AbsSendTime(ext) => ext.marshal_to(buf),
            AudioLevel(ext) => ext.marshal_to(buf),
            PlayoutDelay(ext) => ext.marshal_to(buf),
            TransportCc(ext) => ext.marshal_to(buf),
            VideoOrientation(ext) => ext.marshal_to(buf),
            AbsCaptureTime(ext) => ext.marshal_to(buf),
            CsrcAudioLevel(ext) => ext.marshal_to(buf),
            Mid(ext) => ext.marshal_to(buf),
            RtpStreamId(ext) => ext.marshal_to(buf),
            RepairedRtpStreamId(ext) => ext.marshal_to(buf),
            TransmissionOffset(ext) => ext.marshal_to(buf),
            Custom { extension: ext, .. } => ext.marshal_to(buf),
        }
    }
}

impl fmt::Debug for HeaderExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderExtension::*;

        match self {
            AbsSendTime(ext) => f.debug_tuple("AbsSendTime").field(ext).finish(),
            AudioLevel(ext) => f.debug_tuple("AudioLevel").field(ext).finish(),
            PlayoutDelay(ext) => f.debug_tuple("PlayoutDelay").field(ext).finish(),
            TransportCc(ext) => f.debug_tuple("TransportCc").field(ext).finish(),
            VideoOrientation(ext) => f.debug_tuple("VideoOrientation").field(ext).finish(),
            AbsCaptureTime(ext) => f.debug_tuple("AbsCaptureTime").field(ext).finish(),
            CsrcAudioLevel(ext) => f.debug_tuple("CsrcAudioLevel").field(ext).finish(),
            Mid(ext) => f.debug_tuple("Mid").field(ext).finish(),
            RtpStreamId(ext) => f.debug_tuple("RtpStreamId").field(ext).finish(),
            RepairedRtpStreamId(ext) => f.debug_tuple("RepairedRtpStreamId").field(ext).finish(),
            TransmissionOffset(ext) => f.debug_tuple("TransmissionOffset").field(ext).finish(),
            Custom { uri, extension: _ } => f.debug_struct("Custom").field("uri", uri).finish(),
        }
    }
}

#[cfg(test)]
mod extension_test;
