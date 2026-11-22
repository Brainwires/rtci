use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

/// RTP encoding parameters for individual encodings in a simulcast or layered stream.
///
/// This is a subset of the ORTC specification since this implementation
/// doesn't perform encoding directly.
///
/// ## Specifications
///
/// * [ORTC](http://draft.ortc.org/#dom-rtcrtpencodingparameters)
#[derive(Debug, Clone)]
pub struct RTCRtpEncodingParameters {
    /// Base coding parameters (RID, SSRC, RTX, FEC)
    pub rtp_coding_parameters: RTCRtpCodingParameters,
    /// Whether this encoding is sent: `false` drops what is written for it and marks its rid
    /// paused (`~rid`) in the `a=simulcast` attribute (RFC 8853, Section 5.3). `true` by
    /// default, as W3C `RTCRtpEncodingParameters.active` is.
    pub active: bool,
    /// Codec to use for this encoding
    pub codec: RTCRtpCodec,
    /// Maximum bitrate in bits per second
    pub max_bitrate: u32,
    /// Maximum framerate in frames per second
    pub max_framerate: Option<f64>,
    /// Resolution scaling factor (must be >= 1.0)
    pub scale_resolution_down_by: Option<f64>,
    /// W3C webrtc-priority `priority`: the encoding's priority relative to the other flows of
    /// the connection, `low` by default. It sets the DSCP of its packets unless
    /// [`network_priority`](Self::network_priority) does (RFC 8837).
    pub priority: crate::peer_connection::priority::RTCPriorityType,
    /// W3C webrtc-priority `networkPriority`: the priority its packets are marked with (the
    /// DSCP, RFC 8837), when it is to differ from [`priority`](Self::priority).
    pub network_priority: Option<crate::peer_connection::priority::RTCPriorityType>,
}

impl Default for RTCRtpEncodingParameters {
    fn default() -> Self {
        Self {
            rtp_coding_parameters: RTCRtpCodingParameters::default(),
            active: true,
            codec: RTCRtpCodec::default(),
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
            priority: Default::default(),
            network_priority: None,
        }
    }
}
