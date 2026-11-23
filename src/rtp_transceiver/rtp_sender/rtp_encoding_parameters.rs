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
    /// W3C webrtc-svc `scalabilityMode`: the scalability mode of the stream (a mode of the
    /// webrtc-svc table, case sensitive, such as `"L1T3"`), video only. `None` leaves it to
    /// the encoder; `"L1T1"` is no scalability. Validated by `addTransceiver` and
    /// `setParameters` against the codecs (`rtp::codec::svc::ScalabilityMode::supported_by`).
    pub scalability_mode: Option<String>,
    /// webrtc-extensions 5 `scaleResolutionDownTo`: the largest frame this encoding sends,
    /// orientation agnostic; when set, `scale_resolution_down_by` is ignored and frames are
    /// never upscaled ([`RTCRtpEncodingParameters::scale_down_factor`]). Video only. When one
    /// active encoding has it, every active one must (OperationError in addTransceiver,
    /// InvalidModificationError in setParameters), with both dimensions above 0.
    pub scale_resolution_down_to: Option<RTCResolutionRestriction>,
    /// webrtc-extensions 5 `ptime`: the preferred duration of media in a packet, in
    /// milliseconds (the application's packetizer applies it).
    pub ptime: Option<u32>,
    /// webrtc-extensions 5 `adaptivePtime`: whether the frame length may change at any time;
    /// when false (the default) it is fixed. Set together with `ptime` it is an
    /// InvalidModificationError.
    pub adaptive_ptime: bool,
}

/// webrtc-extensions 5.1 `RTCResolutionRestriction`: the largest dimensions of a frame,
/// orientation agnostic (1280x720 and 720x1280 restrict alike).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RTCResolutionRestriction {
    /// `maxWidth`.
    pub max_width: u32,
    /// `maxHeight`.
    pub max_height: u32,
}

impl RTCResolutionRestriction {
    /// The factor a `width` x `height` frame is scaled down by to fit the restriction: the
    /// same for both dimensions, at least 1 (never an upscale), with the restriction turned
    /// to the frame's orientation.
    pub fn scale_down_factor(&self, width: u32, height: u32) -> f64 {
        let (long, short) = (width.max(height), width.min(height));
        let (max_long, max_short) = (
            self.max_width.max(self.max_height),
            self.max_width.min(self.max_height),
        );
        if long == 0 || short == 0 || max_long == 0 || max_short == 0 {
            return 1.0;
        }
        (f64::from(long) / f64::from(max_long))
            .max(f64::from(short) / f64::from(max_short))
            .max(1.0)
    }
}

impl RTCRtpEncodingParameters {
    /// The factor a `width` x `height` frame of the track is scaled down by for this
    /// encoding: by `scale_resolution_down_to` when it is set (and `scale_resolution_down_by`
    /// is then ignored, webrtc-extensions 5), else by `scale_resolution_down_by` (1 when
    /// unset). What the application's encoder applies.
    pub fn scale_down_factor(&self, width: u32, height: u32) -> f64 {
        match &self.scale_resolution_down_to {
            Some(restriction) => restriction.scale_down_factor(width, height),
            None => self.scale_resolution_down_by.unwrap_or(1.0),
        }
    }
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
            scalability_mode: None,
            scale_resolution_down_to: None,
            ptime: None,
            adaptive_ptime: false,
        }
    }
}
