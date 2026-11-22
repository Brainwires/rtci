/// RTCP parameters for RTP streams.
///
/// ## Specifications
///
/// * [W3C](https://www.w3.org/TR/webrtc/#rtcrtcpparameters)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtcpParameters {
    /// The Canonical Name (CNAME) used by RTCP (e.g., in SDES messages)
    pub cname: String,
    /// Whether reduced-size RTCP mode is in use
    pub reduced_size: bool,
}

/// Transport-wide congestion control feedback type
pub const TYPE_RTCP_FB_TRANSPORT_CC: &str = "transport-cc";

/// Google REMB (Receiver Estimated Maximum Bitrate) feedback type
pub const TYPE_RTCP_FB_GOOG_REMB: &str = "goog-remb";

/// Acknowledgment feedback type
pub const TYPE_RTCP_FB_ACK: &str = "ack";

/// The `ack` parameter of RFC 8888 congestion control feedback: `a=rtcp-fb:<pt> ack ccfb`.
pub const RTCP_FB_ACK_CCFB: &str = "ccfb";

/// Whether a feedback list negotiates RFC 8888 congestion control feedback (`ack ccfb`).
pub(crate) fn negotiates_ccfb<'a>(feedback: impl IntoIterator<Item = (&'a str, &'a str)>) -> bool {
    feedback
        .into_iter()
        .any(|(typ, parameter)| typ == TYPE_RTCP_FB_ACK && parameter == RTCP_FB_ACK_CCFB)
}

/// Codec Control Message feedback type
pub const TYPE_RTCP_FB_CCM: &str = "ccm";

/// Negative Acknowledgment feedback type
pub const TYPE_RTCP_FB_NACK: &str = "nack";

/// The `nack` parameter of the RFC 6679 RTCP ECN feedback packet: `a=rtcp-fb:<pt> nack ecn`.
pub const RTCP_FB_NACK_ECN: &str = "ecn";

/// RTCP feedback parameters for specifying additional packet types.
///
/// Used to signal support for specific RTCP feedback mechanisms such as NACK, PLI, FIR, etc.
///
/// ## Specifications
///
/// * [ORTC](https://draft.ortc.org/#dom-rtcrtcpfeedback)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCPFeedback {
    /// The type of feedback mechanism.
    ///
    /// Valid values: `ack`, `ccm`, `nack`, `goog-remb`, `transport-cc`
    ///
    /// ## Specifications
    ///
    /// * [ORTC](https://draft.ortc.org/#dom-rtcrtcpfeedback)
    pub typ: String,

    /// Additional parameter specific to the feedback type.
    ///
    /// For example: `type="nack" parameter="pli"` indicates Picture Loss Indicator packets.
    pub parameter: String,
}
