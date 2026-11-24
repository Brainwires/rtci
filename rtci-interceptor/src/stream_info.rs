//! Stream information types for interceptor binding.
//!
//! This module provides types that describe media streams for interceptor binding.
//! When a stream is bound to an interceptor chain, [`StreamInfo`] provides all the
//! necessary metadata about the stream's codec, SSRC, and supported features.
//!
//! # Stream Binding
//!
//! Interceptors need to know about streams before they can process packets:
//!
//! - **Local streams** (outgoing): Bind with [`Interceptor::bind_local_stream`]
//! - **Remote streams** (incoming): Bind with [`Interceptor::bind_remote_stream`]
//!
//! # Feature Detection
//!
//! Interceptors use [`StreamInfo`] to detect which features are supported:
//!
//! - **NACK support**: Check [`rtcp_feedback`](StreamInfo::rtcp_feedback) for `type: "nack"`
//! - **TWCC support**: Check [`rtp_header_extensions`](StreamInfo::rtp_header_extensions) for the TWCC URI
//! - **RTX support**: Check if [`ssrc_rtx`](StreamInfo::ssrc_rtx) and [`payload_type_rtx`](StreamInfo::payload_type_rtx) are set

/// RTP header extension as negotiated via SDP (RFC 5285).
///
/// Represents a header extension that can be used to add metadata to RTP packets,
/// such as audio levels, video orientation, or custom application data.
///
/// # Common Extension URIs
///
/// | URI | Description |
/// |-----|-------------|
/// | `urn:ietf:params:rtp-hdrext:ssrc-audio-level` | Audio level indication |
/// | `urn:ietf:params:rtp-hdrext:toffset` | Transmission time offset |
/// | `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time` | Absolute send time |
/// | `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01` | TWCC sequence number |
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTPHeaderExtension {
    /// URI identifying the extension type (e.g., "urn:ietf:params:rtp-hdrext:ssrc-audio-level")
    pub uri: String,
    /// Local identifier (1-14 for one-byte, 1-255 for two-byte) used in RTP packets to reference this extension
    pub id: u16,
}

/// RTCP feedback mechanism negotiated for the stream.
///
/// Specifies additional RTCP packet types that can be used for feedback
/// between peers, such as NACK for retransmissions or PLI for picture loss.
///
/// # Common Feedback Types
///
/// | Type | Parameter | Description | RFC |
/// |------|-----------|-------------|-----|
/// | `nack` | (empty) | Generic NACK for retransmission | RFC 4585 |
/// | `nack` | `pli` | Picture Loss Indication | RFC 4585 |
/// | `nack` | `fir` | Full Intra Request | RFC 5104 |
/// | `ccm` | `fir` | Codec Control Message: FIR | RFC 5104 |
/// | `goog-remb` | (empty) | Google REMB for bandwidth estimation | - |
/// | `transport-cc` | (empty) | Transport-wide CC feedback | draft-holmer |
///
/// See: <https://draft.ortc.org/#dom-rtcrtcpfeedback>
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCPFeedback {
    /// Type of feedback mechanism.
    ///
    /// Valid values: "ack", "ccm", "nack", "goog-remb", "transport-cc"
    ///
    /// See: <https://draft.ortc.org/#dom-rtcrtcpfeedback>
    pub typ: String,

    /// Parameter value that depends on the feedback type.
    ///
    /// For example, `typ="nack"` with `parameter="pli"` enables Picture Loss Indicator packets.
    /// An empty string indicates the base feedback type without additional parameters.
    pub parameter: String,
}

/// Stream context passed to interceptor bind/unbind callbacks.
///
/// Contains all relevant information about a media stream (audio or video)
/// when it's bound to or unbound from an interceptor. This includes codec
/// parameters, SSRC, RTP extensions, and RTCP feedback mechanisms.
///
/// Used by [`Interceptor::bind_local_stream`](crate::Interceptor::bind_local_stream),
/// [`Interceptor::unbind_local_stream`](crate::Interceptor::unbind_local_stream),
/// [`Interceptor::bind_remote_stream`](crate::Interceptor::bind_remote_stream), and
/// [`Interceptor::unbind_remote_stream`](crate::Interceptor::unbind_remote_stream).
///
/// # Example
///
/// ```
/// use rtci_interceptor::{StreamInfo, RTCPFeedback, RTPHeaderExtension};
///
/// let info = StreamInfo {
///     ssrc: 0x12345678,
///     clock_rate: 90000,
///     mime_type: "video/VP8".to_string(),
///     payload_type: 96,
///     // Enable NACK for retransmission
///     rtcp_feedback: vec![RTCPFeedback {
///         typ: "nack".to_string(),
///         parameter: String::new(),
///     }],
///     ..Default::default()
/// };
/// ```
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    /// Synchronization Source identifier (SSRC) of the stream.
    ///
    /// Uniquely identifies the source of an RTP stream within an RTP session.
    pub ssrc: u32,

    /// RTX (Retransmission) SSRC for RFC 4588 retransmission.
    ///
    /// When set, retransmissions will use this separate SSRC instead of the
    /// original stream's SSRC. This allows the receiver to distinguish between
    /// original and retransmitted packets.
    pub ssrc_rtx: Option<u32>,

    /// FEC (Forward Error Correction) SSRC.
    ///
    /// SSRC used for FEC packets if separate-stream FEC is configured.
    pub ssrc_fec: Option<u32>,

    /// RTP payload type (e.g., 96 for VP8, 111 for Opus).
    ///
    /// Dynamic payload types (96-127) are typically used for modern codecs.
    pub payload_type: u8,

    /// RTX payload type for RFC 4588 retransmission.
    ///
    /// When set along with `ssrc_rtx`, retransmitted packets will use this
    /// payload type to distinguish them from original packets.
    pub payload_type_rtx: Option<u8>,

    /// FEC payload type.
    ///
    /// Payload type used for FEC packets if configured.
    pub payload_type_fec: Option<u8>,

    /// Negotiated RTP header extensions for this stream.
    ///
    /// Contains the list of header extensions that can be used with this stream,
    /// such as TWCC sequence numbers, audio levels, or video orientation.
    pub rtp_header_extensions: Vec<RTPHeaderExtension>,

    /// MIME type of the codec (e.g., "video/VP8", "audio/opus").
    pub mime_type: String,

    /// Clock rate in Hz (e.g., 90000 for video, 48000 for Opus audio).
    ///
    /// Used to convert between RTP timestamps and wall-clock time.
    pub clock_rate: u32,

    /// Number of audio channels (0 for video, 1 for mono, 2 for stereo).
    pub channels: u16,

    /// Format-specific parameters from SDP (fmtp line).
    ///
    /// Contains codec-specific parameters like "profile-level-id" for H.264
    /// or "minptime" for audio codecs.
    pub sdp_fmtp_line: String,

    /// RTCP feedback mechanisms negotiated for this stream.
    ///
    /// Specifies which RTCP feedback types (NACK, PLI, REMB, etc.) are
    /// supported for this stream.
    pub rtcp_feedback: Vec<RTCPFeedback>,

    /// MIME type of the FEC format `payload_type_fec` names (e.g. "video/flexfec-03",
    /// "video/flexfec").
    ///
    /// It selects the coder: FlexFEC draft-03 (`flexfec-03`) and RFC 8627 (`flexfec`) are
    /// different wire formats. Empty means the stream does not say, and the draft-03
    /// interceptors, the only FEC there was before this field, take it as theirs.
    pub mime_type_fec: String,

    /// Format-specific parameters of the FEC format (its `a=fmtp` line), e.g.
    /// "repair-window=200000".
    pub sdp_fmtp_line_fec: String,

    /// The clock rate of each payload type the stream may carry besides `payload_type`, for a
    /// source that switches payload type (and with it clock rate, RFC 7160 section 4.3), e.g.
    /// Opus at 48000 and PCMU at 8000 on one SSRC. Empty: every packet is at `clock_rate`.
    pub payload_clock_rates: Vec<(u8, u32)>,

    /// A local stream the session description starts paused (RFC 8853 section 5.2: a rid-id
    /// marked `~`, "an unsolicited locally paused stream"). The RFC 7728 interceptor starts
    /// it paused when pause and resume were negotiated for it; other interceptors ignore it.
    pub initially_paused: bool,
    /// The `a=fmtp` parameters of every format of the stream's m= section by payload type,
    /// repair and redundancy formats included (RTX, RED, ULPFEC, FlexFEC), for an interceptor
    /// that acts on a format the stream does not name itself: the ULPFEC interceptors read
    /// `onelevelonly` (RFC 5109 section 13) of their `ulpfec` format here. Empty when the
    /// binder did not say.
    pub section_fmtp_lines: Vec<(u8, String)>,
    /// The MIME type of every format of the stream's m= section by payload type, repair and
    /// redundancy formats included, for an interceptor that acts on a format the stream does
    /// not name itself: the RED interceptor finds the section's `red` format here (RFC 2198
    /// section 5). For a local stream the peer connection lists them in the order of the
    /// remote description's m= line, the remote side's order of preference (RFC 3264 sections
    /// 5.1 and 6.1), which decides whether the RED interceptor sends RED. Empty when the
    /// binder did not say.
    pub section_mime_types: Vec<(u8, String)>,
    /// The stream's ULPFEC stream when it runs in an RTP session of its own (RFC 5109 section
    /// 14.1): see [`FecSessionStream`]. `None` for FEC in the media's own session (RED, or a
    /// repair flow on [`ssrc_fec`](Self::ssrc_fec)) and for no FEC.
    pub fec_session: Option<FecSessionStream>,
}

/// The FEC stream of a media stream, sent in a separate RTP session (RFC 5109 section 14.1:
/// "the FEC stream and the payload stream SHOULD be sent through two separate RTP session").
///
/// In that session the FEC stream has the media stream's SSRC (section 7.2: "The SSRC value
/// SHALL be the same as the SSRC value of the media stream it protects"). A chain keys what
/// it keeps on the SSRC, and both sessions pass through the one chain, so within the chain
/// the FEC stream is known by an SSRC of its own, [`ssrc`](Self::ssrc); whoever drives the
/// chain puts the media stream's SSRC back on the FEC session's transport and takes it off
/// again on the way in ([`FecSessionSsrcMap`](crate::FecSessionSsrcMap)), and binds
/// [`ssrc`](Self::ssrc) as a stream of that session.
///
/// It is a field of its own, not [`StreamInfo::ssrc_fec`]: a repair flow named there is part
/// of the media stream's own RTP session for every interceptor (the RTCP session reports on
/// it there, the per-session wrappers move the stream with it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecSessionStream {
    /// The SSRC the FEC stream has inside the chain.
    pub ssrc: u32,
    /// The payload type of `ulpfec` in the FEC session's m= section (RFC 5109 section 14.1:
    /// "dynamic payload type numbers MUST be used").
    pub payload_type: u8,
    /// `onelevelonly=1` on that format (RFC 5109 section 13).
    pub one_level_only: bool,
}

impl StreamInfo {
    /// Whether this stream's FEC flow is FlexFEC draft-03 (`<type>/flexfec-03`), or does not
    /// name its format.
    pub fn fec_is_flexfec03(&self) -> bool {
        self.mime_type_fec.is_empty() || fec_subtype_is(&self.mime_type_fec, "flexfec-03")
    }

    /// Whether this stream's FEC flow is ULPFEC as a stream of its own (`<type>/ulpfec`, RFC
    /// 5109 section 14.1, grouped by `a=ssrc-group:FEC-FR`, RFC 5956 section 4.3).
    pub fn fec_is_ulpfec(&self) -> bool {
        fec_subtype_is(&self.mime_type_fec, "ulpfec")
    }

    /// Whether this stream's FEC flow is RFC 8627 FlexFEC (`<type>/flexfec`).
    pub fn fec_is_flexfec(&self) -> bool {
        fec_subtype_is(&self.mime_type_fec, "flexfec")
    }
}

/// Whether `mime_type` is `<type>/<subtype>`, compared without case and exactly: `flexfec` must
/// not match `flexfec-03`.
fn fec_subtype_is(mime_type: &str, subtype: &str) -> bool {
    mime_type
        .split_once('/')
        .is_some_and(|(_, found)| found.eq_ignore_ascii_case(subtype))
}
