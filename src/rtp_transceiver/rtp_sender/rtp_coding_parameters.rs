use crate::rtp_transceiver::{PayloadType, RtpStreamId, SSRC};

/// RTP coding parameters providing information for encoding and decoding.
///
/// Contains the RTP-level parameters that identify and configure a specific
/// encoding or decoding of a media stream. This includes the SSRC, optional
/// RID for simulcast identification, and parameters for retransmission (RTX)
/// and forward error correction (FEC).
///
/// # Fields
///
/// * `rid` - RTP stream identifier, used in simulcast to identify quality layers (e.g., "q", "h", "f")
/// * `ssrc` - Synchronization source identifier, uniquely identifies this RTP stream
/// * `rtx` - Optional retransmission parameters for packet loss recovery
/// * `fec` - Optional forward error correction parameters
/// * `rid_restrictions` - The restrictions of the rid's `a=rid` line (RFC 8851 section 5)
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpCodingParameters;
///
/// // Basic parameters without retransmission or FEC
/// let params = RTCRtpCodingParameters {
///     rid: "".to_string(),
///     ssrc: Some(12345),
///     rtx: None,
///     fec: None,
///     ..Default::default()
/// };
/// ```
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpRtxParameters};
///
/// // Simulcast layer with retransmission
/// let params = RTCRtpCodingParameters {
///     rid: "h".to_string(),  // half resolution layer
///     ssrc: Some(12345),
///     rtx: Some(RTCRtpRtxParameters {
///         ssrc: 12346,  // RTX uses different SSRC
///     }),
///     fec: None,
///     ..Default::default()
/// };
/// ```
///
/// # Specification
///
/// * [ORTC RTCRtpCodingParameters](http://draft.ortc.org/#dom-rtcrtpcodingparameters)
/// * [RFC 4588 - RTP Retransmission Payload Format](https://datatracker.ietf.org/doc/html/rfc4588)
/// * [RFC 8852 - RTP Stream Identifier](https://datatracker.ietf.org/doc/html/rfc8852)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCodingParameters {
    /// RTP stream identifier for simulcast/layered streams
    pub rid: RtpStreamId,

    /// Synchronization source identifier
    pub ssrc: Option<SSRC>,
    /// RTX (retransmission) parameters
    pub rtx: Option<RTCRtpRtxParameters>,
    /// FEC (forward error correction) parameters
    pub fec: Option<RTCRtpFecParameters>,
    /// The restrictions of this rid (RFC 8851 section 5), for an encoding that has a rid.
    ///
    /// On a sender's encoding: what the application sets before the offer is written into
    /// the encoding's `a=rid:<rid> send` line; once an answer is applied, these are the
    /// restrictions the answer kept (the same ones, or tighter: RFC 8851 section 6.4), and
    /// the encoder has to stay within them. On an encoding this endpoint sends because a
    /// remote offer asked to receive it (`a=rid:<rid> recv`), the offer's restrictions.
    ///
    /// On a receiver's coding parameters: what the remote `a=rid:<rid> send` line says the
    /// stream is restricted to.
    pub rid_restrictions: RTCRtpRidRestrictions,
}

/// The restrictions an `a=rid` line places on an RTP stream (RFC 8851 section 5). `None`,
/// or an empty list, is "not restricted".
///
/// The engine carries them between the description and the application: it neither encodes
/// nor measures media, so the application's encoder is what keeps a stream within them.
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpRidRestrictions};
///
/// // `a=rid:q send max-width=320;max-height=180;max-fps=15`
/// let quarter = RTCRtpCodingParameters {
///     rid: "q".to_string(),
///     ssrc: Some(3),
///     rid_restrictions: RTCRtpRidRestrictions {
///         max_width: Some(320),
///         max_height: Some(180),
///         max_fps: Some(15),
///         ..Default::default()
///     },
///     ..Default::default()
/// };
/// assert!(quarter.rid_restrictions.payload_types.is_empty());
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub struct RTCRtpRidRestrictions {
    /// `pt=`: the payload types the stream may use. Empty: any format of the media section.
    pub payload_types: Vec<PayloadType>,
    /// `max-width`: the width of a frame, in pixels.
    pub max_width: Option<u64>,
    /// `max-height`: the height of a frame, in pixels.
    pub max_height: Option<u64>,
    /// `max-fps`: frames per second.
    pub max_fps: Option<u64>,
    /// `max-fs`: the size of a frame, in pixels.
    pub max_fs: Option<u64>,
    /// `max-br`: the bit rate, in bits per second.
    pub max_br: Option<u64>,
    /// `max-pps`: pixels per second.
    pub max_pps: Option<u64>,
    /// `max-bpp`: bits per pixel.
    pub max_bpp: Option<f64>,
    /// `depend`: the rids of the streams this one depends on (RFC 8851 section 5: layered
    /// encodings sent as separate RTP streams).
    pub depend: Vec<RtpStreamId>,
}

impl RTCRtpRidRestrictions {
    /// Whether nothing is restricted.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// RTX parameters for retransmission streams.
///
/// Configures a separate RTP stream used for retransmitting lost packets.
/// The RTX stream uses its own SSRC to avoid interfering with the original
/// media stream.
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpRtxParameters;
///
/// let rtx = RTCRtpRtxParameters {
///     ssrc: 67890,  // Different from the main stream's SSRC
/// };
/// ```
///
/// # Specification
///
/// * [ORTC RTCRtpRtxParameters](https://draft.ortc.org/#dom-rtcrtprtxparameters)
/// * [RFC 4588 - RTP Retransmission Payload Format](https://datatracker.ietf.org/doc/html/rfc4588)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpRtxParameters {
    /// SSRC for the RTX stream
    pub ssrc: SSRC,
}

/// FEC parameters for forward error correction streams.
///
/// Configures a separate RTP stream used for forward error correction,
/// allowing receivers to recover from packet loss without retransmission.
/// The FEC stream uses its own SSRC.
///
/// # Examples
///
/// ```
/// use rtc::rtp_transceiver::rtp_sender::RTCRtpFecParameters;
///
/// let fec = RTCRtpFecParameters {
///     ssrc: 99999,  // Different from the main stream's SSRC
/// };
/// ```
///
/// # Specification
///
/// * [ORTC RTCRtpFecParameters](https://draft.ortc.org/#dom-rtcrtpfecparameters)
/// * [RFC 5109 - RTP Payload Format for Generic FEC](https://datatracker.ietf.org/doc/html/rfc5109)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpFecParameters {
    /// SSRC for the FEC stream
    pub ssrc: SSRC,
}
