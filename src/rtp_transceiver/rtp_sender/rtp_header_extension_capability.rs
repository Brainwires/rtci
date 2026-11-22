/// RTP header extension capability.
///
/// Defines an RFC 5285 RTP header extension supported by a codec.
///
/// ## Specifications
///
/// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpcapabilities-headerextensions)
#[derive(Default, Debug, Clone)]
pub struct RTCRtpHeaderExtensionCapability {
    /// URI identifying the header extension
    pub uri: String,
}

/// An RTP header extension with the direction this transceiver negotiates it in
/// (webrtc-extensions 4.1: `RTCRtpHeaderExtensionCapability` with its `direction` member; the
/// items of `[[HeaderExtensionsToNegotiate]]` and `[[NegotiatedHeaderExtensions]]`).
///
/// `direction` is from this side's point of view; `Stopped` means not negotiated.
/// `Inactive` is offered as `a=extmap:<id>/inactive`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpHeaderExtensionToNegotiate {
    /// The URI of the extension.
    pub uri: String,
    /// The direction: `Sendrecv` (the default), `Sendonly`, `Recvonly`, `Inactive` or
    /// `Stopped`.
    pub direction: crate::rtp_transceiver::RTCRtpTransceiverDirection,
}

/// How offers signal a header extension with respect to header extension encryption (RFC
/// 6904); see [`MediaEngine::set_header_extension_encryption`].
///
/// [`MediaEngine::set_header_extension_encryption`]: crate::peer_connection::configuration::media_engine::MediaEngine::set_header_extension_encryption
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RTCRtpHeaderExtensionEncryption {
    /// Offered in the clear only.
    #[default]
    Clear,
    /// Offered both in the clear and encrypted, under two ids: a peer that implements RFC
    /// 6904 takes the encrypted form, one that does not the clear one (RFC 6904 section 4.1
    /// "best-effort encryption"; an offerer "MUST offer only best-effort negotiation when lack
    /// of confidentiality would be acceptable").
    BestEffort,
    /// Offered encrypted only: a peer that does not implement RFC 6904 negotiates no such
    /// extension.
    Encrypted,
}
