/// Negotiated RTP header extension parameters.
///
/// Represents an RFC 5285 RTP header extension that has been negotiated
/// between sender and receiver.
///
/// ## Specifications
///
/// * [W3C](https://www.w3.org/TR/webrtc/#dictionary-rtcrtpheaderextensionparameters-members)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpHeaderExtensionParameters {
    /// URI identifying the header extension
    pub uri: String,
    /// Local identifier for this extension (1-14 for one-byte, 1-255 for two-byte)
    pub id: u16,
    /// Whether this extension should be encrypted: it was negotiated in its RFC 6904 form
    /// (`a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`), and the SRTP contexts
    /// encrypt and decrypt its payload.
    pub encrypted: bool,
    /// The extension attributes the peer's description gave the extension, after its URI
    /// (RFC 8285 section 5 `extensionattributes`); for the client-to-mixer audio level,
    /// `vad=on` or `vad=off` (RFC 6464 section 4: with `vad=off` the V bit is to be ignored,
    /// see `rtp::extension::audio_level_extension::parse_vad_attribute`). `None` when it gave
    /// none, or before negotiation.
    pub attributes: Option<String>,
}
