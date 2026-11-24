//! A mark on the FEC an encoder sends, so the one who drives the chain can count it.

/// FEC carried by an outgoing RTP packet, attached by the FEC encoder that wrote it
/// ([`Attribute::Custom`](crate::Attribute::Custom)).
///
/// The packet may be a FEC packet of its own (a separate stream, a FEC session's stream, a
/// FlexFEC repair packet, a RED packet holding only FEC) or a media packet in RED that FEC
/// rides with (RFC 5109 section 14.2), so the count is the FEC it holds, not one per packet.
/// Read where packets leave the chain, it counts what the pacer and the circuit breaker let
/// through: `rtci`'s peer connection reports it as the FEC sent for `media_ssrc`
/// (`RTCPeerConnection::fec_stats`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecSent {
    /// The media stream the FEC protects (the first of them, for FlexFEC protecting several).
    pub media_ssrc: u32,
    /// FEC packets, or FEC blocks of a RED packet, in this packet.
    pub packets: u32,
    /// Their octets: the FEC payloads (FEC and level headers, or the FlexFEC header, and the
    /// repair data), not the RTP or RED headers around them.
    pub bytes: u64,
}

impl FecSent {
    /// The mark for one FEC payload of `bytes` octets protecting `media_ssrc`.
    pub fn one(media_ssrc: u32, bytes: usize) -> crate::Attribute {
        crate::Attribute::Custom(std::sync::Arc::new(Self {
            media_ssrc,
            packets: 1,
            bytes: bytes as u64,
        }))
    }
}
