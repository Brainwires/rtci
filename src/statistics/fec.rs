//! FEC counts webrtc-stats has no member for.
//!
//! webrtc-stats defines FEC members for the receiving side only (`fecPacketsReceived`,
//! `fecBytesReceived`, `fecPacketsDiscarded`, `fecSsrc` of `RTCInboundRtpStreamStats`), and
//! the engine fills those in [`RTCPeerConnection::get_stats`]. What it also knows, and the
//! report has no place for, is here: the FEC each outbound stream sent, the media packets FEC
//! rebuilt, and why received FEC was discarded.
//!
//! [`RTCPeerConnection::get_stats`]: crate::peer_connection::RTCPeerConnection::get_stats

/// FEC of the streams of a peer connection
/// ([`RTCPeerConnection::fec_stats`](crate::peer_connection::RTCPeerConnection::fec_stats)).
/// A stream appears once it sent or received FEC, or had a packet rebuilt by FEC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FecStats {
    /// Per outbound stream.
    pub sent: Vec<FecSentStats>,
    /// Per inbound stream.
    pub received: Vec<FecReceivedStats>,
}

/// The FEC an outbound stream sent: the encoder's FEC payloads that left the interceptor
/// chain (the pacer and the circuit breaker let them through), in RED packets of the stream,
/// on a FEC SSRC, in a FEC session of its own (RFC 5109 section 14.1) or as FlexFEC repair
/// packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FecSentStats {
    /// The media stream's SSRC.
    pub ssrc: u32,
    /// FEC packets (or FEC blocks of RED packets) sent.
    pub fec_packets_sent: u64,
    /// Their octets: the FEC payloads, without the RTP or RED headers around them.
    pub fec_bytes_sent: u64,
}

/// The FEC an inbound stream received and what became of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FecReceivedStats {
    /// The media stream's SSRC.
    pub ssrc: u32,
    /// FEC packets received for the stream, by the engine's count: on its FEC SSRC, in a FEC
    /// session of its own and in its RED packets (webrtc-stats `fecPacketsReceived` without
    /// the in-band FEC an application supplies).
    pub fec_packets_received: u64,
    /// Their payload octets (`fecBytesReceived`, likewise).
    pub fec_bytes_received: u64,
    /// Of `fec_packets_received`, the FEC blocks that arrived in RED packets of the stream
    /// (RFC 5109 section 14.2).
    pub fec_packets_in_red: u64,
    /// Media packets FEC rebuilt and handed on (ULPFEC or FlexFEC).
    pub packets_recovered: u64,
    /// ULPFEC packets received whose correction was not used: the sum of the three reasons
    /// below (webrtc-stats `fecPacketsDiscarded` without what an application supplies).
    pub fec_packets_discarded: u64,
    /// Discarded because every packet they protect arrived or was already rebuilt.
    pub discarded_unneeded: u64,
    /// Discarded because the recovery window moved past them while they waited.
    pub discarded_expired: u64,
    /// Refused on arrival: malformed, outside the recovery window, or with more protection
    /// levels than this endpoint signalled (`onelevelonly`, RFC 5109 section 13).
    pub discarded_rejected: u64,
}
