//! ICE candidate statistics.
//!
//! This module contains the [`RTCIceCandidateStats`] type which provides
//! information about ICE candidates.

use super::RTCStats;
use crate::peer_connection::transport::RTCIceCandidateType;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceServerTransportProtocol, RTCIceTcpCandidateType,
};
use serde::{Deserialize, Serialize};

/// Not a relay candidate (or the relay protocol is unknown): `relayProtocol` is left out.
fn relay_protocol_unknown(protocol: &RTCIceServerTransportProtocol) -> bool {
    *protocol == RTCIceServerTransportProtocol::Unspecified
}

/// Not a TCP candidate: `tcpType` is left out.
fn tcp_type_unknown(tcp_type: &RTCIceTcpCandidateType) -> bool {
    *tcp_type == RTCIceTcpCandidateType::Unspecified
}

/// Statistics for an ICE candidate.
///
/// This struct corresponds to the `RTCIceCandidateStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about a local or
/// remote ICE candidate discovered during ICE gathering.
///
/// # Specification
///
/// See [RTCIceCandidateStats](https://www.w3.org/TR/webrtc-stats/#icecandidate-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The ID of the transport this candidate belongs to.
    pub transport_id: String,

    /// The IP address of the candidate.
    ///
    /// This may be `None` if the address is not available or redacted
    /// for privacy reasons.
    pub address: Option<String>,

    /// The port number of the candidate.
    pub port: u16,

    /// The transport protocol used ("udp" or "tcp").
    pub protocol: String,

    /// The type of ICE candidate.
    ///
    /// Values: host, srflx (server-reflexive), prflx (peer-reflexive), relay.
    pub candidate_type: RTCIceCandidateType,

    /// The priority of the candidate (RFC 8445 section 5.1.2), all 32 bits.
    ///
    /// Higher values indicate higher priority candidates.
    pub priority: u32,

    /// The URL of the ICE server used to gather this candidate.
    ///
    /// For host candidates, this is empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,

    /// The protocol used to communicate with the TURN server.
    ///
    /// Only applicable for relay candidates.
    #[serde(default, skip_serializing_if = "relay_protocol_unknown")]
    pub relay_protocol: RTCIceServerTransportProtocol,

    /// The foundation string for the candidate.
    ///
    /// Candidates with the same foundation can potentially be
    /// used for candidate pair pruning.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub foundation: String,

    /// The related address for derived candidates.
    ///
    /// For server-reflexive candidates, this is the host address.
    /// For relay candidates, this is the server-reflexive address.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub related_address: String,

    /// The related port for derived candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_port: Option<u16>,

    /// The username fragment from ICE credentials.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username_fragment: String,

    /// The TCP candidate type.
    ///
    /// Only applicable when protocol is "tcp".
    /// Values: active, passive, so (simultaneous-open).
    #[serde(default, skip_serializing_if = "tcp_type_unknown")]
    pub tcp_type: RTCIceTcpCandidateType,
}
