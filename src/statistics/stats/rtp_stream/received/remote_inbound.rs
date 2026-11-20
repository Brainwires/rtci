//! Remote inbound RTP stream statistics.
//!
//! This module contains the [`RTCRemoteInboundRtpStreamStats`] type which provides
//! statistics about streams received by the remote peer, derived from RTCP reports.

use super::RTCReceivedRtpStreamStats;
use serde::{Deserialize, Serialize};

/// Statistics for a remote inbound RTP stream.
///
/// This struct corresponds to the `RTCRemoteInboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It represents the remote endpoint's view of the
/// stream sent by the local endpoint, derived from RTCP Receiver Reports.
///
/// This provides insight into how well the remote peer is receiving the local
/// peer's transmitted media.
///
/// # Specification
///
/// See [RTCRemoteInboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#remoteinboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteInboundRtpStreamStats {
    /// Base received RTP stream statistics.
    #[serde(flatten)]
    pub received_rtp_stream_stats: RTCReceivedRtpStreamStats,

    /// The ID of the corresponding local outbound stats.
    ///
    /// References an [`RTCOutboundRtpStreamStats`](super::super::sent::outbound::RTCOutboundRtpStreamStats) object.
    pub local_id: String,

    /// The most recent round trip time in seconds, from the receiver report's LSR and DLSR
    /// (RFC 3550 section 6.4.1).
    ///
    /// `None`, and left out of the JSON, until a report echoes one of our sender reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_trip_time: Option<f64>,

    /// Sum of every round trip time measured, in seconds.
    pub total_round_trip_time: f64,

    /// The receiver's fraction lost (0.0 to 1.0), from its latest report.
    pub fraction_lost: f64,

    /// Number of round trip time measurements.
    pub round_trip_time_measurements: u64,

    /// Packets whose ECT(1) marking was bleached; the engine does not see ECN, left out of the
    /// JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_with_bleached_ect1_marking: Option<u64>,
}
