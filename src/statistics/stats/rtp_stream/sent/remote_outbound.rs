//! Remote outbound RTP stream statistics.
//!
//! This module contains the [`RTCRemoteOutboundRtpStreamStats`] type which provides
//! statistics about streams sent by the remote peer, derived from RTCP reports.

use super::RTCSentRtpStreamStats;
use ::serde::{Deserialize, Serialize};
use shared::serde::instant_to_epoch;
use shared::time::SystemInstant;

/// Statistics for a remote outbound RTP stream.
///
/// This struct corresponds to the `RTCRemoteOutboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It represents the remote endpoint's view of the
/// stream it is sending, derived from RTCP Sender Reports.
///
/// This provides insight into the remote peer's transmission characteristics.
///
/// # Specification
///
/// See [RTCRemoteOutboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#remoteoutboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCRemoteOutboundRtpStreamStats {
    /// Base sent RTP stream statistics.
    #[serde(flatten)]
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    /// The ID of the corresponding local inbound stats.
    ///
    /// References an [`RTCInboundRtpStreamStats`](super::super::received::inbound::RTCInboundRtpStreamStats) object.
    pub local_id: String,

    /// The remote timestamp from the RTCP SR.
    ///
    /// This is the NTP timestamp from the sender report.
    #[serde(with = "instant_to_epoch")]
    pub remote_timestamp: SystemInstant,

    /// Number of RTCP Sender Reports sent.
    pub reports_sent: u64,

    /// The most recent round trip time in seconds, measured from an RTCP XR DLRR block
    /// (RFC 3611 section 4.5) answering one of our receiver reference time blocks.
    ///
    /// `None`, and left out of the JSON, until the remote sender has answered one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_trip_time: Option<f64>,

    /// Sum of every round trip time measured, in seconds (0: none is measured).
    pub total_round_trip_time: f64,

    /// Number of round trip time measurements (0: none is measured).
    pub round_trip_time_measurements: u64,
}
