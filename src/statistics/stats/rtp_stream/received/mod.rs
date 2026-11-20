//! Received RTP stream statistics.
//!
//! This module contains statistics types for received RTP streams:
//!
//! - [`RTCReceivedRtpStreamStats`] - Base statistics for received streams
//! - [`inbound::RTCInboundRtpStreamStats`] - Local inbound stream statistics
//! - [`remote_inbound::RTCRemoteInboundRtpStreamStats`] - Remote inbound stream statistics

use super::RTCRtpStreamStats;
use serde::{Deserialize, Serialize};

pub mod inbound;
pub mod remote_inbound;

/// Base statistics for a received RTP stream.
///
/// This struct corresponds to the `RTCReceivedRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API. It provides common fields for streams received
/// from the network, including packet counts and jitter measurements.
///
/// This type is typically not used directly; instead, use
/// [`RTCInboundRtpStreamStats`](inbound::RTCInboundRtpStreamStats) or
/// [`RTCRemoteInboundRtpStreamStats`](remote_inbound::RTCRemoteInboundRtpStreamStats).
///
/// # Specification
///
/// See [RTCReceivedRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#receivedrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCReceivedRtpStreamStats {
    /// Base RTP stream statistics.
    #[serde(flatten)]
    pub rtp_stream_stats: RTCRtpStreamStats,

    /// Total number of RTP packets received.
    ///
    /// For a `remote-inbound-rtp` object this is estimated as webrtc-stats defines it: the
    /// extended highest sequence number the receiver report carries, minus the cumulative loss,
    /// minus the first sequence number sent, plus one (0 before the first report).
    pub packets_received: u64,

    /// Number of packets received with ECT(1) marking.
    ///
    /// The engine does not see ECN marks; left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_received_with_ect1: Option<u64>,

    /// Number of packets received with CE (Congestion Experienced) marking.
    ///
    /// The engine does not see ECN marks; left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_received_with_ce: Option<u64>,

    /// Number of packets reported as lost in RFC 8888 feedback.
    ///
    /// Not measured; left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_reported_as_lost: Option<u64>,

    /// Number of packets reported lost and later recovered.
    ///
    /// Not measured; left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_reported_as_lost_but_recovered: Option<u64>,

    /// Total number of packets lost (RFC 3550 section 6.4.1, cumulative number of packets
    /// lost).
    ///
    /// Signed: it is negative when duplicates make more packets arrive than were expected.
    pub packets_lost: i64,

    /// Inter-arrival jitter in seconds (RFC 3550 section 6.4.1, the report's value divided by
    /// the codec's clock rate).
    ///
    /// `None`, and left out of the JSON, until a report carries it and the clock rate is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<f64>,
}
