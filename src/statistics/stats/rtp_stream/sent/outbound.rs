//! Outbound RTP stream statistics.
//!
//! This module contains the [`RTCOutboundRtpStreamStats`] type which provides
//! detailed statistics about locally sent RTP streams.
//!
//! The engine sends the RTP packets it is given; it does not encode them. Every member that
//! needs an encoder is an `Option` that stays `None`, and is left out of the JSON, until the
//! application supplies it through
//! [`RTCPeerConnection::update_encoder_stats`](crate::peer_connection::RTCPeerConnection::update_encoder_stats).

use super::super::super::RTCQualityLimitationReason;
use super::RTCSentRtpStreamStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `skip_serializing_if` for the congestion controller's estimate: 0 is "no estimate yet".
fn no_estimate(bits_per_second: &f64) -> bool {
    *bits_per_second == 0.0
}

/// Statistics for a locally sent outbound RTP stream.
///
/// This struct corresponds to the `RTCOutboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API.
///
/// # Specification
///
/// See [RTCOutboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#outboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCOutboundRtpStreamStats {
    /// Base sent RTP stream statistics.
    #[serde(flatten)]
    pub sent_rtp_stream_stats: RTCSentRtpStreamStats,

    /// The media ID (mid) from SDP; empty, and left out of the JSON, when there is none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mid: String,

    /// The ID of the media-source stats object of the sender's track.
    ///
    /// Empty, and left out of the JSON, while the sender has no track with a media-source
    /// object.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_source_id: String,

    /// The ID of the corresponding remote-inbound stats object.
    ///
    /// `None`, and left out of the JSON, until the first RTCP receiver report about this SSRC
    /// has arrived: the remote-inbound object does not exist before then (webrtc-stats 6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,

    /// The RTP stream identifier (RID); empty, and left out of the JSON, without simulcast.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rid: String,

    /// Index of this encoding in the sender's encodings; video only, `None` for audio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding_index: Option<u32>,

    /// Total bytes sent in RTP headers.
    pub header_bytes_sent: u64,

    /// Number of retransmitted packets sent.
    pub retransmitted_packets_sent: u64,

    /// Bytes sent via retransmission.
    pub retransmitted_bytes_sent: u64,

    /// SSRC of the RTX stream; left out of the JSON when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtx_ssrc: Option<u32>,

    /// The congestion controller's target bitrate in bits per second.
    ///
    /// 0, and left out of the JSON, until a congestion controller has produced an estimate.
    #[serde(default, skip_serializing_if = "no_estimate")]
    pub target_bitrate: f64,

    /// Cumulative target encoded bytes (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_encoded_bytes_target: Option<u64>,

    /// Width of the last encoded frame in pixels (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_width: Option<u32>,

    /// Height of the last encoded frame in pixels (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_height: Option<u32>,

    /// Encoded frames per second over the last second (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_per_second: Option<f64>,

    /// Frames sent (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_sent: Option<u32>,

    /// Huge frames sent (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub huge_frames_sent: Option<u32>,

    /// Frames encoded (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_encoded: Option<u32>,

    /// Key frames encoded (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_frames_encoded: Option<u32>,

    /// Sum of the QP values of encoded frames (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qp_sum: Option<u64>,

    /// PSNR sums by component; needs an encoder, left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psnr_sum: Option<HashMap<String, f64>>,

    /// Number of PSNR measurements; needs an encoder, left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psnr_measurements: Option<u64>,

    /// Total time spent encoding, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_encode_time: Option<f64>,

    /// Total time packets spent buffered before being sent, in seconds; the engine sends what
    /// it is given at once and has no pacer, so this is left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_packet_send_delay: Option<f64>,

    /// The current quality limitation reason (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_limitation_reason: Option<RTCQualityLimitationReason>,

    /// Time spent in each quality limitation state; needs an encoder, left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_limitation_durations: Option<HashMap<String, f64>>,

    /// Resolution changes made for quality limitation (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_limitation_resolution_changes: Option<u32>,

    /// Number of NACK packets received.
    pub nack_count: u32,

    /// Number of FIR packets received.
    pub fir_count: u32,

    /// Number of PLI packets received.
    pub pli_count: u32,

    /// Name of the encoder implementation (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder_implementation: Option<String>,

    /// Whether the encoder is power efficient (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_efficient_encoder: Option<bool>,

    /// Whether this stream is currently being sent.
    pub active: bool,

    /// The scalability mode, e.g. "L1T3" (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scalability_mode: Option<String>,

    /// Packets sent with ECT(1) marking; the engine does not mark ECN, left out of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_sent_with_ect1: Option<u64>,
}
