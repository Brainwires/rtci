//! Inbound RTP stream statistics.
//!
//! This module contains the [`RTCInboundRtpStreamStats`] type which provides
//! detailed statistics about locally received RTP streams.
//!
//! The engine is a transport: it sees RTP packets, not decoded frames or played-out samples.
//! Every member that needs a decoder, a jitter buffer or a playout device is an `Option` that
//! stays `None`, and is left out of the JSON, until the application supplies it through
//! [`RTCPeerConnection::update_decoder_stats`](crate::peer_connection::RTCPeerConnection::update_decoder_stats)
//! or
//! [`RTCPeerConnection::update_audio_receiver_stats`](crate::peer_connection::RTCPeerConnection::update_audio_receiver_stats).

use super::RTCReceivedRtpStreamStats;
use ::serde::{Deserialize, Serialize};
use shared::time::SystemInstant;

/// Statistics for a locally received inbound RTP stream.
///
/// This struct corresponds to the `RTCInboundRtpStreamStats` dictionary in the
/// W3C WebRTC Statistics API.
///
/// # Specification
///
/// See [RTCInboundRtpStreamStats](https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCInboundRtpStreamStats {
    /// Base received RTP stream statistics.
    #[serde(flatten)]
    pub received_rtp_stream_stats: RTCReceivedRtpStreamStats,

    /// The identifier of the receiver's track.
    pub track_identifier: String,

    /// The media ID (mid) from SDP; empty, and left out of the JSON, when there is none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mid: String,

    /// The ID of the corresponding remote-outbound stats object.
    ///
    /// `None`, and left out of the JSON, until the first RTCP Sender Report for this SSRC has
    /// arrived: the remote-outbound object does not exist before then (webrtc-stats 6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,

    /// Number of frames successfully decoded (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_decoded: Option<u32>,

    /// Number of key frames decoded (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_frames_decoded: Option<u32>,

    /// Number of frames rendered (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_rendered: Option<u32>,

    /// Number of frames dropped before decoding (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_dropped: Option<u32>,

    /// Width of the last decoded frame in pixels (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_width: Option<u32>,

    /// Height of the last decoded frame in pixels (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_height: Option<u32>,

    /// Decoded frames per second over the last second (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_per_second: Option<f64>,

    /// Sum of the QP values of decoded frames (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qp_sum: Option<u64>,

    /// Total time spent decoding, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_decode_time: Option<f64>,

    /// Sum of inter-frame delays, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_inter_frame_delay: Option<f64>,

    /// Sum of squared inter-frame delays (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_squared_inter_frame_delay: Option<f64>,

    /// Number of pauses (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_count: Option<u32>,

    /// Total duration of pauses, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_pauses_duration: Option<f64>,

    /// Number of freezes (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_count: Option<u32>,

    /// Total duration of freezes, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_freezes_duration: Option<f64>,

    /// Timestamp of the last received packet; left out of the JSON before the first one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::statistics::stats::optional_instant_to_epoch"
    )]
    pub last_packet_received_timestamp: Option<SystemInstant>,

    /// Total RTP header and padding bytes received, those of retransmissions and of the
    /// stream's RTX and FEC packets included.
    pub header_bytes_received: u64,

    /// Number of packets the jitter buffer discarded (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets_discarded: Option<u64>,

    /// Total FEC payload bytes received: those of the stream's FEC SSRC, and the in-band FEC
    /// the application reports. A subset of `bytes_received`.
    pub fec_bytes_received: u64,

    /// Number of FEC packets received: on the stream's FEC SSRC, and the in-band ones the
    /// application reports.
    pub fec_packets_received: u64,

    /// Number of FEC packets whose correction was not used (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec_packets_discarded: Option<u64>,

    /// Total payload bytes received (excluding headers).
    pub bytes_received: u64,

    /// Number of NACK packets sent.
    pub nack_count: u32,

    /// Number of FIR packets sent; video only, `None` (and left out of the JSON) for audio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fir_count: Option<u32>,

    /// Number of PLI packets sent; video only, `None` (and left out of the JSON) for audio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pli_count: Option<u32>,

    /// Total processing delay, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_processing_delay: Option<f64>,

    /// The track's playout position on the sender's clock (application-provided).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::statistics::stats::optional_instant_to_epoch"
    )]
    pub estimated_playout_timestamp: Option<SystemInstant>,

    /// Cumulative jitter buffer delay, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_buffer_delay: Option<f64>,

    /// Cumulative jitter buffer target delay, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_buffer_target_delay: Option<f64>,

    /// Samples or frames emitted from the jitter buffer (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_buffer_emitted_count: Option<u64>,

    /// Cumulative jitter buffer minimum delay, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_buffer_minimum_delay: Option<f64>,

    /// Total audio samples received (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_samples_received: Option<u64>,

    /// Concealed audio samples (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concealed_samples: Option<u64>,

    /// Silent concealed audio samples (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silent_concealed_samples: Option<u64>,

    /// Concealment events (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concealment_events: Option<u64>,

    /// Samples inserted to slow playout down (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inserted_samples_for_deceleration: Option<u64>,

    /// Samples removed to speed playout up (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_samples_for_acceleration: Option<u64>,

    /// Audio level, 0.0 to 1.0 (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_level: Option<f64>,

    /// Total audio energy (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_audio_energy: Option<f64>,

    /// Total duration of received audio samples, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_samples_duration: Option<f64>,

    /// Complete frames received (application-provided: the frame assembler counts them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_received: Option<u32>,

    /// Name of the decoder implementation (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder_implementation: Option<String>,

    /// The ID of the audio playout stats object; set once one is fed for this stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playout_id: Option<String>,

    /// Whether the decoder is power efficient (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_efficient_decoder: Option<bool>,

    /// Frames assembled from more than one packet (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_assembled_from_multiple_packets: Option<u32>,

    /// Total time spent assembling frames, in seconds (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_assembly_time: Option<f64>,

    /// Number of retransmitted packets received: RTX packets that repeat a packet (a
    /// padding-only RTX packet repeats none). `None`, and left out of the JSON, for a stream
    /// without an RTX stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted_packets_received: Option<u64>,

    /// Payload bytes of the retransmitted packets received, without the RTX original sequence
    /// number. `None`, and left out of the JSON, for a stream without an RTX stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted_bytes_received: Option<u64>,

    /// SSRC of the RTX stream; left out of the JSON when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtx_ssrc: Option<u32>,

    /// SSRC of the FEC stream; left out of the JSON when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec_ssrc: Option<u32>,

    /// Sum of the corruption probability measurements (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_corruption_probability: Option<f64>,

    /// Sum of the squared corruption probability measurements (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_squared_corruption_probability: Option<f64>,

    /// Number of corruption probability measurements (application-provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corruption_measurements: Option<u64>,
}
