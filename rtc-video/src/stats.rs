//! The receive pipeline's statistics: the W3C `RTCInboundRtpStreamStats` video members the
//! engine cannot measure, and the pipeline's own counters.

use std::collections::HashMap;

use crate::keyframe::KeyFrameReason;

/// Receive statistics. Members named after W3C webrtc-stats; times in seconds.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiveStats {
    /// `framesReceived`: complete frames assembled.
    pub frames_received: u32,
    /// `framesDecoded`.
    pub frames_decoded: u32,
    /// `keyFramesDecoded`.
    pub key_frames_decoded: u32,
    /// `framesDropped`: frames that left the buffers undecoded.
    pub frames_dropped: u32,
    /// `packetsDiscarded`: packets refused as late, and the packets of dropped frames.
    pub packets_discarded: u64,
    /// `framesAssembledFromMultiplePackets` (decoded frames only).
    pub frames_assembled_from_multiple_packets: u32,
    /// `totalAssemblyTime` (decoded frames of more than one packet).
    pub total_assembly_time: f64,
    /// `totalDecodeTime`.
    pub total_decode_time: f64,
    /// `totalProcessingDelay`: first packet received to decoded.
    pub total_processing_delay: f64,
    /// `qpSum`, when the decoder reports QPs.
    pub qp_sum: Option<u64>,
    /// `frameWidth`, `frameHeight` of the last decoded frame.
    pub frame_size: Option<(u32, u32)>,
    /// `framesPerSecond`: frames decoded in the last second.
    pub frames_per_second: f64,
    /// `jitterBufferDelay`: for each picture, its first packet's arrival to its release.
    pub jitter_buffer_delay: f64,
    /// `jitterBufferTargetDelay`.
    pub jitter_buffer_target_delay: f64,
    /// `jitterBufferMinimumDelay`: the target without `jitterBufferTarget` and A/V sync.
    pub jitter_buffer_minimum_delay: f64,
    /// `jitterBufferEmittedCount`.
    pub jitter_buffer_emitted_count: u64,
    /// `framesRendered`.
    pub frames_rendered: u32,
    /// `totalInterFrameDelay`.
    pub total_inter_frame_delay: f64,
    /// `totalSquaredInterFrameDelay`.
    pub total_squared_inter_frame_delay: f64,
    /// `freezeCount`.
    pub freeze_count: u32,
    /// `totalFreezesDuration`.
    pub total_freezes_duration: f64,
    /// `pauseCount`.
    pub pause_count: u32,
    /// `totalPausesDuration`.
    pub total_pauses_duration: f64,
    /// Not W3C: the longest interval between rendered frames, in seconds.
    pub longest_render_interval: f64,
    /// Not W3C: duplicate packets dropped.
    pub packets_duplicated: u64,
    /// Not W3C: packets taken as retransmissions.
    pub packets_retransmitted: u64,
    /// Not W3C: key frames asked for, by reason.
    pub key_frame_requests: HashMap<KeyFrameReason, u32>,
    /// Not W3C: decode failures.
    pub decode_errors: u32,
}

impl ReceiveStats {
    /// Key frames asked for, every reason together.
    pub fn key_frame_requests_total(&self) -> u32 {
        self.key_frame_requests.values().sum()
    }
}
