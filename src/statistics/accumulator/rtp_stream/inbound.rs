use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::{AudioReceiverStatsUpdate, DecoderStatsUpdate};
use crate::statistics::stats::rtp_stream::RTCRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::inbound::RTCInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::RTCSentRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::remote_outbound::RTCRemoteOutboundRtpStreamStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use shared::time::SystemInstant;
use std::time::Instant;

/// The stats id of the inbound-rtp object for `ssrc`.
pub(crate) fn inbound_stats_id(kind: RtpCodecKind, ssrc: SSRC) -> String {
    format!("RTCInboundRTPStream_{kind}_{ssrc}")
}

/// The stats id of the remote-outbound-rtp object for `ssrc`.
pub(crate) fn remote_outbound_stats_id(kind: RtpCodecKind, ssrc: SSRC) -> String {
    format!("RTCRemoteOutboundRTPStream_{kind}_{ssrc}")
}

/// An RTCP interarrival jitter (RFC 3550 section 6.4.1, in RTP timestamp units) in seconds, or
/// `None` while the clock rate it is counted in is not known.
pub(crate) fn jitter_seconds(jitter_rtp_units: Option<u32>, clock_rate: u32) -> Option<f64> {
    match (jitter_rtp_units, clock_rate) {
        (Some(units), rate) if rate > 0 => Some(f64::from(units) / f64::from(rate)),
        _ => None,
    }
}

/// Accumulated statistics for an inbound RTP stream.
///
/// This struct tracks packet counters, RTCP feedback and FEC/RTX counters for an incoming RTP
/// stream, plus whatever the application supplied about decoding and playout.
#[derive(Debug, Default)]
pub struct InboundRtpStreamAccumulator {
    // Base identification
    /// The SSRC identifier for this stream.
    pub ssrc: SSRC,
    /// The media kind (audio/video).
    pub kind: RtpCodecKind,
    /// Reference to the transport stats.
    pub transport_id: String,
    /// Reference to the codec stats.
    pub codec_id: String,
    /// The codec's clock rate, which the RTCP jitter is counted in (0 until the codec is known).
    pub clock_rate: u32,
    /// The track identifier from the MediaStreamTrack.
    pub track_identifier: String,
    /// The media stream identification tag from SDP.
    pub mid: String,
    /// The transceiver ID that owns this stream (for filtering).
    pub transceiver_id: RTCRtpTransceiverId,

    // Packet counters
    /// Total RTP packets received.
    pub packets_received: u64,
    /// Total payload bytes received (excluding headers).
    pub bytes_received: u64,
    /// Total RTP header bytes received.
    pub header_bytes_received: u64,
    /// Cumulative packets lost (negative when duplicates outnumber losses), from the latest
    /// reception report this side sent about the stream.
    pub packets_lost: i64,
    /// Interarrival jitter in RTP timestamp units, from the latest reception report this side
    /// sent about the stream.
    pub jitter_rtp_units: Option<u32>,
    /// Timestamp of the last RTP packet received.
    pub last_packet_received_timestamp: Option<Instant>,

    // RTCP feedback sent
    /// Number of NACKs sent for this stream.
    pub nack_count: u32,
    /// Number of FIRs sent for this stream.
    pub fir_count: u32,
    /// Number of PLIs sent for this stream.
    pub pli_count: u32,

    // FEC stats
    /// FEC packets received.
    pub fec_packets_received: u64,
    /// FEC bytes received.
    pub fec_bytes_received: u64,

    // Retransmission
    /// Retransmitted packets received (RTX).
    pub retransmitted_packets_received: u64,
    /// Retransmitted bytes received.
    pub retransmitted_bytes_received: u64,
    /// RTX SSRC if available.
    pub rtx_ssrc: Option<u32>,
    /// FEC SSRC if available.
    pub fec_ssrc: Option<u32>,

    // Remote sender info (from RTCP SR)
    /// Packets sent by the remote sender (from SR).
    pub remote_packets_sent: u64,
    /// Bytes sent by the remote sender (from SR).
    pub remote_bytes_sent: u64,
    /// When the latest remote sender report arrived.
    pub remote_timestamp: Option<Instant>,
    /// Number of RTCP SR reports received.
    pub reports_received: u64,

    // Application-provided stats
    /// Frame assembly, decoder and renderer statistics provided by the application.
    pub decoder_stats: DecoderStatsUpdate,
    /// Jitter buffer, concealment and audio statistics provided by the application.
    pub audio_receiver_stats: AudioReceiverStatsUpdate,
    /// The id of the audio playout stats object this stream plays out through, once the
    /// application has supplied one.
    pub playout_id: Option<String>,
}

impl InboundRtpStreamAccumulator {
    /// Called when an RTP packet is received.
    pub fn on_rtp_received(&mut self, header_bytes: usize, payload_bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.header_bytes_received += header_bytes as u64;
        self.bytes_received += payload_bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    /// Called when this side sends a reception report about the stream (in an RTCP RR or SR):
    /// the cumulative loss (already sign-extended, RFC 3550 section 6.4.1) and the interarrival
    /// jitter in RTP timestamp units.
    pub fn on_rtcp_rr_generated(&mut self, packets_lost: i64, jitter_rtp_units: u32) {
        self.packets_lost = packets_lost;
        self.jitter_rtp_units = Some(jitter_rtp_units);
    }

    /// Called when a NACK is sent.
    pub fn on_nack_sent(&mut self) {
        self.nack_count += 1;
    }

    /// Called when a FIR is sent.
    pub fn on_fir_sent(&mut self) {
        self.fir_count += 1;
    }

    /// Called when a PLI is sent.
    pub fn on_pli_sent(&mut self) {
        self.pli_count += 1;
    }

    /// Called when RTCP Sender Report is received from remote.
    pub fn on_rtcp_sr_received(&mut self, packets_sent: u64, bytes_sent: u64, now: Instant) {
        self.remote_packets_sent = packets_sent;
        self.remote_bytes_sent = bytes_sent;
        self.remote_timestamp = Some(now);
        self.reports_received += 1;
    }

    /// Counts one complete frame received (`framesReceived`).
    pub fn on_frame_received(&mut self) {
        let frames = self.decoder_stats.frames_received.unwrap_or(0);
        self.decoder_stats.frames_received = Some(frames.saturating_add(1));
    }

    /// Counts one frame dropped before decoding (`framesDropped`).
    pub fn on_frame_dropped(&mut self) {
        let frames = self.decoder_stats.frames_dropped.unwrap_or(0);
        self.decoder_stats.frames_dropped = Some(frames.saturating_add(1));
    }

    /// Called when an RTX packet is received.
    pub fn on_rtx_received(&mut self, bytes: usize) {
        self.retransmitted_packets_received += 1;
        self.retransmitted_bytes_received += bytes as u64;
    }

    /// Called when a FEC packet is received.
    pub fn on_fec_received(&mut self, bytes: usize) {
        self.fec_packets_received += 1;
        self.fec_bytes_received += bytes as u64;
    }

    /// Whether the remote-outbound object exists: webrtc-stats 6.1 creates it when the first
    /// RTCP Sender Report for the SSRC arrives.
    pub fn has_remote(&self) -> bool {
        self.reports_received > 0
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCInboundRtpStreamStats {
        let decoder = &self.decoder_stats;
        let audio = &self.audio_receiver_stats;
        RTCInboundRtpStreamStats {
            received_rtp_stream_stats: RTCReceivedRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: SystemInstant::now(now),
                        typ: RTCStatsType::InboundRTP,
                        id: id.to_string(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_received: self.packets_received,
                packets_received_with_ect1: None,
                packets_received_with_ce: None,
                packets_reported_as_lost: None,
                packets_reported_as_lost_but_recovered: None,
                packets_lost: self.packets_lost,
                jitter: jitter_seconds(self.jitter_rtp_units, self.clock_rate),
            },
            track_identifier: self.track_identifier.clone(),
            mid: self.mid.clone(),
            remote_id: self
                .has_remote()
                .then(|| remote_outbound_stats_id(self.kind, self.ssrc)),
            frames_decoded: decoder.frames_decoded,
            key_frames_decoded: decoder.key_frames_decoded,
            frames_rendered: decoder.frames_rendered,
            frames_dropped: decoder.frames_dropped,
            frame_width: decoder.frame_width,
            frame_height: decoder.frame_height,
            frames_per_second: decoder.frames_per_second,
            qp_sum: decoder.qp_sum,
            total_decode_time: decoder.total_decode_time,
            total_inter_frame_delay: decoder.total_inter_frame_delay,
            total_squared_inter_frame_delay: decoder.total_squared_inter_frame_delay,
            pause_count: decoder.pause_count,
            total_pauses_duration: decoder.total_pauses_duration,
            freeze_count: decoder.freeze_count,
            total_freezes_duration: decoder.total_freezes_duration,
            last_packet_received_timestamp: self
                .last_packet_received_timestamp
                .map(SystemInstant::now),
            header_bytes_received: self.header_bytes_received,
            packets_discarded: decoder.packets_discarded,
            fec_bytes_received: self.fec_bytes_received,
            fec_packets_received: self.fec_packets_received,
            fec_packets_discarded: None,
            bytes_received: self.bytes_received,
            nack_count: self.nack_count,
            fir_count: self.fir_count,
            pli_count: self.pli_count,
            total_processing_delay: decoder.total_processing_delay,
            estimated_playout_timestamp: None,
            jitter_buffer_delay: audio.jitter_buffer_delay,
            jitter_buffer_target_delay: audio.jitter_buffer_target_delay,
            jitter_buffer_emitted_count: audio.jitter_buffer_emitted_count,
            jitter_buffer_minimum_delay: audio.jitter_buffer_minimum_delay,
            total_samples_received: audio.total_samples_received,
            concealed_samples: audio.concealed_samples,
            silent_concealed_samples: audio.silent_concealed_samples,
            concealment_events: audio.concealment_events,
            inserted_samples_for_deceleration: audio.inserted_samples_for_deceleration,
            removed_samples_for_acceleration: audio.removed_samples_for_acceleration,
            audio_level: audio.audio_level,
            total_audio_energy: audio.total_audio_energy,
            total_samples_duration: audio.total_samples_duration,
            frames_received: decoder.frames_received,
            decoder_implementation: decoder.decoder_implementation.clone(),
            playout_id: self.playout_id.clone(),
            power_efficient_decoder: decoder.power_efficient_decoder,
            frames_assembled_from_multiple_packets: decoder.frames_assembled_from_multiple_packets,
            total_assembly_time: decoder.total_assembly_time,
            retransmitted_packets_received: self.retransmitted_packets_received,
            retransmitted_bytes_received: self.retransmitted_bytes_received,
            rtx_ssrc: self.rtx_ssrc,
            fec_ssrc: self.fec_ssrc,
            total_corruption_probability: None,
            total_squared_corruption_probability: None,
            corruption_measurements: None,
        }
    }

    /// Creates a snapshot of remote outbound stats from RTCP SR data.
    ///
    /// Only meaningful once [`has_remote`](Self::has_remote) is true; the report leaves the
    /// object out before that.
    pub fn snapshot_remote(&self, now: Instant) -> RTCRemoteOutboundRtpStreamStats {
        RTCRemoteOutboundRtpStreamStats {
            sent_rtp_stream_stats: RTCSentRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: SystemInstant::now(now),
                        typ: RTCStatsType::RemoteOutboundRTP,
                        id: remote_outbound_stats_id(self.kind, self.ssrc),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_sent: self.remote_packets_sent,
                bytes_sent: self.remote_bytes_sent,
            },
            local_id: inbound_stats_id(self.kind, self.ssrc),
            remote_timestamp: SystemInstant::now(self.remote_timestamp.unwrap_or(now)),
            reports_sent: self.reports_received,
            round_trip_time: None,
            total_round_trip_time: 0.0,
            round_trip_time_measurements: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = InboundRtpStreamAccumulator::default();
        assert_eq!(acc.ssrc, 0);
        assert_eq!(acc.packets_received, 0);
        assert_eq!(acc.bytes_received, 0);
        assert_eq!(acc.header_bytes_received, 0);
        assert_eq!(acc.packets_lost, 0);
        assert_eq!(acc.jitter_rtp_units, None);
        assert_eq!(acc.nack_count, 0);
        assert_eq!(acc.fir_count, 0);
        assert_eq!(acc.pli_count, 0);
        assert_eq!(acc.decoder_stats.frames_received, None);
        assert_eq!(acc.decoder_stats.frames_dropped, None);
        assert_eq!(acc.fec_packets_received, 0);
        assert_eq!(acc.retransmitted_packets_received, 0);
    }

    #[test]
    fn test_on_rtp_received() {
        let mut acc = InboundRtpStreamAccumulator::default();
        let now = Instant::now();

        acc.on_rtp_received(12, 1188, now);
        assert_eq!(acc.packets_received, 1);
        assert_eq!(acc.header_bytes_received, 12);
        assert_eq!(acc.bytes_received, 1188);
        assert_eq!(acc.last_packet_received_timestamp, Some(now));

        let later = now + std::time::Duration::from_millis(20);
        acc.on_rtp_received(12, 1000, later);
        assert_eq!(acc.packets_received, 2);
        assert_eq!(acc.header_bytes_received, 24);
        assert_eq!(acc.bytes_received, 2188);
        assert_eq!(acc.last_packet_received_timestamp, Some(later));
    }

    #[test]
    fn test_on_rtcp_rr_generated() {
        let mut acc = InboundRtpStreamAccumulator::default();

        acc.on_rtcp_rr_generated(10, 450);
        assert_eq!(acc.packets_lost, 10);
        assert_eq!(acc.jitter_rtp_units, Some(450));

        // Update with new values
        acc.on_rtcp_rr_generated(-2, 720);
        assert_eq!(acc.packets_lost, -2);
        assert_eq!(acc.jitter_rtp_units, Some(720));
    }

    #[test]
    fn test_rtcp_feedback_counters() {
        let mut acc = InboundRtpStreamAccumulator::default();

        acc.on_nack_sent();
        acc.on_nack_sent();
        assert_eq!(acc.nack_count, 2);

        acc.on_fir_sent();
        assert_eq!(acc.fir_count, 1);

        acc.on_pli_sent();
        acc.on_pli_sent();
        acc.on_pli_sent();
        assert_eq!(acc.pli_count, 3);
    }

    #[test]
    fn test_on_rtcp_sr_received() {
        let mut acc = InboundRtpStreamAccumulator::default();
        let now = Instant::now();
        assert!(!acc.has_remote());

        acc.on_rtcp_sr_received(1000, 1_000_000, now);
        assert_eq!(acc.remote_packets_sent, 1000);
        assert_eq!(acc.remote_bytes_sent, 1_000_000);
        assert_eq!(acc.remote_timestamp, Some(now));
        assert_eq!(acc.reports_received, 1);
        assert!(acc.has_remote());

        let later = now + std::time::Duration::from_secs(5);
        acc.on_rtcp_sr_received(2000, 2_000_000, later);
        assert_eq!(acc.remote_packets_sent, 2000);
        assert_eq!(acc.remote_bytes_sent, 2_000_000);
        assert_eq!(acc.remote_timestamp, Some(later));
        assert_eq!(acc.reports_received, 2);
    }

    #[test]
    fn test_frame_tracking() {
        let mut acc = InboundRtpStreamAccumulator::default();

        acc.on_frame_received();
        acc.on_frame_received();
        acc.on_frame_received();
        assert_eq!(acc.decoder_stats.frames_received, Some(3));

        acc.on_frame_dropped();
        assert_eq!(acc.decoder_stats.frames_dropped, Some(1));
    }

    #[test]
    fn test_rtx_and_fec_received() {
        let mut acc = InboundRtpStreamAccumulator::default();

        acc.on_rtx_received(500);
        acc.on_rtx_received(600);
        assert_eq!(acc.retransmitted_packets_received, 2);
        assert_eq!(acc.retransmitted_bytes_received, 1100);

        acc.on_fec_received(200);
        acc.on_fec_received(300);
        acc.on_fec_received(250);
        assert_eq!(acc.fec_packets_received, 3);
        assert_eq!(acc.fec_bytes_received, 750);
    }

    #[test]
    fn test_snapshot() {
        let now = Instant::now();
        let mut acc = InboundRtpStreamAccumulator {
            ssrc: 11111111,
            kind: RtpCodecKind::Audio,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_audio_111".to_string(),
            clock_rate: 48000,
            track_identifier: "audio-track".to_string(),
            mid: "1".to_string(),
            ..Default::default()
        };

        acc.on_rtp_received(12, 160, now);
        acc.on_rtp_received(12, 160, now);
        acc.on_rtcp_rr_generated(0, 48);

        let stats = acc.snapshot(now, "RTCInboundRTPStream_audio_11111111");

        assert_eq!(
            stats.received_rtp_stream_stats.rtp_stream_stats.stats.id,
            "RTCInboundRTPStream_audio_11111111"
        );
        assert_eq!(
            stats.received_rtp_stream_stats.rtp_stream_stats.stats.typ,
            RTCStatsType::InboundRTP
        );
        assert_eq!(
            stats.received_rtp_stream_stats.rtp_stream_stats.ssrc,
            11111111
        );
        assert_eq!(stats.received_rtp_stream_stats.packets_received, 2);
        assert_eq!(stats.bytes_received, 320);
        assert_eq!(stats.header_bytes_received, 24);
        // 48 RTP units at 48 kHz is 1 ms.
        assert_eq!(stats.received_rtp_stream_stats.jitter, Some(0.001));
        assert_eq!(stats.track_identifier, "audio-track");
        assert_eq!(stats.mid, "1");
        // No sender report yet: no remote-outbound object to name.
        assert_eq!(stats.remote_id, None);
    }

    #[test]
    fn test_snapshot_remote() {
        let now = Instant::now();
        let mut acc = InboundRtpStreamAccumulator {
            ssrc: 22222222,
            kind: RtpCodecKind::Video,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_video_96".to_string(),
            ..Default::default()
        };

        acc.on_rtcp_sr_received(500, 600000, now);
        acc.on_rtcp_sr_received(1000, 1200000, now);

        let remote_stats = acc.snapshot_remote(now);

        assert_eq!(
            remote_stats
                .sent_rtp_stream_stats
                .rtp_stream_stats
                .stats
                .typ,
            RTCStatsType::RemoteOutboundRTP
        );
        assert_eq!(remote_stats.sent_rtp_stream_stats.packets_sent, 1000);
        assert_eq!(remote_stats.sent_rtp_stream_stats.bytes_sent, 1200000);
        assert_eq!(remote_stats.reports_sent, 2);
        assert_eq!(remote_stats.round_trip_time, None);
        assert_eq!(remote_stats.local_id, "RTCInboundRTPStream_video_22222222");
        assert_eq!(
            acc.snapshot(now, "x").remote_id.as_deref(),
            Some("RTCRemoteOutboundRTPStream_video_22222222")
        );
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let mut acc = InboundRtpStreamAccumulator {
            ssrc: 33333333,
            kind: RtpCodecKind::Video,
            ..Default::default()
        };

        acc.on_rtp_received(12, 1200, now);
        acc.on_frame_received();
        acc.on_nack_sent();

        let stats = acc.snapshot(now, "RTCInboundRTPStream_video_33333333");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"ssrc\":33333333"));
        assert!(json.contains("\"packetsReceived\":1"));
        assert!(json.contains("\"bytesReceived\":1200"));
        assert!(json.contains("\"framesReceived\":1"));
        assert!(json.contains("\"nackCount\":1"));
        assert!(json.contains("\"type\":\"inbound-rtp\""));
        // What needs a decoder was never supplied, so it is absent rather than 0.
        assert!(!json.contains("framesDecoded"));
        assert!(!json.contains("jitterBufferDelay"));
        assert!(!json.contains("remoteId"));
    }
}
