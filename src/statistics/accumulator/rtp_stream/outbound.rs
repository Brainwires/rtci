use super::inbound::{OnlyFor, generation_suffix, jitter_seconds};
use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::{CcfbTally, EncoderStatsUpdate};
use crate::statistics::stats::rtp_stream::RTCRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::remote_inbound::RTCRemoteInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::RTCSentRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::outbound::RTCOutboundRtpStreamStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use rtcp::reception_report::ReceptionReport;
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReportBlock;
use shared::time::SystemInstant;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// How many of our own sender reports are remembered per stream, to match a receiver report's
/// LSR against. Reports go out about once a second, so this covers a report that comes back
/// many seconds late.
const SENDER_REPORTS_REMEMBERED: usize = 16;

/// How many packets written and not yet sent a stream remembers the write time of, to measure
/// how long an interceptor held each (`totalPacketSendDelay`). A pacer queue longer than this
/// measures nothing for the packets beyond it.
const WRITES_REMEMBERED: usize = 2048;

/// The stats id of the outbound-rtp object for `ssrc`, before the report seals it
/// (`generation`: see [`generation_suffix`]).
pub(crate) fn outbound_stats_id(kind: RtpCodecKind, ssrc: SSRC, generation: u64) -> String {
    format!(
        "RTCOutboundRTPStream_{kind}_{ssrc}{}",
        generation_suffix(generation)
    )
}

/// The stats id of the remote-inbound-rtp object for `ssrc`, before the report seals it.
pub(crate) fn remote_inbound_stats_id(kind: RtpCodecKind, ssrc: SSRC, generation: u64) -> String {
    format!(
        "RTCRemoteInboundRTPStream_{kind}_{ssrc}{}",
        generation_suffix(generation)
    )
}

/// The middle 32 bits of a 64-bit NTP timestamp: what a reception report's LSR field echoes
/// (RFC 3550 section 6.4.1).
pub(crate) fn compact_ntp(ntp_time: u64) -> u32 {
    (ntp_time >> 16) as u32
}

/// Accumulated statistics for an outbound RTP stream.
///
/// This struct tracks packet counters, RTCP feedback received and what the remote receiver
/// reports about the stream, plus whatever the application supplied about encoding.
#[derive(Debug, Default)]
pub struct OutboundRtpStreamAccumulator {
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
    /// The media stream identification tag from SDP.
    pub mid: String,
    /// The RTP stream ID (RID) for simulcast.
    pub rid: String,
    /// The encoding index in simulcast.
    pub encoding_index: u32,
    /// Reference to the media source stats.
    pub media_source_id: String,
    /// The transceiver ID that owns this stream (for filtering).
    pub transceiver_id: RTCRtpTransceiverId,
    /// Tells this object's id from that of a deleted one with the same SSRC
    /// ([`generation_suffix`]).
    pub generation: u64,

    // Packet counters
    /// Total RTP packets sent for the SSRC, with those sent on its RTX SSRC (webrtc-stats 7.1:
    /// an RTX stream is not an object of its own and counts here).
    pub packets_sent: u64,
    /// Total payload bytes sent (excluding headers and padding).
    pub bytes_sent: u64,
    /// Total RTP header and padding bytes sent; an RTX packet's original sequence number
    /// (RFC 4588 section 4) is header too.
    pub header_bytes_sent: u64,
    /// Timestamp of the last RTP packet sent.
    pub last_packet_sent_timestamp: Option<Instant>,
    /// The sequence number of the first RTP packet sent, the base `packetsReceived` of the
    /// remote-inbound object is counted from.
    pub first_sequence_number: Option<u16>,
    /// The packets the application wrote that have not come out of the interceptor chain yet:
    /// each one's sequence number and when it was written.
    pub writes_pending: VecDeque<(u16, Instant)>,
    /// The time the stream's packets spent between being written and being handed out for
    /// sending, summed, in seconds.
    pub total_packet_send_delay: f64,

    // Retransmission
    /// Retransmitted packets sent (RTX).
    pub retransmitted_packets_sent: u64,
    /// Retransmitted bytes sent.
    pub retransmitted_bytes_sent: u64,
    /// RTX SSRC if available.
    pub rtx_ssrc: Option<u32>,

    // RTCP feedback received
    /// Number of NACKs received for this stream.
    pub nack_count: u32,
    /// Number of FIRs received for this stream.
    pub fir_count: u32,
    /// Number of PLIs received for this stream.
    pub pli_count: u32,

    // State
    /// Whether the stream's encoding is active (`RTCRtpEncodingParameters.active`), as of the
    /// last time the report was asked for.
    pub active: bool,

    // ECN (RFC 3168, L4S RFC 9331) and RFC 8888 congestion control feedback
    /// The application's socket layer applies the ECN codepoint each datagram names, so
    /// `packetsSentWithEct1` is measured (`SettingEngineBuilder::with_ecn`).
    pub ecn: bool,
    /// The stream's codec negotiated RFC 8888 feedback (`a=rtcp-fb:<pt> ack ccfb`).
    pub ccfb_negotiated: bool,
    /// Whether the stream negotiated RFC 6679 ECN reports (`a=rtcp-xr:ecn-sum`, with or
    /// without `nack ecn`), the ECN feedback of a stream not reported in RFC 8888.
    pub rfc6679_negotiated: bool,
    /// The stream's RTP packets (and its RTX packets) may be sent ECT(1): ECN is on and RFC
    /// 8888 feedback, which reports CE marks back, is negotiated. Which ones are is
    /// `ecn_validation`'s decision.
    pub ect1_marking: bool,
    /// RFC 6679 sections 7.2-7.4 for the stream, fed from the RFC 8888 reports (RFC 8888
    /// section 7); `Some` while `ect1_marking`.
    pub ecn_validation: Option<Box<interceptor::EcnValidation>>,
    /// The codepoint the stream marks with, as the peer's `a=ecn-capable-rtp` `ect=` asked
    /// (ECT(0) unless it asked for ECT(1)); `None` (ECT(1)) when not negotiated by SDP.
    pub ect_codepoint: Option<shared::EcnCodepoint>,
    /// RTP packets sent with ECT(1).
    pub packets_sent_with_ect1: u64,
    /// What the RFC 8888 reports received from the remote say about the stream.
    pub ccfb_received: Option<Box<CcfbTally>>,

    /// The congestion controller's estimate for the connection (0 until it has produced one),
    /// which is the stream's `targetBitrate` while it is the only stream and the application
    /// supplies none.
    pub target_bitrate: f64,

    // Remote receiver info (from RTCP reception reports about this SSRC)
    /// Number of reception reports received about this stream.
    pub remote_reports_received: u64,
    /// Packets received by the remote receiver, estimated as webrtc-stats defines it.
    pub remote_packets_received: u64,
    /// Cumulative packets lost at the remote receiver (signed, RFC 3550 section 6.4.1).
    pub remote_packets_lost: i64,
    /// Interarrival jitter at the remote receiver, in RTP timestamp units.
    pub remote_jitter: Option<u32>,
    /// Fraction lost at the remote receiver (0.0 to 1.0).
    pub remote_fraction_lost: f64,
    /// The latest round trip time measured from a reception report's LSR and DLSR, in seconds.
    pub remote_round_trip_time: Option<f64>,
    /// The sum of every round trip time measured, in seconds.
    pub remote_total_round_trip_time: f64,
    /// Number of RTT measurements.
    pub rtt_measurements: u64,
    /// When the latest report from the remote receiver about this stream arrived: the
    /// remote-inbound object's `timestamp`.
    pub remote_report_received_at: Option<Instant>,
    /// Our latest sender reports: the compact NTP timestamp each carried and when it was sent.
    pub sender_reports_sent: VecDeque<(u32, Instant)>,

    // Application-provided stats (encoder)
    /// Encoder statistics provided by the application.
    pub encoder_stats: EncoderStatsUpdate,
}

impl OutboundRtpStreamAccumulator {
    /// Called when an RTP packet is sent: `header_bytes` is its header and padding,
    /// `payload_bytes` its payload.
    pub fn on_rtp_sent(&mut self, header_bytes: usize, payload_bytes: usize, now: Instant) {
        self.packets_sent += 1;
        self.header_bytes_sent += header_bytes as u64;
        self.bytes_sent += payload_bytes as u64;
        self.last_packet_sent_timestamp = Some(now);
    }

    /// Called when the application writes an RTP packet, before the interceptor chain has it:
    /// remembers when, so the time until it is handed out for sending can be measured.
    pub fn on_rtp_written(&mut self, sequence_number: u16, now: Instant) {
        if self.writes_pending.len() == WRITES_REMEMBERED {
            self.writes_pending.pop_front();
        }
        self.writes_pending.push_back((sequence_number, now));
    }

    /// Called when the packet the application wrote with `sequence_number` is handed out for
    /// sending at `now`: the time since it was written is added to `totalPacketSendDelay`.
    /// Packets written before it that never came out (an interceptor dropped them) are
    /// forgotten. A packet nobody wrote (a retransmission, FEC) adds nothing.
    pub fn on_written_rtp_sent(&mut self, sequence_number: u16, now: Instant) {
        if let Some(at) = self
            .writes_pending
            .iter()
            .position(|(written, _)| *written == sequence_number)
        {
            let (_, written_at) = self.writes_pending[at];
            self.writes_pending.drain(..=at);
            self.total_packet_send_delay += now.saturating_duration_since(written_at).as_secs_f64();
        }
    }

    /// Records the sequence number of a sent RTP packet; the first one is the base of the
    /// remote receiver's `packetsReceived`.
    pub fn on_sequence_number_sent(&mut self, sequence_number: u16) {
        self.first_sequence_number.get_or_insert(sequence_number);
    }

    /// Counts an RTP packet of the stream sent with ECT(1).
    pub fn on_ect1_sent(&mut self) {
        self.packets_sent_with_ect1 += 1;
    }

    /// What an RFC 6679 report about the stream says (an RTCP ECN Feedback packet or an XR ECN
    /// Summary Report with the reception report it rides with): the stream's ECN validation
    /// runs on it, unless the stream is reported in RFC 8888, which reports every packet.
    pub fn on_ecn_counters_received(
        &mut self,
        extended_highest: u32,
        counters: rtcp::transport_feedbacks::ecn_feedback::EcnCounters,
        now: Instant,
    ) {
        if self.ccfb_negotiated {
            return;
        }
        if let Some(validation) = self.ecn_validation.as_deref_mut() {
            validation.on_counters(now, extended_highest, counters);
        }
    }

    /// Counts what an RFC 8888 report block from the remote, arriving at `now`, says about the
    /// stream.
    pub fn on_ccfb_block_received(&mut self, block: &CcFeedbackReportBlock, now: Instant) {
        self.remote_report_received_at = Some(now);
        if let Some(validation) = self.ecn_validation.as_deref_mut() {
            for (offset, metric) in block.metric_blocks.iter().enumerate() {
                validation.on_report(
                    now,
                    block.begin_sequence.wrapping_add(offset as u16),
                    metric.received,
                    metric.ecn,
                );
            }
        }
        // Bleaching is a Not-ECT report of a packet that was sent ECT(1): which packets were
        // is known per packet, since a stream initiating ECN marks only some.
        let validation = self.ecn_validation.as_deref();
        self.ccfb_received
            .get_or_insert_with(|| Box::new(CcfbTally::new()))
            .on_report_block_marked(block, |sequence_number| {
                validation.is_some_and(|v| v.was_marked(sequence_number))
            });
    }

    /// The remote-inbound RFC 8888 member `pick` selects, where `ccfb` is negotiated (or
    /// reports came anyway); 0 until the first report.
    fn ccfb_member(&self, pick: impl Fn(&CcfbTally) -> u64) -> Option<u64> {
        (self.ccfb_negotiated || self.ccfb_received.is_some())
            .then(|| self.ccfb_received.as_deref().map_or(0, pick))
    }

    /// Called when a NACK is received.
    pub fn on_nack_received(&mut self) {
        self.nack_count += 1;
    }

    /// Called when a FIR is received.
    pub fn on_fir_received(&mut self) {
        self.fir_count += 1;
    }

    /// Called when a PLI is received.
    pub fn on_pli_received(&mut self) {
        self.pli_count += 1;
    }

    /// Called when a retransmission is sent, besides [`on_rtp_sent`](Self::on_rtp_sent) for
    /// the packet that carries it: `bytes` is the payload of the packet it repeats (an RTX
    /// packet's payload without the original sequence number). `retransmittedPacketsSent` and
    /// `retransmittedBytesSent` are subsets of `packetsSent` and `bytesSent`.
    pub fn on_rtx_sent(&mut self, bytes: usize) {
        self.retransmitted_packets_sent += 1;
        self.retransmitted_bytes_sent += bytes as u64;
    }

    /// The stats id of this object, before the report seals it.
    pub fn stats_id(&self) -> String {
        outbound_stats_id(self.kind, self.ssrc, self.generation)
    }

    /// The stats id of the remote-inbound object, before the report seals it.
    fn remote_stats_id(&self) -> String {
        remote_inbound_stats_id(self.kind, self.ssrc, self.generation)
    }

    /// Called when this side sends an RTCP sender report for the stream: remembers when, so a
    /// reception report that echoes it can be turned into a round trip time.
    pub fn on_sender_report_sent(&mut self, ntp_time: u64, now: Instant) {
        if self.sender_reports_sent.len() == SENDER_REPORTS_REMEMBERED {
            self.sender_reports_sent.pop_front();
        }
        self.sender_reports_sent
            .push_back((compact_ntp(ntp_time), now));
    }

    /// Called when a reception report about this stream arrives (in an RTCP RR or SR).
    ///
    /// * Loss: the cumulative number of packets lost is signed (RFC 3550 section 6.4.1).
    /// * `packetsReceived`, as webrtc-stats defines it for the sending side: the extended
    ///   highest sequence number received, minus the cumulative loss, minus the first sequence
    ///   number sent, plus one.
    /// * Round trip time: `A - LSR - DLSR` (RFC 3550 section 6.4.1), where `A - LSR` is the time
    ///   since we sent the sender report whose compact NTP timestamp the LSR field echoes. A
    ///   report with LSR 0 (no sender report received yet) or naming a report we no longer
    ///   remember gives no measurement.
    pub fn on_receiver_report(&mut self, report: &ReceptionReport, now: Instant) {
        self.remote_reports_received += 1;
        self.remote_report_received_at = Some(now);
        self.remote_packets_lost = i64::from(report.cumulative_lost());
        self.remote_jitter = Some(report.jitter);
        self.remote_fraction_lost = f64::from(report.fraction_lost) / 256.0;
        // A total only ever grows (webrtc-stats 8.1): a report that arrives out of order, or
        // counts a loss before the packets after it, does not take packets back.
        if let Some(first) = self.first_sequence_number {
            let received = i64::from(report.last_sequence_number) - i64::from(first) + 1
                - self.remote_packets_lost;
            self.remote_packets_received = self.remote_packets_received.max(received.max(0) as u64);
        }

        // webrtc-stats: no round trip time "until a RTCP Receiver Report is received with a
        // DLSR value other than 0"; LSR 0 means the receiver has seen no sender report at all
        // (RFC 3550 section 6.4.1).
        if report.last_sender_report == 0 || report.delay == 0 {
            return;
        }
        let Some(&(_, sent_at)) = self
            .sender_reports_sent
            .iter()
            .rev()
            .find(|(lsr, _)| *lsr == report.last_sender_report)
        else {
            return;
        };
        let Some(since_sent) = now.checked_duration_since(sent_at) else {
            return;
        };
        let delay = Duration::from_secs_f64(f64::from(report.delay) / 65536.0);
        // DLSR is truncated to 1/65536 s, so on a near-zero path it can exceed the elapsed
        // time by a fraction of a tick: that is a round trip of 0, not a missing one.
        let rtt = since_sent.saturating_sub(delay).as_secs_f64();
        self.remote_round_trip_time = Some(rtt);
        self.remote_total_round_trip_time += rtt;
        self.rtt_measurements += 1;
    }

    /// Counts one frame sent (`framesSent`), and a huge one (`hugeFramesSent`).
    pub fn on_frame_sent(&mut self, is_huge: bool) {
        let encoder = &mut self.encoder_stats;
        encoder.frames_sent = Some(encoder.frames_sent.unwrap_or(0).saturating_add(1));
        if is_huge {
            encoder.huge_frames_sent =
                Some(encoder.huge_frames_sent.unwrap_or(0).saturating_add(1));
        }
    }

    /// Whether the remote-inbound object exists: webrtc-stats 6.1 creates it when the first
    /// reception report about the SSRC arrives, here an RFC 8888 report block too.
    pub fn has_remote(&self) -> bool {
        self.remote_reports_received > 0 || self.ccfb_received.is_some()
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCOutboundRtpStreamStats {
        let encoder = &self.encoder_stats;
        // webrtc-stats 4.2: a member that does not apply to the object does not exist; the
        // video-only members are reported for a video stream only, whatever was supplied.
        let video = OnlyFor(self.kind == RtpCodecKind::Video);
        RTCOutboundRtpStreamStats {
            sent_rtp_stream_stats: RTCSentRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: SystemInstant::now(now),
                        typ: RTCStatsType::OutboundRTP,
                        id: id.to_string(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_sent: self.packets_sent,
                bytes_sent: self.bytes_sent,
            },
            mid: self.mid.clone(),
            media_source_id: self.media_source_id.clone(),
            remote_id: self.has_remote().then(|| self.remote_stats_id()),
            // A rid and an encoding index are simulcast, which is video.
            rid: if video.0 {
                self.rid.clone()
            } else {
                String::new()
            },
            encoding_index: video.the(Some(self.encoding_index)),
            header_bytes_sent: self.header_bytes_sent,
            retransmitted_packets_sent: self.retransmitted_packets_sent,
            retransmitted_bytes_sent: self.retransmitted_bytes_sent,
            rtx_ssrc: self.rtx_ssrc,
            target_bitrate: encoder
                .target_bitrate
                .or((self.target_bitrate > 0.0).then_some(self.target_bitrate)),
            frame_width: video.the(encoder.frame_width),
            frame_height: video.the(encoder.frame_height),
            frames_per_second: video.the(encoder.frames_per_second),
            frames_sent: video.the(encoder.frames_sent),
            huge_frames_sent: video.the(encoder.huge_frames_sent),
            frames_encoded: video.the(encoder.frames_encoded),
            key_frames_encoded: video.the(encoder.key_frames_encoded),
            qp_sum: video.the(encoder.qp_sum),
            psnr_sum: video.the(encoder.psnr_sum).map(|psnr| {
                HashMap::from([
                    ("y".to_owned(), psnr.y),
                    ("u".to_owned(), psnr.u),
                    ("v".to_owned(), psnr.v),
                ])
            }),
            psnr_measurements: video.the(encoder.psnr_measurements),
            total_encode_time: video.the(encoder.total_encode_time),
            total_packet_send_delay: self.total_packet_send_delay,
            quality_limitation_reason: video.the(encoder.quality_limitation_reason),
            quality_limitation_durations: video.the(encoder.quality_limitation_durations).map(
                |durations| {
                    HashMap::from([
                        ("none".to_owned(), durations.none),
                        ("cpu".to_owned(), durations.cpu),
                        ("bandwidth".to_owned(), durations.bandwidth),
                        ("other".to_owned(), durations.other),
                    ])
                },
            ),
            quality_limitation_resolution_changes: video
                .the(encoder.quality_limitation_resolution_changes),
            nack_count: self.nack_count,
            // FIR and PLI ask for a video key frame: the members exist for video only.
            fir_count: video.the(Some(self.fir_count)),
            pli_count: video.the(Some(self.pli_count)),
            encoder_implementation: video.the(encoder.encoder_implementation.clone()),
            power_efficient_encoder: video.the(encoder.power_efficient_encoder),
            active: self.active,
            scalability_mode: video.the(encoder.scalability_mode.clone()),
            packets_sent_with_ect1: self.ecn.then_some(self.packets_sent_with_ect1),
        }
    }

    /// Creates a snapshot of remote inbound stats from the reception reports received.
    ///
    /// Only meaningful once [`has_remote`](Self::has_remote) is true; the report leaves the
    /// object out before that.
    ///
    /// Its `timestamp` is when the latest report about the stream arrived (webrtc 8.4: for
    /// statistics that came from a remote source, the time the information reached the local
    /// endpoint).
    pub fn snapshot_remote(&self, now: Instant) -> RTCRemoteInboundRtpStreamStats {
        RTCRemoteInboundRtpStreamStats {
            received_rtp_stream_stats: RTCReceivedRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: SystemInstant::now(
                            self.remote_report_received_at.unwrap_or(now),
                        ),
                        typ: RTCStatsType::RemoteInboundRTP,
                        id: self.remote_stats_id(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_received: self.remote_packets_received,
                packets_received_with_ect1: self.ccfb_member(|t| t.received_with_ect1),
                packets_received_with_ce: self.ccfb_member(|t| t.received_with_ce),
                packets_reported_as_lost: self.ccfb_member(|t| t.reported_as_lost),
                packets_reported_as_lost_but_recovered: self
                    .ccfb_member(|t| t.reported_as_lost_but_recovered),
                packets_lost: self.remote_packets_lost,
                jitter: jitter_seconds(self.remote_jitter, self.clock_rate),
            },
            local_id: self.stats_id(),
            round_trip_time: self.remote_round_trip_time,
            total_round_trip_time: self.remote_total_round_trip_time,
            fraction_lost: self.remote_fraction_lost,
            round_trip_time_measurements: self.rtt_measurements,
            packets_with_bleached_ect1_marking: self.ccfb_member(|t| t.bleached_ect1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statistics::stats::RTCQualityLimitationReason;

    fn report(last_sequence_number: u32, total_lost: u32, jitter: u32) -> ReceptionReport {
        ReceptionReport {
            ssrc: 0,
            fraction_lost: 0,
            total_lost,
            last_sequence_number,
            jitter,
            last_sender_report: 0,
            delay: 0,
        }
    }

    #[test]
    fn test_default() {
        let acc = OutboundRtpStreamAccumulator::default();
        assert_eq!(acc.ssrc, 0);
        assert_eq!(acc.packets_sent, 0);
        assert_eq!(acc.bytes_sent, 0);
        assert_eq!(acc.header_bytes_sent, 0);
        assert_eq!(acc.retransmitted_packets_sent, 0);
        assert_eq!(acc.retransmitted_bytes_sent, 0);
        assert_eq!(acc.encoder_stats.frames_sent, None);
        assert_eq!(acc.encoder_stats.huge_frames_sent, None);
        assert_eq!(acc.nack_count, 0);
        assert_eq!(acc.fir_count, 0);
        assert_eq!(acc.pli_count, 0);
        assert!(!acc.active);
        assert!(!acc.has_remote());
    }

    #[test]
    fn test_on_rtp_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();
        let now = Instant::now();

        acc.on_rtp_sent(12, 1188, now);
        assert_eq!(acc.packets_sent, 1);
        assert_eq!(acc.header_bytes_sent, 12);
        assert_eq!(acc.bytes_sent, 1188);
        assert_eq!(acc.last_packet_sent_timestamp, Some(now));

        let later = now + std::time::Duration::from_millis(20);
        acc.on_rtp_sent(12, 1000, later);
        assert_eq!(acc.packets_sent, 2);
        assert_eq!(acc.header_bytes_sent, 24);
        assert_eq!(acc.bytes_sent, 2188);
        assert_eq!(acc.last_packet_sent_timestamp, Some(later));
    }

    #[test]
    fn test_rtcp_feedback_counters() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_nack_received();
        acc.on_nack_received();
        assert_eq!(acc.nack_count, 2);

        acc.on_fir_received();
        assert_eq!(acc.fir_count, 1);

        acc.on_pli_received();
        acc.on_pli_received();
        acc.on_pli_received();
        assert_eq!(acc.pli_count, 3);
    }

    #[test]
    fn test_on_rtx_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_rtx_sent(500);
        acc.on_rtx_sent(600);
        assert_eq!(acc.retransmitted_packets_sent, 2);
        assert_eq!(acc.retransmitted_bytes_sent, 1100);
    }

    #[test]
    fn test_on_receiver_report() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            clock_rate: 90000,
            ..Default::default()
        };
        acc.on_sequence_number_sent(1000);
        acc.on_sequence_number_sent(1001);

        let mut first = report(1099, 5, 270);
        first.fraction_lost = 64;
        acc.on_receiver_report(&first, now);
        assert_eq!(acc.remote_reports_received, 1);
        // 1099 - 1000 + 1 - 5
        assert_eq!(acc.remote_packets_received, 95);
        assert_eq!(acc.remote_packets_lost, 5);
        assert_eq!(acc.remote_jitter, Some(270));
        assert_eq!(acc.remote_fraction_lost, 0.25);
        // LSR 0: no sender report reached the receiver yet, so no round trip either.
        assert_eq!(acc.remote_round_trip_time, None);
        assert_eq!(acc.rtt_measurements, 0);
        assert!(acc.has_remote());
    }

    #[test]
    fn test_on_frame_sent() {
        let mut acc = OutboundRtpStreamAccumulator::default();

        acc.on_frame_sent(false);
        acc.on_frame_sent(false);
        acc.on_frame_sent(true); // huge frame
        acc.on_frame_sent(false);
        acc.on_frame_sent(true); // huge frame

        assert_eq!(acc.encoder_stats.frames_sent, Some(5));
        assert_eq!(acc.encoder_stats.huge_frames_sent, Some(2));
    }

    #[test]
    fn test_snapshot() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 44444444,
            kind: RtpCodecKind::Audio,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_audio_111".to_string(),
            mid: "1".to_string(),
            active: true,
            ..Default::default()
        };

        acc.on_rtp_sent(12, 160, now);
        acc.on_rtp_sent(12, 160, now);

        let stats = acc.snapshot(now, "RTCOutboundRTPStream_audio_44444444");

        assert_eq!(
            stats.sent_rtp_stream_stats.rtp_stream_stats.stats.id,
            "RTCOutboundRTPStream_audio_44444444"
        );
        assert_eq!(
            stats.sent_rtp_stream_stats.rtp_stream_stats.stats.typ,
            RTCStatsType::OutboundRTP
        );
        assert_eq!(stats.sent_rtp_stream_stats.packets_sent, 2);
        assert_eq!(stats.sent_rtp_stream_stats.bytes_sent, 320);
        assert_eq!(stats.header_bytes_sent, 24);
        assert_eq!(stats.mid, "1");
        assert!(stats.active);
        // encodingIndex is a video member.
        assert_eq!(stats.encoding_index, None);
        // No receiver report yet: no remote-inbound object to name.
        assert_eq!(stats.remote_id, None);
    }

    #[test]
    fn test_snapshot_remote() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 55555555,
            kind: RtpCodecKind::Video,
            transport_id: "RTCTransport_0".to_string(),
            codec_id: "RTCCodec_video_96".to_string(),
            clock_rate: 90000,
            ..Default::default()
        };
        acc.on_sequence_number_sent(0);

        acc.on_receiver_report(&report(509, 10, 450), now);
        acc.on_receiver_report(&report(1019, 20, 360), now);

        let remote_stats = acc.snapshot_remote(now);

        assert_eq!(
            remote_stats
                .received_rtp_stream_stats
                .rtp_stream_stats
                .stats
                .typ,
            RTCStatsType::RemoteInboundRTP
        );
        assert_eq!(
            remote_stats.received_rtp_stream_stats.packets_received,
            1000
        );
        assert_eq!(remote_stats.received_rtp_stream_stats.packets_lost, 20);
        // 360 RTP units at 90 kHz is 4 ms.
        assert_eq!(remote_stats.received_rtp_stream_stats.jitter, Some(0.004));
        assert_eq!(remote_stats.round_trip_time, None);
        assert_eq!(remote_stats.round_trip_time_measurements, 0);
        assert_eq!(remote_stats.local_id, "RTCOutboundRTPStream_video_55555555");
        assert_eq!(
            acc.snapshot(now, "x").remote_id.as_deref(),
            Some("RTCRemoteInboundRTPStream_video_55555555")
        );
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let mut acc = OutboundRtpStreamAccumulator {
            ssrc: 66666666,
            kind: RtpCodecKind::Video,
            active: true,
            ..Default::default()
        };

        acc.on_rtp_sent(12, 1200, now);
        acc.on_frame_sent(false);
        acc.on_nack_received();

        let stats = acc.snapshot(now, "RTCOutboundRTPStream_video_66666666");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"ssrc\":66666666"));
        assert!(json.contains("\"packetsSent\":1"));
        assert!(json.contains("\"bytesSent\":1200"));
        assert!(json.contains("\"framesSent\":1"));
        assert!(json.contains("\"nackCount\":1"));
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"type\":\"outbound-rtp\""));
        // Encoder members were never supplied, and there is no estimate yet.
        assert!(!json.contains("framesEncoded"));
        assert!(!json.contains("qualityLimitationReason"));
        assert!(!json.contains("targetBitrate"));
        assert!(!json.contains("remoteId"));
    }

    #[test]
    fn test_quality_limitation_tracking() {
        let mut acc = OutboundRtpStreamAccumulator {
            kind: RtpCodecKind::Video,
            ..Default::default()
        };

        acc.encoder_stats.merge(EncoderStatsUpdate {
            quality_limitation_reason: Some(RTCQualityLimitationReason::Bandwidth),
            quality_limitation_resolution_changes: Some(3),
            ..Default::default()
        });
        acc.target_bitrate = 1_500_000.0;

        let now = Instant::now();
        let stats = acc.snapshot(now, "test");

        assert_eq!(
            stats.quality_limitation_reason,
            Some(RTCQualityLimitationReason::Bandwidth)
        );
        assert_eq!(stats.quality_limitation_resolution_changes, Some(3));
        assert_eq!(stats.target_bitrate, Some(1_500_000.0));
    }
}
