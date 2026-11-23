use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::{AudioReceiverStatsUpdate, CcfbTally, DecoderStatsUpdate};
use crate::statistics::stats::rtp_stream::RTCRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::RTCReceivedRtpStreamStats;
use crate::statistics::stats::rtp_stream::received::inbound::RTCInboundRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::RTCSentRtpStreamStats;
use crate::statistics::stats::rtp_stream::sent::remote_outbound::RTCRemoteOutboundRtpStreamStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReportBlock;
use shared::EcnCodepoint;
use shared::time::SystemInstant;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many of our latest RTCP XR receiver reference times (RFC 3611 section 4.4) a stream
/// remembers, for the DLRR block that echoes one.
const REFERENCE_TIMES_REMEMBERED: usize = 16;

/// The suffix that tells a stream object from an earlier, deleted one that had the same SSRC:
/// `generation` is how many RTP stream objects the connection had deleted when this one was
/// created, so it differs from that of any deleted object with the SSRC (webrtc-stats 4.3: the
/// id of a deleted object is never reused; 8.1: a recycled SSRC is a new object with a new id).
pub(crate) fn generation_suffix(generation: u64) -> String {
    if generation == 0 {
        String::new()
    } else {
        format!("_{generation}")
    }
}

/// The stats id of the inbound-rtp object for `ssrc`, before the report seals it.
pub(crate) fn inbound_stats_id(kind: RtpCodecKind, ssrc: SSRC, generation: u64) -> String {
    format!(
        "RTCInboundRTPStream_{kind}_{ssrc}{}",
        generation_suffix(generation)
    )
}

/// The stats id of the remote-outbound-rtp object for `ssrc`, before the report seals it.
pub(crate) fn remote_outbound_stats_id(kind: RtpCodecKind, ssrc: SSRC, generation: u64) -> String {
    format!(
        "RTCRemoteOutboundRTPStream_{kind}_{ssrc}{}",
        generation_suffix(generation)
    )
}

/// The wall-clock time an RTCP sender report's 64-bit NTP timestamp names, as a duration since
/// the Unix epoch; `None` for a timestamp before 1970 (a sender that does not have wall-clock
/// time puts something else there, RFC 3550 section 6.4.1).
pub(crate) fn ntp_to_unix(ntp_time: u64) -> Option<Duration> {
    /// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
    const NTP_TO_UNIX_SECONDS: u64 = 0x83AA_7E80;
    let seconds = (ntp_time >> 32).checked_sub(NTP_TO_UNIX_SECONDS)?;
    let nanos = ((ntp_time & 0xFFFF_FFFF) * 1_000_000_000) >> 32;
    Some(Duration::new(seconds, nanos as u32))
}

/// An RTCP interarrival jitter (RFC 3550 section 6.4.1, in RTP timestamp units) in seconds, or
/// `None` while the clock rate it is counted in is not known.
pub(crate) fn jitter_seconds(jitter_rtp_units: Option<u32>, clock_rate: u32) -> Option<f64> {
    match (jitter_rtp_units, clock_rate) {
        (Some(units), rate) if rate > 0 => Some(f64::from(units) / f64::from(rate)),
        _ => None,
    }
}

/// Whether the members of one media kind apply to a stream.
pub(crate) struct OnlyFor(pub(crate) bool);

impl OnlyFor {
    /// `value` if the stream is of that kind, `None` (the member does not exist) otherwise.
    pub(crate) fn the<T>(&self, value: Option<T>) -> Option<T> {
        value.filter(|_| self.0)
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
    /// Tells this object's id from that of a deleted one with the same SSRC
    /// ([`generation_suffix`]).
    pub generation: u64,

    // Packet counters
    /// Total RTP packets received for the SSRC, with those of its RTX and FEC streams
    /// (webrtc-stats 7.1: they are not objects of their own and count here).
    pub packets_received: u64,
    /// Total payload bytes received (excluding headers and padding).
    pub bytes_received: u64,
    /// Total RTP header and padding bytes received; an RTX packet's original sequence number
    /// (RFC 4588 section 4) is header too.
    pub header_bytes_received: u64,
    /// Cumulative packets lost (negative when duplicates outnumber losses), from the latest
    /// reception report this side sent about the stream.
    pub packets_lost: i64,
    /// Interarrival jitter in RTP timestamp units, from the latest reception report this side
    /// sent about the stream.
    pub jitter_rtp_units: Option<u32>,
    /// Timestamp of the last RTP packet received.
    pub last_packet_received_timestamp: Option<Instant>,

    // ECN (RFC 3168) and RFC 8888 congestion control feedback
    /// The application's socket layer reports each datagram's ECN codepoint, so the ECN
    /// counts below are measured (`SettingEngineBuilder::with_ecn`).
    pub ecn: bool,
    /// RTP packets received with ECT(1).
    pub packets_received_with_ect1: u64,
    /// RTP packets received with CE.
    pub packets_received_with_ce: u64,
    /// The stream's codec negotiated RFC 8888 feedback (`a=rtcp-fb:<pt> ack ccfb`).
    pub ccfb_negotiated: bool,
    /// What the RFC 8888 reports this side sent say about the stream.
    pub ccfb_sent: Option<Box<CcfbTally>>,

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
    /// When the latest remote sender report arrived: the remote-outbound object's `timestamp`.
    pub remote_report_received_at: Option<Instant>,
    /// The NTP timestamp the latest remote sender report carried, the remote clock's reading:
    /// the remote-outbound object's `remoteTimestamp`.
    pub remote_ntp_time: Option<u64>,
    /// The RTP timestamp the latest remote sender report carried, the same instant as
    /// `remote_ntp_time` on the stream's media clock (RFC 3550 section 6.4.1).
    pub remote_rtp_time: Option<u32>,
    /// Number of RTCP SR reports received.
    pub reports_received: u64,

    // Round trip time from RTCP XR (RFC 3611 sections 4.4, 4.5)
    /// The SSRC our receiver reports about this stream are sent from, which our XR receiver
    /// reference time blocks carry and the remote sender's DLRR sub-blocks name.
    pub receiver_ssrc: Option<u32>,
    /// Our latest receiver reference times for the stream: the compact NTP timestamp each
    /// carried and when it was sent.
    pub reference_times_sent: VecDeque<(u32, Instant)>,
    /// The latest round trip time measured from a DLRR block, in seconds.
    pub remote_round_trip_time: Option<f64>,
    /// Sum of the round trip times measured from DLRR blocks, in seconds.
    pub remote_total_round_trip_time: f64,
    /// Number of round trip times measured from DLRR blocks.
    pub remote_rtt_measurements: u64,
    /// When the latest of them was measured: a sender report arriving at that instant came
    /// with the block.
    pub remote_rtt_measured_at: Option<Instant>,

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
    /// Called when an RTP packet is received: `header_bytes` is its header and padding,
    /// `payload_bytes` its payload.
    pub fn on_rtp_received(&mut self, header_bytes: usize, payload_bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.header_bytes_received += header_bytes as u64;
        self.bytes_received += payload_bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    /// Counts header-side bytes of a packet that [`on_rtp_received`](Self::on_rtp_received)
    /// counts without them: the original sequence number and the padding of an RTX packet,
    /// both gone once it is de-encapsulated.
    pub fn on_header_overhead_received(&mut self, bytes: usize) {
        self.header_bytes_received += bytes as u64;
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

    /// Called when RTCP Sender Report is received from remote: its sender's packet and octet
    /// counts, the NTP timestamp it carries (the remote clock) and when it arrived (ours).
    pub fn on_rtcp_sr_received(
        &mut self,
        packets_sent: u64,
        bytes_sent: u64,
        ntp_time: u64,
        now: Instant,
    ) {
        self.remote_packets_sent = packets_sent;
        self.remote_bytes_sent = bytes_sent;
        self.remote_ntp_time = Some(ntp_time);
        self.remote_report_received_at = Some(now);
        self.reports_received += 1;
        // webrtc-stats: `roundTripTime` does not exist "if the latest SR does not contain the
        // DLRR report block". The block comes after the sender report in the compound packet
        // and sets it again; the total and the count of measurements stay. A block that
        // arrived at this very instant is this report's too, in whichever RTCP packet or
        // datagram of the sender's burst it travelled.
        if self.remote_rtt_measured_at != Some(now) {
            self.remote_round_trip_time = None;
        }
    }

    /// The RTP timestamp of the sender report `on_rtcp_sr_received` took.
    pub fn on_rtcp_sr_rtp_time(&mut self, rtp_time: u32) {
        self.remote_rtp_time = Some(rtp_time);
    }

    /// webrtc-extensions 15 "remote capture timestamp": when a frame of this stream was
    /// captured, on this side's clock, by the latest sender report (RFC 3550 section 6.4.1).
    /// `capture_ntp` is the capture time on the sender's NTP clock in seconds when the frame
    /// said it (abs-capture-time with the sender's offset), else the frame's RTP timestamp is
    /// placed by the report's NTP / RTP pair at `clock_rate`. The sender's clock is brought to
    /// this one by the report's arrival less half the round trip time (webrtc-extensions 8:
    /// `senderReceiverTimeOffset`), 0 while no round trip is known. `None` before a report.
    pub fn remote_capture_instant(
        &self,
        rtp_timestamp: u32,
        clock_rate: u32,
        capture_ntp: Option<f64>,
    ) -> Option<Instant> {
        let received_at = self.remote_report_received_at?;
        let report_ntp = self.remote_ntp_time? as f64 / 4_294_967_296.0;
        let capture_ntp = match capture_ntp {
            Some(ntp) => ntp,
            None => {
                if clock_rate == 0 {
                    return None;
                }
                let report_rtp = self.remote_rtp_time?;
                let elapsed = rtp_timestamp.wrapping_sub(report_rtp) as i32;
                report_ntp + f64::from(elapsed) / f64::from(clock_rate)
            }
        };
        let one_way = self.remote_round_trip_time.unwrap_or(0.0) / 2.0;
        let offset = capture_ntp - report_ntp - one_way;
        if offset >= 0.0 {
            received_at.checked_add(Duration::from_secs_f64(offset))
        } else {
            received_at.checked_sub(Duration::from_secs_f64(-offset))
        }
    }

    /// Called when this side sends an RTCP XR receiver reference time block (RFC 3611 section
    /// 4.4) for the stream: remembers when, so the DLRR sub-block that echoes it gives a round
    /// trip time.
    pub fn on_reference_time_sent(&mut self, compact_ntp: u32, now: Instant) {
        if self.reference_times_sent.len() == REFERENCE_TIMES_REMEMBERED {
            self.reference_times_sent.pop_front();
        }
        self.reference_times_sent.push_back((compact_ntp, now));
    }

    /// Called when a DLRR sub-block (RFC 3611 section 4.5) answers one of our receiver
    /// reference times: the round trip time is `A - LRR - DLRR`, where `A - LRR` is the time
    /// since we sent the reference time the LRR field echoes. A sub-block with LRR 0 (no
    /// reference time received yet) or naming one we no longer remember gives none.
    pub fn on_dlrr_received(&mut self, last_rr: u32, dlrr: u32, now: Instant) {
        // webrtc-stats: no round trip time "if the last RR timestamp in the DLRR report block
        // is zero, or if the delay since last RR value in the DLRR report block is zero".
        if last_rr == 0 || dlrr == 0 {
            return;
        }
        let Some(&(_, sent_at)) = self
            .reference_times_sent
            .iter()
            .rev()
            .find(|(lrr, _)| *lrr == last_rr)
        else {
            return;
        };
        let Some(since_sent) = now.checked_duration_since(sent_at) else {
            return;
        };
        let delay = Duration::from_secs_f64(f64::from(dlrr) / 65536.0);
        // DLRR is truncated to 1/65536 s: on a near-zero path it can exceed the elapsed time by
        // a fraction of a tick, which is a round trip of 0.
        let rtt = since_sent.saturating_sub(delay).as_secs_f64();
        self.remote_round_trip_time = Some(rtt);
        self.remote_rtt_measured_at = Some(now);
        self.remote_total_round_trip_time += rtt;
        self.remote_rtt_measurements += 1;
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

    /// Counts the ECN codepoint an RTP packet of the stream arrived with.
    pub fn on_ecn_received(&mut self, ecn: Option<EcnCodepoint>) {
        match ecn {
            Some(EcnCodepoint::Ect1) => self.packets_received_with_ect1 += 1,
            Some(EcnCodepoint::Ce) => self.packets_received_with_ce += 1,
            _ => {}
        }
    }

    /// Counts what an RFC 8888 report block this side sent says about the stream: the packets
    /// it reported lost (`packetsReportedAsLost`) and, of those, the ones a later report said
    /// arrived (`packetsReportedAsLostButRecovered`).
    pub fn on_ccfb_block_sent(&mut self, block: &CcFeedbackReportBlock) {
        self.ccfb_sent
            .get_or_insert_with(|| Box::new(CcfbTally::new()))
            .on_report_block(block, false);
    }

    /// Whether the RFC 8888 members exist: webrtc-stats has them only where `ccfb` is
    /// negotiated.
    fn reports_ccfb(&self) -> bool {
        self.ccfb_negotiated || self.ccfb_sent.is_some()
    }

    /// Called when a retransmission is received: `bytes` is the payload of the packet it
    /// repeats (an RTX packet's payload without the original sequence number).
    pub fn on_rtx_received(&mut self, bytes: usize) {
        self.retransmitted_packets_received += 1;
        self.retransmitted_bytes_received += bytes as u64;
    }

    /// Called when a packet of the stream's FEC SSRC is received: it counts as a packet of the
    /// stream (`packetsReceived`, `bytesReceived`, `headerBytesReceived`) and as FEC, which
    /// webrtc-stats defines as a subset of those.
    pub fn on_fec_received(&mut self, header_bytes: usize, payload_bytes: usize, now: Instant) {
        self.on_rtp_received(header_bytes, payload_bytes, now);
        self.fec_packets_received += 1;
        self.fec_bytes_received += payload_bytes as u64;
    }

    /// Called when a packet of the stream's RTX SSRC that repeats nothing is received (padding
    /// only, a bandwidth probe: RFC 4588 section 4): a packet of the stream, all of it header
    /// and padding, and not a retransmission.
    pub fn on_rtx_padding_received(&mut self, bytes: usize, now: Instant) {
        self.on_rtp_received(bytes, 0, now);
    }

    /// The stats id of this object, before the report seals it.
    pub fn stats_id(&self) -> String {
        inbound_stats_id(self.kind, self.ssrc, self.generation)
    }

    /// The stats id of the remote-outbound object, before the report seals it.
    fn remote_stats_id(&self) -> String {
        remote_outbound_stats_id(self.kind, self.ssrc, self.generation)
    }

    /// Whether the remote-outbound object exists: webrtc-stats 6.1 creates it when the first
    /// RTCP Sender Report for the SSRC arrives.
    pub fn has_remote(&self) -> bool {
        self.reports_received > 0
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCInboundRtpStreamStats {
        let decoder = &self.decoder_stats;
        let receiver = &self.audio_receiver_stats;
        // webrtc-stats 4.2: a member that does not apply to the object does not exist. The
        // application may supply any member for any stream; a video-only member is reported
        // for a video stream only, an audio-only one for an audio stream only.
        let video = OnlyFor(self.kind == RtpCodecKind::Video);
        let audio = OnlyFor(self.kind == RtpCodecKind::Audio);
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
                packets_received_with_ect1: self.ecn.then_some(self.packets_received_with_ect1),
                packets_received_with_ce: self.ecn.then_some(self.packets_received_with_ce),
                packets_reported_as_lost: self.reports_ccfb().then(|| {
                    self.ccfb_sent
                        .as_ref()
                        .map_or(0, |tally| tally.reported_as_lost)
                }),
                packets_reported_as_lost_but_recovered: self.reports_ccfb().then(|| {
                    self.ccfb_sent
                        .as_ref()
                        .map_or(0, |tally| tally.reported_as_lost_but_recovered)
                }),
                packets_lost: self.packets_lost,
                jitter: jitter_seconds(self.jitter_rtp_units, self.clock_rate),
            },
            track_identifier: self.track_identifier.clone(),
            mid: self.mid.clone(),
            remote_id: self.has_remote().then(|| self.remote_stats_id()),
            frames_decoded: video.the(decoder.frames_decoded),
            key_frames_decoded: video.the(decoder.key_frames_decoded),
            frames_rendered: video.the(decoder.frames_rendered),
            frames_dropped: video.the(decoder.frames_dropped),
            frame_width: video.the(decoder.frame_width),
            frame_height: video.the(decoder.frame_height),
            frames_per_second: video.the(decoder.frames_per_second),
            qp_sum: video.the(decoder.qp_sum),
            total_decode_time: video.the(decoder.total_decode_time),
            total_inter_frame_delay: video.the(decoder.total_inter_frame_delay),
            total_squared_inter_frame_delay: video.the(decoder.total_squared_inter_frame_delay),
            pause_count: video.the(decoder.pause_count),
            total_pauses_duration: video.the(decoder.total_pauses_duration),
            freeze_count: video.the(decoder.freeze_count),
            total_freezes_duration: video.the(decoder.total_freezes_duration),
            last_packet_received_timestamp: self
                .last_packet_received_timestamp
                .map(SystemInstant::now),
            header_bytes_received: self.header_bytes_received,
            packets_discarded: decoder.packets_discarded,
            fec_bytes_received: self.fec_bytes_received
                + receiver.in_band_fec_bytes_received.unwrap_or(0),
            fec_packets_received: self.fec_packets_received
                + receiver.in_band_fec_packets_received.unwrap_or(0),
            fec_packets_discarded: receiver.fec_packets_discarded,
            bytes_received: self.bytes_received,
            nack_count: self.nack_count,
            // FIR and PLI ask for a video key frame: the members exist for video only.
            fir_count: video.the(Some(self.fir_count)),
            pli_count: video.the(Some(self.pli_count)),
            total_processing_delay: decoder.total_processing_delay,
            // The sender's clock, as the application read it: not an instant of ours.
            estimated_playout_timestamp: receiver
                .estimated_playout_timestamp
                .map(|sender_clock| SystemInstant::at(now, sender_clock)),
            jitter_buffer_delay: receiver.jitter_buffer_delay,
            jitter_buffer_target_delay: receiver.jitter_buffer_target_delay,
            jitter_buffer_emitted_count: receiver.jitter_buffer_emitted_count,
            jitter_buffer_minimum_delay: receiver.jitter_buffer_minimum_delay,
            total_samples_received: audio.the(receiver.total_samples_received),
            concealed_samples: audio.the(receiver.concealed_samples),
            silent_concealed_samples: audio.the(receiver.silent_concealed_samples),
            concealment_events: audio.the(receiver.concealment_events),
            inserted_samples_for_deceleration: audio
                .the(receiver.inserted_samples_for_deceleration),
            removed_samples_for_acceleration: audio.the(receiver.removed_samples_for_acceleration),
            audio_level: audio.the(receiver.audio_level),
            total_audio_energy: audio.the(receiver.total_audio_energy),
            total_samples_duration: audio.the(receiver.total_samples_duration),
            frames_received: video.the(decoder.frames_received),
            decoder_implementation: video.the(decoder.decoder_implementation.clone()),
            playout_id: audio.the(self.playout_id.clone()),
            power_efficient_decoder: video.the(decoder.power_efficient_decoder),
            frames_assembled_from_multiple_packets: video
                .the(decoder.frames_assembled_from_multiple_packets),
            total_assembly_time: video.the(decoder.total_assembly_time),
            // webrtc-stats: these do not exist where RTX is not negotiated.
            retransmitted_packets_received: self
                .rtx_ssrc
                .map(|_| self.retransmitted_packets_received),
            retransmitted_bytes_received: self.rtx_ssrc.map(|_| self.retransmitted_bytes_received),
            rtx_ssrc: self.rtx_ssrc,
            fec_ssrc: self.fec_ssrc,
            total_corruption_probability: video.the(decoder.total_corruption_probability),
            total_squared_corruption_probability: video
                .the(decoder.total_squared_corruption_probability),
            corruption_measurements: video.the(decoder.corruption_measurements),
        }
    }

    /// Creates a snapshot of remote outbound stats from RTCP SR data.
    ///
    /// Only meaningful once [`has_remote`](Self::has_remote) is true; the report leaves the
    /// object out before that.
    ///
    /// Its `timestamp` is when the latest sender report arrived (webrtc 8.4: for statistics
    /// that came from a remote source, the time the information reached the local endpoint),
    /// its `remoteTimestamp` the NTP time that report carries.
    pub fn snapshot_remote(&self, now: Instant) -> RTCRemoteOutboundRtpStreamStats {
        let received_at = self.remote_report_received_at.unwrap_or(now);
        RTCRemoteOutboundRtpStreamStats {
            sent_rtp_stream_stats: RTCSentRtpStreamStats {
                rtp_stream_stats: RTCRtpStreamStats {
                    stats: RTCStats {
                        timestamp: SystemInstant::now(received_at),
                        typ: RTCStatsType::RemoteOutboundRTP,
                        id: self.remote_stats_id(),
                    },
                    ssrc: self.ssrc,
                    kind: self.kind,
                    transport_id: self.transport_id.clone(),
                    codec_id: self.codec_id.clone(),
                },
                packets_sent: self.remote_packets_sent,
                bytes_sent: self.remote_bytes_sent,
            },
            local_id: self.stats_id(),
            remote_timestamp: self
                .remote_ntp_time
                .and_then(ntp_to_unix)
                .map(|unix| SystemInstant::at(received_at, unix)),
            reports_sent: self.reports_received,
            round_trip_time: self.remote_round_trip_time,
            total_round_trip_time: self.remote_total_round_trip_time,
            round_trip_time_measurements: self.remote_rtt_measurements,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dlrr_answering_a_reference_time_gives_a_round_trip_time() {
        let mut acc = InboundRtpStreamAccumulator::default();
        let t0 = Instant::now();
        acc.on_dlrr_received(0x1234_0000, 0, t0 + Duration::from_millis(50));
        assert_eq!(acc.remote_rtt_measurements, 0, "nothing was sent yet");

        acc.on_reference_time_sent(0x1234_0000, t0);
        // Echoed 50 ms after it was sent, held 10 ms by the remote: 40 ms on the wire.
        acc.on_dlrr_received(
            0x1234_0000,
            (0.010 * 65536.0) as u32,
            t0 + Duration::from_millis(50),
        );
        assert_eq!(acc.remote_rtt_measurements, 1);
        let rtt = acc.remote_round_trip_time.expect("a round trip time");
        assert!((rtt - 0.040).abs() < 0.001, "{rtt}");
        acc.on_dlrr_received(0, 0, t0 + Duration::from_millis(60));
        acc.on_dlrr_received(0x9999_0000, 0, t0 + Duration::from_millis(60));
        assert_eq!(
            acc.remote_rtt_measurements, 1,
            "LRR 0 or unknown gives none"
        );

        let remote = acc.snapshot_remote(t0);
        assert_eq!(remote.round_trip_time, Some(rtt));
        assert_eq!(remote.round_trip_time_measurements, 1);
        assert!((remote.total_round_trip_time - rtt).abs() < 1e-9);
    }

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

        acc.on_rtcp_sr_received(1000, 1_000_000, 0, now);
        assert_eq!(acc.remote_packets_sent, 1000);
        assert_eq!(acc.remote_bytes_sent, 1_000_000);
        assert_eq!(acc.remote_report_received_at, Some(now));
        assert_eq!(acc.reports_received, 1);
        assert!(acc.has_remote());

        let later = now + std::time::Duration::from_secs(5);
        acc.on_rtcp_sr_received(2000, 2_000_000, 0, later);
        assert_eq!(acc.remote_packets_sent, 2000);
        assert_eq!(acc.remote_bytes_sent, 2_000_000);
        assert_eq!(acc.remote_report_received_at, Some(later));
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

        let now = Instant::now();
        acc.on_fec_received(12, 200, now);
        acc.on_fec_received(12, 300, now);
        acc.on_fec_received(12, 250, now);
        assert_eq!(acc.fec_packets_received, 3);
        assert_eq!(acc.fec_bytes_received, 750);
        // FEC packets are packets of the stream: `fecBytesReceived` is a subset of
        // `bytesReceived`.
        assert_eq!(acc.packets_received, 3);
        assert_eq!(acc.bytes_received, 750);
        assert_eq!(acc.header_bytes_received, 36);
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

        acc.on_rtcp_sr_received(500, 600000, 0, now);
        acc.on_rtcp_sr_received(1000, 1200000, 0, now);

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
