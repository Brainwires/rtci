//! The limits a congestion controller takes from outside its algorithm, and what it does when
//! the feedback it runs on stops.
//!
//! REMB (draft-ietf-rmcat-gcc-02 sections 3 and 6), TMMBR / TMMBN (RFC 5104 sections 3.5.4 and
//! 4.2), the negotiated session bit rate (`b=AS` / `b=TIAS`), receiver reports when there is no
//! per-packet feedback (draft section 7), and missing feedback (RFC 8888 section 5, RFC 8836
//! requirement 10).

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, BandwidthEstimator, CongestionControlBuilder,
    CongestionControlHandle, Gcc, Interceptor, Packet, PacketReport, RTCPFeedback,
    RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::raw_packet::RawPacket;
use rtcp::transport_feedbacks::tmmb::{
    TemporaryMaximumBitrateNotification, TemporaryMaximumBitrateRequest, TmmbEntry,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const LOCAL: u32 = 0x0A0B_0C0D;
const REMOTE: u32 = 0x5E5E_5E5E;

/// What an estimator was told from outside.
#[derive(Clone, Default)]
struct Told {
    bounds: Arc<Mutex<Vec<(Option<f64>, Option<f64>)>>>,
    round_trips: Arc<Mutex<Vec<Duration>>>,
    receiver_reports: Arc<Mutex<Vec<f64>>>,
    path_changes: Arc<Mutex<u32>>,
}

impl Told {
    fn max(&self) -> Option<f64> {
        self.bounds.lock().unwrap().last().and_then(|(_, max)| *max)
    }
}

impl BandwidthEstimator for Told {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}
    fn target_bitrate(&self) -> f64 {
        1_000_000.0
    }
    fn on_round_trip_time(&mut self, _now: Instant, round_trip_time: Duration) {
        self.round_trips.lock().unwrap().push(round_trip_time);
    }
    fn set_external_bounds(&mut self, min: Option<f64>, max: Option<f64>) {
        self.bounds.lock().unwrap().push((min, max));
    }
    fn on_receiver_report(&mut self, _now: Instant, fraction_lost: f64) {
        self.receiver_reports.lock().unwrap().push(fraction_lost);
    }
    fn on_path_change(&mut self, _now: Instant) {
        *self.path_changes.lock().unwrap() += 1;
    }
}

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: LOCAL,
        clock_rate: 90_000,
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

struct Harness {
    chain: Box<dyn Interceptor>,
    handle: CongestionControlHandle,
    epoch: Instant,
    sequence: u16,
    /// RTCP the chain sent.
    sent_rtcp: Vec<Box<dyn rtcp::Packet>>,
    /// Targets announced on the read leg, in order.
    announced: Vec<f64>,
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

impl Harness {
    fn new<E: BandwidthEstimator + 'static>(estimator: E) -> Self {
        let (interceptor, handle) = CongestionControlBuilder::new(estimator).build_with_handle();
        let mut chain = Registry::new()
            .with(Slot::CongestionControl, interceptor)
            .with(Slot::TwccSender, TwccSenderBuilder::new().build())
            .build();
        chain.bind_local_stream(&stream());
        Self {
            chain: Box::new(chain),
            handle,
            epoch: Instant::now(),
            sequence: 0,
            sent_rtcp: Vec::new(),
            announced: Vec::new(),
        }
    }

    fn drain(&mut self) {
        while let Some(packet) = self.chain.poll_write() {
            if let Packet::Rtcp(packets) = packet.message.packet {
                self.sent_rtcp.extend(packets);
            }
        }
        while let Some(packet) = self.chain.poll_read() {
            if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
                packet.message.get(&Attribute::TargetBitrateChanged {
                    bits_per_second: 0.0,
                })
            {
                self.announced.push(*bits_per_second);
            }
        }
    }

    fn tagged(&self, at: Duration, packet: Packet) -> TaggedPacket {
        TaggedPacket {
            now: self.epoch + at,
            transport: TransportContext::default(),
            message: AttributedPacket::new(packet),
        }
    }

    /// One RTP packet of `size` bytes on the wire.
    fn send(&mut self, at: Duration, size: usize) {
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number: self.sequence,
                ssrc: LOCAL,
                ..Default::default()
            },
            // 12 bytes of header and 8 of the transport-cc extension are added to this.
            payload: vec![0u8; size - 20].into(),
        };
        self.sequence = self.sequence.wrapping_add(1);
        let message = self.tagged(at, Packet::Rtp(packet));
        self.chain.handle_write(message).expect("write");
        self.drain();
    }

    fn receive(&mut self, at: Duration, packet: Box<dyn rtcp::Packet>) {
        let message = self.tagged(at, Packet::Rtcp(vec![packet]));
        self.chain.handle_read(message).expect("read");
        self.drain();
    }

    /// TWCC feedback: the `count` packets from `base` arrived, `spacing` apart.
    fn acknowledge(&mut self, at: Duration, base: u16, count: u16, spacing: Duration) {
        self.receive(
            at,
            Box::new(TransportLayerCc {
                sender_ssrc: REMOTE,
                media_ssrc: LOCAL,
                base_sequence_number: base,
                packet_status_count: count,
                reference_time: (at.as_millis() / 64) as u32,
                fb_pkt_count: (base / count.max(1)) as u8,
                packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                    type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                    packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                    run_length: count,
                })],
                recv_deltas: (0..count)
                    .map(|_| RecvDelta {
                        type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                        delta: spacing.as_micros() as i64,
                    })
                    .collect(),
            }),
        );
    }

    fn tick(&mut self, at: Duration) {
        self.chain.handle_timeout(self.epoch + at).expect("timeout");
        self.drain();
    }

    fn deadline(&mut self) -> Option<Duration> {
        self.chain
            .poll_timeout()
            .map(|at| at.duration_since(self.epoch))
    }

    /// The TMMBN packets sent so far: the sender SSRC and the (owner, bit rate, overhead)
    /// tuples of each.
    fn tmmbns(&self) -> Vec<(u32, Vec<(u32, u64, u16)>)> {
        self.sent_rtcp
            .iter()
            .filter_map(|packet| {
                packet
                    .as_any()
                    .downcast_ref::<TemporaryMaximumBitrateNotification>()
            })
            .map(|tmmbn| {
                (
                    tmmbn.sender_ssrc,
                    tmmbn
                        .entries
                        .iter()
                        .map(|entry| (entry.ssrc, entry.bitrate(), entry.measured_overhead))
                        .collect(),
                )
            })
            .collect()
    }
}

/// A TMMBR from `sender` with one FCI entry (RFC 5104 section 4.2.1.1).
fn tmmbr(sender: u32, target: u32, exponent: u32, mantissa: u32, overhead: u32) -> Box<RawPacket> {
    let mut raw = vec![0x83, 205, 0, 4];
    raw.extend_from_slice(&sender.to_be_bytes());
    raw.extend_from_slice(&0u32.to_be_bytes());
    raw.extend_from_slice(&target.to_be_bytes());
    raw.extend_from_slice(&(exponent << 26 | mantissa << 9 | overhead).to_be_bytes());
    Box::new(RawPacket(Bytes::from(raw)))
}

fn remb(bitrate: f32, ssrcs: Vec<u32>) -> Box<ReceiverEstimatedMaximumBitrate> {
    Box::new(ReceiverEstimatedMaximumBitrate {
        sender_ssrc: REMOTE,
        bitrate,
        ssrcs,
    })
}

// ---------------------------------------------------------------------------------------------
// REMB
// ---------------------------------------------------------------------------------------------

/// draft-ietf-rmcat-gcc-02 sections 3 and 6: the sender takes a received REMB as a bound of its
/// estimate (draft-ietf-rmcat-gcc.md bug G5: an inbound REMB changed nothing).
#[test]
fn a_remb_bounds_the_target() {
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));
    assert_eq!(1_000_000.0, harness.handle.target_bitrate());

    harness.receive(ms(100), remb(400_000.0, vec![LOCAL]));

    assert_eq!(400_000.0, harness.handle.target_bitrate());
    assert_eq!(Some(400_000.0), harness.handle.remb_limit());
    assert_eq!(
        Some(&400_000.0),
        harness.announced.last(),
        "the pacer is told as the REMB passes"
    );
}

/// A REMB for other senders' SSRCs is not about this endpoint.
#[test]
fn a_remb_for_another_sender_is_ignored() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.receive(ms(100), remb(400_000.0, vec![0x7777_7777]));

    assert_eq!(None, told.max());
    assert_eq!(None, harness.handle.remb_limit());
}

/// A receiver that uses REMB repeats it at least once per second (section 3). One that stopped
/// has no other way to lift its bound: it lapses after three seconds.
#[test]
fn a_remb_that_is_not_repeated_lapses() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.receive(ms(0), remb(400_000.0, vec![LOCAL]));
    assert_eq!(Some(400_000.0), told.max());
    assert_eq!(Some(ms(3000)), harness.deadline());

    harness.tick(ms(2999));
    assert_eq!(Some(400_000.0), told.max());
    harness.tick(ms(3000));
    assert_eq!(None, told.max());
    assert_eq!(None, harness.handle.remb_limit());
    assert_eq!(None, harness.deadline(), "nothing left to wait for");
}

// ---------------------------------------------------------------------------------------------
// TMMBR and TMMBN
// ---------------------------------------------------------------------------------------------

/// RFC 5104 section 4.2.1.2: a media sender stays within the limit a TMMBR sets for its SSRC,
/// and answers every TMMBR with a TMMBN carrying the bounding set (section 4.2.2.2): FMT 4,
/// media source 0, the requester as owner of the tuple.
#[test]
fn a_tmmbr_limits_the_sender_and_is_answered_with_a_tmmbn() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    // 2^2 * 65536 = 262 144 bit/s, 40 bytes of overhead per packet; nothing is being sent, so
    // the packet rate is 0 and the whole of it is available to RTP.
    harness.receive(ms(100), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));

    assert_eq!(Some(262_144.0), told.max());
    assert_eq!(Some(262_144.0), harness.handle.tmmbr_limit());

    assert_eq!(
        vec![(LOCAL, vec![(REMOTE, 262_144, 40)])],
        harness.tmmbns(),
        "sent from this endpoint's SSRC, with the requester as owner of the tuple"
    );
}

/// The same through the typed packet `rtc-rtcp` parses a TMMBR into.
#[test]
fn a_typed_tmmbr_limits_the_sender_and_is_answered_with_a_tmmbn() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.receive(
        ms(100),
        Box::new(TemporaryMaximumBitrateRequest {
            sender_ssrc: REMOTE,
            entries: vec![TmmbEntry::new(LOCAL, 500_000, 20)],
        }),
    );

    assert_eq!(Some(500_000.0), told.max());
    assert_eq!(vec![(LOCAL, vec![(REMOTE, 500_000, 20)])], harness.tmmbns());
}

/// RFC 5104 section 3.5.4.2: the bit rate left for RTP is the TMMBR bit rate minus the packet
/// rate times the reported overhead. At 50 packets per second, 40 bytes of overhead cost
/// 16 kbit/s.
#[test]
fn the_tmmbr_overhead_is_charged_at_the_packet_rate_in_use() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    for index in 0..50u64 {
        harness.send(ms(index * 20), 200);
    }
    harness.receive(ms(1000), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));

    assert_eq!(Some(262_144.0 - 50.0 * 40.0 * 8.0), told.max());
}

/// A TMMBR entry is for the media sender its SSRC names: one for another sender limits nothing
/// here and is not this endpoint's to acknowledge.
#[test]
fn a_tmmbr_for_another_sender_is_not_answered() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.receive(ms(100), tmmbr(REMOTE, 0x7777_7777, 2, 65_536, 40));

    assert_eq!(None, told.max());
    assert!(harness.tmmbns().is_empty());
}

/// RFC 5104 section 4.2.2.2: a TMMBR that changes nothing still results in a TMMBN, and when
/// the owner of the bounding tuple leaves, a TMMBN without it is sent, with no FCI when the set
/// is empty.
#[test]
fn a_repeated_tmmbr_is_acknowledged_again_and_a_bye_empties_the_bounding_set() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.receive(ms(100), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));
    harness.receive(ms(200), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));
    assert_eq!(2, harness.tmmbns().len(), "one TMMBN per TMMBR");

    harness.receive(
        ms(300),
        Box::new(rtcp::goodbye::Goodbye {
            sources: vec![REMOTE],
            ..Default::default()
        }),
    );
    let tmmbns = harness.tmmbns();
    assert_eq!(3, tmmbns.len());
    assert_eq!((LOCAL, Vec::new()), tmmbns[2], "a TMMBN without FCI");

    // Section 4.2.1.2: the looser limit (none) applies after 2 * RTT + T_Dither_Max; no round
    // trip has been measured, so at the next wake-up.
    harness.tick(ms(301));
    assert_eq!(None, told.max());
}

// ---------------------------------------------------------------------------------------------
// Signalling inputs, round trip time, receiver reports
// ---------------------------------------------------------------------------------------------

/// The bit rate the remote description allows (`b=AS`, `b=TIAS`) is a bound of the target, and
/// the tightest of the outside limits is the one in force.
#[test]
fn the_session_bitrate_limit_bounds_the_target_with_the_other_limits() {
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));

    harness.handle.set_session_bitrate_limit(Some(600_000.0));
    harness.tick(ms(10));
    assert_eq!(600_000.0, harness.handle.target_bitrate());
    assert_eq!(
        Some(&600_000.0),
        harness.announced.last(),
        "with no packet to ride on, the change still reaches the pacer's leg"
    );

    harness.receive(ms(20), remb(450_000.0, vec![LOCAL]));
    assert_eq!(450_000.0, harness.handle.target_bitrate());

    harness.receive(ms(30), tmmbr(REMOTE, LOCAL, 2, 65_536, 0));
    assert_eq!(262_144.0, harness.handle.target_bitrate());
}

/// A path change reaches the estimator once (RFC 8836 section 2, requirement 1d).
#[test]
fn a_path_change_is_passed_to_the_estimator() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    harness.handle.notify_path_change();
    harness.tick(ms(10));
    harness.tick(ms(20));

    assert_eq!(1, *told.path_changes.lock().unwrap());
}

/// The round trip time the feedback implies reaches the estimator: the additive increase of
/// draft-ietf-rmcat-gcc-02 section 5.5 is scaled by it.
#[test]
fn the_round_trip_time_from_feedback_reaches_the_estimator() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    for index in 0..5u64 {
        harness.send(ms(index * 10), 1200);
    }
    harness.acknowledge(ms(120), 0, 5, ms(10));

    // The newest packet left at 40 ms and its feedback was read at 120 ms.
    assert_eq!(vec![ms(80)], *told.round_trips.lock().unwrap());
}

/// draft-ietf-rmcat-gcc-02 section 7: against a receiver that sends no per-packet feedback the
/// loss-based controller runs on the fraction lost of its receiver reports. Once per-packet
/// feedback has been seen the reports are no longer an input.
#[test]
fn receiver_reports_feed_the_estimator_only_without_per_packet_feedback() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());
    let report = |fraction_lost: u8| {
        Box::new(rtcp::receiver_report::ReceiverReport {
            ssrc: REMOTE,
            reports: vec![rtcp::reception_report::ReceptionReport {
                ssrc: LOCAL,
                fraction_lost,
                ..Default::default()
            }],
            ..Default::default()
        })
    };

    harness.receive(ms(1000), report(64));
    assert_eq!(vec![0.25], *told.receiver_reports.lock().unwrap());

    harness.send(ms(1100), 1200);
    harness.acknowledge(ms(1200), 0, 1, ms(1));
    harness.receive(ms(2000), report(128));
    assert_eq!(vec![0.25], *told.receiver_reports.lock().unwrap());
}

/// And with `Gcc`: 25% reported loss, with no TWCC or RFC 8888 feedback at all, brings the
/// target down.
#[test]
fn gcc_backs_off_on_reported_loss_when_there_is_no_per_packet_feedback() {
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));

    for second in 1..=5u64 {
        harness.receive(
            ms(second * 1000),
            Box::new(rtcp::receiver_report::ReceiverReport {
                ssrc: REMOTE,
                reports: vec![rtcp::reception_report::ReceptionReport {
                    ssrc: LOCAL,
                    fraction_lost: 64,
                    ..Default::default()
                }],
                ..Default::default()
            }),
        );
    }

    // Each report above 10% loss multiplies the target by 1 - 0.5 * 0.25.
    let expected = 1_000_000.0 * 0.875f64.powi(5);
    assert!(
        (harness.handle.target_bitrate() - expected).abs() < 1.0,
        "expected {expected}, got {}",
        harness.handle.target_bitrate()
    );
}

// ---------------------------------------------------------------------------------------------
// Missing feedback
// ---------------------------------------------------------------------------------------------

/// RFC 8888 section 5 and RFC 8836 requirement 10: when feedback stops while media is being
/// sent, the sender treats it as possible over-use and rapidly reduces its rate. `Gcc` halves
/// the target for every 500 ms without feedback.
#[test]
fn gcc_halves_the_target_for_every_feedback_timeout_without_feedback() {
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));

    // A second of media with feedback every 100 ms.
    let mut acknowledged = 0u16;
    for index in 0..100u64 {
        harness.send(ms(index * 10), 1200);
        if index % 10 == 9 {
            harness.acknowledge(ms(index * 10 + 5), acknowledged, 10, ms(10));
            acknowledged += 10;
        }
    }
    let before = harness.handle.target_bitrate();
    assert_eq!(
        None,
        harness.deadline(),
        "everything sent has been reported on"
    );

    // The feedback stops; the media does not.
    for index in 100..220u64 {
        harness.send(ms(index * 10), 1200);
    }
    assert_eq!(
        Some(ms(1500)),
        harness.deadline(),
        "500 ms after the first packet nothing has been heard about"
    );
    harness.tick(ms(1499));
    assert_eq!(before, harness.handle.target_bitrate());

    harness.tick(ms(1500));
    assert_eq!(before * 0.5, harness.handle.target_bitrate());
    assert_eq!(
        Some(&(before * 0.5)),
        harness.announced.last(),
        "the pacer is told, with no packet to ride on"
    );

    harness.tick(ms(2000));
    assert_eq!(before * 0.25, harness.handle.target_bitrate());
}

/// A sender that stopped sending is not waiting for feedback: nothing is cut and no timer runs.
#[test]
fn an_idle_sender_is_not_cut_for_missing_feedback() {
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));

    for index in 0..10u64 {
        harness.send(ms(index * 10), 1200);
    }
    harness.acknowledge(ms(100), 0, 10, ms(10));
    let before = harness.handle.target_bitrate();

    assert_eq!(None, harness.deadline());
    harness.tick(ms(60_000));
    assert_eq!(before, harness.handle.target_bitrate());
}

/// A receiver that holds its feedback to the RTCP bandwidth reports every few hundred
/// milliseconds at a low media rate. That rhythm is not missing feedback: the timeout is three
/// of the receiver's own intervals when those are longer than 500 ms.
#[test]
fn a_slow_but_regular_feedback_rhythm_is_not_missing_feedback() {
    let mut harness = Harness::new(Gcc::new(300_000.0, 50_000.0, 10_000_000.0));

    // 100 kbit/s of media (a 250-byte packet every 20 ms), feedback every 600 ms: more than
    // 500 ms without feedback passes in every interval, with a wake-up every 100 ms.
    let mut acknowledged = 0u16;
    let mut lowest = f64::INFINITY;
    for index in 0..1000u64 {
        harness.send(ms(index * 20), 250);
        if index % 5 == 4 {
            harness.tick(ms(index * 20 + 1));
        }
        if index % 30 == 29 {
            harness.acknowledge(ms(index * 20 + 5), acknowledged, 30, ms(20));
            acknowledged += 30;
        }
        if index >= 100 {
            lowest = lowest.min(harness.handle.target_bitrate());
        }
    }

    // Held by the received rate (1.5 x 100 kbit/s), never halved for a timeout.
    assert!(
        lowest >= 140_000.0,
        "the target fell to {lowest} on a clean path with regular feedback"
    );
}
