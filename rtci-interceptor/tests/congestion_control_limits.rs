//! The limits a congestion controller takes from outside its algorithm, and what it does when
//! the feedback it runs on stops.
//!
//! REMB (draft-ietf-rmcat-gcc-02 sections 3 and 6), TMMBR / TMMBN (RFC 5104 sections 3.5.4 and
//! 4.2), the negotiated session bit rate (`b=AS` / `b=TIAS`), receiver reports when there is no
//! per-packet feedback (draft section 7), and missing feedback (RFC 8888 section 5, RFC 8836
//! requirement 10).

use bytes::Bytes;
use rtci_interceptor::{
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
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
            // RFC 5104 section 7.1: TMMBR is in use on a stream that negotiated it.
            RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "tmmbr".to_owned(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

/// The same stream from a session whose description has no `a=rtcp-fb:<pt> ccm tmmbr`.
fn stream_without_tmmbr() -> StreamInfo {
    let mut info = stream();
    info.rtcp_feedback.retain(|feedback| feedback.typ != "ccm");
    info
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
        Self::with(CongestionControlBuilder::new(estimator), &stream())
    }

    fn with<E: BandwidthEstimator + 'static>(
        builder: CongestionControlBuilder<E>,
        info: &StreamInfo,
    ) -> Self {
        let (interceptor, handle) = builder.build_with_handle();
        let mut chain = Registry::new()
            .with(Slot::CongestionControl, interceptor)
            .with(Slot::TwccSender, TwccSenderBuilder::new().build())
            .build();
        chain.bind_local_stream(info);
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

/// The same through the typed packet `rtci-rtcp` parses a TMMBR into.
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

/// RFC 5104 section 3.5.4.2: "the packet rate used" is the one the sender uses now. A TMMBR
/// that arrives during a burst (a probe cluster after the start) leaves nothing for RTP at that
/// packet rate; once the sender is back at 50 packets per second, the same tuple leaves it
/// 80 kbit/s less 50 * 60 bytes of overhead. The limit was once frozen at the rate of the
/// moment the request came, which held the sender at nothing for as long as the tuple stood.
#[test]
fn the_tmmbr_limit_follows_the_packet_rate_the_sender_uses() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    for index in 0..170u64 {
        harness.send(ms(index * 5), 200);
    }
    // 80 000 bit/s (exponent 0), 60 bytes of overhead: 170 * 60 * 8 is more than that.
    harness.receive(ms(1000), tmmbr(REMOTE, LOCAL, 0, 80_000, 60));
    assert_eq!(Some(0.0), told.max(), "nothing is left at the burst's rate");

    for index in 0..100u64 {
        harness.send(ms(1000 + index * 20), 200);
    }
    harness.tick(ms(2990));
    assert_eq!(Some(80_000.0 - 50.0 * 60.0 * 8.0), told.max());
    assert_eq!(
        Some(80_000.0 - 50.0 * 60.0 * 8.0),
        harness.handle.tmmbr_limit()
    );
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

/// RFC 5104 sections 7.1 and 7.2: a codec control message is in use when the session
/// description names it (`a=rtcp-fb:<pt> ccm tmmbr`), and an answerer removes what it does not
/// support. A TMMBR for a stream that did not negotiate it limits nothing and is not answered.
#[test]
fn a_tmmbr_for_a_stream_that_did_not_negotiate_it_is_ignored() {
    let told = Told::default();
    let mut harness = Harness::with(
        CongestionControlBuilder::new(told.clone()),
        &stream_without_tmmbr(),
    );

    harness.receive(ms(100), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));

    assert_eq!(
        None,
        told.max(),
        "no limit from a message the session lacks"
    );
    assert_eq!(None, harness.handle.tmmbr_limit());
    assert!(harness.tmmbns().is_empty(), "and no TMMBN for it");
}

/// The lenient setting: a TMMBR limits the stream it names whatever was negotiated.
#[test]
fn the_lenient_setting_honours_a_tmmbr_that_was_not_negotiated() {
    let told = Told::default();
    let mut harness = Harness::with(
        CongestionControlBuilder::new(told.clone()).with_unnegotiated_tmmbr(true),
        &stream_without_tmmbr(),
    );

    harness.receive(ms(100), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));

    assert_eq!(Some(262_144.0), told.max());
    assert_eq!(vec![(LOCAL, vec![(REMOTE, 262_144, 40)])], harness.tmmbns());
}

/// `tmmbr smaxpr=<n>` (RFC 5104 section 7.1) is TMMBR negotiated, with a packet rate bound.
#[test]
fn tmmbr_negotiated_with_a_maximum_packet_rate_is_honoured() {
    let told = Told::default();
    let mut info = stream_without_tmmbr();
    info.rtcp_feedback.push(RTCPFeedback {
        typ: "ccm".to_owned(),
        parameter: "tmmbr smaxpr=120".to_owned(),
    });
    let mut harness = Harness::with(CongestionControlBuilder::new(told.clone()), &info);

    harness.receive(ms(100), tmmbr(REMOTE, LOCAL, 2, 65_536, 40));

    assert_eq!(Some(262_144.0), told.max());
}

/// RFC 5104 section 4.2.2.2: "only a single TMMBN SHALL be sent, even if more than one TMMBR
/// is received" between two: two TMMBR packets in one compound RTCP packet are answered with
/// one TMMBN, which carries the bounding set after both.
#[test]
fn several_tmmbrs_in_one_compound_packet_get_one_tmmbn() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());

    let first: Box<dyn rtcp::Packet> = tmmbr(REMOTE, LOCAL, 2, 65_536, 40);
    let second: Box<dyn rtcp::Packet> = tmmbr(REMOTE + 1, LOCAL, 1, 65_536, 40);
    let message = harness.tagged(ms(100), Packet::Rtcp(vec![first, second]));
    harness.chain.handle_read(message).expect("read");
    harness.drain();

    let tmmbns = harness.tmmbns();
    assert_eq!(1, tmmbns.len(), "one notification for the compound packet");
    assert_eq!(
        vec![(REMOTE + 1, 131_072, 40)],
        tmmbns[0].1,
        "the tighter of the two limits is the bounding set"
    );
    assert_eq!(Some(131_072.0), told.max());
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

/// The peer connection's word that it selected another candidate pair (`PathChanged`, on the
/// read leg) is a path change also when every packet keeps its addresses (a TURN relay that
/// keeps them, an application that hands datagrams over with one placeholder pair): the
/// estimator is told once. Packets that then arrive between other addresses than before are
/// the new path's, not a second change.
#[test]
fn the_peer_connections_path_change_reaches_the_estimator_with_the_same_addresses() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());
    for index in 0..5u64 {
        harness.receive(ms(100 + index * 20), remb(1e6, vec![LOCAL]));
    }
    assert_eq!(0, *told.path_changes.lock().unwrap());

    let carrier = rtci_interceptor::PathChanged.into_packet(harness.epoch + ms(300), None);
    harness.chain.handle_read(carrier).expect("read");
    harness.drain();
    assert_eq!(1, *told.path_changes.lock().unwrap(), "told");

    // The new pair's packets, from another address than before: the same change.
    for index in 0..5u64 {
        let mut message = harness.tagged(
            ms(320 + index * 20),
            Packet::Rtcp(vec![remb(1e6, vec![LOCAL])]),
        );
        message.transport.peer_addr = std::net::SocketAddr::from(([192, 0, 2, 7], 6000));
        harness.chain.handle_read(message).expect("read");
        harness.drain();
    }
    assert_eq!(1, *told.path_changes.lock().unwrap(), "told once");
}

/// What the estimator was handed: each report's transport-wide sequence number and whether it
/// arrived.
#[derive(Clone, Default)]
struct Reported(Arc<Mutex<Vec<(u16, bool)>>>);

impl BandwidthEstimator for Reported {
    fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
        self.0.lock().unwrap().extend(
            reports
                .iter()
                .map(|report| (report.twcc_sequence_number, report.arrived)),
        );
    }
    fn target_bitrate(&self) -> f64 {
        1_000_000.0
    }
}

/// The packets sent before a path change went into the path that was left: the feedback that
/// reports them missing after the change is no loss of the new path's, and the estimator is
/// not handed them (libwebrtc's feedback adapter "only reports packets sent on the new route",
/// `RtpTransportControllerSend::OnNetworkRouteChanged`). Ten packets into a dead path, the
/// peer connection's path change, five on the new one: the feedback on the new path names the
/// ten lost and the five received, and only the five reach the estimator.
#[test]
fn packets_sent_before_a_path_change_are_no_loss_of_the_new_path() {
    let reported = Reported::default();
    let mut harness = Harness::new(reported.clone());
    for index in 0..10u64 {
        harness.send(ms(index * 10), 1200);
    }
    let carrier = rtci_interceptor::PathChanged.into_packet(harness.epoch + ms(2_000), None);
    harness.chain.handle_read(carrier).expect("read");
    harness.drain();
    for index in 0..10u64 {
        harness.send(ms(2_010 + index * 10), 1200);
    }
    // 0..9 lost, 10..14 received; then 15..19 received, which releases the losses the first
    // feedback held back for one more.
    let run = |symbol, run_length| {
        PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length,
        })
    };
    let received = |count: u16| -> Vec<RecvDelta> {
        (0..count)
            .map(|_| RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 10_000,
            })
            .collect()
    };
    harness.receive(
        ms(2_100),
        Box::new(TransportLayerCc {
            sender_ssrc: REMOTE,
            media_ssrc: LOCAL,
            base_sequence_number: 0,
            packet_status_count: 15,
            reference_time: (2_060 / 64) as u32,
            fb_pkt_count: 0,
            packet_chunks: vec![
                run(SymbolTypeTcc::PacketNotReceived, 10),
                run(SymbolTypeTcc::PacketReceivedSmallDelta, 5),
            ],
            recv_deltas: received(5),
        }),
    );
    harness.receive(
        ms(2_160),
        Box::new(TransportLayerCc {
            sender_ssrc: REMOTE,
            media_ssrc: LOCAL,
            base_sequence_number: 15,
            packet_status_count: 5,
            reference_time: (2_120 / 64) as u32,
            fb_pkt_count: 1,
            packet_chunks: vec![run(SymbolTypeTcc::PacketReceivedSmallDelta, 5)],
            recv_deltas: received(5),
        }),
    );
    let reports = reported.0.lock().unwrap().clone();
    assert!(
        reports.iter().all(|(_, arrived)| *arrived),
        "the old path's packets counted as lost: {reports:?}"
    );
    assert_eq!(
        (10..20).collect::<Vec<u16>>(),
        reports.iter().map(|(seq, _)| *seq).collect::<Vec<u16>>()
    );
}

/// The round trip time the feedback implies reaches the estimator: the additive increase of
/// RFC 8836 section 2, requirement 1: the controller reacts to a change of the path. The
/// engine does not have to be asked: packets that keep arriving between other addresses than
/// before (another candidate pair) are a path change, and the estimator is told once. A
/// single packet from elsewhere is not one.
#[test]
fn packets_arriving_between_new_addresses_are_a_path_change() {
    let told = Told::default();
    let mut harness = Harness::new(told.clone());
    let from = |port: u16| TransportContext {
        peer_addr: std::net::SocketAddr::from(([192, 0, 2, 7], port)),
        ..TransportContext::default()
    };
    let mut at = 100;
    let mut receive = |harness: &mut Harness, port: u16| {
        let mut message = harness.tagged(ms(at), Packet::Rtcp(vec![remb(1e6, vec![LOCAL])]));
        message.transport = from(port);
        harness.chain.handle_read(message).expect("read");
        harness.drain();
        at += 20;
    };

    for _ in 0..5 {
        receive(&mut harness, 5000);
    }
    assert_eq!(
        0,
        *told.path_changes.lock().unwrap(),
        "the first path is no change"
    );

    // One stray packet from another address, then the old one again.
    receive(&mut harness, 6000);
    receive(&mut harness, 5000);
    assert_eq!(0, *told.path_changes.lock().unwrap());

    // The peer moved.
    for _ in 0..5 {
        receive(&mut harness, 6000);
    }
    assert_eq!(1, *told.path_changes.lock().unwrap(), "told once");
}

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

/// A receiver report on the local stream: extended highest sequence number received,
/// cumulative number lost and fraction lost (in 1/256), as RFC 3550 section 6.4.1 has them.
fn receiver_report(highest: u32, cumulative_lost: i32, fraction_lost: u8) -> Box<dyn rtcp::Packet> {
    let mut block = rtcp::reception_report::ReceptionReport {
        ssrc: LOCAL,
        fraction_lost,
        last_sequence_number: highest,
        ..Default::default()
    };
    block.set_cumulative_lost(cumulative_lost);
    Box::new(rtcp::receiver_report::ReceiverReport {
        ssrc: REMOTE,
        reports: vec![block],
        ..Default::default()
    })
}

/// Sends the sequence numbers `numbers` in order, 2 ms apart from `from`, except those
/// `discarded` names: those are numbered and never leave, as after a pacer discard upstream
/// of the interceptor (`PacerQueueOverflow::Drop`).
fn send_numbers(
    harness: &mut Harness,
    from: Duration,
    numbers: std::ops::Range<u32>,
    discarded: impl Fn(u32) -> bool,
) {
    for (index, number) in numbers.enumerate() {
        harness.sequence = number as u16;
        if !discarded(number) {
            harness.send(from + ms(2 * index as u64), 1200);
        }
    }
    harness.sequence = harness.sequence.wrapping_add(1);
}

/// draft-ietf-rmcat-gcc-02 section 7 runs the loss-based controller on the fraction lost of
/// the receiver's reports. The receiver counts every sequence number it did not receive as lost
/// (RFC 3550 section 6.4.1), and the pacer, application-ward of the interceptor, discards
/// media the target has no room for after the application numbered it. Those numbers never
/// left: over the interval a report covers they come out of the loss, and the fraction is that
/// of the packets that left.
///
/// 400 numbers, of which 150 to 249 never leave, and a report of 100 lost (64/256): the
/// estimator is given no loss. Then 400 to 599, of which 400 to 449 never leave, and a report
/// of 60 more lost: 10 of the 150 sent, (10 << 8) / 150 = 17/256 (RFC 3550 A.3). The same
/// reports after a stream that left whole are the path's loss, passed on as reported.
#[test]
fn sequence_numbers_the_pacer_discarded_are_not_loss_to_the_loss_based_controller() {
    let run = |discards: bool| {
        let told = Told::default();
        let mut harness = Harness::new(told.clone());
        send_numbers(&mut harness, ms(0), 0..400, |number| {
            discards && (150..250).contains(&number)
        });
        harness.receive(ms(1000), receiver_report(399, 100, 64));
        send_numbers(&mut harness, ms(1000), 400..600, |number| {
            discards && number < 450
        });
        harness.receive(ms(2000), receiver_report(599, 160, 76));
        told.receiver_reports.lock().unwrap().clone()
    };

    assert_eq!(vec![0.0, 17.0 / 256.0], run(true));
    assert_eq!(
        vec![0.25, 76.0 / 256.0],
        run(false),
        "a stream that left whole"
    );
}

/// The same across the wrap of the 16-bit sequence number: 65380 to 65535 and 0 to 243 are
/// numbered, 65530 to 65535 and 0 to 93 (100 numbers) never leave, and the receiver reports
/// its extended highest sequence number one cycle on.
#[test]
fn sequence_numbers_discarded_across_the_wrap_are_not_loss_to_the_loss_based_controller() {
    let run = |discards: bool| {
        let told = Told::default();
        let mut harness = Harness::new(told.clone());
        send_numbers(&mut harness, ms(0), 65_380..65_780, |number| {
            discards && (65_530..65_630).contains(&number)
        });
        harness.receive(ms(1000), receiver_report((1 << 16) | 243, 100, 64));
        told.receiver_reports.lock().unwrap().clone()
    };

    assert_eq!(vec![0.0], run(true));
    assert_eq!(vec![0.25], run(false), "a stream that left whole");
}

/// And with `Gcc`: five seconds of reports of 25% loss that is all numbers the pacer
/// discarded leave the target where it was or above, and the estimator's loss at zero; the
/// same reports after a stream that left whole bring it down by 1 - 0.5 * 0.25 each.
#[test]
fn gcc_does_not_back_off_on_reported_loss_of_numbers_the_pacer_discarded() {
    let run = |discards: bool| {
        let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));
        for second in 0..5u32 {
            let first = second * 400;
            send_numbers(
                &mut harness,
                ms(u64::from(second) * 1000),
                first..first + 400,
                |number| discards && (first + 150..first + 250).contains(&number),
            );
            harness.receive(
                ms(u64::from(second) * 1000 + 999),
                receiver_report(first + 399, (second as i32 + 1) * 100, 64),
            );
        }
        (harness.handle.target_bitrate(), harness.handle.stats())
    };

    let (target, stats) = run(true);
    assert!(target >= 1_000_000.0, "target fell to {target}");
    assert_eq!(Some(0.0), stats.packet_loss);
    let (target, _) = run(false);
    let expected = 1_000_000.0 * 0.875f64.powi(5);
    assert!(
        (target - expected).abs() < 1.0,
        "a stream that left whole: expected {expected}, got {target}"
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

/// Feedback is missing only for packets that feedback covers. The video (transport-wide
/// sequence numbers) stops; the audio, a stream that negotiated no per-packet feedback, goes
/// on for five seconds. Nothing will ever report those packets, so no timer runs for them and
/// the target stays where it was: before, they started the wait like any packet and the
/// target was halved every 500 ms down to the floor on a path that had shown nothing.
#[test]
fn packets_of_a_stream_without_per_packet_feedback_do_not_start_the_wait_for_feedback() {
    const AUDIO: u32 = LOCAL + 100;
    let mut harness = Harness::new(Gcc::new(1_000_000.0, 50_000.0, 10_000_000.0));
    harness.chain.bind_local_stream(&StreamInfo {
        ssrc: AUDIO,
        clock_rate: 48_000,
        payload_type: 111,
        ..Default::default()
    });

    // A second of video with feedback every 100 ms: the feedback has a rhythm.
    let mut acknowledged = 0u16;
    for index in 0..100u64 {
        harness.send(ms(index * 10), 1200);
        if index % 10 == 9 {
            harness.acknowledge(ms(index * 10 + 5), acknowledged, 10, ms(10));
            acknowledged += 10;
        }
    }
    let before = harness.handle.target_bitrate();

    // The camera goes off; the audio carries on, 50 packets a second.
    for index in 0..250u16 {
        let at = ms(1000 + u64::from(index) * 20);
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 111,
                sequence_number: index,
                ssrc: AUDIO,
                ..Default::default()
            },
            payload: vec![0u8; 150].into(),
        };
        let message = harness.tagged(at, Packet::Rtp(packet));
        harness.chain.handle_write(message).expect("write");
        harness.drain();
        assert_eq!(None, harness.deadline(), "no feedback is awaited at {at:?}");
        harness.tick(at);
    }

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
