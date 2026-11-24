//! A request for a packet whose retransmission is on its way. The receiver asks again every
//! round trip while a packet is missing, and a retransmission can wait in the path's queue for
//! longer than that; answering every request repaired such packets twice, the second copy
//! arriving after the first (a capacity drop in `tests/capacity_cap_video_rtc2rtc.rs`: 24 to 28
//! of 92 to 101 retransmissions). RFC 4588 section 7 lets the sender "selectively retransmit
//! only the packets that it deems important and ignore NACK messages for other packets", and
//! RFC 8834 section 6.1 says "It is not appropriate to blindly retransmit RTP packets in
//! response to a NACK". With transport-wide feedback the sender knows: the TWCC sender reports
//! what the feedback said of each retransmission (`RetransmissionsReported`), and the NACK
//! responder does not repair again a packet whose retransmission arrived, holds a request for
//! one whose retransmission is not reported yet, answers it at once when the retransmission is
//! reported lost, and answers it when no report comes within two round trips and the feedback
//! interval. Without transport-wide feedback every request is answered as before.

use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback,
    RTPHeaderExtension, Registry, ReportedRetransmission, RetransmissionRateLimit,
    RetransmissionsLeft, RetransmissionsReported, Slot, StreamInfo, TaggedPacket,
    TwccSenderBuilder,
};
use rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Unmarshal;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
const RTX_PAYLOAD_TYPE: u8 = 97;
const TWCC_ID: u8 = 5;
const TWCC_URI: &str = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

fn stream_info(twcc: bool) -> StreamInfo {
    let mut rtcp_feedback = vec![RTCPFeedback {
        typ: "nack".to_string(),
        parameter: String::new(),
    }];
    let mut rtp_header_extensions = Vec::new();
    if twcc {
        rtcp_feedback.push(RTCPFeedback {
            typ: "transport-cc".to_string(),
            parameter: String::new(),
        });
        rtp_header_extensions.push(RTPHeaderExtension {
            uri: TWCC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        });
    }
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type_rtx: Some(RTX_PAYLOAD_TYPE),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback,
        rtp_header_extensions,
        ..Default::default()
    }
}

/// The NACK responder with the TWCC sender wire-ward of it, as the default interceptors have
/// them; `twcc` whether the stream negotiated transport-wide feedback. No rate limit, so what
/// is answered leaves at once.
fn chain(twcc: bool) -> impl Interceptor {
    chain_with(twcc, RetransmissionRateLimit::Unlimited)
}

fn chain_with(twcc: bool, rate_limit: RetransmissionRateLimit) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new()
                .with_rate_limit(rate_limit)
                .build(),
        )
        .build();
    chain.bind_local_stream(&stream_info(twcc));
    chain
}

/// A retransmission that left: the packet it repairs and its transport-wide number.
#[derive(Debug, PartialEq)]
struct Left {
    repaired: u16,
    number: Option<u16>,
    /// The RTX packet's own sequence number.
    rtx_sequence: u16,
}

/// What leaves toward the wire: the retransmissions, with the transport-wide number each got.
fn drain(chain: &mut impl Interceptor) -> Vec<Left> {
    while chain.poll_read().is_some() {}
    let mut left = Vec::new();
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtp(packet) = &tagged.message.packet
            && packet.header.ssrc == RTX_SSRC
        {
            let number = packet.header.get_extension(TWCC_ID).and_then(|data| {
                rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                    &mut data.as_ref(),
                )
                .ok()
                .map(|extension| extension.transport_sequence)
            });
            left.push(Left {
                repaired: u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
                number,
                rtx_sequence: packet.header.sequence_number,
            });
        }
    }
    left
}

/// Originals 0 to 9 from `base`, 10 ms apart; returns the transport-wide number of the last.
fn send_originals(chain: &mut impl Interceptor, base: Instant) {
    for sequence_number in 0..10u16 {
        chain
            .handle_write(TaggedPacket {
                now: base + Duration::from_millis(10) * u32::from(sequence_number),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc: SSRC,
                        ..Default::default()
                    },
                    payload: vec![0u8; 500].into(),
                })),
            })
            .unwrap();
    }
    drain(chain);
}

fn read(chain: &mut (impl Interceptor + ?Sized), now: Instant, message: AttributedPacket) {
    chain
        .handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        })
        .unwrap();
}

/// The receiver asks for `sequence_numbers` at `now`; the retransmissions that leave for it.
fn nack(chain: &mut impl Interceptor, now: Instant, sequence_numbers: &[u16]) -> Vec<Left> {
    read(
        chain,
        now,
        AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: nack_pairs_from_sequence_numbers(sequence_numbers),
        })])),
    );
    drain(chain)
}

/// Transport-wide feedback on the one packet `number`: received or not.
fn feedback(chain: &mut impl Interceptor, now: Instant, number: u16, received: bool) -> Vec<Left> {
    let (symbol, recv_deltas) = if received {
        (
            SymbolTypeTcc::PacketReceivedSmallDelta,
            vec![RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 1000,
            }],
        )
    } else {
        (SymbolTypeTcc::PacketNotReceived, vec![])
    };
    read(
        chain,
        now,
        AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            base_sequence_number: number,
            packet_status_count: 1,
            reference_time: 1,
            fb_pkt_count: 0,
            packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: symbol,
                run_length: 1,
            })],
            recv_deltas,
        })])),
    );
    drain(chain)
}

fn ms(base: Instant, milliseconds: u64) -> Instant {
    base + Duration::from_millis(milliseconds)
}

/// The TWCC sender reports what the feedback said of a retransmission under the packet it
/// repairs (the original sequence number ahead of the RTX payload), not of the originals.
#[test]
fn the_feedback_on_a_retransmission_is_reported_by_the_packet_it_repairs() {
    let base = Instant::now();
    let mut chain = Registry::new()
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new()
                .with_rate_limit(RetransmissionRateLimit::Unlimited)
                .build(),
        )
        .with(Slot::from(5_000), Reports::default())
        .build();
    chain.bind_local_stream(&stream_info(true));
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3, 4]);
    assert_eq!(2, left.len());
    let (three, four) = (left[0].number.unwrap(), left[1].number.unwrap());
    // Feedback on an original says nothing of a retransmission.
    feedback(&mut chain, ms(base, 250), 0, true);
    feedback(&mut chain, ms(base, 260), three, true);
    feedback(&mut chain, ms(base, 270), four, false);
    // A second report on the same number is not passed on again.
    feedback(&mut chain, ms(base, 280), three, true);
    let reports = REPORTS.with(|reports| reports.take());
    assert_eq!(
        vec![
            RetransmissionsReported {
                received: vec![reported(3, ms(base, 200))],
                lost: vec![],
            },
            RetransmissionsReported {
                received: vec![],
                lost: vec![reported(4, ms(base, 200))],
            },
        ],
        reports
    );
}

/// The retransmission of `sequence_number` made at `sent`, as a report names it.
fn reported(sequence_number: u16, sent: Instant) -> ReportedRetransmission {
    ReportedRetransmission {
        ssrc: RTX_SSRC,
        sequence_number,
        sent,
    }
}

thread_local! {
    static REPORTS: std::cell::RefCell<Vec<RetransmissionsReported>> = Default::default();
}

/// Records the `RetransmissionsReported` that reach it on the read leg.
#[derive(Default)]
struct Reports {
    reads: std::collections::VecDeque<TaggedPacket>,
    writes: std::collections::VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Reports {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Some(report) = msg.message.custom::<RetransmissionsReported>() {
            REPORTS.with(|reports| reports.borrow_mut().push(report.clone()));
        }
        self.reads.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.reads.pop_front()
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.writes.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.writes.pop_front()
    }
    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
}

impl Interceptor for Reports {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// A request that reaches the sender after the feedback reported the retransmission of its
/// packet received crossed that retransmission: it is not answered. A packet whose
/// retransmission was not reported on is answered as before.
#[test]
fn a_request_for_a_packet_whose_retransmission_arrived_is_not_answered() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    feedback(&mut chain, ms(base, 300), left[0].number.unwrap(), true);
    assert_eq!(
        Vec::<Left>::new(),
        nack(&mut chain, ms(base, 320), &[3]),
        "its retransmission arrived"
    );
    let repaired: Vec<u16> = nack(&mut chain, ms(base, 330), &[3, 5])
        .iter()
        .map(|left| left.repaired)
        .collect();
    assert_eq!(vec![5], repaired, "another packet is repaired");
}

/// A request that comes while the retransmission of its packet has no report yet waits for
/// one, and is answered at once when the retransmission is reported lost (the next request,
/// RFC 4585's feedback rules permitting, could be long in coming).
#[test]
fn a_request_crossing_a_retransmission_is_answered_when_the_retransmission_is_reported_lost() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    // Feedback has reported on a retransmission once: the sender has reports to go by.
    let first = nack(&mut chain, ms(base, 200), &[1]);
    feedback(&mut chain, ms(base, 250), first[0].number.unwrap(), true);

    let left = nack(&mut chain, ms(base, 300), &[3]);
    assert_eq!(1, left.len());
    assert_eq!(
        Vec::<Left>::new(),
        nack(&mut chain, ms(base, 360), &[3]),
        "60 ms after it left, no report yet: the request waits"
    );
    let again = feedback(&mut chain, ms(base, 400), left[0].number.unwrap(), false);
    assert_eq!(
        vec![3],
        again.iter().map(|left| left.repaired).collect::<Vec<_>>(),
        "reported lost: repaired at once"
    );
}

/// A request held for a report that never comes is answered when the wait ends, and the
/// responder's deadline wakes the driver for it.
#[test]
fn a_request_crossing_a_retransmission_is_answered_when_no_report_comes() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let first = nack(&mut chain, ms(base, 200), &[1]);
    feedback(&mut chain, ms(base, 250), first[0].number.unwrap(), true);

    let left = nack(&mut chain, ms(base, 300), &[3]);
    assert_eq!(1, left.len());
    assert!(nack(&mut chain, ms(base, 360), &[3]).is_empty());
    // No round trip known: the wait is the lifetime of a request, 1 s from the departure.
    let due = chain
        .poll_timeout()
        .expect("a deadline for the held request");
    assert_eq!(ms(base, 1_300), due);
    chain
        .handle_timeout(due - Duration::from_millis(1))
        .unwrap();
    assert!(drain(&mut chain).is_empty(), "not before the wait ends");
    chain.handle_timeout(due).unwrap();
    assert_eq!(
        vec![3],
        drain(&mut chain)
            .iter()
            .map(|left| left.repaired)
            .collect::<Vec<_>>(),
        "answered when the wait ended"
    );
}

/// Without transport-wide feedback (none negotiated, or none received yet) the responder
/// answers every request as it always has: a request 50 ms after a retransmission left, past
/// the 20 ms resend interval, repairs the packet again.
#[test]
fn without_transport_wide_feedback_a_crossing_request_is_answered() {
    for twcc in [false, true] {
        let base = Instant::now();
        let mut chain = chain(twcc);
        send_originals(&mut chain, base);
        assert_eq!(1, nack(&mut chain, ms(base, 300), &[3]).len());
        assert_eq!(
            1,
            nack(&mut chain, ms(base, 350), &[3]).len(),
            "transport-wide feedback negotiated: {twcc}"
        );
    }
}

/// A report on a retransmission reaches the responder only as the TWCC sender's notice; the
/// notice alone, read on its own carrier, does it.
#[test]
fn the_report_rides_an_empty_carrier() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    nack(&mut chain, ms(base, 200), &[3]);
    read(
        &mut chain,
        ms(base, 250),
        AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
            RetransmissionsReported {
                received: vec![reported(3, ms(base, 200))],
                lost: vec![],
            },
        ))),
    );
    drain(&mut chain);
    assert!(nack(&mut chain, ms(base, 300), &[3]).is_empty());
}

/// With RFC 8888 feedback (the default between two endpoints of this engine: RFC 8888 section 6,
/// one feedback format per stream) the report on the RTX stream names each retransmission by
/// its own sequence number; the responder maps it back to the packet it repaired. A request
/// for a packet whose retransmission arrived is not answered; one crossing a retransmission
/// reported lost is answered at once.
#[test]
fn rfc_8888_feedback_on_the_rtx_stream_counts_as_the_report() {
    let base = Instant::now();
    let mut chain = chain(false);
    send_originals(&mut chain, base);
    let ccfb = |chain: &mut dyn Interceptor, now: Instant, rtx_sequence: u16, received: bool| {
        read(
            chain,
            now,
            AttributedPacket::new(Packet::Rtcp(vec![Box::new(CcFeedbackReport {
                sender_ssrc: 1,
                report_blocks: vec![CcFeedbackReportBlock {
                    media_ssrc: RTX_SSRC,
                    begin_sequence: rtx_sequence,
                    metric_blocks: vec![CcFeedbackMetricBlock {
                        received,
                        ecn: Ecn::NotEct,
                        arrival_time_offset: if received { 10 } else { 0 },
                    }],
                }],
                report_timestamp: 65_536,
            })])),
        );
    };
    let three = nack(&mut chain, ms(base, 200), &[3]);
    ccfb(&mut chain, ms(base, 250), three[0].rtx_sequence, true);
    drain(&mut chain);
    assert!(
        nack(&mut chain, ms(base, 300), &[3]).is_empty(),
        "its retransmission arrived"
    );
    let five = nack(&mut chain, ms(base, 400), &[5]);
    assert!(
        nack(&mut chain, ms(base, 450), &[5]).is_empty(),
        "no report yet: the request waits"
    );
    ccfb(&mut chain, ms(base, 500), five[0].rtx_sequence, false);
    assert_eq!(
        vec![5],
        drain(&mut chain)
            .iter()
            .map(|left| left.repaired)
            .collect::<Vec<_>>(),
        "reported lost: repaired at once"
    );
}

/// Under a rate limit, with a target: the held request's deadline is the end of its wait, not
/// the end of its lifetime (1 s after it was last asked for), so it is answered then.
#[test]
fn a_held_request_under_a_rate_limit_is_due_when_its_wait_ends() {
    let base = Instant::now();
    let mut chain = chain_with(true, RetransmissionRateLimit::UpToTarget);
    read(
        &mut chain,
        base,
        AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::TargetBitrateChanged {
            bits_per_second: 10_000_000.0,
        }),
    );
    send_originals(&mut chain, base);
    let first = nack(&mut chain, ms(base, 200), &[1]);
    feedback(&mut chain, ms(base, 250), first[0].number.unwrap(), true);
    assert_eq!(1, nack(&mut chain, ms(base, 300), &[3]).len());
    assert!(nack(&mut chain, ms(base, 360), &[3]).is_empty());
    assert_eq!(Some(ms(base, 1_300)), chain.poll_timeout());
    chain.handle_timeout(ms(base, 1_300)).unwrap();
    assert_eq!(1, drain(&mut chain).len(), "answered when the wait ended");
}

/// One original packet `sequence_number` written at `now`; the retransmissions that leave
/// with it.
fn original(chain: &mut impl Interceptor, now: Instant, sequence_number: u16) -> Vec<Left> {
    chain
        .handle_write(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number,
                    ssrc: SSRC,
                    ..Default::default()
                },
                payload: vec![0u8; 500].into(),
            })),
        })
        .unwrap();
    drain(chain)
}

/// A whole cycle of sequence numbers after `send_originals`' ten (10 to 65535, then 0 to 9
/// again), `spacing` apart from `from`; the instant of the last. The stream's ten first
/// packets are then long out of the send buffer, and ten new ones have their numbers. Nothing
/// is retransmitted meanwhile: nobody asks.
fn a_cycle_of_originals(chain: &mut impl Interceptor, from: Instant, spacing: Duration) -> Instant {
    let mut now = from;
    for sequence_number in (10..=u16::MAX).chain(0..10) {
        now += spacing;
        let left = original(chain, now, sequence_number);
        assert!(
            left.is_empty(),
            "retransmitted with the original {sequence_number}, unasked: {left:?}"
        );
    }
    now
}

/// Transport-wide feedback on the one packet `number`; the reports on retransmissions it
/// made the TWCC sender pass on.
fn reports_of_feedback(
    chain: &mut impl Interceptor,
    now: Instant,
    number: u16,
) -> Vec<RetransmissionsReported> {
    read(
        chain,
        now,
        AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            base_sequence_number: number,
            packet_status_count: 1,
            reference_time: 1,
            fb_pkt_count: 0,
            packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                run_length: 1,
            })],
            recv_deltas: vec![RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 1000,
            }],
        })])),
    );
    let mut reported = Vec::new();
    while let Some(tagged) = chain.poll_read() {
        if let Some(report) = tagged.message.custom::<RetransmissionsReported>() {
            reported.push(report.clone());
        }
    }
    reported
}

/// The memory of a retransmission reported received ends by the clock of the request itself
/// (four seconds, `DELIVERED_MEMORY`), not when some later report happens to arrive: with no
/// further report at all, a request thirty seconds on is answered. (Independent review,
/// 2026-11-24: the memory was pruned only on the next report, so the request was declined for
/// ever.)
#[test]
fn a_request_after_the_delivered_memory_is_answered_with_no_report_in_between() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    assert_eq!(1, left.len(), "{left:?}");
    let number = left[0].number.expect("numbered");
    assert!(feedback(&mut chain, ms(base, 300), number, true).is_empty());
    // Within the memory: crossed the retransmission, not answered.
    assert!(nack(&mut chain, ms(base, 350), &[3]).is_empty());
    assert!(
        nack(&mut chain, ms(base, 4_250), &[3]).is_empty(),
        "50 ms before the memory ends"
    );
    // Thirty seconds on, with no other report in between: the memory (4 s) is long over.
    let later = nack(&mut chain, ms(base, 30_000), &[3]);
    assert_eq!(
        1,
        later.len(),
        "a request 30 s after the retransmission was reported received is still declined"
    );
}

/// What is remembered of a repair is the memory of one packet. The sequence numbers wrap
/// (65536 packets, 197 s here), the new packet with the number of one repaired a cycle ago is
/// lost, and its request is answered: the old packet's "received" is not the new one's.
/// (Independent review, 2026-11-24.)
#[test]
fn a_new_packet_with_a_sequence_number_repaired_a_cycle_ago_is_repaired() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    assert_eq!(1, left.len(), "{left:?}");
    let number = left[0].number.expect("numbered");
    assert!(feedback(&mut chain, ms(base, 300), number, true).is_empty());
    // A whole cycle of sequence numbers without a loss.
    let now = a_cycle_of_originals(&mut chain, ms(base, 400), Duration::from_millis(3));
    // The new packet 3 is lost.
    let repaired = nack(&mut chain, now + Duration::from_millis(100), &[3]);
    assert_eq!(
        1,
        repaired.len(),
        "the new packet 3, {:?} after the old one's repair, is not retransmitted",
        now.duration_since(base)
    );
}

/// At a high packet rate the sequence numbers come round inside the memory itself (65536
/// packets in 0.66 s, 100 000 packets a second): the time has not run out, the packet is
/// another one all the same, and it is repaired.
#[test]
fn a_sequence_number_reused_within_the_delivered_memory_is_another_packet() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    feedback(&mut chain, ms(base, 300), left[0].number.unwrap(), true);
    assert!(nack(&mut chain, ms(base, 350), &[3]).is_empty());
    let now = a_cycle_of_originals(&mut chain, ms(base, 400), Duration::from_micros(10));
    assert!(now < ms(base, 1_100), "the cycle took under 0.7 s");
    let repaired = nack(&mut chain, ms(base, 1_200), &[3]);
    assert_eq!(
        vec![3],
        repaired
            .iter()
            .map(|left| left.repaired)
            .collect::<Vec<_>>(),
        "0.9 s after the old packet 3 was reported received (memory 4 s), the new packet 3"
    );
}

/// Nor is a new packet held for the report on an old packet's retransmission: the wait for a
/// report is one packet's too.
#[test]
fn a_new_packet_is_not_held_for_the_report_on_an_old_packets_retransmission() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    // Reports have come once, so requests wait for them.
    let first = nack(&mut chain, ms(base, 150), &[1]);
    feedback(&mut chain, ms(base, 180), first[0].number.unwrap(), true);
    assert_eq!(1, nack(&mut chain, ms(base, 200), &[3]).len());
    assert!(
        nack(&mut chain, ms(base, 300), &[3]).is_empty(),
        "no report yet: the request for the old packet 3 waits (1 s, no round trip known)"
    );
    // The waiting request ends with its packet (the new packet 3 is not retransmitted as it
    // is written, which the cycle checks); a cycle on, 3 is another packet.
    let now = a_cycle_of_originals(&mut chain, ms(base, 310), Duration::from_micros(10));
    assert!(now < ms(base, 1_000));
    let repaired = nack(&mut chain, ms(base, 1_000), &[3]);
    assert_eq!(
        vec![3],
        repaired
            .iter()
            .map(|left| left.repaired)
            .collect::<Vec<_>>(),
        "the new packet 3 is repaired at once, 0.2 s before the old one's wait would end"
    );
}

/// The TWCC sender keeps the transport-wide number of a retransmission for the feedback on
/// it. When that feedback is lost, the number comes round to another packet a cycle of
/// transport-wide numbers later (197 s here): feedback on that packet is not a report on the
/// old retransmission. (Independent review, 2026-11-24.)
#[test]
fn feedback_on_a_reused_transport_wide_number_is_not_an_old_retransmission() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    assert_eq!(1, left.len(), "{left:?}");
    let number = left[0].number.expect("numbered");
    // The feedback on that retransmission is lost. A cycle of transport-wide numbers later
    // another packet carries `number`.
    let now = a_cycle_of_originals(&mut chain, ms(base, 400), Duration::from_millis(3));
    let reported = reports_of_feedback(&mut chain, now + Duration::from_millis(50), number);
    assert!(
        reported.is_empty(),
        "feedback on an original packet was reported as a retransmission's: {reported:?}"
    );
}

/// The same at a high packet rate, where the transport-wide numbers come round within the
/// time a report still counts (65536 packets in 0.66 s; the horizon is 4 s): the number is
/// the new packet's from the moment it is handed out again.
#[test]
fn a_transport_wide_number_handed_out_again_within_the_horizon_is_the_new_packets() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    let number = left[0].number.expect("numbered");
    let now = a_cycle_of_originals(&mut chain, ms(base, 400), Duration::from_micros(10));
    assert!(now < ms(base, 1_100));
    let reported = reports_of_feedback(&mut chain, ms(base, 1_150), number);
    assert!(reported.is_empty(), "{reported:?}");
}

/// Half a cycle of transport-wide numbers on, a number can no longer be told from one ahead
/// (the feedback's base and the sender's own numbering are 16 bits): feedback that names the
/// retransmission's number then is not reported, time or no time.
#[test]
fn feedback_half_a_cycle_of_transport_wide_numbers_late_is_not_reported() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    let number = left[0].number.expect("numbered");
    // 33 000 more packets in 0.33 s: more than half the cycle, the number not yet reused.
    let mut now = ms(base, 400);
    for sequence_number in 10..33_010u16 {
        now += Duration::from_micros(10);
        assert!(original(&mut chain, now, sequence_number).is_empty());
    }
    let reported = reports_of_feedback(&mut chain, ms(base, 800), number);
    assert!(reported.is_empty(), "{reported:?}");
}

/// Feedback on a retransmission counts for four seconds after it was made
/// (`RETRANSMISSION_REPORT_HORIZON`), by the clock of the feedback that names it: later it is
/// not reported, however few packets were sent since. Just inside, it is.
#[test]
fn feedback_on_a_retransmission_after_the_report_horizon_is_not_reported() {
    for (after, counts) in [(3_900, true), (4_000, false), (60_000, false)] {
        let base = Instant::now();
        let mut chain = chain(true);
        send_originals(&mut chain, base);
        let left = nack(&mut chain, ms(base, 200), &[3]);
        let number = left[0].number.expect("numbered");
        let reported = reports_of_feedback(&mut chain, ms(base, 200 + after), number);
        assert_eq!(
            counts,
            !reported.is_empty(),
            "feedback {after} ms after the retransmission: {reported:?}"
        );
    }
}

/// A retransmission handed to a pacer that never says what became of it (no
/// `RetransmissionsLeft` for it, and none for any other) holds its packet's requests off for
/// four seconds, by the clock of the request: after that the packet is repaired again.
#[test]
fn a_retransmission_the_pacer_never_reports_on_holds_its_packet_for_four_seconds_only() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    // A pacer is there: it has reported once.
    read(
        &mut chain,
        ms(base, 100),
        AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
            RetransmissionsLeft {
                departed: vec![],
                dropped: vec![(RTX_SSRC, 9)],
            },
        ))),
    );
    drain(&mut chain);
    assert_eq!(1, nack(&mut chain, ms(base, 200), &[3]).len());
    assert!(
        nack(&mut chain, ms(base, 1_000), &[3]).is_empty(),
        "its retransmission waits in the pacer"
    );
    assert!(nack(&mut chain, ms(base, 4_100), &[3]).is_empty());
    assert_eq!(
        1,
        nack(&mut chain, ms(base, 4_300), &[3]).len(),
        "4.1 s on, nothing heard of the first retransmission: repaired again"
    );
}

/// A receiver whose feedback reports every retransmission received, whether it got it or not,
/// stops the repairs of its own packet for the memory of each report and no longer: every
/// request after that memory is answered, round after round.
#[test]
fn a_receiver_that_reports_every_repair_received_is_repaired_again_after_each_memory() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let mut at = 200;
    for round in 0..5 {
        let left = nack(&mut chain, ms(base, at), &[3]);
        assert_eq!(1, left.len(), "round {round}: the request is answered");
        // The false report, 50 ms later, and the receiver asking on every 500 ms.
        feedback(&mut chain, ms(base, at + 50), left[0].number.unwrap(), true);
        for asked in (at + 100..at + 4_050).step_by(500) {
            assert!(
                nack(&mut chain, ms(base, asked), &[3]).is_empty(),
                "round {round}: declined within the memory, at {asked} ms"
            );
        }
        at += 4_100;
    }
}

/// RFC 8888 feedback reports a span of recent packets in every report, so the same RTX packet
/// is reported received again and again. The memory runs from the first report: a receiver
/// repeating it (as the format has it, or to keep a repair off) does not extend it, and a
/// report that comes after the memory ended does not begin it again.
#[test]
fn a_report_repeated_does_not_extend_the_delivered_memory() {
    let base = Instant::now();
    let mut chain = chain(false);
    send_originals(&mut chain, base);
    let ccfb = |chain: &mut dyn Interceptor, now: Instant, rtx_sequence: u16| {
        read(
            chain,
            now,
            AttributedPacket::new(Packet::Rtcp(vec![Box::new(CcFeedbackReport {
                sender_ssrc: 1,
                report_blocks: vec![CcFeedbackReportBlock {
                    media_ssrc: RTX_SSRC,
                    begin_sequence: rtx_sequence,
                    metric_blocks: vec![CcFeedbackMetricBlock {
                        received: true,
                        ecn: Ecn::NotEct,
                        arrival_time_offset: 10,
                    }],
                }],
                report_timestamp: 65_536,
            })])),
        );
    };
    let three = nack(&mut chain, ms(base, 200), &[3]);
    let rtx_sequence = three[0].rtx_sequence;
    // The same report every 100 ms for six seconds.
    for at in (250..6_250).step_by(100) {
        ccfb(&mut chain, ms(base, at), rtx_sequence);
        drain(&mut chain);
        if at == 4_150 {
            assert!(
                nack(&mut chain, ms(base, 4_200), &[3]).is_empty(),
                "3.95 s after the first report: within the memory"
            );
        }
    }
    assert_eq!(
        1,
        nack(&mut chain, ms(base, 6_300), &[3]).len(),
        "6 s after the first report, 50 ms after the latest repeat of it"
    );
}

/// Feedback that names every transport-wide number as received (a receiver making the most
/// of it) reports the retransmissions that were made and nothing else: a packet never
/// retransmitted is not remembered as delivered, and its first request is answered.
#[test]
fn feedback_naming_every_number_reports_only_the_retransmissions_made() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let left = nack(&mut chain, ms(base, 200), &[3]);
    let number = left[0].number.expect("numbered");
    let mut reports = Vec::new();
    for flood in 0..3u64 {
        for first in (0..=u16::MAX).step_by(0x1fff) {
            read(
                &mut chain,
                ms(base, 300 + flood),
                AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
                    sender_ssrc: 1,
                    media_ssrc: SSRC,
                    base_sequence_number: first,
                    packet_status_count: 0x1fff,
                    reference_time: 1,
                    fb_pkt_count: 0,
                    packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                        type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                        packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                        run_length: 0x1fff,
                    })],
                    recv_deltas: vec![
                        RecvDelta {
                            type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                            delta: 250,
                        };
                        0x1fff
                    ],
                })])),
            );
            while let Some(tagged) = chain.poll_read() {
                if let Some(report) = tagged.message.custom::<RetransmissionsReported>() {
                    reports.push(report.clone());
                }
            }
            drain(&mut chain);
        }
    }
    assert_eq!(
        vec![RetransmissionsReported {
            received: vec![reported(3, ms(base, 200))],
            lost: vec![],
        }],
        reports,
        "the one retransmission, numbered {number}, once"
    );
    let repaired: Vec<u16> = nack(&mut chain, ms(base, 400), &[3, 4, 5, 6])
        .iter()
        .map(|left| left.repaired)
        .collect();
    assert_eq!(
        vec![4, 5, 6],
        repaired,
        "3 arrived; the others were never sent again"
    );
}

/// A receiver that asks for everything all the time and reports every retransmission lost (so
/// that each request is answered at once) gets no more than the rate limit: in every second
/// the retransmissions stay within the target, here 400 kbit/s (50 000 octets), while the
/// stream itself sends 100 packets a second.
#[test]
fn requests_and_lost_reports_without_end_stay_within_the_rate_limit() {
    let base = Instant::now();
    let mut chain = chain_with(true, RetransmissionRateLimit::UpToTarget);
    read(
        &mut chain,
        base,
        AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::TargetBitrateChanged {
            bits_per_second: 400_000.0,
        }),
    );
    drain(&mut chain);
    // The instant (ms) of every retransmission; each is 514 octets (12 of header, 2 of
    // original sequence number, 500 of payload), as the responder counts it.
    let mut sent: Vec<u64> = Vec::new();
    let mut next_sequence = 0u16;
    for at in 0..10_000u64 {
        let now = ms(base, at);
        let mut left = Vec::new();
        if at % 10 == 0 {
            left.extend(original(&mut chain, now, next_sequence));
            next_sequence += 1;
        }
        chain.handle_timeout(now).unwrap();
        left.extend(drain(&mut chain));
        if at % 5 == 0 {
            // Everything the receiver could still want: the last 600 packets.
            let asked: Vec<u16> = (next_sequence.saturating_sub(600)..next_sequence).collect();
            left.extend(nack(&mut chain, now, &asked));
        }
        // Every retransmission that left is reported lost within the same millisecond.
        for retransmission in left {
            sent.push(at);
            let number = retransmission.number.expect("numbered");
            sent.extend(feedback(&mut chain, now, number, false).iter().map(|_| at));
        }
    }
    assert!(sent.len() > 500, "repairs were made: {}", sent.len());
    let mut worst = 0usize;
    for (index, from) in sent.iter().enumerate() {
        let packets = sent[index..]
            .iter()
            .take_while(|at| **at < from + 1_000)
            .count();
        worst = worst.max(packets * 514);
    }
    assert!(
        worst <= 50_000,
        "{worst} octets of retransmissions within one second, the target allows 50 000"
    );
}

/// A packet repaired twice (the report on the first retransmission was overdue, the receiver
/// asked again): a report that the first copy was lost says nothing of the second, which is
/// on its way, so a request keeps waiting for the second's report; that one lost, it is
/// answered at once.
#[test]
fn the_loss_of_an_earlier_retransmission_does_not_end_the_wait_for_the_later_one() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let other = nack(&mut chain, ms(base, 150), &[1]);
    feedback(&mut chain, ms(base, 180), other[0].number.unwrap(), true);
    let first = nack(&mut chain, ms(base, 200), &[3]);
    // No report within the wait (1 s, no round trip known): asked again, repaired again.
    let second = nack(&mut chain, ms(base, 1_300), &[3]);
    assert_eq!(1, second.len());
    assert!(
        feedback(&mut chain, ms(base, 1_350), first[0].number.unwrap(), false).is_empty(),
        "the first copy lost: nothing leaves for it"
    );
    assert!(
        nack(&mut chain, ms(base, 1_400), &[3]).is_empty(),
        "the second copy has no report yet: the request waits"
    );
    let again = feedback(
        &mut chain,
        ms(base, 1_450),
        second[0].number.unwrap(),
        false,
    );
    assert_eq!(
        vec![3],
        again.iter().map(|left| left.repaired).collect::<Vec<_>>(),
        "the second copy lost: repaired at once"
    );
}

/// And a report that the first copy arrived is the packet's: the receiver has it, whichever
/// copy came, so later requests are declined although the second copy's report never comes.
#[test]
fn the_arrival_of_an_earlier_retransmission_counts_for_the_packet() {
    let base = Instant::now();
    let mut chain = chain(true);
    send_originals(&mut chain, base);
    let other = nack(&mut chain, ms(base, 150), &[1]);
    feedback(&mut chain, ms(base, 180), other[0].number.unwrap(), true);
    let first = nack(&mut chain, ms(base, 200), &[3]);
    assert_eq!(1, nack(&mut chain, ms(base, 1_300), &[3]).len());
    feedback(&mut chain, ms(base, 1_350), first[0].number.unwrap(), true);
    // Past the wait for the second copy's report (2.3 s), inside the memory of the first's.
    assert!(
        nack(&mut chain, ms(base, 2_500), &[3]).is_empty(),
        "the packet arrived with its first retransmission"
    );
}

/// A request that waits for room in the rate limit is a request for its packet. Behind
/// another stream's request that does not fit, it is not looked at while its own stream
/// sends on; when that stream's sequence numbers have come round (65536 packets in 0.66 s
/// here) and room is made, the new packet that has the number asked for is not
/// retransmitted: nobody asked for it.
#[test]
fn a_waiting_request_is_not_answered_with_the_packet_that_has_its_number_a_cycle_later() {
    const OTHER: u32 = 0x2222;
    let base = Instant::now();
    let mut chain = chain_with(true, RetransmissionRateLimit::UpToTarget);
    chain.bind_local_stream(&StreamInfo {
        ssrc: OTHER,
        ssrc_rtx: Some(0x3333),
        ..stream_info(true)
    });
    let target = |chain: &mut dyn Interceptor, now: Instant, bits_per_second: f64| {
        read(
            chain,
            now,
            AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::TargetBitrateChanged { bits_per_second }),
        );
    };
    // 2 kbit/s: 250 octets a second, less than one retransmission (514 octets).
    target(&mut chain, base, 2_000.0);
    drain(&mut chain);
    send_originals(&mut chain, base);
    chain
        .handle_write(TaggedPacket {
            now: base,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number: 50,
                    ssrc: OTHER,
                    ..Default::default()
                },
                payload: vec![0u8; 500].into(),
            })),
        })
        .unwrap();
    drain(&mut chain);
    // The other stream's request first: it does not fit and stays at the head.
    read(
        &mut chain,
        ms(base, 300),
        AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: OTHER,
            nacks: nack_pairs_from_sequence_numbers(&[50]),
        })])),
    );
    assert!(drain(&mut chain).is_empty());
    assert!(
        nack(&mut chain, ms(base, 301), &[3]).is_empty(),
        "no room: the request waits behind the other stream's"
    );
    let now = a_cycle_of_originals(&mut chain, ms(base, 310), Duration::from_micros(10));
    assert!(now < ms(base, 1_000), "within the requests' lifetime (1 s)");
    // Room for everything.
    target(&mut chain, ms(base, 1_000), 10_000_000.0);
    let left = drain(&mut chain);
    assert!(
        left.is_empty(),
        "the new packet 3 was retransmitted for a request made for the old one: {left:?}"
    );
}
