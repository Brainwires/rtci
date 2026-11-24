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

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback,
    RTPHeaderExtension, Registry, RetransmissionRateLimit, RetransmissionsReported, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
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
                received: vec![(RTX_SSRC, 3)],
                lost: vec![],
            },
            RetransmissionsReported {
                received: vec![],
                lost: vec![(RTX_SSRC, 4)],
            },
        ],
        reports
    );
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
                received: vec![(RTX_SSRC, 3)],
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
