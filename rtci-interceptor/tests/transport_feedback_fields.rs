//! What the fields of transport-wide feedback say, and what a loss report is not.
//!
//! draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1 (the feedback packet count,
//! the media source SSRC, one arrival per sequence number) and RFC 8888 section 3.1 (a report
//! of a lost packet is not a request to retransmit it).

use rtci_interceptor::{
    AttributedPacket, CongestionControlBuilder, ConstantBitrate, Interceptor, NackResponderBuilder,
    Packet, RTCPFeedback, RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket,
    TwccReceiverBuilder, convert_twcc,
};
use rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
};
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const FIRST: u32 = 0x0000_1001;
const SECOND: u32 = 0x0000_2002;

fn stream(ssrc: u32, feedback: &[(&str, &str)]) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_rtx: Some(ssrc + 1),
        payload_type: 96,
        payload_type_rtx: Some(97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: feedback
            .iter()
            .map(|(typ, parameter)| RTCPFeedback {
                typ: (*typ).to_owned(),
                parameter: (*parameter).to_owned(),
            })
            .collect(),
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

fn numbered(ssrc: u32, sequence_number: u16, transport_sequence: u16) -> Packet {
    let mut header = rtp::header::Header {
        version: 2,
        payload_type: 96,
        sequence_number,
        ssrc,
        ..Default::default()
    };
    let extension =
        rtp::extension::transport_cc_extension::TransportCcExtension { transport_sequence };
    header
        .set_extension(TWCC_ID, extension.marshal().expect("marshal").freeze())
        .expect("set extension");
    Packet::Rtp(rtp::Packet {
        header,
        payload: vec![0u8; 100].into(),
    })
}

fn receiver() -> impl Interceptor {
    let mut chain = Registry::new()
        .with(
            Slot::TwccReceiver,
            TwccReceiverBuilder::new()
                .with_interval(Duration::from_millis(100))
                .with_adaptive_interval(false)
                .build(),
        )
        .build();
    chain.bind_remote_stream(&stream(FIRST, &[("transport-cc", "")]));
    chain.bind_remote_stream(&stream(SECOND, &[("transport-cc", "")]));
    chain
}

fn feedback_at(chain: &mut impl Interceptor, at: Instant) -> Vec<TransportLayerCc> {
    chain.handle_timeout(at).expect("timeout");
    let mut feedback = Vec::new();
    while let Some(out) = chain.poll_write() {
        if let Packet::Rtcp(packets) = out.message.packet {
            for packet in packets {
                if let Some(twcc) = packet.as_any().downcast_ref::<TransportLayerCc>() {
                    feedback.push(twcc.clone());
                }
            }
        }
    }
    feedback
}

/// Section 3.1: "feedback packet count: a counter incremented by one for each feedback packet
/// sent", which is how the sender notices one that was lost. And "SSRC of media source" is a
/// stream the feedback is about.
#[test]
fn the_feedback_packet_count_goes_up_by_one_and_the_media_source_is_a_reported_stream() {
    let epoch = Instant::now();
    let mut chain = receiver();

    let mut feedback = Vec::new();
    let mut transport_sequence = 0u16;
    for interval in 0..6u64 {
        for packet in 0..4u64 {
            let at = epoch + Duration::from_millis(interval * 100 + packet * 20);
            let ssrc = if packet % 2 == 0 { FIRST } else { SECOND };
            chain
                .handle_read(tagged(
                    at,
                    numbered(ssrc, transport_sequence, transport_sequence),
                ))
                .expect("read");
            transport_sequence += 1;
            while chain.poll_read().is_some() {}
        }
        feedback.extend(feedback_at(
            &mut chain,
            epoch + Duration::from_millis((interval + 1) * 100),
        ));
    }

    assert!(feedback.len() >= 5, "one feedback packet per interval");
    for pair in feedback.windows(2) {
        assert_eq!(
            pair[0].fb_pkt_count.wrapping_add(1),
            pair[1].fb_pkt_count,
            "the count goes up by one"
        );
    }
    for packet in &feedback {
        assert!(
            packet.media_ssrc == FIRST || packet.media_ssrc == SECOND,
            "media source {:#x} is not a stream the feedback is about",
            packet.media_ssrc
        );
        assert_ne!(0, packet.sender_ssrc);
    }
}

/// Section 3.1.1: a sequence number is reported with its first arrival. A second copy of a
/// packet (a duplicate on the path) does not add a second report or move the first.
#[test]
fn a_duplicate_is_reported_once_with_its_first_arrival() {
    let epoch = Instant::now();
    let mut chain = receiver();

    for (millis, transport_sequence) in [(0u64, 10u16), (10, 11), (20, 12), (60, 11), (70, 13)] {
        chain
            .handle_read(tagged(
                epoch + Duration::from_millis(millis),
                numbered(FIRST, transport_sequence, transport_sequence),
            ))
            .expect("read");
        while chain.poll_read().is_some() {}
    }
    let feedback = feedback_at(&mut chain, epoch + Duration::from_millis(100));
    let acknowledgements: Vec<_> = feedback.iter().flat_map(convert_twcc).collect();

    let reported: Vec<u16> = acknowledgements
        .iter()
        .filter(|ack| ack.arrived)
        .map(|ack| ack.sequence_number)
        .collect();
    assert_eq!(vec![10, 11, 12, 13], reported, "each number once");

    let arrival = |sequence: u16| {
        acknowledgements
            .iter()
            .find(|ack| ack.sequence_number == sequence)
            .and_then(|ack| ack.arrival)
            .expect("an arrival time")
    };
    assert_eq!(
        Duration::from_millis(10),
        arrival(11).saturating_sub(arrival(10)),
        "the first copy's arrival, 10 ms after its predecessor, not the second's at 60 ms"
    );
}

/// RFC 8888 section 3.1: "a report block indicating that certain RTP packets were lost is not
/// to be interpreted as a request to retransmit the lost packets". A stream with NACK and RTX
/// negotiated, told by RFC 8888 feedback that a packet did not arrive, sends nothing again.
#[test]
fn a_loss_report_is_not_a_retransmission_request() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(ConstantBitrate::new(1_000_000.0)).build(),
        )
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(FIRST, &[("nack", ""), ("ack", "ccfb")]));

    for sequence_number in 0..8u16 {
        chain
            .handle_write(tagged(
                epoch + Duration::from_millis(u64::from(sequence_number) * 10),
                Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc: FIRST,
                        ..Default::default()
                    },
                    payload: vec![0u8; 100].into(),
                }),
            ))
            .expect("write");
    }
    let mut sent = 0;
    while chain.poll_write().is_some() {
        sent += 1;
    }
    assert_eq!(8, sent);

    // Packets 3 and 4 did not arrive.
    let metric_blocks = (0..8u16)
        .map(|sequence_number| CcFeedbackMetricBlock {
            received: sequence_number != 3 && sequence_number != 4,
            ecn: Ecn::NotEct,
            arrival_time_offset: 100 - sequence_number * 10,
        })
        .collect();
    chain
        .handle_read(tagged(
            epoch + Duration::from_millis(150),
            Packet::Rtcp(vec![Box::new(CcFeedbackReport {
                sender_ssrc: 0x5E5E_5E5E,
                report_blocks: vec![CcFeedbackReportBlock {
                    media_ssrc: FIRST,
                    begin_sequence: 0,
                    metric_blocks,
                }],
                report_timestamp: 0x0002_0000,
            })]),
        ))
        .expect("read");
    while chain.poll_read().is_some() {}
    chain
        .handle_timeout(epoch + Duration::from_millis(200))
        .expect("timeout");

    let mut retransmitted = 0;
    while let Some(out) = chain.poll_write() {
        if matches!(out.message.packet, Packet::Rtp(_)) {
            retransmitted += 1;
        }
    }
    assert_eq!(0, retransmitted, "a loss report asks for nothing");
}
