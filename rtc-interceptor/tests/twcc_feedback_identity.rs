//! draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1: the "SSRC of packet
//! sender" of a feedback message is its originator's. Through the RTCP session it is the SSRC
//! this endpoint reports from, the one its receiver reports and SDES carry.

mod rtcp_session_common;

use rtc_interceptor::{
    AttributedPacket, Interceptor, Packet, RTCPFeedback, RTPHeaderExtension, Registry,
    RtcpSessionControl, Slot, StreamInfo, TaggedPacket, TwccReceiverBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtcp_session_common::*;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const EXT_ID: u8 = 5;

fn stream(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_string(),
            id: u16::from(EXT_ID),
        }],
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn packet(now: Instant, ssrc: u32, seq: u16) -> TaggedPacket {
    let mut packet = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            ssrc,
            sequence_number: seq,
            payload_type: 96,
            ..Default::default()
        },
        payload: vec![0u8; 100].into(),
    };
    let extension = rtp::extension::transport_cc_extension::TransportCcExtension {
        transport_sequence: seq,
    }
    .marshal()
    .unwrap();
    packet
        .header
        .set_extension(EXT_ID, extension.freeze())
        .unwrap();
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

#[test]
fn transport_wide_feedback_leaves_from_the_reporting_ssrc() {
    let mut chain = Registry::new()
        .with(Slot::RtcpSession, builder().build())
        .with(
            Slot::TwccReceiver,
            TwccReceiverBuilder::new()
                .with_adaptive_interval(false)
                .build(),
        )
        .build();
    chain.bind_remote_stream(&stream(0x0BAD));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for seq in 0..20u16 {
        chain
            .handle_read(packet(
                base + Duration::from_millis(u64::from(seq) * 10),
                0x0BAD,
                seq,
            ))
            .unwrap();
    }
    read(&mut chain);
    let sent = run(&mut chain, base + secs(1.0));
    let feedback: Vec<&TransportLayerCc> = sent
        .iter()
        .flat_map(|sent| sent.get::<TransportLayerCc>())
        .collect();
    assert!(!feedback.is_empty());
    assert!(
        feedback.iter().all(|f| f.sender_ssrc == REPORTER),
        "{:?}",
        feedback.iter().map(|f| f.sender_ssrc).collect::<Vec<_>>()
    );
    assert!(feedback.iter().all(|f| f.media_ssrc == 0x0BAD));
    // The same SSRC leads the compound packets and names itself in their SDES.
    assert!(
        sent.iter()
            .filter(|s| s.is_compound())
            .all(|s| s.leader() == Some(REPORTER))
    );
}
