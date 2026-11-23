//! What the read leg of a chain makes for its write leg is due at once.
//!
//! A driver reads after it writes and then sleeps until `poll_timeout` (`wakeup_common`).
//! Each case reads what makes an interceptor write (an RTCP-SR-REQ, a NACK, a probe request,
//! a PAUSE) and checks that the chain's `poll_timeout` is not later than now while the packet
//! waits for `poll_write`.

mod rtcp_session_common;
mod wakeup_common;

use bytes::Bytes;
use rtc_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, PauseResumeBuilder, ProbeRequest,
    RTCPFeedback, Registry, RtcpBandwidth, RtcpSessionControl, Slot, StreamInfo, TaggedPacket,
};
use rtcp::sender_report::SenderReport;
use rtcp::transport_feedbacks::pause_resume::{PauseResume, PauseResumeEntry};
use rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};
use wakeup_common::read_then_sleep;

const MEDIA: u32 = 0x1234;
const RTX: u32 = 0x5678;

fn rtcp(now: Instant, packet: Box<dyn rtcp::Packet>) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![packet])),
    }
}

fn media(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc: MEDIA,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0xAA; 100]),
        })),
    }
}

fn responder() -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&StreamInfo {
        ssrc: MEDIA,
        ssrc_rtx: Some(RTX),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(97),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    });
    chain
}

/// RFC 4585 / RFC 4588: a NACK read is answered with a retransmission.
#[test]
fn a_retransmission_is_due_when_the_nack_is_read() {
    let start = Instant::now();
    let mut chain = responder();
    for n in 0..5 {
        chain.handle_write(media(start, n)).unwrap();
    }
    while chain.poll_write().is_some() {}
    let at = start + Duration::from_millis(50);
    let written = read_then_sleep(
        &mut chain,
        rtcp(
            at,
            Box::new(TransportLayerNack {
                sender_ssrc: 1,
                media_ssrc: MEDIA,
                nacks: vec![NackPair {
                    packet_id: 3,
                    lost_packets: 0,
                }],
            }),
        ),
    );
    assert_eq!(1, written.len(), "the retransmission");
}

/// A probe cluster the congestion controller asks for (on the read leg) is filled with
/// padding at once.
#[test]
fn a_probe_clusters_padding_is_due_when_the_request_is_read() {
    let start = Instant::now();
    let mut chain = responder();
    chain.handle_write(media(start, 0)).unwrap();
    while chain.poll_write().is_some() {}
    let at = start + Duration::from_millis(50);
    let written = read_then_sleep(
        &mut chain,
        ProbeRequest {
            cluster: 1,
            bits_per_second: 600_000.0,
            octets: 6000,
        }
        .into_packet(at),
    );
    assert!(!written.is_empty(), "the padding");
}

/// RFC 6051 section 3.2: an RTCP-SR-REQ is answered with an SR "as soon as possible", in an
/// Early packet when the feedback rules allow it at once.
#[test]
fn an_early_sender_report_is_due_when_the_request_is_read() {
    use rtcp_session_common::*;
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    while chain.poll_write().is_some() {}

    let now = base + Duration::from_millis(50);
    let written = read_then_sleep(
        &mut chain,
        rtcp_session_common::rtcp(
            now,
            vec![Box::new(RapidResynchronizationRequest {
                sender_ssrc: 200,
                media_ssrc: 100,
            })],
        ),
    );
    assert!(
        written.iter().any(|packet| matches!(
            &packet.message.packet,
            Packet::Rtcp(packets) if packets.iter().any(|p| p.as_any().is::<SenderReport>())
        )),
        "the Early SR"
    );
}

/// RFC 7728 section 6.2 with `nowait`: a PAUSE read pauses the stream at once, and the
/// PAUSED that says so is due.
#[test]
fn a_paused_answer_is_due_when_the_pause_is_read() {
    let (pause, _handle) = PauseResumeBuilder::new().build();
    let mut chain = Registry::new().with(Slot::PauseResume, pause).build();
    let stream = StreamInfo {
        ssrc: MEDIA,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "ccm".to_owned(),
            parameter: "pause nowait".to_owned(),
        }],
        ..Default::default()
    };
    chain.bind_local_stream(&stream);
    let start = Instant::now();
    chain.handle_write(media(start, 1)).unwrap();
    while chain.poll_write().is_some() {}

    let at = start + Duration::from_millis(50);
    let written = read_then_sleep(
        &mut chain,
        rtcp(
            at,
            Box::new(PauseResume {
                sender_ssrc: 0x0B0B,
                entries: vec![PauseResumeEntry::pause(MEDIA, 0)],
            }),
        ),
    );
    assert!(!written.is_empty(), "the PAUSED answer");
}
