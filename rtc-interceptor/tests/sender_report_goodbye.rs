//! RFC 3550 6.6: a sending stream that is unbound (its sender stopped) says goodbye with a final
//! sender report and a BYE for its SSRC and repair flows, in one compound packet.

use rtc_interceptor::{
    AttributedPacket, Interceptor, Packet, Registry, SenderReportBuilder, Slot, StreamInfo,
    TaggedPacket,
};
use rtcp::goodbye::Goodbye;
use rtcp::sender_report::SenderReport;
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

fn info() -> StreamInfo {
    StreamInfo {
        ssrc: 1,
        ssrc_rtx: Some(2),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        ..Default::default()
    }
}

fn rtp(now: Instant) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                ssrc: 1,
                payload_type: 96,
                ..Default::default()
            },
            payload: vec![0u8; 100].into(),
        })),
    }
}

fn chain() -> impl Interceptor {
    Registry::new()
        .with(Slot::SenderReport, SenderReportBuilder::new().build())
        .build()
}

#[test]
fn a_stopped_sender_says_goodbye() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    let now = Instant::now();
    chain.handle_write(rtp(now)).unwrap();
    chain
        .handle_timeout(now + Duration::from_millis(10))
        .unwrap();
    while chain.poll_write().is_some() {}

    chain.unbind_local_stream(&info());

    let compound = std::iter::from_fn(|| chain.poll_write())
        .find_map(|tagged| match tagged.message.packet {
            Packet::Rtcp(packets) => Some(packets),
            _ => None,
        })
        .expect("a goodbye compound packet");
    assert_eq!(2, compound.len());
    let report = compound[0]
        .as_any()
        .downcast_ref::<SenderReport>()
        .expect("a sender report first");
    assert_eq!(1, report.ssrc);
    assert_eq!(1, report.packet_count);
    let goodbye = compound[1]
        .as_any()
        .downcast_ref::<Goodbye>()
        .expect("then a BYE");
    assert_eq!(vec![1, 2], goodbye.sources);
}

#[test]
fn a_stream_that_never_sent_leaves_quietly() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    chain.handle_timeout(Instant::now()).unwrap();
    chain.unbind_local_stream(&info());
    assert!(chain.poll_write().is_none());
}
