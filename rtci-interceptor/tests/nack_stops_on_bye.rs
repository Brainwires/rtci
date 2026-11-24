//! RFC 4588 5.3: "a receiver MUST stop requesting retransmissions for an SSRC on receiving its
//! BYE". A gap still open when the source leaves is not asked for again.

use rtci_interceptor::{
    AttributedPacket, Interceptor, NackGeneratorBuilder, Packet, RTCPFeedback, Registry, Slot,
    StreamInfo, TaggedPacket,
};
use rtcp::goodbye::Goodbye;
use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const OTHER_SSRC: u32 = 0x4321;

fn stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc,
                ..Default::default()
            },
            payload: vec![0u8; 10].into(),
        })),
    }
}

/// The media SSRCs NACKed while the chain runs from `from` for `ticks` NACK intervals.
fn nacked(chain: &mut impl Interceptor, from: Instant, ticks: u32) -> Vec<u32> {
    let mut media_ssrcs = vec![];
    for tick in 1..=ticks {
        chain
            .handle_timeout(from + Duration::from_millis(100) * tick)
            .unwrap();
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtcp(packets) = tagged.message.packet {
                for packet in packets {
                    if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                        media_ssrcs.push(nack.media_ssrc);
                    }
                }
            }
        }
    }
    media_ssrcs
}

#[test]
fn a_gap_is_not_requested_after_the_sources_bye() {
    let mut chain = Registry::new()
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
        .build();
    chain.bind_remote_stream(&stream_info(SSRC));
    chain.bind_remote_stream(&stream_info(OTHER_SSRC));

    let now = Instant::now();
    for (ssrc, sequence_number) in [
        (SSRC, 1),
        (SSRC, 2),
        (SSRC, 4),
        (OTHER_SSRC, 1),
        (OTHER_SSRC, 3),
    ] {
        chain.handle_read(rtp(now, ssrc, sequence_number)).unwrap();
    }
    while chain.poll_read().is_some() {}

    // Before the BYE both gaps are asked for.
    let before = nacked(&mut chain, now, 1);
    assert!(before.contains(&SSRC) && before.contains(&OTHER_SSRC));

    chain
        .handle_read(TaggedPacket {
            now: now + Duration::from_millis(150),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(Goodbye {
                sources: vec![SSRC],
                reason: Default::default(),
            })])),
        })
        .unwrap();
    while chain.poll_read().is_some() {}

    let after = nacked(&mut chain, now + Duration::from_millis(100), 100);
    assert!(
        !after.contains(&SSRC),
        "a source that said BYE is not asked for retransmissions"
    );
    assert!(
        after.contains(&OTHER_SSRC),
        "the BYE of one source leaves the other's requests alone"
    );
}
