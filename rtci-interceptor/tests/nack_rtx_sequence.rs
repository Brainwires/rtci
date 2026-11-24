//! RFC 4588 4: the retransmission stream has its own sequence number space, "one higher than
//! the previous packet", for as long as the RTX SSRC lives. A stream bound again with the same
//! SSRCs (a renegotiation re-binding it) is the same RTX stream and carries on; restarting it
//! would repeat packet indices SRTP has already used for that SSRC.

use bytes::Bytes;
use rtci_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, Registry, Slot,
    StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;

fn stream_info() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(97),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn original(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
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
            payload: Bytes::from_static(&[0xAA, 0xBB]),
        })),
    }
}

fn nack(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: vec![NackPair {
                packet_id: sequence_number,
                lost_packets: 0,
            }],
        })])),
    }
}

/// Sends `first..first + 5`, has each one NACKed, and returns the RTX sequence numbers used.
fn retransmit_five(chain: &mut impl Interceptor, now: Instant, first: u16) -> Vec<u16> {
    for sequence_number in first..first + 5 {
        chain.handle_write(original(now, sequence_number)).unwrap();
    }
    while chain.poll_write().is_some() {}

    let mut rtx = vec![];
    for sequence_number in first..first + 5 {
        chain.handle_read(nack(now, sequence_number)).unwrap();
        while chain.poll_read().is_some() {}
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtp(packet) = tagged.message.packet
                && packet.header.ssrc == RTX_SSRC
            {
                rtx.push(packet.header.sequence_number);
            }
        }
    }
    rtx
}

#[test]
fn rtx_sequence_numbers_increase_by_one_per_retransmission() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream_info());

    let rtx = retransmit_five(&mut chain, Instant::now(), 100);

    assert_eq!(5, rtx.len());
    for pair in rtx.windows(2) {
        assert_eq!(pair[0].wrapping_add(1), pair[1]);
    }
}

#[test]
fn rtx_sequence_numbers_carry_on_when_the_stream_is_bound_again() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    let now = Instant::now();

    chain.bind_local_stream(&stream_info());
    let before = retransmit_five(&mut chain, now, 100);
    assert_eq!(5, before.len());

    // A renegotiation that changes the codec re-binds the stream with the same SSRCs.
    chain.unbind_local_stream(&stream_info());
    chain.bind_local_stream(&StreamInfo {
        payload_type: 102,
        payload_type_rtx: Some(103),
        mime_type: "video/H264".to_string(),
        ..stream_info()
    });

    let after = retransmit_five(&mut chain, now + Duration::from_secs(1), 200);
    assert_eq!(5, after.len());

    assert_eq!(
        before[4].wrapping_add(1),
        after[0],
        "the RTX stream continues: {before:?} then {after:?}"
    );
    let mut all: Vec<u16> = before.iter().chain(&after).copied().collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(10, all.len(), "no RTX sequence number is used twice");
}

/// RFC 4588 4 (and RFC 3550 5.1): the initial sequence number of a retransmission stream is
/// random, so two streams do not both start at the same value (zero, before).
#[test]
fn rtx_sequence_numbers_do_not_start_at_a_fixed_value() {
    let now = Instant::now();
    let mut starts = std::collections::HashSet::new();
    for _ in 0..8 {
        let mut chain = Registry::new()
            .with(Slot::NackResponder, NackResponderBuilder::new().build())
            .build();
        chain.bind_local_stream(&stream_info());
        starts.insert(retransmit_five(&mut chain, now, 100)[0]);
    }
    assert!(
        starts.len() > 1,
        "eight RTX streams all started at {starts:?}"
    );
}
