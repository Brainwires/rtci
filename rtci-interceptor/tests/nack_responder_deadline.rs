//! What the NACK responder makes on the read leg is due at once.
//!
//! A retransmission (a NACK arrived) and a probe cluster's padding (the congestion controller
//! asked for a cluster) are made while the chain's read leg runs, which a driver reaches after
//! its `poll_write`. The responder's `poll_timeout` says they are waiting, or the driver sleeps
//! until something else wakes it and they leave that much later.

use bytes::Bytes;
use rtci_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, ProbeRequest, RTCPFeedback,
    StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
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

/// A responder with one stream (RTX negotiated) that has sent packets 100 to 104 at `start`:
/// the interceptor by itself, as an application drives it without a chain (a chain reports what
/// its read leg made by itself, `tests/read_work_is_due.rs`).
fn sender(start: Instant) -> impl Interceptor {
    let mut chain = NackResponderBuilder::new().build();
    chain.bind_local_stream(&stream_info());
    for sequence_number in 100..105 {
        chain
            .handle_write(original(start, sequence_number))
            .unwrap();
    }
    while chain.poll_write().is_some() {}
    assert_eq!(None, chain.poll_timeout(), "nothing waits once sent");
    chain
}

/// What the driver does after reading: everything the read leg hands the application.
fn read(chain: &mut impl Interceptor, packet: TaggedPacket) {
    chain.handle_read(packet).unwrap();
    while chain.poll_read().is_some() {}
}

/// The RTP packets on the RTX SSRC the chain hands to the wire now.
fn rtx_written(chain: &mut impl Interceptor) -> usize {
    let mut count = 0;
    while let Some(tagged) = chain.poll_write() {
        if matches!(&tagged.message.packet, Packet::Rtp(rtp) if rtp.header.ssrc == RTX_SSRC) {
            count += 1;
        }
    }
    count
}

#[test]
fn a_retransmission_a_nack_asks_for_is_due_at_once() {
    let start = Instant::now();
    let mut chain = sender(start);
    let at = start + Duration::from_millis(100);

    read(&mut chain, nack(at, 102));

    let due = chain
        .poll_timeout()
        .expect("the retransmission waits for the driver");
    assert!(due <= at, "due at {due:?}, the NACK arrived at {at:?}");
    chain.handle_timeout(at).unwrap();
    assert_eq!(1, rtx_written(&mut chain));
    assert_eq!(
        None,
        chain.poll_timeout(),
        "nothing is due once it has left"
    );
}

#[test]
fn the_padding_of_a_probe_cluster_is_due_at_once() {
    let start = Instant::now();
    let mut chain = sender(start);
    let at = start + Duration::from_millis(100);

    read(
        &mut chain,
        ProbeRequest {
            cluster: 1,
            bits_per_second: 600_000.0,
            octets: 6000,
        }
        .into_packet(at),
    );

    let due = chain
        .poll_timeout()
        .expect("the cluster waits for the driver");
    assert!(
        due <= at,
        "due at {due:?}, the cluster was asked for at {at:?}"
    );
    chain.handle_timeout(at).unwrap();
    assert!(rtx_written(&mut chain) > 0, "the cluster's padding leaves");
    assert_eq!(
        None,
        chain.poll_timeout(),
        "nothing is due once it has left"
    );
}
