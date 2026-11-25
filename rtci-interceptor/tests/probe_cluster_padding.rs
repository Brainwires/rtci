//! The padding of a probe cluster belongs to the cluster.
//!
//! A probe cluster (`ProbeRequest`) is filled with what waits in the pacer's media queue
//! first, at the cluster's rate and with its mark, and with padding-only packets on the RTX
//! stream for the rest. The pacer says how much padding that is (`ProbeFill`), the NACK
//! responder makes that much, and padding that could not leave in its cluster is discarded
//! when the cluster ends.
//!
//! Before, the responder made a whole cluster of padding for every request and the pacer kept
//! what did not leave "until budget was spare": after a capacity drop, with a backlog in the
//! pacer, every cluster was filled by the backlog and its 22 padding packets stayed queued
//! (191 of them after ten clusters in `tests/capacity_cap_video_rtc2rtc.rs`). They left
//! seconds later inside later clusters, with the RTX sequence numbers they were given when
//! made, far behind the stream's newest: no feedback ever named them, so those clusters were
//! never reported in full and gave no result, and an estimate at its floor stayed there.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackResponderBuilder, PacerBuilder, Packet,
    ProbeFill, ProbePacket, ProbeRequest, RTCPFeedback, StreamInfo, TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
/// The pacer's rate in these tests: 12 000 bits (one media packet) every 120 ms.
const TARGET: f64 = 100_000.0;

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

/// A media packet of 1500 octets (12 000 bits) on the wire.
fn media(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3000,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 1488]),
        })),
    }
}

/// A padding-only packet of the RTX stream, as the responder fills a cluster with.
fn padding(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                padding: true,
                payload_type: 97,
                sequence_number,
                ssrc: RTX_SSRC,
                padding_size: 255,
                ..Default::default()
            },
            payload: Bytes::new(),
        }))
        .with(Attribute::Retransmission),
    }
}

fn request(cluster: u32, at: Instant) -> TaggedPacket {
    ProbeRequest {
        cluster,
        bits_per_second: 2.0 * TARGET,
        octets: 6000,
    }
    .into_packet(at)
}

fn pacer() -> impl Interceptor {
    let mut pacer = PacerBuilder::new().with_target_bitrate(TARGET).build();
    pacer.bind_local_stream(&stream_info());
    pacer
}

/// Hands `packet` to the chain on its read leg and returns the padding the pacer asks for on
/// it (`ProbeFill`), if it says.
fn read_fill(chain: &mut impl Interceptor, packet: TaggedPacket) -> Option<usize> {
    chain.handle_read(packet).unwrap();
    let mut fill = None;
    while let Some(read) = chain.poll_read() {
        if let Some(asked) = read.message.custom::<ProbeFill>() {
            fill = Some(asked.octets);
        }
    }
    fill
}

/// Runs the chain's timers up to `until` and returns what left: (SSRC, sequence number,
/// the cluster it was marked with).
fn run_until(
    chain: &mut impl Interceptor,
    until: Instant,
    left: &mut Vec<(u32, u16, Option<u32>)>,
) {
    loop {
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                left.push((
                    rtp.header.ssrc,
                    rtp.header.sequence_number,
                    packet.message.custom::<ProbePacket>().map(|p| p.cluster),
                ));
            }
        }
        match chain.poll_timeout() {
            Some(deadline) if deadline <= until => chain.handle_timeout(deadline).unwrap(),
            _ => break,
        }
    }
}

/// The pacer asks for the padding a cluster needs beyond the media it holds: all of the
/// cluster with nothing queued, the rest of it with a little queued, none with a backlog.
#[test]
fn the_pacer_asks_for_the_padding_its_queue_leaves_room_for() {
    let epoch = Instant::now();

    let mut idle = pacer();
    assert_eq!(Some(6000), read_fill(&mut idle, request(1, epoch)));

    // Four packets written: what the budget's burst lets out at once has left, the others
    // wait, 1500 octets each.
    let mut some = pacer();
    for sequence_number in 0..4 {
        some.handle_write(media(epoch, sequence_number)).unwrap();
    }
    let waiting = 4 - std::iter::from_fn(|| some.poll_write()).count();
    assert!((2..=3).contains(&waiting), "{waiting} packets wait");
    assert_eq!(
        Some(6000 - 1500 * waiting),
        read_fill(&mut some, request(1, epoch))
    );

    let mut backlog = pacer();
    for sequence_number in 0..20 {
        backlog.handle_write(media(epoch, sequence_number)).unwrap();
    }
    assert_eq!(Some(0), read_fill(&mut backlog, request(1, epoch)));
}

/// A cluster asked while a backlog waits is made of the backlog. Padding written for it all
/// the same (a responder that does not read `ProbeFill`) does not leave in it, and is not
/// kept for later: once the cluster has ended none of it ever leaves, in the next cluster or
/// from spare budget.
#[test]
fn padding_left_over_when_its_cluster_ends_is_discarded() {
    let epoch = Instant::now();
    let mut chain = pacer();
    let mut left = Vec::new();
    for sequence_number in 0..20 {
        chain.handle_write(media(epoch, sequence_number)).unwrap();
    }

    // The first cluster, during the backlog: 22 padding packets written for it.
    let first = epoch + Duration::from_millis(10);
    read_fill(&mut chain, request(1, first));
    for sequence_number in 100..122 {
        chain.handle_write(padding(first, sequence_number)).unwrap();
    }
    // The backlog leaves (19 packets at 100 kbit/s: 2.3 s), then the queue is empty for
    // seconds: spare budget, which the padding would have left from.
    run_until(&mut chain, epoch + Duration::from_secs(6), &mut left);
    assert_eq!(
        20,
        left.iter().filter(|(ssrc, ..)| *ssrc == SSRC).count(),
        "every media packet left: {left:?}"
    );
    assert!(
        left.iter()
            .any(|(ssrc, _, cluster)| *ssrc == SSRC && *cluster == Some(1)),
        "the backlog filled the cluster: {left:?}"
    );

    // A second cluster on the idle pacer, with its own padding.
    let second = epoch + Duration::from_secs(6);
    assert_eq!(Some(6000), read_fill(&mut chain, request(2, second)));
    for sequence_number in 200..222 {
        chain
            .handle_write(padding(second, sequence_number))
            .unwrap();
    }
    run_until(&mut chain, epoch + Duration::from_secs(12), &mut left);

    let stale: Vec<_> = left
        .iter()
        .filter(|(ssrc, sequence_number, _)| *ssrc == RTX_SSRC && *sequence_number < 200)
        .collect();
    assert!(
        stale.is_empty(),
        "padding of the first cluster left after it ended: {stale:?}"
    );
    let second_cluster: Vec<u16> = left
        .iter()
        .filter(|(_, _, cluster)| *cluster == Some(2))
        .map(|(_, sequence_number, _)| *sequence_number)
        .collect();
    assert!(
        second_cluster.len() >= 18 && second_cluster.iter().all(|seq| *seq >= 200),
        "the second cluster is made of the padding written for it: {second_cluster:?}"
    );
}

/// Padding written while no cluster is being sent keeps its place until budget is spare.
#[test]
fn padding_outside_a_cluster_is_sent_when_budget_is_spare() {
    let epoch = Instant::now();
    let mut chain = pacer();
    let mut left = Vec::new();
    for sequence_number in 0..5 {
        chain.handle_write(media(epoch, sequence_number)).unwrap();
    }
    for sequence_number in 100..103 {
        chain.handle_write(padding(epoch, sequence_number)).unwrap();
    }
    run_until(&mut chain, epoch + Duration::from_secs(3), &mut left);
    assert_eq!(
        3,
        left.iter().filter(|(ssrc, ..)| *ssrc == RTX_SSRC).count(),
        "{left:?}"
    );
}

/// The NACK responder makes the padding the pacer asks for: the whole cluster without a
/// pacer's word, that much with it, none when the pacer's queue fills the cluster.
#[test]
fn the_responder_makes_the_padding_the_pacer_asks_for() {
    let epoch = Instant::now();
    let padding_made = |fill: Option<usize>| {
        let mut responder = NackResponderBuilder::new().build();
        responder.bind_local_stream(&stream_info());
        responder.handle_write(media(epoch, 1)).unwrap();
        while responder.poll_write().is_some() {}
        let at = epoch + Duration::from_millis(100);
        let mut carrier = request(1, at);
        if let Some(octets) = fill {
            carrier.message.add(Attribute::Custom(Arc::new(ProbeFill {
                cluster: 1,
                octets,
            })));
        }
        responder.handle_read(carrier).unwrap();
        while responder.poll_read().is_some() {}
        responder.handle_timeout(at).unwrap();
        let mut count = 0;
        while let Some(packet) = responder.poll_write() {
            if matches!(&packet.message.packet, Packet::Rtp(rtp) if rtp.header.ssrc == RTX_SSRC && rtp.header.padding)
            {
                count += 1;
            }
        }
        count
    };
    let whole = padding_made(None);
    assert!(whole >= 20, "a 6000-octet cluster of padding: {whole}");
    assert_eq!(whole, padding_made(Some(6000)));
    let part = padding_made(Some(1500));
    assert!((5..=7).contains(&part), "1500 octets of padding: {part}");
    assert_eq!(0, padding_made(Some(0)));
    // A word about another cluster is not this one's.
    let other = {
        let mut responder = NackResponderBuilder::new().build();
        responder.bind_local_stream(&stream_info());
        responder.handle_write(media(epoch, 1)).unwrap();
        while responder.poll_write().is_some() {}
        let at = epoch + Duration::from_millis(100);
        let mut carrier = request(2, at);
        carrier.message.add(Attribute::Custom(Arc::new(ProbeFill {
            cluster: 1,
            octets: 0,
        })));
        responder.handle_read(carrier).unwrap();
        while responder.poll_read().is_some() {}
        responder.handle_timeout(at).unwrap();
        std::iter::from_fn(|| responder.poll_write()).count()
    };
    assert!(other >= 20, "{other}");
}
