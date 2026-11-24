//! ULPFEC as a stream in an RTP session of its own (RFC 5109 sections 7.2 and 14.1): the send
//! interceptor's output, taken to the wire form of the FEC session by `FecSessionSsrcMap`, and
//! back into a receive chain.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, FecSessionPacket, FecSessionSsrcMap, FecSessionStream,
    Interceptor, Packet, RedPlacement, Registry, Slot, StreamInfo, TaggedPacket, UlpfecPacket,
    UlpfecReceiveBuilder, UlpfecSendBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x5109_0072;
const KEY: u32 = 0x0141_0141;
const MEDIA_PT: u8 = 96;
const RED_PT: u8 = 100;
const RED_FEC_PT: u8 = 101;
/// The payload type of `ulpfec` in the FEC session's own m= section.
const SESSION_FEC_PT: u8 = 127;

fn map() -> FecSessionSsrcMap {
    FecSessionSsrcMap::new(KEY)
}

/// A video stream whose FEC runs in a session of its own. The media section also lists `red`
/// and `ulpfec`, which the separate session overrides.
fn stream_info(one_level_only: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        payload_type: MEDIA_PT,
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90_000,
        section_mime_types: vec![
            (MEDIA_PT, "video/VP8".to_owned()),
            (RED_PT, "video/red".to_owned()),
            (RED_FEC_PT, "video/ulpfec".to_owned()),
        ],
        fec_session: Some(FecSessionStream {
            ssrc: map().map(MEDIA_SSRC),
            payload_type: SESSION_FEC_PT,
            one_level_only,
        }),
        ..Default::default()
    }
}

fn media(sequence_number: u16, timestamp: u32, marker: bool, length: usize) -> rtp::Packet {
    let payload: Vec<u8> = (0..length)
        .map(|index| (index as u8).wrapping_mul(29) ^ (sequence_number as u8).wrapping_mul(7))
        .collect();
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker,
            payload_type: MEDIA_PT,
            sequence_number,
            timestamp,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: Bytes::from(payload),
    }
}

fn block(first: u16, timestamp: u32) -> Vec<rtp::Packet> {
    (0..5u16)
        .map(|index| {
            media(
                first.wrapping_add(index),
                timestamp,
                index == 4,
                120 + 40 * index as usize,
            )
        })
        .collect()
}

fn on(transport: TransportContext, now: Instant, packet: rtp::Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport,
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

/// The address pair of the media session and of the FEC session: two transports.
fn transports() -> (TransportContext, TransportContext) {
    let pair = |local: &str, peer: &str| TransportContext {
        local_addr: local.parse::<SocketAddr>().unwrap(),
        peer_addr: peer.parse::<SocketAddr>().unwrap(),
        ..Default::default()
    };
    (
        pair("192.0.2.1:5000", "198.51.100.1:6000"),
        pair("192.0.2.1:5002", "198.51.100.1:6002"),
    )
}

/// A send chain whose builder asks for RED: the stream's FEC session is what counts.
fn sender(info: &StreamInfo, levels: &[u16]) -> impl Interceptor + use<> {
    let mut chain = Registry::new()
        .with(
            Slot::FecEncoder,
            UlpfecSendBuilder::red(RED_PT, RED_FEC_PT)
                .with_red_placement(RedPlacement::OwnPacket)
                .with_adaptive_rate(false)
                .with_level_lengths(levels.to_vec())
                .with_initial_fec_sequence_number(40_000)
                .build(),
        )
        .build();
    chain.bind_local_stream(info);
    chain
}

fn receiver(info: &StreamInfo) -> impl Interceptor + use<> {
    let mut chain = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED_PT, RED_FEC_PT).build(),
        )
        .build();
    chain.bind_remote_stream(info);
    chain
}

/// Everything the chain writes for `packets`, each `step` after the one before.
fn send(
    chain: &mut impl Interceptor,
    start: Instant,
    step: Duration,
    packets: &[rtp::Packet],
) -> Vec<rtp::Packet> {
    let mut wire = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let now = start + step * index as u32;
        chain
            .handle_write(on(TransportContext::default(), now, packet.clone()))
            .unwrap();
        while let Some(out) = chain.poll_write() {
            if let Packet::Rtp(packet) = out.message.packet {
                wire.push(packet);
            }
        }
    }
    wire
}

/// What the chain wrote, split into the media session's packets and the FEC session's, the
/// latter as they are on the FEC session's transport.
fn sessions(wire: Vec<rtp::Packet>) -> (Vec<rtp::Packet>, Vec<rtp::Packet>) {
    let alias = map().map(MEDIA_SSRC);
    let (fec, media): (Vec<_>, Vec<_>) = wire
        .into_iter()
        .partition(|packet| packet.header.ssrc == alias);
    let fec = fec
        .into_iter()
        .map(|mut packet| {
            map().map_rtp(&mut packet);
            packet
        })
        .collect();
    (media, fec)
}

/// RFC 5109 section 7.2: on the FEC session's transport a FEC packet has the SSRC of the media
/// stream it protects, the marker 0, the FEC session's payload type, and sequence numbers of
/// its own that count up by one; section 14.1: the media stream is left as it is.
#[test]
fn the_fec_of_a_separate_session_has_the_media_ssrc_and_leaves_the_media_stream_alone() {
    let info = stream_info(false);
    let mut chain = sender(&info, &[]);
    let start = Instant::now();
    // Two frames of five packets, 50 ms (4500 ticks) apart, each sent in one go.
    let packets: Vec<rtp::Packet> = block(100, 3_000)
        .into_iter()
        .chain(block(105, 7_500))
        .collect();
    let wire = send(&mut chain, start, Duration::from_millis(10), &packets);
    // (The packets are written 10 ms apart, so the FEC of each block leaves 50 ms after the
    // one before.)
    let (media_wire, fec_wire) = sessions(wire);

    // The media stream: every packet as the application wrote it, not wrapped in RED although
    // the section lists it, with no sequence number given to FEC.
    assert_eq!(media_wire.len(), packets.len());
    for (sent, original) in media_wire.iter().zip(&packets) {
        assert_eq!(sent.marshal().unwrap(), original.marshal().unwrap());
    }

    assert_eq!(fec_wire.len(), 2, "one FEC packet for each block of five");
    for (index, fec) in fec_wire.iter().enumerate() {
        assert_eq!(
            fec.header.ssrc, MEDIA_SSRC,
            "the SSRC of the protected stream"
        );
        assert!(!fec.header.marker, "the marker is not used and is 0");
        assert_eq!(fec.header.payload_type, SESSION_FEC_PT);
        assert_eq!(
            fec.header.sequence_number,
            40_000 + index as u16,
            "one higher than the FEC packet before"
        );
        assert!(fec.header.csrc.is_empty());
        let parsed = UlpfecPacket::parse(&fec.payload).unwrap();
        assert_eq!(parsed.sn_base, 100 + 5 * index as u16);
    }
    // The timestamp is the media clock when the FEC packet is sent: the second FEC packet
    // left 50 ms, 4500 ticks, after the first.
    assert_eq!(
        fec_wire[1]
            .header
            .timestamp
            .wrapping_sub(fec_wire[0].header.timestamp),
        4_500
    );
}

/// RFC 5109 section 9 across two sessions: a media packet lost on the media transport is
/// rebuilt from the FEC packet that arrived on the FEC session's transport, and the rebuilt
/// packet is media of the media session.
#[test]
fn a_media_packet_lost_in_its_session_is_rebuilt_from_the_fec_session() {
    let info = stream_info(false);
    let mut send_chain = sender(&info, &[]);
    let start = Instant::now();
    let packets = block(65_533, 3_000);
    let wire = send(&mut send_chain, start, Duration::ZERO, &packets);
    let (media_wire, fec_wire) = sessions(wire);
    assert_eq!(fec_wire.len(), 1);

    let (media_transport, fec_transport) = transports();
    let mut chain = receiver(&info);
    let mut delivered = Vec::new();
    for (index, packet) in media_wire.iter().enumerate() {
        if index == 2 {
            continue;
        }
        chain
            .handle_read(on(media_transport, start, packet.clone()))
            .unwrap();
    }
    // The FEC packet as the FEC session's transport delivers it: the media SSRC, taken into
    // the chain's SSRC by the map.
    let mut fec = fec_wire[0].clone();
    assert_eq!(fec.header.ssrc, MEDIA_SSRC);
    map().map_rtp(&mut fec);
    chain.handle_read(on(fec_transport, start, fec)).unwrap();
    // The media, not the carriers of the decoder's counts (empty RTCP).
    while let Some(out) = chain.poll_read() {
        if matches!(out.message.packet, Packet::Rtp(_)) {
            delivered.push(out);
        }
    }

    assert_eq!(delivered.len(), 5, "four that arrived and the rebuilt one");
    let rebuilt = delivered.last().unwrap();
    let Packet::Rtp(packet) = &rebuilt.message.packet else {
        panic!("expected RTP");
    };
    assert_eq!(packet.marshal().unwrap(), packets[2].marshal().unwrap());
    assert!(
        rebuilt
            .message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, Attribute::RecoveredByFec))
    );
    assert_eq!(
        rebuilt.transport, media_transport,
        "rebuilt media belongs to the media session, not to the transport its FEC came on"
    );
    assert!(
        delivered.iter().all(|out| match &out.message.packet {
            Packet::Rtp(packet) => packet.header.ssrc == MEDIA_SSRC,
            _ => false,
        }),
        "the FEC stream itself is not delivered"
    );
}

/// RFC 5109 section 13: `onelevelonly=1` on the FEC session's `ulpfec` format keeps the sender
/// to one level, and has the receiver refuse FEC with two.
#[test]
fn onelevelonly_of_the_fec_session_is_followed_in_both_directions() {
    let start = Instant::now();
    let packets = block(500, 3_000);
    let levels = |one_level_only: bool| {
        let mut chain = sender(&stream_info(one_level_only), &[40, 60]);
        let (_, fec) = sessions(send(&mut chain, start, Duration::ZERO, &packets));
        assert_eq!(fec.len(), 1);
        UlpfecPacket::parse(&fec[0].payload).unwrap().levels.len()
    };
    assert_eq!(levels(false), 2);
    assert_eq!(levels(true), 1, "only one level is sent");

    // A receiver that said onelevelonly=1 takes nothing from FEC with two levels.
    for (one_level_only, expected) in [(false, 1), (true, 0)] {
        let mut chain = receiver(&stream_info(one_level_only));
        // Short packets, within the two levels' reach.
        let short: Vec<rtp::Packet> = (0..5u16)
            .map(|i| media(500 + i, 3_000, i == 4, 80))
            .collect();
        let mut send_chain = sender(&stream_info(false), &[40, 60]);
        let (media_wire, fec) = sessions(send(&mut send_chain, start, Duration::ZERO, &short));
        for (index, packet) in media_wire.iter().enumerate() {
            if index != 3 {
                chain
                    .handle_read(on(TransportContext::default(), start, packet.clone()))
                    .unwrap();
            }
        }
        let mut fec = fec[0].clone();
        map().map_rtp(&mut fec);
        chain
            .handle_read(on(TransportContext::default(), start, fec))
            .unwrap();
        let mut recovered = 0;
        while let Some(out) = chain.poll_read() {
            if out
                .message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, Attribute::RecoveredByFec))
            {
                recovered += 1;
            }
        }
        assert_eq!(recovered, expected, "onelevelonly={one_level_only}");
    }
}

/// How many packets a receive chain rebuilt from what it was given.
fn rebuilt(chain: &mut impl Interceptor) -> Vec<rtp::Packet> {
    let mut out = Vec::new();
    while let Some(read) = chain.poll_read() {
        let recovered = read
            .message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, Attribute::RecoveredByFec));
        match read.message.packet {
            Packet::Rtp(packet) if recovered => out.push(packet),
            Packet::Rtp(packet) => assert_eq!(packet.header.ssrc, MEDIA_SSRC, "only media"),
            _ => {}
        }
    }
    out
}

/// A binder that learns which stream a FEC session protects only from its packets marks each
/// one (`FecSessionPacket`): the stream was bound without a word about FEC, and its decoder,
/// kept from the start, takes the session's FEC. The payload type and `onelevelonly` of the
/// session are the mark's.
#[test]
fn fec_marked_as_a_sessions_reaches_the_decoder_of_the_stream_it_names() {
    let start = Instant::now();
    let short: Vec<rtp::Packet> = (0..5u16)
        .map(|i| media(700 + i, 3_000, i == 4, 80))
        .collect();
    let mut send_chain = sender(&stream_info(false), &[40, 60]);
    let (media_wire, fec_wire) = sessions(send(&mut send_chain, start, Duration::ZERO, &short));
    assert_eq!(fec_wire.len(), 1);

    let plain = StreamInfo {
        fec_session: None,
        ..stream_info(false)
    };
    let feed = |builder: UlpfecReceiveBuilder, mark: FecSessionPacket| {
        let mut chain = Registry::new()
            .with(Slot::FecDecoder, builder.build())
            .build();
        chain.bind_remote_stream(&plain);
        for (index, packet) in media_wire.iter().enumerate() {
            if index != 1 {
                chain
                    .handle_read(on(TransportContext::default(), start, packet.clone()))
                    .unwrap();
            }
        }
        let mut fec = fec_wire[0].clone();
        map().map_rtp(&mut fec);
        let mut read = on(TransportContext::default(), start, fec);
        read.message.add(Attribute::Custom(Arc::new(mark)));
        chain.handle_read(read).unwrap();
        rebuilt(&mut chain)
    };
    let mark = FecSessionPacket {
        media_ssrc: MEDIA_SSRC,
        payload_type: SESSION_FEC_PT,
        one_level_only: false,
    };

    let recovered = feed(UlpfecReceiveBuilder::sessions(), mark);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].marshal().unwrap(), short[1].marshal().unwrap());
    // The RED carriage keeps a decoder for each stream as well.
    assert_eq!(
        feed(UlpfecReceiveBuilder::red(RED_PT, RED_FEC_PT), mark).len(),
        1
    );

    // Another payload type than the session's `ulpfec`: not FEC.
    let other_type = FecSessionPacket {
        payload_type: SESSION_FEC_PT - 1,
        ..mark
    };
    assert_eq!(feed(UlpfecReceiveBuilder::sessions(), other_type).len(), 0);
    // Two levels where this endpoint said onelevelonly=1.
    let one_level = FecSessionPacket {
        one_level_only: true,
        ..mark
    };
    assert_eq!(feed(UlpfecReceiveBuilder::sessions(), one_level).len(), 0);
    // A stream the mark does not name.
    let other_stream = FecSessionPacket {
        media_ssrc: MEDIA_SSRC + 1,
        ..mark
    };
    assert_eq!(
        feed(UlpfecReceiveBuilder::sessions(), other_stream).len(),
        0
    );
    // A separate-stream receiver that was not built for sessions keeps no decoder for a
    // stream bound without a FEC flow: the session's packet ends there, rebuilt nothing.
    assert_eq!(feed(UlpfecReceiveBuilder::stream(), mark).len(), 0);
}
