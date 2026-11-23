//! ULPFEC (RFC 5109) in a chain: the send interceptor's output fed, with scripted losses, to the
//! receive interceptor, in both carriages (RED, RFC 5109 14.2, and a stream of its own, 14.1).

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackGeneratorBuilder, Packet, RTCPFeedback,
    RedPlacement, Registry, Slot, StreamInfo, TaggedPacket, UlpfecPacket, UlpfecReceiveBuilder,
    UlpfecRepair, UlpfecSendBuilder, depacketize_red_for_ulpfec,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 2;
const FEC_SSRC: u32 = 0x0FEC_0FEC;
const MEDIA_PT: u8 = 11;
const RED_PT: u8 = 100;
const FEC_PT: u8 = 127;

/// The RED carriage with FEC in RED packets of its own (libwebrtc's form), which most of these
/// tests are about. The builder's default is the form of RFC 5109 14.2 (FEC with the next media
/// packet); tests of that say so with `with_red_placement`.
fn red_builder() -> UlpfecSendBuilder {
    UlpfecSendBuilder::red(RED_PT, FEC_PT).with_red_placement(RedPlacement::OwnPacket)
}

fn stream_info(mime_type: &str, separate_fec: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: separate_fec.then_some(FEC_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: separate_fec.then_some(FEC_PT),
        mime_type: mime_type.to_owned(),
        clock_rate: 90_000,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn media(sequence_number: u16, timestamp: u32, marker: bool, length: usize) -> rtp::Packet {
    let payload: Vec<u8> = (0..length)
        .map(|index| (index as u8).wrapping_mul(13) ^ (sequence_number as u8).wrapping_mul(5))
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

/// The five media packets of RFC 5109 10.3: A to E from SSRC 2, sequence numbers 8 to 12,
/// timestamps 3 to 11, payload type 11, 200 / 140 / 100 / 340 / 160 octets, marker on A and C.
fn rfc_packets() -> Vec<rtp::Packet> {
    vec![
        media(8, 3, true, 200),
        media(9, 5, false, 140),
        media(10, 7, true, 100),
        media(11, 9, false, 340),
        media(12, 11, false, 160),
    ]
}

fn tagged(now: Instant, packet: rtp::Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

/// Write `packets` through a send chain and return everything it put on the wire, in order.
fn send(chain: &mut impl Interceptor, now: Instant, packets: &[rtp::Packet]) -> Vec<rtp::Packet> {
    let mut wire = Vec::new();
    for packet in packets {
        chain.handle_write(tagged(now, packet.clone())).unwrap();
        while let Some(out) = chain.poll_write() {
            if let Packet::Rtp(packet) = out.message.packet {
                wire.push(packet);
            }
        }
    }
    wire
}

/// Read `wire` through a receive chain and return what comes out of its far end.
fn receive(
    chain: &mut impl Interceptor,
    now: Instant,
    wire: &[rtp::Packet],
) -> Vec<AttributedPacket> {
    let mut delivered = Vec::new();
    for packet in wire {
        chain.handle_read(tagged(now, packet.clone())).unwrap();
        while let Some(out) = chain.poll_read() {
            delivered.push(out.message);
        }
    }
    delivered
}

fn rtp_of(message: &AttributedPacket) -> &rtp::Packet {
    match &message.packet {
        Packet::Rtp(packet) => packet,
        _ => panic!("expected RTP"),
    }
}

fn red_sender(builder: UlpfecSendBuilder) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, builder.build())
        .build();
    chain.bind_local_stream(&stream_info("video/VP8", false));
    chain
}

fn red_receiver(builder: UlpfecReceiveBuilder) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::FecDecoder, builder.build())
        .build();
    chain.bind_remote_stream(&stream_info("video/VP8", false));
    chain
}

/// Media packets a receive chain delivered: not repair markers, in arrival order.
fn media_delivered(delivered: &[AttributedPacket]) -> Vec<&AttributedPacket> {
    delivered
        .iter()
        .filter(|message| message.custom::<UlpfecRepair>().is_none())
        .collect()
}

fn assert_same_packet(expected: &rtp::Packet, actual: &rtp::Packet) {
    assert_eq!(expected.marshal().unwrap(), actual.marshal().unwrap());
}

// --- RED carriage, send side ---

/// RFC 5109 10.3, Figures 19 to 22: four media packets each in a RED packet, the FEC over them
/// as a redundant block in the fifth, ahead of media packet E.
#[test]
fn rfc_5109_10_3_fec_rides_as_a_redundant_block_with_the_next_media_packet() {
    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(4)
            .with_num_fec_packets(1)
            .with_red_placement(RedPlacement::WithNextMedia),
    );
    let packets = rfc_packets();
    let wire = send(&mut chain, Instant::now(), &packets);

    assert_eq!(5, wire.len(), "FEC is not sent by itself");
    for (red, original) in wire.iter().zip(&packets) {
        assert_eq!(RED_PT, red.header.payload_type, "Figure 19: PT is RED's");
        assert_eq!(original.header.sequence_number, red.header.sequence_number);
        assert_eq!(original.header.timestamp, red.header.timestamp);
        assert_eq!(MEDIA_SSRC, red.header.ssrc);
    }
    // Figures 18 and 20: one octet of primary block header, F = 0 and block PT 11, then the
    // media data.
    for (red, original) in wire[..4].iter().zip(&packets) {
        assert_eq!(0b0000_1011, red.payload[0]);
        assert_eq!(&original.payload[..], &red.payload[1..]);
    }

    let fifth = &wire[4].payload;
    // Figure 22: F = 1, block PT 127, timestamp offset 0, block length 354.
    assert_eq!(&[0xFF, 0x00, 0x01, 0x62], &fifth[..4]);
    // RFC 2198 3: every block header comes before the first data block, so the primary block
    // header is next (Figure 21 draws each header next to its data), then the FEC data, then
    // the media data.
    assert_eq!(0b0000_1011, fifth[4]);
    let fec = &fifth[5..5 + 354];
    // Figure 8: the FEC header. PT recovery is 0 here as well: all four packets have PT 11.
    assert_eq!(
        &[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x01, 0x74],
        &fec[..10]
    );
    // Figure 9: L0 = 340, mask 61440.
    assert_eq!(&[0x01, 0x54, 0xF0, 0x00], &fec[10..14]);
    assert_eq!(&packets[4].payload[..], &fifth[5 + 354..]);
}

/// RFC 5109 14.2: "the FEC MUST NOT be sent by itself for this stream", and "the FEC data ...
/// is sent in the same packets as the protected payload". That is the builder's default: with
/// no placement chosen, every RED packet on the wire has a media primary block, and the FEC
/// rides ahead of one as a redundant block.
#[test]
fn by_default_fec_is_never_sent_by_itself() {
    let mut chain = red_sender(
        UlpfecSendBuilder::red(RED_PT, FEC_PT)
            .with_num_media_packets(4)
            .with_num_fec_packets(1),
    );
    let packets = rfc_packets();
    let wire = send(&mut chain, Instant::now(), &packets);

    assert_eq!(
        packets.len(),
        wire.len(),
        "no packet beside the media packets"
    );
    let mut with_fec = 0;
    for (red, original) in wire.iter().zip(&packets) {
        assert_eq!(original.header.sequence_number, red.header.sequence_number);
        let first = red.payload[0];
        if first & 0x80 != 0 {
            // A redundant block header (F = 1) with the FEC payload type, then the primary's.
            assert_eq!(FEC_PT, first & 0x7F);
            assert_eq!(
                MEDIA_PT,
                red.payload[4] & 0x7F,
                "media is the primary block"
            );
            with_fec += 1;
        } else {
            assert_eq!(MEDIA_PT, first & 0x7F, "media is the only block");
        }
    }
    assert_eq!(
        1, with_fec,
        "the block's FEC rides with the next media packet"
    );
}

#[test]
fn a_fec_packet_of_its_own_takes_the_next_sequence_number_of_the_media_stream() {
    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(2)
            .with_num_fec_packets(1),
    );
    let packets: Vec<_> = (100..106).map(|seq| media(seq, 3000, false, 50)).collect();
    let wire = send(&mut chain, Instant::now(), &packets);

    assert_eq!(9, wire.len(), "three blocks of two, one FEC packet each");
    let sequence_numbers: Vec<u16> = wire.iter().map(|p| p.header.sequence_number).collect();
    assert_eq!(
        (100..109).collect::<Vec<u16>>(),
        sequence_numbers,
        "one sequence space, without a gap or a repeat"
    );
    for (index, packet) in wire.iter().enumerate() {
        assert_eq!(MEDIA_SSRC, packet.header.ssrc);
        assert_eq!(RED_PT, packet.header.payload_type);
        let block_pt = packet.payload[0];
        if index % 3 == 2 {
            assert_eq!(FEC_PT, block_pt, "a single block, of the FEC payload type");
            assert!(!packet.header.marker);
            let fec = UlpfecPacket::parse(&packet.payload[1..]).unwrap();
            // It protects the two media packets just before it, as numbered on the wire.
            assert_eq!(packet.header.sequence_number - 2, fec.sn_base);
            assert_eq!(0b11, fec.levels[0].mask);
        } else {
            assert_eq!(MEDIA_PT, block_pt);
        }
    }
}

#[test]
fn the_marker_bit_of_a_media_packet_stays_on_its_red_packet() {
    let mut chain = red_sender(red_builder());
    let wire = send(
        &mut chain,
        Instant::now(),
        &[media(1, 0, false, 10), media(2, 0, true, 10)],
    );
    assert!(!wire[0].header.marker);
    assert!(wire[1].header.marker);
}

#[test]
fn a_block_closes_at_the_end_of_a_frame_when_asked_to() {
    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(10)
            .with_flush_on_marker(true),
    );
    let wire = send(
        &mut chain,
        Instant::now(),
        &[
            media(1, 0, false, 10),
            media(2, 0, false, 10),
            media(3, 0, true, 10),
        ],
    );
    assert_eq!(4, wire.len(), "FEC follows the frame's last packet");
    assert_eq!(FEC_PT, wire[3].payload[0]);
    let fec = UlpfecPacket::parse(&wire[3].payload[1..]).unwrap();
    assert_eq!(0b111, fec.levels[0].mask);
}

#[test]
fn only_video_streams_are_protected_unless_the_filter_says_otherwise() {
    let mut chain = Registry::new()
        .with(
            Slot::FecEncoder,
            red_builder().with_num_media_packets(1).build(),
        )
        .build();
    chain.bind_local_stream(&stream_info("audio/opus", false));
    let packet = media(1, 0, false, 10);
    let wire = send(&mut chain, Instant::now(), std::slice::from_ref(&packet));
    assert_eq!(vec![packet.clone()], wire, "audio is left alone");

    let mut chain = Registry::new()
        .with(
            Slot::FecEncoder,
            red_builder()
                .with_num_media_packets(1)
                .with_stream_filter(|info| info.mime_type == "audio/opus")
                .build(),
        )
        .build();
    chain.bind_local_stream(&stream_info("audio/opus", false));
    let wire = send(&mut chain, Instant::now(), &[packet]);
    assert_eq!(2, wire.len());
    assert_eq!(RED_PT, wire[0].header.payload_type);
}

#[test]
fn a_rebound_stream_continues_its_wire_sequence_numbers() {
    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(1)
            .with_num_fec_packets(1),
    );
    let now = Instant::now();
    let wire = send(&mut chain, now, &[media(10, 0, false, 5)]);
    assert_eq!(
        vec![10, 11],
        wire.iter()
            .map(|p| p.header.sequence_number)
            .collect::<Vec<_>>()
    );

    let info = stream_info("video/VP8", false);
    chain.unbind_local_stream(&info);
    chain.bind_local_stream(&info);
    let wire = send(&mut chain, now, &[media(11, 0, false, 5)]);
    assert_eq!(
        12, wire[0].header.sequence_number,
        "11 is on the wire already, as the FEC packet"
    );
}

#[test]
fn level_lengths_give_each_fec_packet_those_levels_and_onelevelonly_keeps_the_first() {
    let packets: Vec<_> = (1..5).map(|seq| media(seq, 0, false, 100)).collect();

    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(4)
            .with_level_lengths([20u16, 30]),
    );
    let wire = send(&mut chain, Instant::now(), &packets);
    let fec = UlpfecPacket::parse(&wire[4].payload[1..]).unwrap();
    assert_eq!(
        vec![20, 30],
        fec.levels
            .iter()
            .map(|l| l.payload.len())
            .collect::<Vec<_>>()
    );
    assert_eq!(0b1111, fec.levels[1].mask);

    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(4)
            .with_level_lengths([20u16, 30])
            .with_one_level_only(true),
    );
    let wire = send(&mut chain, Instant::now(), &packets);
    let fec = UlpfecPacket::parse(&wire[4].payload[1..]).unwrap();
    assert_eq!(
        1,
        fec.levels.len(),
        "onelevelonly=1: one level SHALL be used"
    );
    assert_eq!(20, fec.levels[0].payload.len());
}

// --- RED carriage, both sides ---

/// Send `packets` through RED + ULPFEC, drop the wire packets at the indices in `lost`, and
/// return what the receive chain delivers.
fn red_round_trip(
    builder: UlpfecSendBuilder,
    packets: &[rtp::Packet],
    lost: &[usize],
) -> (Vec<rtp::Packet>, Vec<AttributedPacket>) {
    let now = Instant::now();
    let mut sender = red_sender(builder);
    let wire = send(&mut sender, now, packets);
    let arriving: Vec<rtp::Packet> = wire
        .iter()
        .enumerate()
        .filter(|(index, _)| !lost.contains(index))
        .map(|(_, packet)| packet.clone())
        .collect();
    let mut receiver = red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT));
    let delivered = receive(&mut receiver, now, &arriving);
    (wire, delivered)
}

#[test]
fn red_packets_are_delivered_as_the_media_packets_they_carry() {
    let packets = rfc_packets();
    let (_, delivered) = red_round_trip(red_builder().with_num_media_packets(48), &packets, &[]);
    assert_eq!(5, delivered.len());
    for (original, message) in packets.iter().zip(&delivered) {
        assert_same_packet(original, rtp_of(message));
        assert!(!message.has(&Attribute::RecoveredByFec));
    }
}

#[test]
fn a_lost_media_packet_is_rebuilt_and_marked_recovered() {
    let packets = rfc_packets();
    for lost in 0..4 {
        let (wire, delivered) = red_round_trip(
            red_builder().with_num_media_packets(4),
            &packets[..4],
            &[lost],
        );
        assert_eq!(5, wire.len());
        let media = media_delivered(&delivered);
        assert_eq!(4, media.len(), "three arrived, one rebuilt");
        let recovered: Vec<_> = media
            .iter()
            .filter(|message| message.has(&Attribute::RecoveredByFec))
            .collect();
        assert_eq!(1, recovered.len());
        assert_same_packet(&packets[lost], rtp_of(recovered[0]));
        assert_eq!(
            MEDIA_PT,
            rtp_of(recovered[0]).header.payload_type,
            "the virtual packet has the primary's payload type, not RED's"
        );
    }
}

#[test]
fn a_fec_only_packet_goes_on_emptied_and_marked_so_its_sequence_number_is_seen() {
    let packets = rfc_packets();
    let (wire, delivered) =
        red_round_trip(red_builder().with_num_media_packets(4), &packets[..4], &[]);
    let repair: Vec<_> = delivered
        .iter()
        .filter(|message| message.custom::<UlpfecRepair>().is_some())
        .collect();
    assert_eq!(1, repair.len());
    let packet = rtp_of(repair[0]);
    assert_eq!(
        wire[4].header.sequence_number,
        packet.header.sequence_number
    );
    assert_eq!(FEC_PT, packet.header.payload_type);
    assert!(
        packet.payload.is_empty(),
        "no FEC octets travel on as media"
    );
}

#[test]
fn a_fec_only_packet_can_be_swallowed_instead() {
    let now = Instant::now();
    let mut sender = red_sender(red_builder().with_num_media_packets(2));
    let wire = send(
        &mut sender,
        now,
        &[media(1, 0, false, 10), media(2, 0, false, 10)],
    );
    let mut receiver =
        red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT).with_repair_forwarding(false));
    let delivered = receive(&mut receiver, now, &wire);
    assert_eq!(2, delivered.len());
    assert!(
        delivered
            .iter()
            .all(|m| rtp_of(m).header.payload_type == MEDIA_PT)
    );
}

#[test]
fn a_burst_is_rebuilt_when_there_are_as_many_fec_packets_as_losses() {
    let packets: Vec<_> = (500..506)
        .map(|seq| media(seq, 9000, seq == 505, 80 + usize::from(seq - 500) * 7))
        .collect();
    // Six media packets and three FEC packets, each over every third: wire indices 0..6 are
    // media, 6..9 FEC. A burst of three consecutive media packets is one loss per FEC packet.
    let (_, delivered) = red_round_trip(
        red_builder()
            .with_num_media_packets(6)
            .with_num_fec_packets(3),
        &packets,
        &[2, 3, 4],
    );
    let mut media: Vec<_> = media_delivered(&delivered)
        .into_iter()
        .map(|m| rtp_of(m).clone())
        .collect();
    media.sort_by_key(|p| p.header.sequence_number);
    assert_eq!(6, media.len());
    for (original, delivered) in packets.iter().zip(&media) {
        assert_same_packet(original, delivered);
    }
}

#[test]
fn losses_beyond_the_fec_are_left_lost() {
    let packets: Vec<_> = (500..504).map(|seq| media(seq, 0, false, 60)).collect();
    let (_, delivered) = red_round_trip(
        red_builder()
            .with_num_media_packets(4)
            .with_num_fec_packets(1),
        &packets,
        &[1, 2],
    );
    let media = media_delivered(&delivered);
    assert_eq!(2, media.len(), "one FEC packet cannot rebuild two");
    assert!(media.iter().all(|m| !m.has(&Attribute::RecoveredByFec)));
}

#[test]
fn losing_the_fec_packet_loses_nothing_else() {
    let packets = rfc_packets();
    let (_, delivered) =
        red_round_trip(red_builder().with_num_media_packets(4), &packets[..4], &[4]);
    assert_eq!(4, delivered.len());
    for (original, message) in packets.iter().zip(&delivered) {
        assert_same_packet(original, rtp_of(message));
    }
}

#[test]
fn recovery_works_where_the_sequence_numbers_wrap() {
    let packets: Vec<_> = [65533u16, 65534, 65535, 0]
        .into_iter()
        .map(|seq| media(seq, 100, false, 40))
        .collect();
    for lost in 0..4 {
        let (wire, delivered) =
            red_round_trip(red_builder().with_num_media_packets(4), &packets, &[lost]);
        assert_eq!(
            1, wire[4].header.sequence_number,
            "the FEC packet follows 0"
        );
        let recovered: Vec<_> = delivered
            .iter()
            .filter(|m| m.has(&Attribute::RecoveredByFec))
            .collect();
        assert_eq!(1, recovered.len());
        assert_same_packet(&packets[lost], rtp_of(recovered[0]));
    }
}

#[test]
fn a_lost_packet_with_csrc_extension_and_padding_is_rebuilt_whole() {
    let mut rich = media(2, 50, true, 45);
    rich.header.csrc = vec![0x1111_1111, 0x2222_2222];
    rich.header.padding = true;
    rich.header.padding_size = 5;
    rich.header
        .set_extension(4, Bytes::from_static(&[0xAB, 0xCD, 0xEF]))
        .unwrap();
    let packets = vec![
        media(1, 50, false, 70),
        rich.clone(),
        media(3, 60, false, 20),
    ];
    let (_, delivered) = red_round_trip(red_builder().with_num_media_packets(3), &packets, &[1]);
    let recovered: Vec<_> = delivered
        .iter()
        .filter(|m| m.has(&Attribute::RecoveredByFec))
        .collect();
    assert_eq!(1, recovered.len());
    let packet = rtp_of(recovered[0]);
    assert_same_packet(&rich, packet);
    assert_eq!(rich.header.csrc, packet.header.csrc);
    assert_eq!(
        Some(Bytes::from_static(&[0xAB, 0xCD, 0xEF])),
        packet.header.get_extension(4)
    );
    assert_eq!(5, packet.header.padding_size);
}

#[test]
fn uneven_protection_rebuilds_short_packets_and_withholds_a_long_one_cut_short() {
    // Level 0 covers 30 octets, level 1 the next 40: packets up to 70 octets are fully covered.
    let builder = || {
        red_builder()
            .with_num_media_packets(3)
            .with_level_lengths([30u16, 40])
    };
    let packets = vec![
        media(1, 0, false, 25),
        media(2, 0, false, 66),
        media(3, 0, false, 300),
    ];

    for lost in [0usize, 1] {
        let (_, delivered) = red_round_trip(builder(), &packets, &[lost]);
        let recovered: Vec<_> = delivered
            .iter()
            .filter(|m| m.has(&Attribute::RecoveredByFec))
            .collect();
        assert_eq!(
            1,
            recovered.len(),
            "packet {lost} lies within the two levels"
        );
        assert_same_packet(&packets[lost], rtp_of(recovered[0]));
    }

    let (_, delivered) = red_round_trip(builder(), &packets, &[2]);
    assert!(
        delivered.iter().all(|m| !m.has(&Attribute::RecoveredByFec)),
        "70 of 300 octets rebuilt is a partial recovery, and is not delivered as a packet"
    );
}

#[test]
fn fec_as_a_redundant_block_is_used_and_the_media_behind_it_delivered() {
    let now = Instant::now();
    let mut sender = red_sender(
        red_builder()
            .with_num_media_packets(4)
            .with_red_placement(RedPlacement::WithNextMedia),
    );
    let packets = rfc_packets();
    let wire = send(&mut sender, now, &packets);
    assert_eq!(5, wire.len());

    // B is lost; the FEC arrives inside the packet that carries E.
    let arriving: Vec<_> = wire
        .iter()
        .filter(|p| p.header.sequence_number != 9)
        .cloned()
        .collect();
    let mut receiver = red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT));
    let delivered = receive(&mut receiver, now, &arriving);

    assert_eq!(5, delivered.len());
    assert!(
        delivered
            .iter()
            .all(|m| m.custom::<UlpfecRepair>().is_none())
    );
    let mut by_sequence: Vec<_> = delivered.iter().map(|m| rtp_of(m).clone()).collect();
    by_sequence.sort_by_key(|p| p.header.sequence_number);
    for (original, delivered) in packets.iter().zip(&by_sequence) {
        assert_same_packet(original, delivered);
    }
}

#[test]
fn fec_too_long_for_a_redundant_block_gets_a_packet_of_its_own() {
    let mut chain = red_sender(
        red_builder()
            .with_num_media_packets(2)
            .with_red_placement(RedPlacement::WithNextMedia),
    );
    let wire = send(
        &mut chain,
        Instant::now(),
        &[media(1, 0, false, 1100), media(2, 0, false, 1100)],
    );
    assert_eq!(
        3,
        wire.len(),
        "1114 octets of FEC exceed the 10-bit block length"
    );
    assert_eq!(FEC_PT, wire[2].payload[0]);
    assert_eq!(3, wire[2].header.sequence_number);
}

#[test]
fn bare_fec_and_malformed_red_on_the_media_stream_are_dropped() {
    let now = Instant::now();
    let mut receiver = red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT));

    let mut bare_fec = media(1, 0, false, 30);
    bare_fec.header.payload_type = FEC_PT;
    assert!(
        receive(&mut receiver, now, &[bare_fec]).is_empty(),
        "FEC is not sent by itself in a RED stream"
    );

    let mut broken = media(2, 0, false, 0);
    broken.header.payload_type = RED_PT;
    // A redundant block header that promises 5 octets, and a primary header, with 1 octet left.
    broken.payload = Bytes::from_static(&[0xFF, 0x00, 0x00, 0x05, 0x0B, 0x01]);
    assert!(receive(&mut receiver, now, &[broken]).is_empty());
}

#[test]
fn a_bare_media_packet_on_a_red_stream_is_accepted_and_protected() {
    // RFC 2198 5: a receiver that lists RED takes the encodings bare as well.
    let now = Instant::now();
    let mut sender = red_sender(red_builder().with_num_media_packets(3));
    let packets = vec![
        media(1, 0, false, 30),
        media(2, 0, false, 30),
        media(3, 0, false, 30),
    ];
    let mut wire = send(&mut sender, now, &packets);
    // The first packet travels bare instead of in RED; the second is lost.
    wire[0] = packets[0].clone();
    wire.remove(1);

    let mut receiver = red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT));
    let delivered = receive(&mut receiver, now, &wire);
    let media = media_delivered(&delivered);
    assert_eq!(3, media.len());
    assert_same_packet(&packets[0], rtp_of(media[0]));
    assert!(media[2].has(&Attribute::RecoveredByFec));
    assert_same_packet(&packets[1], rtp_of(media[2]));
}

#[test]
fn a_receiver_that_signalled_onelevelonly_refuses_two_levels() {
    let now = Instant::now();
    let mut sender = red_sender(
        red_builder()
            .with_num_media_packets(2)
            .with_level_lengths([10u16, 30]),
    );
    let packets = vec![media(1, 0, false, 30), media(2, 0, false, 30)];
    let mut wire = send(&mut sender, now, &packets);
    wire.remove(0);

    let mut receiver =
        red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT).with_one_level_only(true));
    let delivered = receive(&mut receiver, now, &wire);
    assert!(
        delivered.iter().all(|m| !m.has(&Attribute::RecoveredByFec)),
        "the two-level FEC packet is not used"
    );

    let mut receiver = red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT));
    let delivered = receive(&mut receiver, now, &wire);
    assert_eq!(
        1,
        delivered
            .iter()
            .filter(|m| m.has(&Attribute::RecoveredByFec))
            .count(),
        "without the restriction it is"
    );
}

#[test]
fn an_unbound_stream_is_left_as_it_arrives() {
    let now = Instant::now();
    let mut receiver = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED_PT, FEC_PT).build(),
        )
        .build();
    let mut red = media(1, 0, false, 10);
    red.header.payload_type = RED_PT;
    let delivered = receive(&mut receiver, now, std::slice::from_ref(&red));
    assert_eq!(1, delivered.len());
    assert_same_packet(&red, rtp_of(&delivered[0]));

    // And after an unbind the stream is unbound again.
    let info = stream_info("video/VP8", false);
    receiver.bind_remote_stream(&info);
    receiver.unbind_remote_stream(&info);
    let delivered = receive(&mut receiver, now, std::slice::from_ref(&red));
    assert_same_packet(&red, rtp_of(&delivered[0]));
}

/// The FEC packet has a sequence number of the media stream. Passed on (emptied), it fills that
/// number in the NACK generator's log; swallowed, it would be asked for as if it were lost
/// media. Nor is a rebuilt packet asked for.
#[test]
fn the_nack_generator_asks_for_neither_the_fec_packet_nor_what_it_rebuilt() {
    const NACK_INTERVAL: Duration = Duration::from_millis(100);
    let now = Instant::now();

    let mut sender = red_sender(red_builder().with_num_media_packets(4));
    let first: Vec<_> = (200..204).map(|seq| media(seq, 0, false, 40)).collect();
    let second: Vec<_> = (204..208).map(|seq| media(seq, 0, false, 40)).collect();
    let mut wire = send(&mut sender, now, &first);
    wire.extend(send(&mut sender, now, &second));
    assert_eq!(
        10,
        wire.len(),
        "sequence numbers 200 to 209; 204 and 209 are FEC"
    );
    // 202 is lost and rebuilt.
    wire.remove(2);

    let mut receiver = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED_PT, FEC_PT).build(),
        )
        .with(
            Slot::NackGenerator,
            NackGeneratorBuilder::new()
                .with_interval(NACK_INTERVAL)
                .build(),
        )
        .build();
    receiver.bind_remote_stream(&stream_info("video/VP8", false));
    receive(&mut receiver, now, &wire);
    receiver.handle_timeout(now + NACK_INTERVAL * 2).unwrap();

    let mut asked_for = Vec::new();
    while let Some(packet) = receiver.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    ) {
                    for pair in &nack.nacks {
                        asked_for.extend(pair.packet_list());
                    }
                }
            }
        }
    }
    assert!(asked_for.is_empty(), "asked for {asked_for:?}");
}

// --- Separate stream ---

fn stream_chains(num_media: usize) -> (impl Interceptor, impl Interceptor) {
    let mut sender = Registry::new()
        .with(
            Slot::FecEncoder,
            UlpfecSendBuilder::stream()
                .with_num_media_packets(num_media)
                .with_initial_fec_sequence_number(65535)
                .build(),
        )
        .build();
    sender.bind_local_stream(&stream_info("video/VP8", true));
    let mut receiver = Registry::new()
        .with(Slot::FecDecoder, UlpfecReceiveBuilder::stream().build())
        .build();
    receiver.bind_remote_stream(&stream_info("video/VP8", true));
    (sender, receiver)
}

#[test]
fn a_separate_fec_stream_has_its_own_sequence_numbers_payload_type_and_clock() {
    let (mut sender, _) = stream_chains(2);
    let start = Instant::now();
    let mut wire = send(
        &mut sender,
        start,
        &[media(10, 9000, false, 20), media(11, 9000, true, 20)],
    );
    wire.extend(send(
        &mut sender,
        start + Duration::from_millis(33),
        &[media(12, 12_000, false, 20), media(13, 12_000, true, 20)],
    ));

    assert_eq!(6, wire.len());
    for (index, original) in [(0, 10u16), (1, 11), (3, 12), (4, 13)] {
        assert_eq!(
            MEDIA_PT, wire[index].header.payload_type,
            "media is untouched"
        );
        assert_eq!(original, wire[index].header.sequence_number);
        assert_eq!(MEDIA_SSRC, wire[index].header.ssrc);
    }
    let (first, second) = (&wire[2], &wire[5]);
    assert_eq!(FEC_PT, first.header.payload_type);
    assert_eq!(FEC_SSRC, first.header.ssrc);
    assert!(!first.header.marker, "RFC 5109 7.2: the marker SHALL be 0");
    assert_eq!(65535, first.header.sequence_number);
    assert_eq!(
        0, second.header.sequence_number,
        "one higher than the previous FEC packet"
    );
    assert_eq!(
        9000, first.header.timestamp,
        "the media clock when it is sent"
    );
    assert_eq!(12_000, second.header.timestamp);
    let fec = UlpfecPacket::parse(&first.payload).unwrap();
    assert_eq!(10, fec.sn_base);
}

#[test]
fn a_separate_fec_stream_rebuilds_a_lost_packet_and_is_not_delivered() {
    let packets = rfc_packets();
    for lost in 0..4 {
        let (mut sender, mut receiver) = stream_chains(4);
        let now = Instant::now();
        let mut wire = send(&mut sender, now, &packets[..4]);
        wire.remove(lost);
        let delivered = receive(&mut receiver, now, &wire);

        assert_eq!(
            4,
            delivered.len(),
            "three arrived and one rebuilt; no FEC packet"
        );
        assert!(
            delivered
                .iter()
                .all(|m| rtp_of(m).header.ssrc == MEDIA_SSRC)
        );
        let recovered: Vec<_> = delivered
            .iter()
            .filter(|m| m.has(&Attribute::RecoveredByFec))
            .collect();
        assert_eq!(1, recovered.len());
        assert_same_packet(&packets[lost], rtp_of(recovered[0]));
    }
}

#[test]
fn a_stream_without_a_repair_ssrc_is_not_protected_as_a_separate_stream() {
    let mut sender = Registry::new()
        .with(
            Slot::FecEncoder,
            UlpfecSendBuilder::stream()
                .with_num_media_packets(1)
                .build(),
        )
        .build();
    sender.bind_local_stream(&stream_info("video/VP8", false));
    let wire = send(&mut sender, Instant::now(), &[media(1, 0, false, 10)]);
    assert_eq!(1, wire.len());
}

#[test]
fn a_packet_on_the_repair_ssrc_with_another_payload_type_is_not_fec() {
    let (mut sender, mut receiver) = stream_chains(2);
    let now = Instant::now();
    let packets = vec![media(1, 0, false, 30), media(2, 0, false, 30)];
    let mut wire = send(&mut sender, now, &packets);
    wire.remove(0);
    wire[1].header.payload_type = 99;
    let delivered = receive(&mut receiver, now, &wire);
    assert_eq!(1, delivered.len(), "consumed, and nothing rebuilt from it");
}

// --- The RED reader, as a peer reaches it ---

#[test]
fn the_red_reader_refuses_headers_that_overrun_the_payload() {
    assert!(depacketize_red_for_ulpfec(&[], FEC_PT).is_err());
    assert!(depacketize_red_for_ulpfec(&[0x80 | FEC_PT, 0, 0, 9, MEDIA_PT, 1], FEC_PT).is_err());
    let parsed = depacketize_red_for_ulpfec(&[MEDIA_PT, 1, 2, 3], FEC_PT).unwrap();
    assert_eq!(
        Some((MEDIA_PT, Bytes::from_static(&[1, 2, 3]))),
        parsed.primary
    );
    assert!(parsed.fec.is_empty());
}

/// The input the `ulpfec_receive` fuzz target stopped on (bytes `0a 0a`): an empty packet with
/// the FEC payload type on an SSRC the RED-carriage receiver was never bound with. In the RED
/// carriage FEC shares the media SSRC, so that SSRC is a stranger's: the packet is not FEC to
/// this receiver, is not given to its decoder, and passes on exactly as it arrived. (The target
/// asserted that only media-SSRC packets come out; the assertion was wrong, not the receiver.)
#[test]
fn a_packet_on_an_ssrc_the_red_receiver_does_not_know_passes_through_untouched() {
    let now = Instant::now();
    let mut receiver =
        red_receiver(UlpfecReceiveBuilder::red(RED_PT, FEC_PT).with_repair_forwarding(false));

    let stranger = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: FEC_PT,
            sequence_number: 2560,
            timestamp: 2560 * 3000,
            ssrc: FEC_SSRC,
            ..Default::default()
        },
        payload: Bytes::new(),
    };
    let delivered = receive(&mut receiver, now, std::slice::from_ref(&stranger));

    assert_eq!(1, delivered.len());
    assert_eq!(&stranger, rtp_of(&delivered[0]));
    assert!(!delivered[0].has(&Attribute::RecoveredByFec));
}

/// RFC 5109 section 14 ("indicated out of band") with RFC 5956 section 4.3: a remote stream
/// whose signalled repair flow (`a=ssrc-group:FEC-FR`) has the `ulpfec` format is a separate
/// FEC stream, even for a receiver built for the RED carriage (the default set's); a repair
/// flow of another format (FlexFEC) is left to its own decoder.
#[test]
fn a_ulpfec_repair_flow_the_signalling_groups_is_decoded_as_a_separate_stream() {
    let (mut sender, _) = stream_chains(2);
    let start = Instant::now();
    let wire = send(
        &mut sender,
        start,
        &[media(10, 9000, false, 20), media(11, 9000, true, 20)],
    );
    assert_eq!(3, wire.len(), "two media packets and one FEC packet");

    let receiver_for = |mime_type_fec: &str| {
        let mut receiver = Registry::new()
            .with(
                Slot::FecDecoder,
                UlpfecReceiveBuilder::red(RED_PT, FEC_PT).build(),
            )
            .build();
        let mut info = stream_info("video/VP8", true);
        info.mime_type_fec = mime_type_fec.to_owned();
        receiver.bind_remote_stream(&info);
        receiver
    };

    // Packet 11 is lost.
    let arrived = [wire[0].clone(), wire[2].clone()];
    let mut receiver = receiver_for("video/ulpfec");
    let delivered = receive(&mut receiver, start, &arrived);
    let sequence_numbers: Vec<u16> = delivered
        .iter()
        .map(|m| rtp_of(m).header.sequence_number)
        .collect();
    assert_eq!(
        vec![10, 11],
        sequence_numbers,
        "11 rebuilt; the FEC packet swallowed"
    );
    assert!(delivered[1].has(&Attribute::RecoveredByFec));

    let mut receiver = receiver_for("video/flexfec-03");
    let delivered = receive(&mut receiver, start, &arrived);
    assert_eq!(
        2,
        delivered.len(),
        "not ULPFEC: the repair flow passes untouched"
    );
    assert!(delivered.iter().all(|m| !m.has(&Attribute::RecoveredByFec)));
}
