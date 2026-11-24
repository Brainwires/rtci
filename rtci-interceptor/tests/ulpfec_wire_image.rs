//! ULPFEC over the packets as sent (RFC 5109 section 8), with a TWCC sender in the chain.
//!
//! The TWCC sender sits below the FEC encoder and writes the transport-wide sequence number into
//! every packet, adding the header extension when the packet has none. The encoder reads the
//! media from the wire-image tap below it, so what it protects is what the receiver XORs. In RED
//! carriage the FEC packets also take sequence numbers of the media stream; those are set aside
//! as the media passes the encoder and filled when the FEC is computed, so the stream on the wire
//! has no gap and no duplicate.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, PacerBuilder, Packet, RTCPFeedback,
    RTPHeaderExtension, RedPlacement, Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder,
    UlpfecReceiveBuilder, UlpfecSendBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, Unmarshal};
use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;

const MEDIA_SSRC: u32 = 0x1111_1111;
const FEC_SSRC: u32 = 0x2222_2222;
const MEDIA_PT: u8 = 96;
const RED_PT: u8 = 116;
const FEC_PT: u8 = 117;

/// The RED carriage with FEC in RED packets of its own (libwebrtc's form), which most of these
/// tests are about. The builder's default is the form of RFC 5109 14.2 (FEC with the next media
/// packet); tests of that say so with `with_red_placement`.
fn red_builder() -> UlpfecSendBuilder {
    UlpfecSendBuilder::red(RED_PT, FEC_PT).with_red_placement(RedPlacement::OwnPacket)
}

fn stream(separate_fec: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: separate_fec.then_some(FEC_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: separate_fec.then_some(FEC_PT),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

/// A media packet as the application writes it: no header extension, a size of its own.
fn media(sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: sequence_number % 5 == 4,
            payload_type: MEDIA_PT,
            sequence_number,
            timestamp: 90_000 + u32::from(sequence_number) * 3_000,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: Bytes::from(
            (0..(30 + usize::from(sequence_number % 7) * 11))
                .map(|index| (index as u8).wrapping_mul(sequence_number as u8 | 1))
                .collect::<Vec<u8>>(),
        ),
    }
}

fn tagged(now: Instant, packet: rtp::Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

fn wire_bytes(packet: &rtp::Packet) -> Vec<u8> {
    packet.marshal().expect("marshal").to_vec()
}

fn transport_sequence(packet: &rtp::Packet) -> Option<u16> {
    let data = packet.header.get_extension(TWCC_ID)?;
    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut data.as_ref())
        .ok()
        .map(|extension| extension.transport_sequence)
}

/// The sender chain: ULPFEC encoder with its wire tap, a TWCC sender between the two.
fn sender(builder: UlpfecSendBuilder, separate_fec: bool) -> impl Interceptor {
    let mut fec = builder.build();
    let tap = fec.wire_tap();
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::FecWireImage, tap)
        .build();
    chain.bind_local_stream(&stream(separate_fec));
    chain
}

/// Write `count` media packets from sequence number `first`, one per call, and return what left.
fn send(chain: &mut impl Interceptor, first: u16, count: u16) -> Vec<rtp::Packet> {
    let now = Instant::now();
    let mut wire = Vec::new();
    for offset in 0..count {
        chain
            .handle_write(tagged(now, media(first.wrapping_add(offset))))
            .expect("write");
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = packet.message.packet {
                wire.push(rtp);
            }
        }
    }
    wire
}

/// What a receive chain delivers for `wire`: every media packet, with whether FEC rebuilt it.
fn receive(
    builder: UlpfecReceiveBuilder,
    separate_fec: bool,
    wire: &[rtp::Packet],
) -> Vec<(rtp::Packet, bool)> {
    let mut chain = Registry::new()
        .with(Slot::FecDecoder, builder.build())
        .build();
    chain.bind_remote_stream(&stream(separate_fec));
    let now = Instant::now();
    let mut delivered = Vec::new();
    for packet in wire {
        chain
            .handle_read(tagged(now, packet.clone()))
            .expect("read");
        while let Some(out) = chain.poll_read() {
            let recovered = out.message.has(&Attribute::RecoveredByFec);
            if let Packet::Rtp(rtp) = out.message.packet
                && rtp.header.ssrc == MEDIA_SSRC
                && rtp.header.payload_type == MEDIA_PT
            {
                delivered.push((rtp, recovered));
            }
        }
    }
    delivered
}

/// Drop each media packet in turn and check FEC rebuilds it exactly as the receiver has it when
/// nothing is lost: the packet that left, header extension included.
fn every_single_loss_is_rebuilt_as_sent(
    wire: &[rtp::Packet],
    receiver: impl Fn() -> UlpfecReceiveBuilder,
    separate_fec: bool,
    is_media: impl Fn(&rtp::Packet) -> bool,
) {
    let intact = receive(receiver(), separate_fec, wire);
    assert!(intact.iter().all(|(_, recovered)| !recovered));
    assert!(
        intact
            .iter()
            .all(|(packet, _)| transport_sequence(packet).is_some()),
        "the TWCC sender numbered every media packet below the encoder"
    );

    let media_positions: Vec<usize> = wire
        .iter()
        .enumerate()
        .filter(|(_, packet)| is_media(packet))
        .map(|(position, _)| position)
        .collect();
    assert_eq!(intact.len(), media_positions.len());

    for (index, lost) in media_positions.iter().enumerate() {
        let arriving: Vec<rtp::Packet> = wire
            .iter()
            .enumerate()
            .filter(|(position, _)| position != lost)
            .map(|(_, packet)| packet.clone())
            .collect();
        let delivered = receive(receiver(), separate_fec, &arriving);
        let rebuilt: Vec<&rtp::Packet> = delivered
            .iter()
            .filter(|(_, recovered)| *recovered)
            .map(|(packet, _)| packet)
            .collect();
        assert_eq!(1, rebuilt.len(), "media packet {index} was not rebuilt");
        assert_eq!(
            wire_bytes(&intact[index].0),
            wire_bytes(rebuilt[0]),
            "media packet {index} came back different from the packet that left"
        );
    }
}

/// RED carriage, FEC in packets of its own (the form browsers send).
#[test]
fn red_fec_in_its_own_packets_rebuilds_the_packet_as_sent_under_twcc() {
    let mut chain = sender(
        red_builder()
            .with_num_media_packets(5)
            .with_num_fec_packets(1),
        false,
    );
    // Two blocks of five and their FEC packets; an eleventh media packet follows them.
    let wire = send(&mut chain, 100, 11);
    assert_eq!(13, wire.len());
    let block: Vec<rtp::Packet> = wire[..12].to_vec();

    every_single_loss_is_rebuilt_as_sent(
        &block,
        || UlpfecReceiveBuilder::red(RED_PT, FEC_PT),
        false,
        |packet| {
            // A RED packet whose primary block is media: more than the one-octet FEC-only header.
            packet
                .payload
                .first()
                .is_some_and(|first| first & 0x7F == MEDIA_PT)
        },
    );
}

/// RED carriage, FEC as a redundant block of the next media packet (RFC 5109 section 14.2).
#[test]
fn red_fec_riding_with_the_next_media_packet_rebuilds_the_packet_as_sent_under_twcc() {
    let mut chain = sender(
        red_builder()
            .with_red_placement(RedPlacement::WithNextMedia)
            .with_num_media_packets(5)
            .with_num_fec_packets(1),
        false,
    );
    // Ten media packets in two blocks; the FEC of the second rides with the twelfth packet.
    let wire = send(&mut chain, 100, 12);

    let intact = receive(UlpfecReceiveBuilder::red(RED_PT, FEC_PT), false, &wire);
    assert_eq!(12, intact.len());
    for lost in 0..10usize {
        let arriving: Vec<rtp::Packet> = wire
            .iter()
            .enumerate()
            .filter(|(position, _)| *position != lost)
            .map(|(_, packet)| packet.clone())
            .collect();
        let delivered = receive(UlpfecReceiveBuilder::red(RED_PT, FEC_PT), false, &arriving);
        let rebuilt: Vec<&rtp::Packet> = delivered
            .iter()
            .filter(|(_, recovered)| *recovered)
            .map(|(packet, _)| packet)
            .collect();
        assert_eq!(1, rebuilt.len(), "media packet {lost} was not rebuilt");
        assert_eq!(wire_bytes(&intact[lost].0), wire_bytes(rebuilt[0]));
        assert!(transport_sequence(rebuilt[0]).is_some());
    }
}

/// FEC as a stream of its own.
#[test]
fn a_separate_fec_stream_rebuilds_the_packet_as_sent_under_twcc() {
    let mut chain = sender(
        UlpfecSendBuilder::stream()
            .with_num_media_packets(5)
            .with_num_fec_packets(1),
        true,
    );
    let wire = send(&mut chain, 65_530, 11);
    let fec: Vec<&rtp::Packet> = wire
        .iter()
        .filter(|packet| packet.header.ssrc == FEC_SSRC)
        .collect();
    assert_eq!(2, fec.len(), "one FEC packet per block of five");
    assert!(
        fec.iter()
            .all(|packet| transport_sequence(packet).is_some()),
        "the FEC packets passed the TWCC sender too"
    );

    // The media of the two blocks and their FEC; the eleventh packet only flushed the second.
    let block: Vec<rtp::Packet> = wire
        .iter()
        .filter(|packet| {
            packet.header.ssrc == FEC_SSRC
                || packet.header.sequence_number.wrapping_sub(65_530) < 10
        })
        .cloned()
        .collect();
    every_single_loss_is_rebuilt_as_sent(&block, UlpfecReceiveBuilder::stream, true, |packet| {
        packet.header.ssrc == MEDIA_SSRC
    });
}

/// In RED carriage with FEC in its own packets, FEC takes sequence numbers of the media stream.
/// Whatever the timing, each sequence number is on the wire exactly once: no gap, no duplicate,
/// across the wrap at 65535.
#[test]
fn the_media_stream_has_no_gap_and_no_duplicate_sequence_number_on_the_wire() {
    let mut chain = sender(
        red_builder()
            .with_num_media_packets(5)
            .with_num_fec_packets(2),
        false,
    );
    let wire = send(&mut chain, 65_500, 101);

    // 100 media packets in 20 blocks with 2 FEC packets each, and the 101st media packet.
    let first = wire[0].header.sequence_number;
    let offsets: Vec<u16> = wire
        .iter()
        .filter(|packet| packet.header.ssrc == MEDIA_SSRC)
        .map(|packet| packet.header.sequence_number.wrapping_sub(first))
        .collect();
    let distinct: BTreeSet<u16> = offsets.iter().copied().collect();
    assert_eq!(
        offsets.len(),
        distinct.len(),
        "a sequence number was used twice"
    );
    assert_eq!(141, offsets.len());
    assert_eq!(
        (0..141).collect::<BTreeSet<u16>>(),
        distinct,
        "a sequence number was skipped"
    );
}

/// The same with a pacer between the encoder and the wire: media queues behind the budget, so a
/// block's FEC is computed while later media, already numbered past the FEC's reserved sequence
/// numbers, is still waiting. The FEC leaves later than its number says; nothing is skipped or
/// repeated, and every loss is still rebuilt.
#[test]
fn a_pacer_between_encoder_and_wire_reorders_fec_but_leaves_no_gap() {
    let mut fec = red_builder()
        .with_num_media_packets(5)
        .with_num_fec_packets(1)
        .build();
    let tap = fec.wire_tap();
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(
            Slot::Pacer,
            // Every packet queues, as when the budget is already spent: the case this test
            // is about. (By default a packet inside the budget leaves as it is written.)
            PacerBuilder::new()
                .with_target_bitrate(400_000.0)
                .with_immediate_release(false)
                .build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::FecWireImage, tap)
        .build();
    chain.bind_local_stream(&stream(false));

    // Twenty media packets handed over at once, then the clock runs.
    let epoch = Instant::now();
    for offset in 0..20u16 {
        chain
            .handle_write(tagged(epoch, media(500 + offset)))
            .expect("write");
    }
    let mut wire: VecDeque<rtp::Packet> = VecDeque::new();
    for step in 0..2_000u64 {
        chain
            .handle_timeout(epoch + Duration::from_millis(step))
            .expect("timeout");
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = packet.message.packet {
                wire.push_back(rtp);
            }
        }
    }
    let wire: Vec<rtp::Packet> = wire.into();

    let numbers: Vec<u16> = wire
        .iter()
        .map(|packet| packet.header.sequence_number)
        .collect();
    let distinct: BTreeSet<u16> = numbers.iter().copied().collect();
    assert_eq!(
        numbers.len(),
        distinct.len(),
        "a sequence number was used twice"
    );
    assert_eq!(
        (500..524).collect::<BTreeSet<u16>>(),
        distinct,
        "20 media and 4 FEC"
    );
    assert!(
        numbers.windows(2).any(|pair| pair[1] < pair[0]),
        "with the media queued in the pacer the FEC is expected to leave late: {numbers:?}"
    );

    every_single_loss_is_rebuilt_as_sent(
        &wire,
        || UlpfecReceiveBuilder::red(RED_PT, FEC_PT),
        false,
        |packet| {
            packet
                .payload
                .first()
                .is_some_and(|first| first & 0x7F == MEDIA_PT)
        },
    );
}

/// Drops outgoing RTP with the given sequence numbers, between the encoder and the wire tap.
struct DropOnTheWay {
    drop: Vec<u16>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for DropOnTheWay {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message.packet
            && self.drop.contains(&rtp.header.sequence_number)
        {
            return Ok(());
        }
        self.write_queue.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for DropOnTheWay {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// A media packet that never reaches the wire (a full pacer queue, a circuit breaker) must not
/// leave the encoder waiting for it: the block is closed with what did leave, its reserved
/// sequence number is still used, and the blocks after it are protected as usual.
#[test]
fn a_media_packet_dropped_before_the_wire_does_not_stall_the_encoder() {
    let mut fec = red_builder()
        .with_num_media_packets(5)
        .with_num_fec_packets(1)
        .build();
    let tap = fec.wire_tap();
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(
            Slot::from(3_500),
            // The last packet of the first block, and one in the middle of the second.
            DropOnTheWay {
                drop: vec![204, 208],
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::FecWireImage, tap)
        .build();
    chain.bind_local_stream(&stream(false));

    let wire = send(&mut chain, 200, 16);
    let numbers: BTreeSet<u16> = wire
        .iter()
        .map(|packet| packet.header.sequence_number)
        .collect();
    // 16 media and 3 FEC numbered 200..219, less the two that were dropped on the way.
    let expected: BTreeSet<u16> = (200..219).filter(|n| *n != 204 && *n != 208).collect();
    assert_eq!(expected, numbers);

    // The third block (wire 212..=216, FEC 217) is whole: a loss in it is rebuilt.
    let arriving: Vec<rtp::Packet> = wire
        .iter()
        .filter(|packet| packet.header.sequence_number != 214)
        .cloned()
        .collect();
    let delivered = receive(UlpfecReceiveBuilder::red(RED_PT, FEC_PT), false, &arriving);
    assert_eq!(
        vec![214],
        delivered
            .iter()
            .filter(|(_, recovered)| *recovered)
            .map(|(packet, _)| packet.header.sequence_number)
            .collect::<Vec<_>>()
    );
}
