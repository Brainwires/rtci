//! The RFC 8627 FlexFEC interceptors (`flexfec`): what binds them, what they put on the wire,
//! and a sender chain feeding a receiver chain across scripted loss.
//!
//! Section numbers are RFC 8627's.

use rtci_interceptor::{
    Attribute, AttributedPacket, FlexFec03ReceiveBuilder, FlexFec03SendBuilder, FlexFecHeader,
    FlexFecProtection, FlexFecReceiveBuilder, FlexFecSendBuilder, Interceptor, Packet, Registry,
    Slot, StreamInfo, TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, MarshalSize};
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 1000;
const REPAIR_SSRC: u32 = 2000;
const MEDIA_PT: u8 = 96;
const REPAIR_PT: u8 = 98;

fn stream(mime_type_fec: &str, fmtp: &str) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: Some(REPAIR_PT),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        mime_type_fec: mime_type_fec.to_owned(),
        sdp_fmtp_line_fec: fmtp.to_owned(),
        ..Default::default()
    }
}

fn media(ssrc: u32, sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: sequence_number.is_multiple_of(5),
            payload_type: MEDIA_PT,
            sequence_number,
            timestamp: u32::from(sequence_number) * 3000,
            ssrc,
            ..Default::default()
        },
        payload: (0..=(sequence_number % 9) as u8)
            .collect::<Vec<u8>>()
            .into(),
    }
}

fn bytes_of(packet: &rtp::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    packet.marshal_to(&mut buffer).expect("marshal");
    buffer
}

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

/// A chain with one FEC send interceptor, driven at chosen instants.
struct Sender {
    chain: Box<dyn Interceptor>,
    epoch: Instant,
}

impl Sender {
    fn new(builder: FlexFecSendBuilder) -> Self {
        Self::with_stream(builder, &stream("video/flexfec", "repair-window=10000000"))
    }

    fn with_stream(builder: FlexFecSendBuilder, info: &StreamInfo) -> Self {
        let mut chain = Registry::new()
            .with(Slot::FecEncoder, builder.build())
            .build();
        chain.bind_local_stream(info);
        Self {
            chain: Box::new(chain),
            epoch: Instant::now(),
        }
    }

    /// Write one media packet at `at`; return everything that left the chain, in order.
    fn send_at(&mut self, at: Duration, packet: rtp::Packet) -> Vec<TaggedPacket> {
        self.chain
            .handle_write(tagged(self.epoch + at, Packet::Rtp(packet)))
            .expect("handle_write");
        self.drain()
    }

    fn send(&mut self, sequence_number: u16) -> Vec<TaggedPacket> {
        self.send_at(Duration::ZERO, media(MEDIA_SSRC, sequence_number))
    }

    fn drain(&mut self) -> Vec<TaggedPacket> {
        let mut out = Vec::new();
        while let Some(packet) = self.chain.poll_write() {
            out.push(packet);
        }
        out
    }
}

fn rtp_of(packet: &TaggedPacket) -> &rtp::Packet {
    match &packet.message.packet {
        Packet::Rtp(packet) => packet,
        _ => panic!("an RTP packet"),
    }
}

fn repair_of(out: &[TaggedPacket]) -> Vec<rtp::Packet> {
    out.iter()
        .map(rtp_of)
        .filter(|packet| packet.header.ssrc == REPAIR_SSRC)
        .cloned()
        .collect()
}

fn shape(protection: FlexFecProtection) -> FlexFecSendBuilder {
    FlexFecSendBuilder::new()
        .with_protection(protection)
        .with_initial_sequence_number(100)
        .with_initial_timestamp(0)
}

// ---------------------------------------------------------------------------------------
// Which coder a stream gets
// ---------------------------------------------------------------------------------------

/// `flexfec` selects the RFC 8627 coder and `flexfec-03` the draft-03 one, each exactly: the two
/// wire formats are not compatible, so neither interceptor may take the other's stream.
#[test]
fn the_fec_mime_type_selects_the_coder() {
    let produces_repair = |chain: &mut dyn Interceptor, info: &StreamInfo| {
        chain.bind_local_stream(info);
        let mut repair = 0;
        for sequence_number in 0..10 {
            chain
                .handle_write(tagged(
                    Instant::now(),
                    Packet::Rtp(media(MEDIA_SSRC, sequence_number)),
                ))
                .expect("handle_write");
            while let Some(out) = chain.poll_write() {
                if rtp_of(&out).header.ssrc == REPAIR_SSRC {
                    repair += 1;
                }
            }
        }
        repair > 0
    };
    let rfc8627 = || {
        Registry::new()
            .with(Slot::FecEncoder, FlexFecSendBuilder::new().build())
            .build()
    };
    let draft03 = || {
        Registry::new()
            .with(Slot::FecEncoder, FlexFec03SendBuilder::new().build())
            .build()
    };

    assert!(produces_repair(
        &mut rfc8627(),
        &stream("video/flexfec", "")
    ));
    assert!(produces_repair(
        &mut rfc8627(),
        &stream("VIDEO/FlexFEC", "")
    ));
    assert!(produces_repair(
        &mut rfc8627(),
        &stream("audio/flexfec", "")
    ));
    assert!(!produces_repair(
        &mut rfc8627(),
        &stream("video/flexfec-03", "")
    ));
    assert!(!produces_repair(
        &mut rfc8627(),
        &stream("video/ulpfec", "")
    ));
    assert!(
        !produces_repair(&mut rfc8627(), &stream("", "")),
        "a stream that does not name its FEC format is not RFC 8627"
    );

    assert!(produces_repair(
        &mut draft03(),
        &stream("video/flexfec-03", "")
    ));
    assert!(
        produces_repair(&mut draft03(), &stream("", "")),
        "unnamed FEC is draft-03, as it was before the field existed"
    );
    assert!(!produces_repair(
        &mut draft03(),
        &stream("video/flexfec", "")
    ));
}

/// The receive side makes the same choice: an RFC 8627 repair packet offered to a chain whose
/// stream negotiated `flexfec-03` recovers nothing through either decoder, and the reverse.
#[test]
fn the_receive_interceptors_follow_the_same_selection() {
    let recovers = |mut chain: Box<dyn Interceptor>, info: &StreamInfo, repair: &rtp::Packet| {
        chain.bind_remote_stream(info);
        let now = Instant::now();
        for sequence_number in [1u16, 2, 4] {
            chain
                .handle_read(tagged(now, Packet::Rtp(media(MEDIA_SSRC, sequence_number))))
                .expect("handle_read");
        }
        chain
            .handle_read(tagged(now, Packet::Rtp(repair.clone())))
            .expect("handle_read");
        let mut recovered = false;
        while let Some(out) = chain.poll_read() {
            recovered |= out.message.has(&Attribute::RecoveredByFec);
        }
        recovered
    };
    let block: Vec<rtp::Packet> = (1..=4).map(|n| media(MEDIA_SSRC, n)).collect();
    let rfc_repair = rtci_interceptor::FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC)
        .encode_block(FlexFecProtection::Row { l: 4 }, &block, 0)
        .remove(0);
    let rfc8627 = || -> Box<dyn Interceptor> {
        Box::new(
            Registry::new()
                .with(Slot::FecDecoder, FlexFecReceiveBuilder::new().build())
                .build(),
        )
    };
    let draft03 = || -> Box<dyn Interceptor> {
        Box::new(
            Registry::new()
                .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
                .build(),
        )
    };

    assert!(recovers(
        rfc8627(),
        &stream("video/flexfec", ""),
        &rfc_repair
    ));
    assert!(!recovers(
        rfc8627(),
        &stream("video/flexfec-03", ""),
        &rfc_repair
    ));
    assert!(!recovers(
        draft03(),
        &stream("video/flexfec", ""),
        &rfc_repair
    ));
}

// ---------------------------------------------------------------------------------------
// The send interceptor
// ---------------------------------------------------------------------------------------

/// Section 4.1: source packets are sent unaltered, and before the repair packets that protect
/// them. Section 4.2.1: the repair packets go on the repair SSRC and payload type, marker 0, the
/// protected stream in the CSRC list, sequence numbers one apart.
#[test]
fn source_packets_pass_unaltered_and_repair_packets_follow_on_their_own_stream() {
    let mut sender = Sender::new(shape(FlexFecProtection::RowAndColumn { l: 2, d: 2 }));

    let mut out = Vec::new();
    for sequence_number in 10..14 {
        let packets = sender.send(sequence_number);
        if sequence_number < 13 {
            assert_eq!(1, packets.len(), "no repair until the block is full");
        }
        out.extend(packets);
    }

    assert_eq!(4 + 4, out.len(), "four sources, two rows and two columns");
    for (index, sequence_number) in (10u16..14).enumerate() {
        assert_eq!(
            bytes_of(&media(MEDIA_SSRC, sequence_number)),
            bytes_of(rtp_of(&out[index])),
            "source {sequence_number} as it was handed over"
        );
    }
    for (index, repair) in repair_of(&out).iter().enumerate() {
        assert_eq!(REPAIR_PT, repair.header.payload_type);
        assert!(!repair.header.marker);
        assert_eq!(vec![MEDIA_SSRC], repair.header.csrc);
        assert_eq!(100 + index as u16, repair.header.sequence_number);
        assert!(matches!(
            FlexFecHeader::parse(&repair.header.csrc, &repair.payload),
            Ok(FlexFecHeader::Repair { .. })
        ));
    }
}

/// Section 4.2.1: the initial sequence number of the repair stream is random.
#[test]
fn the_initial_repair_sequence_number_is_random() {
    let firsts: Vec<u16> = (0..16)
        .map(|_| {
            let mut sender = Sender::new(
                FlexFecSendBuilder::new().with_protection(FlexFecProtection::Row { l: 1 }),
            );
            repair_of(&sender.send(1))[0].header.sequence_number
        })
        .collect();
    assert!(
        firsts.iter().any(|&number| number != firsts[0]),
        "every stream started at {}",
        firsts[0]
    );
}

/// Section 4.2.1: the timestamp is the repair packet's transmission time, on the stream's
/// clock rate, from the instants the packets are written with.
#[test]
fn the_repair_timestamp_is_the_transmission_time() {
    let builder = FlexFecSendBuilder::new()
        .with_protection(FlexFecProtection::Row { l: 2 })
        .with_initial_timestamp(1_000);
    let mut sender = Sender::new(builder);

    let mut timestamps = Vec::new();
    for (sequence_number, at_ms) in [(1u16, 0u64), (2, 5), (3, 40), (4, 45), (5, 2000), (6, 2005)] {
        let out = sender.send_at(
            Duration::from_millis(at_ms),
            media(MEDIA_SSRC, sequence_number),
        );
        timestamps.extend(repair_of(&out).iter().map(|packet| packet.header.timestamp));
    }

    assert_eq!(
        vec![1_000, 1_000 + 40 * 90, 1_000 + 2000 * 90],
        timestamps,
        "90 kHz ticks since the first repair packet, sent at 5 ms"
    );
}

/// Every shape yields its number of repair packets per block, block after block (section 8:
/// the amount of FEC is not increased on the sender's own initiative).
#[test]
fn each_shape_sends_a_fixed_amount_of_fec_per_block() {
    for (protection, block_len, per_block) in [
        (FlexFecProtection::Row { l: 5 }, 5usize, 1usize),
        (FlexFecProtection::Column { l: 3, d: 4 }, 12, 3),
        (FlexFecProtection::RowAndColumn { l: 3, d: 4 }, 12, 7),
        (
            FlexFecProtection::Mask {
                media_packets: 10,
                fec_packets: 3,
            },
            10,
            3,
        ),
    ] {
        assert_eq!(block_len, protection.block_len());
        assert_eq!(per_block, protection.repair_packets_per_block());

        let mut sender = Sender::new(shape(protection));
        let mut counts = Vec::new();
        for sequence_number in 0..(block_len as u16 * 20) {
            let repair = repair_of(&sender.send(sequence_number)).len();
            if (usize::from(sequence_number) + 1).is_multiple_of(block_len) {
                counts.push(repair);
            } else {
                assert_eq!(0, repair, "{protection:?}: mid-block");
            }
        }
        assert_eq!(vec![per_block; 20], counts, "{protection:?}");
    }
}

/// L and D count from one base sequence number, so a block is consecutive packets: after a gap
/// the block starts again at the packet after it.
#[test]
fn a_gap_in_the_sequence_numbers_starts_a_new_block() {
    let mut sender = Sender::new(shape(FlexFecProtection::Row { l: 3 }));

    let mut repair = Vec::new();
    for sequence_number in [1u16, 2, 10, 11, 12] {
        repair.extend(repair_of(&sender.send(sequence_number)));
    }

    assert_eq!(1, repair.len());
    let FlexFecHeader::Repair { blocks, .. } =
        FlexFecHeader::parse(&repair[0].header.csrc, &repair[0].payload).expect("parses")
    else {
        panic!("a parity packet");
    };
    assert_eq!(vec![10, 11, 12], blocks[0].sequence_numbers());
}

/// A retransmission on the media SSRC (a NACK answered without RTX: an answer to an offer
/// with FlexFEC and RTX keeps only FlexFEC, section 1.1.7) that leaves in the middle of a block
/// is not taken into it: the packet was protected when it first left, and its old sequence
/// number would break the run of consecutive source packets the block is. With the wire tap,
/// as the standard chain has it (`configure_video_flexfec`), and without.
#[test]
fn a_retransmission_on_the_media_ssrc_does_not_break_the_block() {
    for with_tap in [true, false] {
        let mut fec = shape(FlexFecProtection::Row { l: 5 }).build();
        let registry = Registry::new();
        let registry = if with_tap {
            let tap = fec.wire_tap();
            registry.with(Slot::FecWireImage, tap)
        } else {
            registry
        };
        let mut chain = registry.with(Slot::FecEncoder, fec).build();
        chain.bind_local_stream(&stream("video/flexfec", "repair-window=10000000"));
        let epoch = Instant::now();
        let mut out = Vec::new();
        for (sequence_number, retransmission) in [
            (0u16, false),
            (1, false),
            (0, true),
            (2, false),
            (3, false),
            (4, false),
        ] {
            let mut packet = tagged(epoch, Packet::Rtp(media(MEDIA_SSRC, sequence_number)));
            if retransmission {
                packet.message.add(Attribute::Retransmission);
            }
            chain.handle_write(packet).expect("handle_write");
            while let Some(packet) = chain.poll_write() {
                out.push(packet);
            }
        }
        let repair = repair_of(&out);
        assert_eq!(1, repair.len(), "with tap {with_tap}");
        let FlexFecHeader::Repair { blocks, .. } =
            FlexFecHeader::parse(&repair[0].header.csrc, &repair[0].payload).expect("parses")
        else {
            panic!("a parity packet");
        };
        assert_eq!(
            vec![0, 1, 2, 3, 4],
            blocks[0].sequence_numbers(),
            "with tap {with_tap}"
        );
    }
}

/// Section 1.1.8: repair packets reaching beyond the repair window MUST NOT be sent. A block
/// whose first packet left longer ago than the window gets no repair packets.
#[test]
fn a_block_that_outlasts_the_repair_window_is_not_protected() {
    let builder =
        shape(FlexFecProtection::Row { l: 3 }).with_repair_window(Duration::from_millis(50));
    let mut sender = Sender::new(builder);

    let mut send = |sequence_number: u16, at_ms: u64| {
        repair_of(&sender.send_at(
            Duration::from_millis(at_ms),
            media(MEDIA_SSRC, sequence_number),
        ))
        .len()
    };
    // 0, 20, 50 ms: the block spans exactly the window.
    assert_eq!(0, send(1, 0) + send(2, 20));
    assert_eq!(1, send(3, 50));
    // 100, 120, 151 ms: one millisecond over.
    assert_eq!(0, send(4, 100) + send(5, 120));
    assert_eq!(0, send(6, 151), "51 ms after its first packet");
    // The next block is judged on its own.
    assert_eq!(0, send(7, 200) + send(8, 210));
    assert_eq!(1, send(9, 220));
}

/// Section 5.1: the negotiated `repair-window` bounds the sender; the builder's can narrow it,
/// not widen it.
#[test]
fn the_negotiated_repair_window_bounds_the_sender() {
    let window_of = |builder: FlexFecSendBuilder, fmtp: &str| {
        let mut interceptor = builder.build();
        interceptor.bind_local_stream(&stream("video/flexfec", fmtp));
        interceptor.repair_window(MEDIA_SSRC).expect("bound")
    };

    assert_eq!(
        Duration::from_millis(200),
        window_of(FlexFecSendBuilder::new(), "repair-window=200000"),
        "the 200 ms of RFC 8627 section 7.1"
    );
    assert_eq!(
        Duration::from_millis(50),
        window_of(
            FlexFecSendBuilder::new().with_repair_window(Duration::from_millis(50)),
            "repair-window=200000"
        )
    );
    assert_eq!(
        Duration::from_millis(200),
        window_of(
            FlexFecSendBuilder::new().with_repair_window(Duration::from_secs(60)),
            "repair-window=200000"
        ),
        "never beyond what was negotiated"
    );
    assert_eq!(
        Duration::from_secs(10),
        window_of(FlexFecSendBuilder::new(), ""),
        "none signalled: the builder's default"
    );
}

/// Unbinding stops protection, and a stream bound without a repair association is left alone.
#[test]
fn only_bound_streams_are_protected() {
    let mut sender = Sender::new(shape(FlexFecProtection::Row { l: 1 }));
    assert_eq!(1, repair_of(&sender.send(1)).len());

    let other = sender.send_at(Duration::ZERO, media(4242, 1));
    assert_eq!(1, other.len(), "an unbound stream passes through");

    sender
        .chain
        .unbind_local_stream(&stream("video/flexfec", "repair-window=10000000"));
    assert_eq!(1, sender.send(2).len(), "only the source packet");

    let mut half = stream("video/flexfec", "");
    half.ssrc_fec = None;
    let mut sender = Sender::with_stream(shape(FlexFecProtection::Row { l: 1 }), &half);
    assert_eq!(1, sender.send(1).len(), "no repair SSRC, no repair stream");
}

/// Section 4.2.2.3: "a single repair packet stream (SSRC) MAY be used for [...] multiple source
/// packet streams". Two source streams bound with the same repair SSRC share one repair stream:
/// one sequence-number space, each repair packet naming its own source in the CSRC list.
#[test]
fn two_source_streams_share_one_repair_stream() {
    const SECOND_SSRC: u32 = 1001;
    let mut sender = Sender::new(shape(FlexFecProtection::Row { l: 2 }));
    let mut second = stream("video/flexfec", "repair-window=10000000");
    second.ssrc = SECOND_SSRC;
    sender.chain.bind_local_stream(&second);

    let mut repair = Vec::new();
    for (ssrc, sequence_number) in [
        (MEDIA_SSRC, 1u16),
        (SECOND_SSRC, 500),
        (MEDIA_SSRC, 2),
        (SECOND_SSRC, 501),
        (SECOND_SSRC, 502),
        (SECOND_SSRC, 503),
    ] {
        let out = sender.send_at(Duration::ZERO, media(ssrc, sequence_number));
        repair.extend(repair_of(&out));
    }

    assert_eq!(
        vec![
            (100, vec![MEDIA_SSRC]),
            (101, vec![SECOND_SSRC]),
            (102, vec![SECOND_SSRC])
        ],
        repair
            .iter()
            .map(|packet| (packet.header.sequence_number, packet.header.csrc.clone()))
            .collect::<Vec<_>>()
    );

    // Unbinding one leaves the other protected, on the same repair stream.
    sender.chain.unbind_local_stream(&second);
    sender.send(3);
    let out = sender.send(4);
    assert_eq!(103, repair_of(&out)[0].header.sequence_number);
}

fn nack(sequence_numbers: &[u16]) -> Packet {
    Packet::Rtcp(vec![Box::new(
        rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: MEDIA_SSRC,
            nacks:
                rtcp::transport_feedbacks::transport_layer_nack::nack_pairs_from_sequence_numbers(
                    sequence_numbers,
                ),
        },
    )])
}

/// Section 4.2.2.3: with retransmissions on, a NACK is answered on the repair stream with
/// R=1 packets carrying the source packet whole. Off (the default), the NACK is left to
/// whatever else answers NACKs.
#[test]
fn a_nack_is_answered_with_a_flexfec_retransmission_when_enabled() {
    let builder = shape(FlexFecProtection::Row { l: 4 }).with_retransmissions(true);
    let mut sender = Sender::new(builder);
    for sequence_number in 1..=3 {
        sender.send(sequence_number);
    }

    sender
        .chain
        .handle_read(tagged(sender.epoch, nack(&[2, 3, 77])))
        .expect("handle_read");
    let out = sender.drain();

    assert_eq!(2, out.len(), "2 and 3; 77 was never sent");
    for (packet, sequence_number) in out.iter().zip([2u16, 3]) {
        assert!(packet.message.has(&Attribute::Retransmission));
        let repair = rtp_of(packet);
        assert_eq!(
            (REPAIR_SSRC, REPAIR_PT),
            (repair.header.ssrc, repair.header.payload_type)
        );
        assert_eq!(
            Ok(FlexFecHeader::Retransmission),
            FlexFecHeader::parse(&repair.header.csrc, &repair.payload)
        );
        assert_eq!(
            bytes_of(&media(MEDIA_SSRC, sequence_number)).as_slice(),
            &repair.payload[..],
            "the source packet, RTP header and all"
        );
    }

    // The same request again at once is not answered twice.
    sender
        .chain
        .handle_read(tagged(sender.epoch, nack(&[2])))
        .expect("handle_read");
    assert!(sender.drain().is_empty());

    // The interceptor reads the NACK and passes it on; it does not consume it.
    let mut interceptor = shape(FlexFecProtection::Row { l: 4 })
        .with_retransmissions(true)
        .build();
    interceptor.bind_local_stream(&stream("video/flexfec", ""));
    interceptor
        .handle_read(tagged(Instant::now(), nack(&[2])))
        .expect("handle_read");
    assert!(matches!(
        interceptor.poll_read().map(|out| out.message.packet),
        Some(Packet::Rtcp(_))
    ));

    // Off by default.
    let mut plain = Sender::new(shape(FlexFecProtection::Row { l: 4 }));
    plain.send(1);
    plain
        .chain
        .handle_read(tagged(plain.epoch, nack(&[1])))
        .expect("handle_read");
    assert!(plain.drain().is_empty());
}

/// Section 1.1.8: the receiver accepts retransmissions within the repair window; the sender
/// sends none for a packet older than it.
#[test]
fn a_packet_older_than_the_repair_window_is_not_retransmitted() {
    let builder = shape(FlexFecProtection::Row { l: 200 })
        .with_retransmissions(true)
        .with_repair_window(Duration::from_millis(100));
    let mut sender = Sender::new(builder);
    sender.send_at(Duration::ZERO, media(MEDIA_SSRC, 1));
    sender.send_at(Duration::from_millis(60), media(MEDIA_SSRC, 2));

    sender
        .chain
        .handle_read(tagged(
            sender.epoch + Duration::from_millis(101),
            nack(&[1, 2]),
        ))
        .expect("handle_read");
    let out = sender.drain();

    assert_eq!(1, out.len());
    assert_eq!(
        2,
        u16::from_be_bytes([rtp_of(&out[0]).payload[2], rtp_of(&out[0]).payload[3]])
    );
}

// ---------------------------------------------------------------------------------------
// Sender to receiver
// ---------------------------------------------------------------------------------------

struct Receiver {
    chain: Box<dyn Interceptor>,
    now: Instant,
}

impl Receiver {
    fn new(builder: FlexFecReceiveBuilder, info: &StreamInfo) -> Self {
        let mut chain = Registry::new()
            .with(Slot::FecDecoder, builder.build())
            .build();
        chain.bind_remote_stream(info);
        Self {
            chain: Box::new(chain),
            now: Instant::now(),
        }
    }

    /// Deliver one packet; return what came out of the chain.
    fn receive(&mut self, packet: rtp::Packet) -> Vec<TaggedPacket> {
        self.chain
            .handle_read(tagged(self.now, Packet::Rtp(packet)))
            .expect("handle_read");
        let mut out = Vec::new();
        while let Some(packet) = self.chain.poll_read() {
            out.push(packet);
        }
        out
    }
}

/// The whole path: a sender chain protects twelve packets in 2-D, the wire drops four of them
/// in the pattern of RFC 8627 Figure 16, and the receiver chain hands the application all
/// twelve, the four rebuilt ones tagged as recovered and byte-identical to what was sent. No
/// repair packet reaches the application.
#[test]
fn media_lost_on_the_wire_is_recovered_end_to_end() {
    let info = stream("video/flexfec", "repair-window=200000");
    let mut sender =
        Sender::with_stream(shape(FlexFecProtection::RowAndColumn { l: 4, d: 3 }), &info);
    let mut receiver = Receiver::new(FlexFecReceiveBuilder::new(), &info);

    let mut wire = Vec::new();
    for sequence_number in 1..=12 {
        wire.extend(sender.send(sequence_number));
    }
    assert_eq!(12 + 7, wire.len());

    let mut delivered = Vec::new();
    for packet in &wire {
        let packet = rtp_of(packet).clone();
        let lost = packet.header.ssrc == MEDIA_SSRC
            && [1u16, 2, 10, 11].contains(&packet.header.sequence_number);
        if !lost {
            delivered.extend(receiver.receive(packet));
        }
    }

    assert!(
        delivered
            .iter()
            .all(|packet| rtp_of(packet).header.ssrc == MEDIA_SSRC),
        "repair packets are consumed"
    );
    let mut recovered: Vec<u16> = delivered
        .iter()
        .filter(|packet| packet.message.has(&Attribute::RecoveredByFec))
        .map(|packet| rtp_of(packet).header.sequence_number)
        .collect();
    recovered.sort_unstable();
    assert_eq!(vec![1, 2, 10, 11], recovered);

    let mut all: Vec<&rtp::Packet> = delivered.iter().map(rtp_of).collect();
    all.sort_by_key(|packet| packet.header.sequence_number);
    assert_eq!(12, all.len());
    for (packet, sequence_number) in all.iter().zip(1u16..) {
        assert_eq!(
            bytes_of(&media(MEDIA_SSRC, sequence_number)),
            bytes_of(packet),
            "packet {sequence_number}"
        );
    }
}

/// A FlexFEC retransmission arriving at the receiver chain is delivered as the source packet
/// it carries, tagged as a retransmission.
#[test]
fn a_flexfec_retransmission_is_delivered_as_the_source_packet() {
    let info = stream("video/flexfec", "");
    let mut receiver = Receiver::new(FlexFecReceiveBuilder::new(), &info);
    receiver.receive(media(MEDIA_SSRC, 1));
    receiver.receive(media(MEDIA_SSRC, 3));

    let retransmission = rtci_interceptor::FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC)
        .retransmit(&media(MEDIA_SSRC, 2), 0)
        .expect("retransmits");
    let out = receiver.receive(retransmission);

    assert_eq!(1, out.len());
    assert!(out[0].message.has(&Attribute::Retransmission));
    assert!(!out[0].message.has(&Attribute::RecoveredByFec));
    assert_eq!(bytes_of(&media(MEDIA_SSRC, 2)), bytes_of(rtp_of(&out[0])));
}

/// A packet on the repair SSRC that does not carry the FlexFEC payload type is not a repair
/// packet, and passes through like any other.
#[test]
fn only_the_fec_payload_type_on_the_repair_ssrc_is_consumed() {
    let info = stream("video/flexfec", "");
    let mut receiver = Receiver::new(FlexFecReceiveBuilder::new(), &info);

    let mut stray = media(REPAIR_SSRC, 5);
    stray.header.payload_type = 111;
    assert_eq!(1, receiver.receive(stray).len());

    let mut garbage = media(REPAIR_SSRC, 6);
    garbage.header.payload_type = REPAIR_PT;
    assert!(
        receiver.receive(garbage).is_empty(),
        "consumed, and ignored"
    );
}

/// Section 5.2.1: the receiver must support every configuration within the repair window it
/// agrees to. A window longer than it buffers for is not half supported: the stream is not
/// protected at all.
#[test]
fn a_repair_window_longer_than_the_receiver_supports_is_not_bound() {
    let bound = |max: Duration, fmtp: &str| {
        let mut interceptor = FlexFecReceiveBuilder::new()
            .with_max_repair_window(max)
            .build();
        interceptor.bind_remote_stream(&stream("video/flexfec", fmtp));
        interceptor.protected_streams().count() == 1
    };

    assert!(bound(Duration::from_secs(1), "repair-window=1000000"));
    assert!(!bound(Duration::from_secs(1), "repair-window=1000001"));
    assert!(
        bound(Duration::from_secs(10), ""),
        "none signalled: the 10 s default"
    );
    assert!(
        !bound(Duration::from_secs(1), ""),
        "which is longer than 1 s"
    );
}

/// Section 7.1.1, in-band SSRC mapping: no `FEC-FR` association. A packet with the FlexFEC
/// payload type on an SSRC that is not a media stream is a repair packet, and its CSRC list
/// names the stream it protects.
#[test]
fn in_band_ssrc_mapping_finds_the_source_stream_in_the_csrc_list() {
    let unassociated = StreamInfo {
        ssrc: MEDIA_SSRC,
        payload_type: MEDIA_PT,
        clock_rate: 90_000,
        ..Default::default()
    };
    let block: Vec<rtp::Packet> = (20..24).map(|n| media(MEDIA_SSRC, n)).collect();
    let repair = rtci_interceptor::FlexFecEncoder::new(REPAIR_PT, 0x00C0_FFEE)
        .encode_block(FlexFecProtection::Row { l: 4 }, &block, 0)
        .remove(0);

    let mut receiver = Receiver::new(
        FlexFecReceiveBuilder::new().with_in_band_ssrc_mapping(REPAIR_PT),
        &unassociated,
    );
    for index in [0usize, 1, 3] {
        receiver.receive(block[index].clone());
    }
    let out = receiver.receive(repair.clone());
    assert_eq!(1, out.len());
    assert!(out[0].message.has(&Attribute::RecoveredByFec));
    assert_eq!(bytes_of(&block[2]), bytes_of(rtp_of(&out[0])));

    // Without the option the same packet is no repair packet: it passes through untouched.
    let mut plain = Receiver::new(FlexFecReceiveBuilder::new(), &unassociated);
    for index in [0usize, 1, 3] {
        plain.receive(block[index].clone());
    }
    let out = plain.receive(repair);
    assert_eq!(1, out.len());
    assert_eq!(0x00C0_FFEE, rtp_of(&out[0]).header.ssrc);
}

/// Unbinding a stream drops its protection and its buffers.
#[test]
fn unbinding_a_remote_stream_stops_recovery() {
    let info = stream("video/flexfec", "");
    let block: Vec<rtp::Packet> = (1..=4).map(|n| media(MEDIA_SSRC, n)).collect();
    let repair = rtci_interceptor::FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC)
        .encode_block(FlexFecProtection::Row { l: 4 }, &block, 0)
        .remove(0);

    let mut receiver = Receiver::new(FlexFecReceiveBuilder::new(), &info);
    for index in [0usize, 1, 3] {
        receiver.receive(block[index].clone());
    }
    receiver.chain.unbind_remote_stream(&info);

    let out = receiver.receive(repair);
    assert_eq!(1, out.len(), "no longer a repair stream: it passes through");
    assert!(!out[0].message.has(&Attribute::RecoveredByFec));
}
