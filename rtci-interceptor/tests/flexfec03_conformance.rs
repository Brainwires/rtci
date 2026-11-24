//! FlexFEC draft-03 (`video/flexfec-03`), clause by clause: the rows of
//! `docs/conformance/audit/draft-ietf-payload-flexible-fec-scheme-03.md` that had code and no
//! proof, and the ones the audit found wrong.
//!
//! Section numbers are those of draft-ietf-payload-flexible-fec-scheme-03.

use rtci_interceptor::{
    AttributedPacket, FlexFec03Decoder, FlexFec03Encoder, FlexFec03SendBuilder, Interceptor,
    Packet, Registry, Slot, StreamInfo, TaggedPacket,
};
use shared::TransportContext;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x1122_3344;
const REPAIR_SSRC: u32 = 0x5566_7788;
const MEDIA_PT: u8 = 96;
const REPAIR_PT: u8 = 49;

fn media_packet(sequence_number: u16, payload: &[u8]) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: sequence_number.is_multiple_of(3),
            payload_type: MEDIA_PT,
            sequence_number,
            timestamp: 1_000_000u32.wrapping_add(u32::from(sequence_number) * 3000),
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: payload.to_vec().into(),
    }
}

fn block(first: u16, count: u16) -> Vec<rtp::Packet> {
    (0..count)
        .map(|offset| {
            let payload: Vec<u8> = (0..=offset as u8 % 5).map(|b| b ^ offset as u8).collect();
            media_packet(first.wrapping_add(offset), &payload)
        })
        .collect()
}

fn bytes_of(packet: &rtp::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    packet.marshal_to(&mut buffer).expect("marshal");
    buffer
}

fn encoder() -> FlexFec03Encoder {
    FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC)
}

fn decoder() -> FlexFec03Decoder {
    FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC)
}

/// Feed every media packet but `lost`, then the repair packets; return what was recovered.
fn recover(media: &[rtp::Packet], repair: &[rtp::Packet], lost: &[usize]) -> Vec<rtp::Packet> {
    let mut decoder = decoder();
    let mut recovered = Vec::new();
    for (index, packet) in media.iter().enumerate() {
        if !lost.contains(&index) {
            recovered.extend(decoder.decode(packet.clone()));
        }
    }
    for packet in repair {
        recovered.extend(decoder.decode(packet.clone()));
    }
    recovered
}

/// A repair packet rebuilt with one change to its payload (the FEC header and repair data).
fn with_payload(repair: &rtp::Packet, edit: impl FnOnce(&mut Vec<u8>)) -> rtp::Packet {
    let mut payload = repair.payload.to_vec();
    edit(&mut payload);
    rtp::Packet {
        header: repair.header.clone(),
        payload: payload.into(),
    }
}

// ---------------------------------------------------------------------------------------
// Section 4.2: the repair packet
// ---------------------------------------------------------------------------------------

/// FLEXFEC03-4.2-19. A repair packet describes at most 109 source packets (15 + 31 + 63 mask
/// bits). 110 were accepted: the 110th was XORed into the repair data and not named in the mask,
/// so whatever that repair packet recovered was the lost packet XOR packet 109.
#[test]
fn a_block_of_110_packets_is_refused_and_109_recover() {
    assert!(
        encoder().encode(&block(100, 110), 1, 0).is_empty(),
        "110 packets do not fit a 109-bit mask"
    );

    let media = block(100, 109);
    let repair = encoder().encode(&media, 1, 0);
    assert_eq!(1, repair.len());
    for lost in [0usize, 45, 46, 108] {
        let recovered = recover(&media, &repair, &[lost]);
        assert_eq!(1, recovered.len(), "packet {lost}");
        assert_eq!(
            bytes_of(&media[lost]),
            bytes_of(&recovered[0]),
            "packet {lost}"
        );
    }
}

/// FLEXFEC03-6.2-4. SN base is the lowest sequence number the repair packet itself protects.
/// Every repair packet of a block used to carry the block's first sequence number.
#[test]
fn each_repair_packet_carries_its_own_lowest_sequence_number_as_sn_base() {
    let media = block(4000, 9);
    let repair = encoder().encode(&media, 3, 0);
    assert_eq!(3, repair.len());

    let bases: Vec<u16> = repair
        .iter()
        .map(|packet| u16::from_be_bytes([packet.payload[16], packet.payload[17]]))
        .collect();
    assert_eq!(vec![4000, 4001, 4002], bases);

    // And the receiver still finds every packet: the masks moved with the bases.
    for lost in 0..media.len() {
        let recovered = recover(&media, &repair, &[lost]);
        assert_eq!(1, recovered.len(), "packet {lost}");
        assert_eq!(
            bytes_of(&media[lost]),
            bytes_of(&recovered[0]),
            "packet {lost}"
        );
    }
}

/// FLEXFEC03-4.2-2. The marker bit of a repair packet is 0 although the media's is set.
#[test]
fn a_repair_packet_has_no_marker_bit() {
    let mut media = block(10, 4);
    for packet in &mut media {
        packet.header.marker = true;
    }
    let repair = encoder().encode(&media, 2, 0);
    assert_eq!(2, repair.len());
    for packet in &repair {
        assert_eq!(0, bytes_of(packet)[1] & 0x80);
    }
}

/// FLEXFEC03-4.2-13. SSRCCount 0 is invalid and the packet is ignored; so is any count the
/// decoder cannot honour (it protects one stream per repair packet).
#[test]
fn a_repair_packet_with_ssrc_count_zero_is_ignored() {
    let media = block(100, 4);
    let repair = encoder().encode(&media, 1, 0);

    for count in [0u8, 2] {
        let bad = with_payload(&repair[0], |payload| payload[8] = count);
        let mut decoder = decoder();
        for packet in &media[1..] {
            decoder.decode(packet.clone());
        }
        assert!(decoder.decode(bad).is_empty(), "SSRCCount {count}");
        assert_eq!(0, decoder.pending_repair_packets(), "and it is not kept");
    }

    // The same bytes with the count the encoder wrote do recover: the count is what was refused.
    assert_eq!(1, recover(&media, &repair, &[0]).len());
}

/// FLEXFEC03-4.2-15. The 24 reserved bits after SSRCCount are ignored by a receiver.
#[test]
fn the_reserved_bits_are_ignored_on_receive() {
    let media = block(100, 4);
    let repair = encoder().encode(&media, 1, 0);
    assert_eq!(&[0, 0, 0], &repair[0].payload[9..12], "sent as zero");

    let noisy = with_payload(&repair[0], |payload| {
        payload[9..12].copy_from_slice(&[0xFF, 0xA5, 0x5A])
    });
    let recovered = recover(&media, &[noisy], &[2]);
    assert_eq!(1, recovered.len());
    assert_eq!(bytes_of(&media[2]), bytes_of(&recovered[0]));
}

/// FLEXFEC03-4.2-11 and 4.2-12. Retransmission packets (R = 1) and fixed-offset packets (F = 1)
/// are not implemented: a received one is discarded, never misread as a mask-based repair packet.
#[test]
fn retransmission_and_fixed_offset_repair_packets_are_discarded() {
    let media = block(100, 4);
    let repair = encoder().encode(&media, 1, 0);

    for (name, bit) in [("R", 0x80u8), ("F", 0x40u8), ("R and F", 0xC0u8)] {
        let other = with_payload(&repair[0], |payload| payload[0] |= bit);
        let mut decoder = decoder();
        for packet in &media[1..] {
            decoder.decode(packet.clone());
        }
        assert!(decoder.decode(other).is_empty(), "{name} set");
        assert_eq!(0, decoder.pending_repair_packets(), "{name} set: not kept");
    }
}

// ---------------------------------------------------------------------------------------
// Section 6: protection and recovery
// ---------------------------------------------------------------------------------------

/// A source packet with a CSRC list, a header extension and RTP padding.
fn elaborate_packet(sequence_number: u16) -> rtp::Packet {
    let mut wire = vec![
        0xB2, // V=2, P=1, X=1, CC=2
        0x80 | MEDIA_PT,
    ];
    wire.extend_from_slice(&sequence_number.to_be_bytes());
    wire.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    wire.extend_from_slice(&MEDIA_SSRC.to_be_bytes());
    wire.extend_from_slice(&0x0A0B_0C0Du32.to_be_bytes()); // CSRC 1
    wire.extend_from_slice(&0x1A1B_1C1Du32.to_be_bytes()); // CSRC 2
    wire.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]); // one-byte extensions, one word
    wire.extend_from_slice(&[0x51, 0x12, 0x34, 0x00]); // id 5, two bytes, padding
    wire.extend_from_slice(&[9, 8, 7, 6, 5]); // payload
    wire.extend_from_slice(&[0, 0, 3]); // RTP padding, 3 octets
    let packet = rtp::Packet::unmarshal(&mut wire.as_slice()).expect("a valid packet");
    assert_eq!(
        wire,
        bytes_of(&packet),
        "the packet re-marshals as it arrived"
    );
    packet
}

/// FLEXFEC03-6.2-6 and 6.3.2-2. The CSRC list, the header extension and the padding of a source
/// packet are protected data, and P, X and CC of a lost packet come from the recovered bits.
#[test]
fn a_lost_packet_with_csrcs_an_extension_and_padding_is_recovered_byte_identically() {
    let media = vec![
        media_packet(200, &[1, 2, 3]),
        elaborate_packet(201),
        media_packet(
            202,
            &[
                4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            ],
        ),
    ];
    let repair = encoder().encode(&media, 1, 0);

    // The elaborate packet is the one lost.
    let recovered = recover(&media, &repair, &[1]);
    assert_eq!(1, recovered.len());
    assert_eq!(bytes_of(&media[1]), bytes_of(&recovered[0]));
    assert!(recovered[0].header.padding, "P recovered");
    assert!(recovered[0].header.extension, "X recovered");
    assert_eq!(2, recovered[0].header.csrc.len(), "CC recovered");

    // A plain packet lost beside it: the elaborate one's extra octets are XORed out again.
    let recovered = recover(&media, &repair, &[0]);
    assert_eq!(1, recovered.len());
    assert_eq!(bytes_of(&media[0]), bytes_of(&recovered[0]));
    assert!(!recovered[0].header.padding && !recovered[0].header.extension);
}

/// FLEXFEC03-6.3.4-1. Decoding is iterative: a packet one repair packet recovers is fed back,
/// and completes a second repair packet that was missing two.
#[test]
fn a_recovered_packet_completes_another_repair_packet() {
    let media = block(300, 6); // 300..=305
    let mut encoder = encoder();
    let first = encoder.encode(&media[0..4], 1, 0); // protects 300..=303
    let second = encoder.encode(&media[2..6], 1, 0); // protects 302..=305

    // 301 and 302 are lost. The first repair packet misses two; the second misses only 302.
    let mut decoder = decoder();
    for index in [0usize, 3, 4, 5] {
        assert!(decoder.decode(media[index].clone()).is_empty());
    }
    assert!(
        decoder.decode(first[0].clone()).is_empty(),
        "two losses under one repair packet: nothing yet"
    );
    let mut recovered = decoder.decode(second[0].clone());
    recovered.sort_by_key(|packet| packet.header.sequence_number);

    assert_eq!(
        2,
        recovered.len(),
        "302 from the second, then 301 from the first"
    );
    assert_eq!(bytes_of(&media[1]), bytes_of(&recovered[0]));
    assert_eq!(bytes_of(&media[2]), bytes_of(&recovered[1]));
}

// ---------------------------------------------------------------------------------------
// The send interceptor: sections 4.2 and 8
// ---------------------------------------------------------------------------------------

struct Sender {
    chain: Box<dyn Interceptor>,
    epoch: Instant,
    next_sequence_number: u16,
}

impl Sender {
    fn new(builder: FlexFec03SendBuilder, clock_rate: u32) -> Self {
        let mut chain = Registry::new()
            .with(Slot::FecEncoder, builder.build())
            .build();
        chain.bind_local_stream(&StreamInfo {
            ssrc: MEDIA_SSRC,
            ssrc_fec: Some(REPAIR_SSRC),
            payload_type: MEDIA_PT,
            payload_type_fec: Some(REPAIR_PT),
            clock_rate,
            ..Default::default()
        });
        Self {
            chain: Box::new(chain),
            epoch: Instant::now(),
            next_sequence_number: 7000,
        }
    }

    /// Write one media packet at `at` after the epoch; return the repair packets that left.
    fn send_at(&mut self, at: Duration) -> Vec<rtp::Packet> {
        let packet = media_packet(self.next_sequence_number, &[1, 2, 3, 4]);
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)),
            })
            .expect("handle_write");

        let mut repair = Vec::new();
        while let Some(out) = self.chain.poll_write() {
            if let Packet::Rtp(packet) = out.message.packet
                && packet.header.ssrc == REPAIR_SSRC
            {
                repair.push(packet);
            }
        }
        repair
    }
}

/// FLEXFEC03-4.2-6. The repair timestamp is the transmission time on the repair stream's clock:
/// it advances with the instant the block is sent, at the stream's clock rate, and not with the
/// media timestamps.
#[test]
fn the_repair_timestamp_follows_the_send_clock() {
    let builder = FlexFec03SendBuilder::new()
        .with_num_media_packets(2)
        .with_num_fec_packets(1)
        .with_initial_timestamp(5_000);
    let mut sender = Sender::new(builder, 90_000);

    let mut timestamps = Vec::new();
    for at_ms in [0u64, 10, 20, 30, 1000, 1010] {
        for repair in sender.send_at(Duration::from_millis(at_ms)) {
            timestamps.push(repair.header.timestamp);
        }
    }

    // Blocks complete at 10 ms, 30 ms and 1010 ms; the first repair packet anchors the clock.
    assert_eq!(
        vec![5_000, 5_000 + 20 * 90, 5_000 + 1000 * 90],
        timestamps,
        "90 kHz ticks since the first repair packet"
    );
}

/// The timestamp is modulo 2^32, like every RTP timestamp.
#[test]
fn the_repair_timestamp_wraps() {
    let builder = FlexFec03SendBuilder::new()
        .with_num_media_packets(1)
        .with_num_fec_packets(1)
        .with_initial_timestamp(u32::MAX - 89);
    let mut sender = Sender::new(builder, 90_000);

    let first = sender.send_at(Duration::ZERO);
    let second = sender.send_at(Duration::from_millis(1));
    assert_eq!(u32::MAX - 89, first[0].header.timestamp);
    assert_eq!(
        0, second[0].header.timestamp,
        "90 ticks later, across the wrap"
    );
}

/// FLEXFEC03-4.2-5. The initial sequence number of a repair stream is random; a test pins it
/// through the builder.
#[test]
fn the_initial_repair_sequence_number_is_random_unless_pinned() {
    let shape = || {
        FlexFec03SendBuilder::new()
            .with_num_media_packets(1)
            .with_num_fec_packets(1)
    };

    let mut pinned = Sender::new(shape().with_initial_sequence_number(41_000), 90_000);
    assert_eq!(
        41_000,
        pinned.send_at(Duration::ZERO)[0].header.sequence_number
    );
    assert_eq!(
        41_001,
        pinned.send_at(Duration::ZERO)[0].header.sequence_number
    );

    // Sixteen streams that all start at the same number would be a constant, not a random one
    // (the chance of sixteen equal 16-bit draws is 2^-240).
    let firsts: Vec<u16> = (0..16)
        .map(|_| {
            Sender::new(shape(), 90_000).send_at(Duration::ZERO)[0]
                .header
                .sequence_number
        })
        .collect();
    assert!(
        firsts.iter().any(|&number| number != firsts[0]),
        "every stream started at {}",
        firsts[0]
    );
}

/// FLEXFEC03-8-2. The amount of FEC is never increased on the sender's own initiative: every
/// block yields the configured number of repair packets, however long the stream runs.
#[test]
fn the_amount_of_fec_stays_at_the_configured_ratio() {
    let builder = FlexFec03SendBuilder::new()
        .with_num_media_packets(5)
        .with_num_fec_packets(2);
    let mut sender = Sender::new(builder, 90_000);

    let mut per_block = Vec::new();
    for packet in 0..500u64 {
        let repair = sender.send_at(Duration::from_millis(packet * 5));
        if (packet + 1).is_multiple_of(5) {
            per_block.push(repair.len());
        } else {
            assert!(repair.is_empty(), "no repair before the block is full");
        }
    }
    assert_eq!(vec![2; 100], per_block);
}
