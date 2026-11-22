//! RFC 8627 FlexFEC (`flexfec`), encoder against decoder, under scripted loss.
//!
//! RFC 8627 carries no test vectors, only figures: the byte-exact layouts drawn in section 4.2.2
//! are checked in the unit tests beside the header and the encoder. This file is the other half:
//! for each variant (flexible mask, row, column, 2-D, retransmission) a block is protected,
//! packets are dropped according to a script, and what the decoder returns must be the lost
//! packets, byte for byte, and nothing else.
//!
//! Section numbers are RFC 8627's.

use rtc_interceptor::{
    FlexFecDecoder, FlexFecDecoderConfig, FlexFecEncoder, FlexFecLayout, FlexFecProtection,
};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x1111_2222;
const OTHER_SSRC: u32 = 0x3333_4444;
const REPAIR_SSRC: u32 = 0x9999_AAAA;
const REPAIR_PT: u8 = 98;

/// A source packet whose every recoverable field depends on its sequence number, so a recovery
/// that mixes two packets up cannot pass.
fn source(ssrc: u32, sequence_number: u16) -> rtp::Packet {
    let length = 1 + usize::from(sequence_number % 7) * 3;
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: sequence_number.is_multiple_of(4),
            payload_type: 96 + (sequence_number % 3) as u8,
            sequence_number,
            timestamp: 0x8000_0000u32.wrapping_add(u32::from(sequence_number) * 1500),
            ssrc,
            ..Default::default()
        },
        payload: (0..length)
            .map(|index| (index as u8).wrapping_mul(31) ^ sequence_number as u8)
            .collect::<Vec<u8>>()
            .into(),
    }
}

/// `count` consecutive source packets of the media stream from `first`.
fn block(first: u16, count: u16) -> Vec<rtp::Packet> {
    (0..count)
        .map(|offset| source(MEDIA_SSRC, first.wrapping_add(offset)))
        .collect()
}

fn bytes_of(packet: &rtp::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    packet.marshal_to(&mut buffer).expect("marshal");
    buffer
}

fn encoder() -> FlexFecEncoder {
    FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC)
}

fn decoder() -> FlexFecDecoder {
    let mut decoder = FlexFecDecoder::new(FlexFecDecoderConfig::for_repair_window(
        Duration::from_millis(200),
    ));
    decoder.add_source_stream(MEDIA_SSRC);
    decoder
}

/// Deliver `sources` except the positions in `lost`, then `repair` except the positions in
/// `lost_repair`, all at one instant. Returns what the decoder made available, by sequence
/// number.
fn run(
    decoder: &mut FlexFecDecoder,
    sources: &[rtp::Packet],
    lost: &[usize],
    repair: &[rtp::Packet],
    lost_repair: &[usize],
) -> Vec<rtp::Packet> {
    let now = Instant::now();
    let mut recovered = Vec::new();
    for (index, packet) in sources.iter().enumerate() {
        if !lost.contains(&index) {
            recovered.extend(decoder.push_source(now, packet));
        }
    }
    assert!(
        recovered.is_empty(),
        "nothing is recovered from sources alone"
    );
    for (index, packet) in repair.iter().enumerate() {
        if !lost_repair.contains(&index) {
            recovered.extend(decoder.push_repair(now, packet));
        }
    }
    recovered.sort_by_key(|packet| (packet.header.ssrc, packet.header.sequence_number));
    recovered
}

/// The decoder returned exactly the packets at `expected`, byte-identical to what was sent.
fn assert_recovered(sources: &[rtp::Packet], expected: &[usize], recovered: &[rtp::Packet]) {
    let mut expected: Vec<&rtp::Packet> = expected.iter().map(|&index| &sources[index]).collect();
    expected.sort_by_key(|packet| (packet.header.ssrc, packet.header.sequence_number));
    assert_eq!(
        expected
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect::<Vec<_>>(),
        recovered
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect::<Vec<_>>(),
        "which packets were recovered"
    );
    for (sent, rebuilt) in expected.iter().zip(recovered) {
        assert_eq!(
            bytes_of(sent),
            bytes_of(rebuilt),
            "packet {} byte-identical",
            sent.header.sequence_number
        );
    }
}

// ---------------------------------------------------------------------------------------
// Flexible mask (R=0, F=0)
// ---------------------------------------------------------------------------------------

/// Sections 6.3.1.1, 6.3.2 and 6.3.3: any single loss under a mask is rebuilt, at every mask
/// width (15, 46 and 110 bits).
#[test]
fn a_single_loss_under_a_flexible_mask_is_recovered_at_every_mask_width() {
    for count in [1u16, 5, 15, 16, 46, 47, 110] {
        let sources = block(1000, count);
        let repair = encoder().encode_block(
            FlexFecProtection::Mask {
                media_packets: u32::from(count),
                fec_packets: 1,
            },
            &sources,
            0,
        );
        assert_eq!(1, repair.len(), "{count} packets");

        for lost in [0, usize::from(count) / 2, usize::from(count) - 1] {
            let recovered = run(&mut decoder(), &sources, &[lost], &repair, &[]);
            assert_recovered(&sources, &[lost], &recovered);
        }
    }
}

/// Interleaved masks: a burst as long as the number of repair packets is recovered, because
/// consecutive packets sit under different repair packets.
#[test]
fn a_burst_under_interleaved_masks_is_recovered() {
    let sources = block(500, 12);
    let repair = encoder().encode_block(
        FlexFecProtection::Mask {
            media_packets: 12,
            fec_packets: 3,
        },
        &sources,
        0,
    );
    assert_eq!(3, repair.len());

    let recovered = run(&mut decoder(), &sources, &[4, 5, 6], &repair, &[]);
    assert_recovered(&sources, &[4, 5, 6], &recovered);
}

/// Section 6.3.1.1: "the bitmasks are able to represent arbitrary protection patterns". Two
/// overlapping masks form a staircase: the second rebuilds a packet the first was also missing,
/// and the first then rebuilds its other one (section 6.3.4).
#[test]
fn a_staircase_of_masks_is_decoded_iteratively() {
    let sources = block(40, 6); // 40..=45
    let mut encoder = encoder();
    let first = encoder
        .encode(FlexFecLayout::Mask, &sources[0..4], 0)
        .expect("encodes"); // 40..=43
    let second = encoder
        .encode(FlexFecLayout::Mask, &sources[3..6], 0)
        .expect("encodes"); // 43..=45

    let mut decoder = decoder();
    let now = Instant::now();
    for index in [0usize, 2, 4, 5] {
        assert!(decoder.push_source(now, &sources[index]).is_empty());
    }
    assert!(
        decoder.push_repair(now, &first).is_empty(),
        "41 and 43 are both missing under the first"
    );
    let recovered = decoder.push_repair(now, &second);

    assert_eq!(
        vec![43, 41],
        recovered
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect::<Vec<_>>(),
        "43 from the second, which lets the first rebuild 41"
    );
    assert_eq!(bytes_of(&sources[3]), bytes_of(&recovered[0]));
    assert_eq!(bytes_of(&sources[1]), bytes_of(&recovered[1]));
    assert_eq!(0, decoder.pending_repair_packets(), "both are spent");
}

/// A mask that does not start at a multiple of anything and skips packets: SN base plus bit
/// index is all there is to it (section 4.2.2.1).
#[test]
fn a_sparse_mask_names_exactly_the_packets_protected() {
    let sources = block(65_500, 110);
    let picked: Vec<rtp::Packet> = [3usize, 20, 47, 109]
        .iter()
        .map(|&index| sources[index].clone())
        .collect();
    let repair = encoder()
        .encode(FlexFecLayout::Mask, &picked, 0)
        .expect("encodes");

    // 47 is lost; packets the mask does not name are lost too and do not matter.
    let recovered = run(&mut decoder(), &sources, &[4, 47, 48, 60], &[repair], &[]);
    assert_recovered(&sources, &[47], &recovered);
}

// ---------------------------------------------------------------------------------------
// Fixed L and D: 1-D non-interleaved, 1-D interleaved, 2-D
// ---------------------------------------------------------------------------------------

/// Section 1.1.1: row FEC recovers one loss per row, wherever it is.
#[test]
fn row_fec_recovers_any_single_loss_in_a_row() {
    let sources = block(100, 4);
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);

    for lost in 0..4 {
        let recovered = run(&mut decoder(), &sources, &[lost], &repair, &[]);
        assert_recovered(&sources, &[lost], &recovered);
    }
}

/// Section 1.1.1 (Figure 4): two losses in one row are beyond row FEC, and the decoder makes
/// nothing up.
#[test]
fn row_fec_cannot_recover_two_losses_in_a_row() {
    let sources = block(100, 4);
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);

    let mut decoder = decoder();
    let recovered = run(&mut decoder, &sources, &[1, 2], &repair, &[]);
    assert!(recovered.is_empty());
    assert_eq!(
        1,
        decoder.pending_repair_packets(),
        "kept, in case one shows up"
    );

    // And one does: the late arrival of 101 lets the row rebuild 102.
    let late = decoder.push_source(Instant::now(), &sources[1]);
    assert_recovered(&sources, &[2], &late);
}

/// Section 1.1.2 (Figure 6): column FEC over an L by D block recovers a burst of up to L
/// consecutive losses, since each lands in a different column.
#[test]
fn column_fec_recovers_a_burst_of_l_consecutive_losses() {
    let sources = block(1, 12); // rows 1-4, 5-8, 9-12
    let repair = encoder().encode_block(FlexFecProtection::Column { l: 4, d: 3 }, &sources, 0);
    assert_eq!(4, repair.len());

    for first in 0..=8 {
        let lost: Vec<usize> = (first..first + 4).collect();
        let recovered = run(&mut decoder(), &sources, &lost, &repair, &[]);
        assert_recovered(&sources, &lost, &recovered);
    }
}

/// Two losses in one column are beyond column FEC; the other columns still recover theirs.
#[test]
fn column_fec_cannot_recover_two_losses_in_a_column() {
    let sources = block(1, 12);
    let repair = encoder().encode_block(FlexFecProtection::Column { l: 4, d: 3 }, &sources, 0);

    // 1 and 5 are in column 1; 7 is alone in column 3.
    let recovered = run(&mut decoder(), &sources, &[0, 4, 6], &repair, &[]);
    assert_recovered(&sources, &[6], &recovered);
}

/// Section 1.1.4: two losses in the same row defeat the row packet and are fixed by the column
/// packets; two losses in the same column, by the row packets.
#[test]
fn two_dimensional_fec_fixes_a_row_with_columns_and_a_column_with_rows() {
    let sources = block(1, 12);
    let repair =
        encoder().encode_block(FlexFecProtection::RowAndColumn { l: 4, d: 3 }, &sources, 0);
    assert_eq!(7, repair.len(), "three rows, four columns");

    // 6 and 7: both in the second row.
    let recovered = run(&mut decoder(), &sources, &[5, 6], &repair, &[]);
    assert_recovered(&sources, &[5, 6], &recovered);

    // 2 and 10: both in the second column.
    let recovered = run(&mut decoder(), &sources, &[1, 9], &repair, &[]);
    assert_recovered(&sources, &[1, 9], &recovered);

    // Two rows each missing two packets, in four different columns.
    let recovered = run(&mut decoder(), &sources, &[0, 1, 10, 11], &repair, &[]);
    assert_recovered(&sources, &[0, 1, 10, 11], &recovered);
}

/// Section 6.3.4, Figures 16 to 18, step by step: packets 1, 2, 10 and 11 of a 4 by 3 block
/// are lost. No row can start (two losses each); columns 1 and 3 rebuild 1 and 11; that leaves
/// one loss in each row, and the rows rebuild 2 and 10.
#[test]
fn the_iterative_decoding_example_of_figure_16_recovers_everything() {
    let sources = block(1, 12);
    let repair =
        encoder().encode_block(FlexFecProtection::RowAndColumn { l: 4, d: 3 }, &sources, 0);
    let (rows, columns) = repair.split_at(3);

    let mut decoder = decoder();
    let now = Instant::now();
    for (index, packet) in sources.iter().enumerate() {
        if ![0usize, 1, 9, 10].contains(&index) {
            decoder.push_source(now, packet);
        }
    }
    let sequence_numbers = |packets: Vec<rtp::Packet>| {
        packets
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect::<Vec<_>>()
    };

    for row in rows {
        assert!(
            decoder.push_repair(now, row).is_empty(),
            "rows 1 and 3 miss two packets each, row 2 none"
        );
    }
    // C_1 rebuilds 1; R_1 then misses only 2.
    assert_eq!(
        vec![1, 2],
        sequence_numbers(decoder.push_repair(now, &columns[0]))
    );
    // C_2 covers 2, 6, 10: only 10 is missing now; R_3 then misses only 11.
    assert_eq!(
        vec![10, 11],
        sequence_numbers(decoder.push_repair(now, &columns[1]))
    );
    assert!(decoder.push_repair(now, &columns[2]).is_empty());
    assert!(decoder.push_repair(now, &columns[3]).is_empty());
    assert_eq!(4, decoder.stats().recovered);
    assert_eq!(0, decoder.pending_repair_packets());

    // The same losses with every repair packet delivered in one go, columns first.
    let mut reordered: Vec<rtp::Packet> = columns.to_vec();
    reordered.extend_from_slice(rows);
    let recovered = run(
        &mut self::decoder(),
        &sources,
        &[0, 1, 9, 10],
        &reordered,
        &[],
    );
    assert_recovered(&sources, &[0, 1, 9, 10], &recovered);
}

/// Section 1.1.4 (Figure 8): four losses on the corners of a rectangle leave two in every row
/// and column concerned. 2-D FEC cannot recover them, and returns nothing wrong.
#[test]
fn a_rectangle_of_losses_defeats_two_dimensional_fec() {
    let sources = block(1, 12);
    let repair =
        encoder().encode_block(FlexFecProtection::RowAndColumn { l: 4, d: 3 }, &sources, 0);

    // 2, 3, 10, 11.
    let recovered = run(&mut decoder(), &sources, &[1, 2, 9, 10], &repair, &[]);
    assert!(recovered.is_empty());
}

/// Repair packets are lost too. A lost row packet leaves its row to the columns; a lost column
/// packet leaves its column to the rows; a 1-D block that loses its only repair packet for a
/// row recovers nothing there.
#[test]
fn lost_repair_packets_cost_only_what_they_protected() {
    let sources = block(1, 12);
    let two_d = encoder().encode_block(FlexFecProtection::RowAndColumn { l: 4, d: 3 }, &sources, 0);

    // R_2 (index 1) and source 6 lost: column 2 rebuilds 6.
    let recovered = run(&mut decoder(), &sources, &[5], &two_d, &[1]);
    assert_recovered(&sources, &[5], &recovered);
    // C_2 (index 4) and source 6 lost: row 2 rebuilds 6.
    let recovered = run(&mut decoder(), &sources, &[5], &two_d, &[4]);
    assert_recovered(&sources, &[5], &recovered);
    // Both of them lost with source 6: nothing left that covers it.
    let recovered = run(&mut decoder(), &sources, &[5], &two_d, &[1, 4]);
    assert!(recovered.is_empty());

    let columns = encoder().encode_block(FlexFecProtection::Column { l: 4, d: 3 }, &sources, 0);
    let recovered = run(&mut decoder(), &sources, &[0, 1], &columns, &[0]);
    assert_recovered(&sources, &[1], &recovered);
}

/// The block crosses the sequence-number wrap: bases, columns and recovered sequence numbers
/// all wrap with it.
#[test]
fn a_block_across_the_sequence_wrap_is_recovered() {
    let sources = block(65_530, 12); // 65530..=65535, 0..=5
    for protection in [
        FlexFecProtection::Column { l: 4, d: 3 },
        FlexFecProtection::RowAndColumn { l: 3, d: 4 },
        FlexFecProtection::Mask {
            media_packets: 12,
            fec_packets: 4,
        },
    ] {
        let repair = encoder().encode_block(protection, &sources, 0);
        // 65534, 65535, 0, 1.
        let recovered = run(&mut decoder(), &sources, &[4, 5, 6, 7], &repair, &[]);
        let mut sent: Vec<Vec<u8>> = [4usize, 5, 6, 7]
            .iter()
            .map(|&index| bytes_of(&sources[index]))
            .collect();
        let mut rebuilt: Vec<Vec<u8>> = recovered.iter().map(bytes_of).collect();
        sent.sort();
        rebuilt.sort();
        assert_eq!(sent, rebuilt, "{protection:?}");
    }
}

/// The repair packets arrive before the sources they protect (reordering): they wait, and the
/// last source to arrive releases the recovery.
#[test]
fn a_repair_packet_ahead_of_its_sources_waits_for_them() {
    let sources = block(65_534, 4); // 65534, 65535, 0, 1
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);

    let mut decoder = decoder();
    let now = Instant::now();
    assert!(decoder.push_repair(now, &repair[0]).is_empty());
    assert!(decoder.push_source(now, &sources[3]).is_empty());
    assert!(decoder.push_source(now, &sources[0]).is_empty());
    let recovered = decoder.push_source(now, &sources[2]);
    assert_recovered(&sources, &[1], &recovered);
}

// ---------------------------------------------------------------------------------------
// What is recovered
// ---------------------------------------------------------------------------------------

/// A source packet with a CSRC list, a header extension and RTP padding.
fn elaborate(sequence_number: u16) -> rtp::Packet {
    let mut wire = vec![0xB2, 0x80 | 100]; // V=2, P=1, X=1, CC=2; M=1, PT=100
    wire.extend_from_slice(&sequence_number.to_be_bytes());
    wire.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    wire.extend_from_slice(&MEDIA_SSRC.to_be_bytes());
    wire.extend_from_slice(&0x0A0B_0C0Du32.to_be_bytes());
    wire.extend_from_slice(&0x1A1B_1C1Du32.to_be_bytes());
    wire.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01, 0x51, 0x12, 0x34, 0x00]);
    wire.extend_from_slice(&[9, 8, 7, 6, 5]);
    wire.extend_from_slice(&[0, 0, 3]);
    let packet = rtp::Packet::unmarshal(&mut wire.as_slice()).expect("a valid packet");
    assert_eq!(wire, bytes_of(&packet));
    packet
}

/// Sections 4.1, 6.3.2 and 6.3.3: the CSRC list, the header extension and the padding of a
/// lost source packet are recovered, with P, X, CC, M, PT, the timestamp and the SSRC.
#[test]
fn a_lost_packet_with_csrcs_an_extension_and_padding_is_recovered_whole() {
    let mut sources = block(300, 4);
    sources[2] = elaborate(302);
    for protection in [
        FlexFecProtection::Row { l: 4 },
        FlexFecProtection::Mask {
            media_packets: 4,
            fec_packets: 1,
        },
    ] {
        let repair = encoder().encode_block(protection, &sources, 0);

        let recovered = run(&mut decoder(), &sources, &[2], &repair, &[]);
        assert_recovered(&sources, &[2], &recovered);
        let header = &recovered[0].header;
        assert_eq!(2, header.version);
        assert!(header.padding && header.extension && header.marker);
        assert_eq!(vec![0x0A0B_0C0D, 0x1A1B_1C1D], header.csrc);
        assert_eq!(
            (100, 302, 0xDEAD_BEEF, MEDIA_SSRC),
            (
                header.payload_type,
                header.sequence_number,
                header.timestamp,
                header.ssrc
            )
        );

        // A plain neighbour lost instead: the elaborate packet's extra octets XOR out again.
        let recovered = run(&mut decoder(), &sources, &[0], &repair, &[]);
        assert_recovered(&sources, &[0], &recovered);
    }
}

/// Section 4.2.1: a repair packet's marker bit is ignored by receivers, and its own header
/// extension and padding are independent of the sources'.
#[test]
fn the_repair_packets_own_marker_extension_and_padding_do_not_matter() {
    let sources = block(100, 4);
    let mut repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);

    let dressed = &mut repair[0];
    dressed.header.marker = true;
    dressed.header.padding = true;
    dressed.header.padding_size = 8;
    dressed
        .header
        .set_extension(3, vec![0xAA, 0xBB].into())
        .expect("an extension of its own");
    // As it would arrive: serialized and parsed again.
    let arrived = rtp::Packet::unmarshal(&mut bytes_of(dressed).as_slice()).expect("parses");
    assert!(arrived.header.marker && arrived.header.padding && arrived.header.extension);

    let recovered = run(&mut decoder(), &sources, &[3], &[arrived], &[]);
    assert_recovered(&sources, &[3], &recovered);
}

/// Sections 4.2.2.1 and 4.2.2.2: one repair packet protects packets of several source streams,
/// one SN base block per CSRC. A loss in either stream is rebuilt with that stream's SSRC.
#[test]
fn one_repair_packet_protects_several_source_streams() {
    let mut sources = block(100, 3);
    sources.extend((0..3).map(|offset| source(OTHER_SSRC, 60_000 + offset)));

    for layout in [FlexFecLayout::Mask, FlexFecLayout::Fixed { l: 3, d: 0 }] {
        let repair = encoder().encode(layout, &sources, 0).expect("encodes");
        assert_eq!(vec![MEDIA_SSRC, OTHER_SSRC], repair.header.csrc);

        for lost in [1usize, 4] {
            let mut decoder = decoder();
            decoder.add_source_stream(OTHER_SSRC);
            let recovered = run(
                &mut decoder,
                &sources,
                &[lost],
                std::slice::from_ref(&repair),
                &[],
            );
            assert_recovered(&sources, &[lost], &recovered);
            assert_eq!(sources[lost].header.ssrc, recovered[0].header.ssrc);
        }

        // One loss in each stream is two losses under the one repair packet.
        let mut decoder = decoder();
        decoder.add_source_stream(OTHER_SSRC);
        assert!(
            run(
                &mut decoder,
                &sources,
                &[1, 4],
                std::slice::from_ref(&repair),
                &[]
            )
            .is_empty()
        );
    }
}

/// A packet the decoder rebuilt and then receives after all (it was late, not lost) is not
/// handed out a second time by the decoder.
#[test]
fn a_late_original_is_not_recovered_again() {
    let sources = block(100, 4);
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);

    let mut decoder = decoder();
    let recovered = run(&mut decoder, &sources, &[2], &repair, &[]);
    assert_recovered(&sources, &[2], &recovered);
    assert!(decoder.push_source(Instant::now(), &sources[2]).is_empty());
    assert!(decoder.push_repair(Instant::now(), &repair[0]).is_empty());
}

// ---------------------------------------------------------------------------------------
// Retransmission (R=1, F=0)
// ---------------------------------------------------------------------------------------

/// Sections 1.1.8 and 4.2.2.3: a retransmission of a source packet within the repair window
/// delivers that packet, exactly.
#[test]
fn a_retransmission_delivers_the_lost_packet() {
    let mut sources = block(100, 4);
    sources[1] = elaborate(101);
    let mut encoder = encoder();
    let retransmission = encoder.retransmit(&sources[1], 0).expect("retransmits");

    let recovered = run(
        &mut decoder(),
        &sources,
        &[1],
        std::slice::from_ref(&retransmission),
        &[],
    );
    assert_recovered(&sources, &[1], &recovered);

    // A second copy, or one for a packet that arrived after all, delivers nothing.
    let mut decoder = decoder();
    let now = Instant::now();
    for packet in &sources {
        decoder.push_source(now, packet);
    }
    assert!(decoder.push_repair(now, &retransmission).is_empty());
    assert_eq!(0, decoder.stats().retransmitted);
}

/// A retransmission and parity work together: two losses in a row, one retransmitted, and the
/// row packet rebuilds the other.
#[test]
fn a_retransmission_completes_a_parity_recovery() {
    let sources = block(100, 4);
    let mut encoder = encoder();
    let row = encoder.encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);
    let retransmission = encoder.retransmit(&sources[1], 0).expect("retransmits");

    let mut decoder = decoder();
    assert!(run(&mut decoder, &sources, &[1, 2], &row, &[]).is_empty());
    let available = decoder.push_repair(Instant::now(), &retransmission);

    assert_eq!(
        vec![101, 102],
        available
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect::<Vec<_>>(),
        "the retransmitted packet first, then the one it let the row rebuild"
    );
    assert_eq!(bytes_of(&sources[2]), bytes_of(&available[1]));
    assert_eq!(
        (1, 1),
        (decoder.stats().retransmitted, decoder.stats().recovered)
    );
}

/// Outside the repair window, or for a stream the decoder does not protect, a retransmission
/// is ignored.
#[test]
fn a_retransmission_outside_the_window_or_for_another_stream_is_ignored() {
    let mut decoder = decoder();
    let window = decoder.config().max_source_packets as u16;
    let now = Instant::now();
    decoder.push_source(now, &source(MEDIA_SSRC, 10_000));
    let mut encoder = encoder();

    let too_old = encoder
        .retransmit(&source(MEDIA_SSRC, 10_000 - window), 0)
        .expect("retransmits");
    assert!(decoder.push_repair(now, &too_old).is_empty());

    let other_stream = encoder
        .retransmit(&source(OTHER_SSRC, 10_001), 0)
        .expect("retransmits");
    assert!(decoder.push_repair(now, &other_stream).is_empty());
    assert_eq!(2, decoder.stats().ignored_repair_packets);

    let inside = encoder
        .retransmit(&source(MEDIA_SSRC, 10_001 - window), 0)
        .expect("retransmits");
    assert_eq!(1, decoder.push_repair(now, &inside).len());
}

// ---------------------------------------------------------------------------------------
// What a peer may not do (sections 4.2.2, 4.2.2.2 and 9)
// ---------------------------------------------------------------------------------------

/// A repair packet with a hand-written FEC header and `payload_length` octets of repair data.
fn forged(csrc: &[u32], header: &[u8], payload_length: usize) -> rtp::Packet {
    let mut payload = header.to_vec();
    payload.extend(std::iter::repeat_n(0x5A, payload_length));
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: REPAIR_PT,
            sequence_number: 1,
            ssrc: REPAIR_SSRC,
            csrc: csrc.to_vec(),
            ..Default::default()
        },
        payload: payload.into(),
    }
}

/// Section 4.2.2: R=1 F=1 MUST be ignored. Section 4.2.2.2: L=0 D=0 MUST be ignored.
#[test]
fn reserved_variants_are_ignored() {
    let mut decoder = decoder();
    let now = Instant::now();
    decoder.push_source(now, &source(MEDIA_SSRC, 100));

    let reserved = forged(&[MEDIA_SSRC], &[0xC0, 0, 0, 4, 0, 0, 0, 0, 0, 100, 2, 0], 4);
    let zero_l_d = forged(&[MEDIA_SSRC], &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 0, 0], 4);
    let zero_l = forged(&[MEDIA_SSRC], &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 0, 5], 4);
    for packet in [&reserved, &zero_l_d, &zero_l] {
        assert!(decoder.push_repair(now, packet).is_empty());
    }
    assert_eq!(3, decoder.stats().ignored_repair_packets);
    assert_eq!(0, decoder.pending_repair_packets());
}

/// Section 4.2.2.2: "If the values of L and D result in a repair packet that exceed the repair
/// window of the FLEX FEC session, then the repair packet MUST be ignored." The window holds
/// 200 packets here; a column of 255 rows 255 apart reaches 64771.
#[test]
fn l_and_d_beyond_the_repair_window_are_ignored() {
    let mut decoder = decoder();
    let limit = decoder.config().max_source_packets;
    assert_eq!(200, limit);
    let now = Instant::now();
    decoder.push_source(now, &source(MEDIA_SSRC, 100));

    let huge = forged(
        &[MEDIA_SSRC],
        &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 255, 255],
        4,
    );
    assert!(decoder.push_repair(now, &huge).is_empty());
    // Row of 201, column spanning 201: one packet too many.
    let row = forged(
        &[MEDIA_SSRC],
        &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 201, 0],
        4,
    );
    assert!(decoder.push_repair(now, &row).is_empty());
    let column = forged(
        &[MEDIA_SSRC],
        &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 100, 3],
        4,
    );
    assert!(decoder.push_repair(now, &column).is_empty());
    assert_eq!(3, decoder.stats().ignored_repair_packets);
    assert_eq!(0, decoder.pending_repair_packets());

    // Exactly the window is accepted and waits for its sources.
    let fits = forged(
        &[MEDIA_SSRC],
        &[0x40, 0, 0, 4, 0, 0, 0, 0, 0, 100, 200, 0],
        4,
    );
    assert!(decoder.push_repair(now, &fits).is_empty());
    assert_eq!(1, decoder.pending_repair_packets());
}

/// Section 9: a repair packet naming a stream the session does not protect opens no buffer.
#[test]
fn a_repair_packet_for_an_unknown_stream_opens_no_buffer() {
    let mut decoder = decoder();
    let now = Instant::now();
    let sources: Vec<rtp::Packet> = (0..3).map(|offset| source(0xBAD0_0000, offset)).collect();
    let repair = encoder()
        .encode(FlexFecLayout::Mask, &sources, 0)
        .expect("encodes");

    assert!(decoder.push_repair(now, &repair).is_empty());
    for packet in &sources[1..] {
        assert!(decoder.push_source(now, packet).is_empty());
    }
    assert_eq!(
        vec![MEDIA_SSRC],
        decoder.source_streams().collect::<Vec<_>>()
    );
    assert_eq!(
        (0, 0),
        (
            decoder.held_source_packets(),
            decoder.pending_repair_packets()
        )
    );
}

/// Section 9: length recovery from the wire cannot make the decoder allocate or read beyond
/// the repair packet. A length that points past the repair payload fails the recovery.
#[test]
fn a_length_recovery_beyond_the_repair_payload_fails_cleanly() {
    let sources = block(100, 2);
    let mut decoder = decoder();
    let now = Instant::now();
    decoder.push_source(now, &sources[0]);

    // Row of two; length recovery says the missing packet has 65535 octets; four are present.
    let lying = forged(
        &[MEDIA_SSRC],
        &[0x40, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 100, 2, 0],
        4,
    );
    assert!(decoder.push_repair(now, &lying).is_empty());
    assert_eq!(1, decoder.stats().failed_recoveries);
    assert_eq!(0, decoder.pending_repair_packets(), "and it is not retried");
}

/// A rebuilt "packet" that is not RTP (CC or an extension length reaching past its end) is
/// dropped, not delivered.
#[test]
fn a_recovery_that_is_not_an_rtp_packet_is_dropped() {
    let mut decoder = decoder();
    let now = Instant::now();
    let only = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            sequence_number: 100,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: vec![].into(),
    };
    decoder.push_source(now, &only);

    // CC recovery of 15 with a 4-octet body: fifteen CSRCs cannot fit.
    let broken = forged(&[MEDIA_SSRC], &[0x4F, 0, 0, 4, 0, 0, 0, 0, 0, 100, 2, 0], 4);
    assert!(decoder.push_repair(now, &broken).is_empty());
    assert_eq!(1, decoder.stats().failed_recoveries);
}

/// Sections 1.1.2 and 9: the buffers hold the repair window and no more, however much arrives.
#[test]
fn the_buffers_are_bounded_by_the_repair_window() {
    let mut decoder = decoder();
    let config = *decoder.config();
    let now = Instant::now();

    for sequence_number in 0..20_000u32 {
        decoder.push_source(now, &source(MEDIA_SSRC, sequence_number as u16));
    }
    assert_eq!(config.max_source_packets, decoder.held_source_packets());

    // Repair packets that can never complete (their sources are long gone).
    let mut encoder = encoder();
    for index in 0..5_000u16 {
        let orphan = encoder
            .encode(
                FlexFecLayout::Mask,
                &[
                    source(MEDIA_SSRC, 30_000 + index * 2),
                    source(MEDIA_SSRC, 30_001 + index * 2),
                ],
                0,
            )
            .expect("encodes");
        decoder.push_repair(now, &orphan);
    }
    assert!(decoder.pending_repair_packets() <= config.max_repair_packets);
}

/// Section 1.1.2: packets are kept for the repair window, in time as well. A source that
/// arrived longer ago than the window is gone when its repair packet shows up; one inside the
/// window is still there.
#[test]
fn sources_and_repair_packets_expire_with_the_repair_window() {
    let sources = block(100, 4);
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &sources, 0);
    let start = Instant::now();
    let feed = |decoder: &mut FlexFecDecoder| {
        for packet in &sources[1..] {
            decoder.push_source(start, packet);
        }
    };

    let mut decoder = self::decoder(); // 200 ms window
    feed(&mut decoder);
    let inside = decoder.push_repair(start + Duration::from_millis(200), &repair[0]);
    assert_recovered(&sources, &[0], &inside);

    let mut decoder = self::decoder();
    feed(&mut decoder);
    let outside = decoder.push_repair(start + Duration::from_millis(201), &repair[0]);
    assert!(outside.is_empty());
    assert_eq!(0, decoder.held_source_packets());

    // A waiting repair packet expires the same way.
    let mut decoder = self::decoder();
    decoder.push_repair(start, &repair[0]);
    assert_eq!(1, decoder.pending_repair_packets());
    decoder.push_source(start + Duration::from_millis(201), &sources[0]);
    assert_eq!(0, decoder.pending_repair_packets());
}

/// A stream that restarts at an unrelated sequence number is followed: one stray old packet is
/// refused, two in a row are the stream.
#[test]
fn a_stream_that_restarts_far_behind_is_followed() {
    let mut decoder = decoder();
    let now = Instant::now();
    for packet in block(40_000, 10) {
        decoder.push_source(now, &packet);
    }

    let restarted = block(30_000, 4);
    let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &restarted, 0);
    decoder.push_source(now, &restarted[0]); // refused: a stray, for all the decoder knows
    decoder.push_source(now, &restarted[1]); // the stream did move
    decoder.push_source(now, &restarted[3]);
    let recovered = decoder.push_repair(now, &repair[0]);

    // 30000 was refused as a stray and 30002 is lost: two missing, so nothing yet.
    assert!(recovered.is_empty());
    let recovered = decoder.push_source(now, &restarted[0]);
    assert_recovered(&restarted, &[2], &recovered);
}

/// The decoder config follows the negotiated repair window, within fixed limits.
#[test]
fn the_buffer_size_follows_the_repair_window_within_limits() {
    let packets = |millis| {
        FlexFecDecoderConfig::for_repair_window(Duration::from_millis(millis)).max_source_packets
    };

    assert_eq!(FlexFecDecoderConfig::MIN_SOURCE_PACKETS, packets(0));
    assert_eq!(FlexFecDecoderConfig::MIN_SOURCE_PACKETS, packets(100));
    assert_eq!(200, packets(200));
    assert_eq!(1000, packets(1000));
    assert_eq!(FlexFecDecoderConfig::MAX_SOURCE_PACKETS, packets(10_000));
    assert_eq!(
        FlexFecDecoderConfig::MAX_SOURCE_PACKETS,
        packets(u64::MAX / 2)
    );
}
