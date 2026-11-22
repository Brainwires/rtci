//! RFC 6184, modes 0 and 1: order, aggregation headers, fragments, and what a receiver
//! accepts and ignores.

use super::*;

const SPS: &[u8] = &[0x67, 0x42, 0xC0, 0x1F];
const PPS: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];
const PPS_2: &[u8] = &[0x68, 0xDE, 0x3C, 0x81];
const SEI: &[u8] = &[0x06, 0x05, 0x01, 0xAA, 0x80];
const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33];

fn annex_b(nalus: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for nalu in nalus {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nalu);
    }
    Bytes::from(out)
}

/// The NAL units the payloads carry, through the depacketizer, as Annex B.
fn round_trip(payloads: &[Bytes]) -> Result<Bytes> {
    let mut packet = H264Packet::default();
    let mut out = BytesMut::new();
    for payload in payloads {
        out.put(packet.depacketize(payload)?);
    }
    Ok(out.freeze())
}

// --- Order (5.5, 6.3) and nothing lost ---

#[test]
fn nal_units_are_sent_in_the_order_given() -> Result<()> {
    // The audit's reproduction (bug 2): SPS, SEI, PPS, IDR went out as SEI, STAP-A, IDR.
    let access_unit = annex_b(&[SPS, SEI, PPS, IDR]);
    let payloads = H264Payloader::default().payload(1200, &access_unit)?;
    assert_eq!(access_unit, round_trip(&payloads)?);
    Ok(())
}

#[test]
fn every_parameter_set_of_an_access_unit_is_sent() -> Result<()> {
    // The audit's reproduction (bug 3): the second PPS overwrote the first.
    let access_unit = annex_b(&[SPS, PPS, PPS_2, IDR]);
    let payloads = H264Payloader::default().payload(1200, &access_unit)?;
    assert_eq!(access_unit, round_trip(&payloads)?);
    Ok(())
}

#[test]
fn an_sps_without_a_pps_is_sent_with_its_access_unit() -> Result<()> {
    // Bug 3, second half: the SPS waited for a PPS that never came.
    let access_unit = annex_b(&[SPS, IDR]);
    let payloads = H264Payloader::default().payload(1200, &access_unit)?;
    assert_eq!(access_unit, round_trip(&payloads)?);
    Ok(())
}

#[test]
fn parameter_sets_given_alone_go_out_ahead_of_the_next_access_unit_in_order() -> Result<()> {
    let mut payloader = H264Payloader::default();
    assert!(payloader.payload(1200, &annex_b(&[SPS]))?.is_empty());
    assert!(payloader.payload(1200, &annex_b(&[PPS, PPS_2]))?.is_empty());
    let payloads = payloader.payload(1200, &annex_b(&[SEI, IDR]))?;
    assert_eq!(
        annex_b(&[SPS, PPS, PPS_2, SEI, IDR]),
        round_trip(&payloads)?
    );
    // And once sent they are not sent again.
    let payloads = payloader.payload(1200, &annex_b(&[IDR]))?;
    assert_eq!(annex_b(&[IDR]), round_trip(&payloads)?);
    Ok(())
}

#[test]
fn parameter_sets_are_not_held_without_bound() -> Result<()> {
    let mut payloader = H264Payloader::default();
    let mut sent = 0;
    for _ in 0..200 {
        sent += payloader.payload(1200, &annex_b(&[SPS]))?.len();
        assert!(payloader.held_parameter_sets.len() <= MAX_HELD_PARAMETER_SETS);
    }
    assert!(sent > 0, "past the bound they are sent, not dropped");
    Ok(())
}

#[test]
fn start_codes_of_three_and_four_bytes_both_delimit_nal_units() -> Result<()> {
    let mut stream = vec![0, 0, 0, 1];
    stream.extend_from_slice(SPS);
    stream.extend_from_slice(&[0, 0, 1]);
    stream.extend_from_slice(PPS);
    stream.extend_from_slice(&[0, 0, 0, 0, 1]);
    stream.extend_from_slice(IDR);
    let payloads = H264Payloader::default().payload(1200, &Bytes::from(stream))?;
    assert_eq!(annex_b(&[SPS, PPS, IDR]), round_trip(&payloads)?);
    Ok(())
}

// --- Aggregation (5.7) ---

#[test]
fn the_stap_a_header_has_the_highest_nri_and_the_or_of_the_f_bits() -> Result<()> {
    // The audit's reproduction (bug 6): NRI 1 units gave the constant 0x78.
    let payloads =
        H264Payloader::default().payload(1200, &annex_b(&[&[0x27, 1, 2], &[0x28, 3, 4], IDR]))?;
    assert_eq!(0x38, payloads[0][0], "F=0, NRI=1, type 24");

    // NRI 3 with NRI 0: the maximum.
    let payloads = H264Payloader::default().payload(1200, &annex_b(&[SPS, SEI, IDR]))?;
    assert_eq!(OUTPUT_STAP_AHEADER, payloads[0][0]);

    // One forbidden bit sets the aggregate's.
    let payloads =
        H264Payloader::default().payload(1200, &annex_b(&[&[0x07, 1], &[0x88, 2], IDR]))?;
    assert_eq!(0x98, payloads[0][0], "F=1, NRI=0, type 24");
    Ok(())
}

#[test]
fn a_stap_a_holds_a_run_of_non_vcl_nal_units_and_fits_the_mtu() -> Result<()> {
    // SPS (4), PPS (4), SEI (5): 1 + 6 + 6 + 7 = 20 bytes.
    let access_unit = annex_b(&[SPS, PPS, SEI, IDR]);
    let payloads = H264Payloader::default().payload(20, &access_unit)?;
    assert_eq!(2, payloads.len());
    assert_eq!(20, payloads[0].len());
    assert_eq!(STAPA_NALU_TYPE, payloads[0][0] & NALU_TYPE_BITMASK);
    assert_eq!(Bytes::from_static(IDR), payloads[1], "a slice goes alone");

    // One byte less and the SEI no longer fits the aggregate.
    let payloads = H264Payloader::default().payload(19, &access_unit)?;
    assert_eq!(3, payloads.len());
    assert_eq!(13, payloads[0].len());
    assert_eq!(
        Bytes::from_static(SEI),
        payloads[1],
        "alone: a single NAL unit packet"
    );
    assert!(payloads.iter().all(|payload| payload.len() <= 19));
    assert_eq!(access_unit, round_trip(&payloads)?);
    Ok(())
}

#[test]
fn a_lone_nal_unit_is_a_single_nal_unit_packet() -> Result<()> {
    // 5.6: exactly one NAL unit, no aggregate around it.
    for nalu in [SPS, SEI, IDR] {
        let payloads = H264Payloader::default().payload(1200, &annex_b(&[nalu, IDR]))?;
        assert_eq!(Bytes::from_static(nalu), payloads[0]);
    }
    Ok(())
}

#[test]
fn stap_a_builds_what_the_depacketizer_takes_apart() -> Result<()> {
    let payload = stap_a(&[Bytes::from_static(SPS), Bytes::from_static(PPS)])?;
    assert_eq!(
        &[
            0x78, 0, 4, 0x67, 0x42, 0xC0, 0x1F, 0, 4, 0x68, 0xCE, 0x3C, 0x80
        ],
        &payload[..]
    );
    assert_eq!(annex_b(&[SPS, PPS]), round_trip(&[payload])?);
    Ok(())
}

#[test]
fn an_aggregate_is_never_built_around_another_packet_type() {
    // 5.7: no nesting, no fragments inside.
    for inner in [
        vec![0x78u8, 0, 1, 0x67],
        vec![0x7C, 0x85, 1],
        vec![0x00, 1],
        vec![0x1F, 1],
    ] {
        assert!(stap_a(&[Bytes::from(inner.clone())]).is_err());
        assert!(stap_b(7, &[Bytes::from(inner)]).is_err());
    }
    assert!(stap_a(&[]).is_err());
    assert!(stap_a(&[Bytes::new()]).is_err());
    assert!(stap_a(&[Bytes::from(vec![0x65; 65536])]).is_err());
}

// --- What is not sent (5.4, 5.8) ---

#[test]
fn reserved_and_packet_type_nal_units_are_not_sent() -> Result<()> {
    // Types 0, 30, 31 are reserved; 24 to 29 as a "NAL unit" would be read as an aggregate or
    // a fragment (and, over the MTU, become a nested FU).
    for mode in [0u8, 1, 2] {
        for nalu_type in [0u8, 24, 25, 26, 27, 28, 29, 30, 31] {
            let mut small = vec![0x60 | nalu_type];
            small.extend_from_slice(&[1, 2, 3]);
            let mut large = vec![0x60 | nalu_type];
            large.extend_from_slice(&[0xAB; 300]);
            let mut payloader = H264Payloader::with_packetization_mode(mode);
            assert!(
                payloader.payload(100, &annex_b(&[&small]))?.is_empty(),
                "mode {mode} type {nalu_type}"
            );
            assert!(
                payloader.payload(100, &annex_b(&[&large]))?.is_empty(),
                "mode {mode} type {nalu_type} over the MTU"
            );
        }
    }
    Ok(())
}

// --- Fragments (5.8) ---

#[test]
fn every_octet_of_a_fragmented_nal_unit_is_in_exactly_one_fragment() -> Result<()> {
    for len in [51usize, 52, 97, 98, 99, 500] {
        let mut nalu = vec![0x65];
        nalu.extend((0..len).map(|i| i as u8));
        let payloads = H264Payloader::default().payload(50, &annex_b(&[&nalu]))?;
        assert!(payloads.len() >= 2, "never one FU");
        let last = payloads.len() - 1;
        for (i, payload) in payloads.iter().enumerate() {
            assert!(payload.len() <= 50);
            assert_eq!(0x7C, payload[0], "FU indicator: NRI 3, type 28");
            assert_eq!(i == 0, payload[1] & FU_START_BITMASK != 0);
            assert_eq!(i == last, payload[1] & FU_END_BITMASK != 0);
            assert_eq!(0, payload[1] & 0x20, "R is 0");
            assert_eq!(5, payload[1] & NALU_TYPE_BITMASK);
        }
        assert_eq!(annex_b(&[&nalu]), round_trip(&payloads)?);
    }
    Ok(())
}

#[test]
fn the_f_bit_of_a_fragmented_nal_unit_survives() -> Result<()> {
    let mut nalu = vec![0xE5];
    nalu.extend_from_slice(&[0x11; 200]);
    let payloads = H264Payloader::default().payload(50, &annex_b(&[&nalu]))?;
    assert_eq!(0xFC, payloads[0][0], "F=1, NRI=3, type 28");
    assert_eq!(annex_b(&[&nalu]), round_trip(&payloads)?);
    Ok(())
}

#[test]
fn a_fragment_with_an_empty_payload_is_accepted() -> Result<()> {
    // The audit's reproduction (bug 4): a two-byte FU-A was `ErrShortPacket`.
    let mut packet = H264Packet::default();
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7C, 0x85]))?
            .is_empty()
    );
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7C, 0x05, 1, 2]))?
            .is_empty()
    );
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x65, 1, 2]),
        packet.depacketize(&Bytes::from_static(&[0x7C, 0x45]))?
    );
    Ok(())
}

#[test]
fn the_r_bit_of_the_fu_header_is_ignored() -> Result<()> {
    let mut packet = H264Packet::default();
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7C, 0xA5, 1]))?
            .is_empty()
    );
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x65, 1, 2]),
        packet.depacketize(&Bytes::from_static(&[0x7C, 0x65, 2]))?
    );
    Ok(())
}

#[test]
fn a_nal_unit_sent_in_one_fragment_is_still_received() -> Result<()> {
    // A sender must not do this (5.8); a receiver that gets it has the whole NAL unit.
    let mut packet = H264Packet::default();
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x65, 9]),
        packet.depacketize(&Bytes::from_static(&[0x7C, 0xC5, 9]))?
    );
    Ok(())
}

#[test]
fn a_lost_middle_fragment_discards_the_nal_unit_when_sequence_numbers_are_given() -> Result<()> {
    // The audit's reproduction (bug 7): fragments 1, 2 and 4 gave a NAL unit with a hole.
    let mut nalu = vec![0x65];
    nalu.extend((0..180).map(|i| i as u8));
    let fragments = H264Payloader::default().payload(50, &annex_b(&[&nalu]))?;
    assert_eq!(4, fragments.len());

    let mut packet = H264Packet::default();
    let mut out = BytesMut::new();
    for (sequence_number, fragment) in [(10u16, 0usize), (11, 1), (13, 3)] {
        out.put(packet.depacketize_with_sequence_number(sequence_number, &fragments[fragment])?);
    }
    assert!(out.is_empty(), "no NAL unit with a hole in it");

    // The next NAL unit is received whole, and so is one across the sequence number wrap.
    let mut out = BytesMut::new();
    for (i, fragment) in fragments.iter().enumerate() {
        let sequence_number = 65534u16.wrapping_add(i as u16);
        out.put(packet.depacketize_with_sequence_number(sequence_number, fragment)?);
    }
    assert_eq!(annex_b(&[&nalu]), out.freeze());
    Ok(())
}

#[test]
fn a_fragment_cut_short_is_an_error() {
    let mut packet = H264Packet::default();
    assert!(packet.depacketize(&Bytes::from_static(&[0x7C])).is_err());
    assert!(packet.depacketize(&Bytes::from_static(&[0x7D])).is_err());
    // An FU-B without its DON, and an FU-B that is not a first fragment.
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7D, 0x85, 0]))
            .is_err()
    );
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7D, 0x05, 0, 1, 2]))
            .is_err()
    );
}

#[test]
fn a_fragmented_packet_type_or_reserved_type_is_ignored() -> Result<()> {
    // FUs are not nested and aggregates are not fragmented (5.8); reserved types are ignored.
    for inner in [0u8, 24, 25, 28, 29, 30, 31] {
        let mut packet = H264Packet::default();
        let start = Bytes::from(vec![0x7C, FU_START_BITMASK | inner, 1, 2]);
        let end = Bytes::from(vec![0x7C, FU_END_BITMASK | inner, 3, 4]);
        assert!(packet.depacketize(&start)?.is_empty());
        assert!(packet.depacketize(&end)?.is_empty(), "inner type {inner}");
    }
    Ok(())
}

// --- What a receiver accepts (5.6, 5.4, 5.7.1) ---

#[test]
fn a_nal_unit_that_is_a_header_octet_alone_is_received() -> Result<()> {
    // The audit's reproduction (bug 5): end of sequence (10) and end of stream (11) were
    // `ErrShortPacket`, though the payloader sends them.
    for header in [0x0Au8, 0x0B] {
        let payloads = H264Payloader::default().payload(1200, &annex_b(&[&[header]]))?;
        assert_eq!(vec![Bytes::from(vec![header])], payloads);
        assert_eq!(
            Bytes::from(vec![0, 0, 0, 1, header]),
            H264Packet::default().depacketize(&payloads[0])?
        );
        assert!(H264Packet::default().is_partition_head(&payloads[0]));
    }
    // Two bytes that are not an access unit delimiter, too.
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x06, 0x80]),
        H264Packet::default().depacketize(&Bytes::from_static(&[0x06, 0x80]))?
    );
    let mut avc = H264Packet {
        is_avc: true,
        ..Default::default()
    };
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x0A]),
        avc.depacketize(&Bytes::from_static(&[0x0A]))?
    );
    Ok(())
}

#[test]
fn reserved_packet_types_are_ignored_and_do_not_disturb_a_reassembly() -> Result<()> {
    let mut packet = H264Packet::default();
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x7C, 0x85, 1]))?
            .is_empty()
    );
    for reserved in [0x00u8, 0x1E, 0x1F, 0x7E, 0xFF] {
        assert!(
            packet
                .depacketize(&Bytes::from(vec![reserved, 9, 9]))?
                .is_empty()
        );
        assert!(packet.depacketize(&Bytes::from(vec![reserved]))?.is_empty());
    }
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x65, 1, 2]),
        packet.depacketize(&Bytes::from_static(&[0x7C, 0x45, 2]))?
    );
    Ok(())
}

#[test]
fn a_stap_a_unit_that_is_not_a_nal_unit_is_skipped() -> Result<()> {
    // An empty unit, a nested STAP-A and a reserved type between two NAL units.
    let payload = Bytes::from_static(&[
        0x78, 0, 2, 0x67, 1, 0, 0, 0, 3, 0x78, 0, 0, 0, 1, 0x1F, 0, 2, 0x68, 2,
    ]);
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2]),
        H264Packet::default().depacketize(&payload)?
    );
    Ok(())
}

#[test]
fn an_aggregate_cut_short_is_an_error() {
    for payload in [
        &[0x78u8][..],
        &[0x78, 0],
        &[0x78, 0, 2, 0x67],
        &[0x78, 0, 1, 0x67, 0],
        &[0x79],
        &[0x79, 0, 1],
        &[0x79, 0, 1, 0, 2, 0x67],
        &[0x7A, 0, 1],
        &[0x7A, 0, 1, 0, 1, 0, 0],
        &[0x7A, 0, 1, 0, 2, 0, 0, 0, 0x67],
        &[0x7B, 0, 1, 0, 1, 0, 0, 0],
    ] {
        assert!(
            H264Packet::default()
                .depacketize(&Bytes::copy_from_slice(payload))
                .is_err(),
            "{payload:02x?}"
        );
    }
    assert!(H264Packet::default().depacketize(&Bytes::new()).is_err());
}

#[test]
fn the_head_of_a_partition_is_anything_but_a_later_fragment() {
    let packet = H264Packet::default();
    assert!(!packet.is_partition_head(&Bytes::new()));
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x65])));
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x79, 0, 1])));
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x7D, 0x85])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x7C, 0x05])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x7C])));
}

// --- Modes (6.2 to 6.4, 8.1) ---

#[test]
fn a_packetization_mode_above_2_is_refused() {
    assert!(H264Payloader::try_with_packetization_mode(0).is_ok());
    assert!(H264Payloader::try_with_packetization_mode(1).is_ok());
    assert!(H264Payloader::try_with_packetization_mode(2).is_ok());
    for mode in [3u8, 4, 255] {
        assert!(H264Payloader::try_with_packetization_mode(mode).is_err());
    }
}

#[test]
fn mode_1_never_sends_an_interleaved_packet_type() -> Result<()> {
    let mut big = vec![0x65];
    big.extend_from_slice(&[0xAB; 3000]);
    let payloads = H264Payloader::with_packetization_mode(1)
        .payload(1200, &annex_b(&[SPS, PPS, SEI, &big, IDR]))?;
    for payload in &payloads {
        let packet_type = payload[0] & NALU_TYPE_BITMASK;
        assert!(
            (1..=23).contains(&packet_type)
                || packet_type == STAPA_NALU_TYPE
                || packet_type == FUA_NALU_TYPE,
            "type {packet_type}"
        );
    }
    Ok(())
}
