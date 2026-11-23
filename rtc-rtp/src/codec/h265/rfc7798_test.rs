//! RFC 7798: the depacketizer (single NAL unit, AP, FU, PACI), decoding order numbers, TSCI,
//! and the payloader's order and headers.

use super::*;

const VPS: &[u8] = &[0x40, 0x01, 0x0C, 0x01];
const SPS: &[u8] = &[0x42, 0x01, 0x01, 0x02, 0x03];
const PPS: &[u8] = &[0x44, 0x01, 0xC1];
const IDR: &[u8] = &[0x26, 0x01, 0xAF, 0x08, 0x40];
const EOS: &[u8] = &[0x48, 0x01];
const EOB: &[u8] = &[0x4A, 0x01];

fn annex_b(nalus: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for nalu in nalus {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nalu);
    }
    Bytes::from(out)
}

fn big_idr(len: usize) -> Vec<u8> {
    let mut nalu = vec![0x26, 0x01];
    nalu.extend((0..len).map(|i| i as u8));
    nalu
}

fn depacketize_all(packet: &mut H265Packet, payloads: &[Bytes]) -> Result<Bytes> {
    let mut out = BytesMut::new();
    for payload in payloads {
        out.put(packet.depacketize(payload)?);
    }
    Ok(out.freeze())
}

// --- The depacketizer yields NAL units (4.4, 6) ---

#[test]
fn an_access_unit_comes_back_as_its_nal_units() -> Result<()> {
    // The audit's reproduction (bug 1): the "sample" was the RTP payloads, AP and FU headers
    // included.
    let idr = big_idr(3000);
    let access_unit = annex_b(&[VPS, SPS, PPS, &idr]);
    let payloads = HevcPayloader::default().payload(1200, &access_unit)?;
    assert_eq!(48, (payloads[0][0] >> 1) & 0x3F, "an aggregation packet");
    assert_eq!(49, (payloads[1][0] >> 1) & 0x3F, "then fragmentation units");

    let mut packet = H265Packet::default();
    assert_eq!(access_unit, depacketize_all(&mut packet, &payloads)?);
    Ok(())
}

#[test]
fn a_single_nal_unit_packet_is_its_nal_unit() -> Result<()> {
    let mut packet = H265Packet::default();
    assert_eq!(
        annex_b(&[IDR]),
        packet.depacketize(&Bytes::from_static(IDR))?
    );
    packet.with_length_prefix(true);
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 5, 0x26, 0x01, 0xAF, 0x08, 0x40]),
        packet.depacketize(&Bytes::from_static(IDR))?
    );
    Ok(())
}

#[test]
fn a_nal_unit_that_is_a_header_alone_is_received() -> Result<()> {
    // The audit's reproduction (bug 3): end of sequence and end of bitstream were
    // `ErrShortPacket`, though the payloader sends them.
    for nalu in [EOS, EOB] {
        let payloads = HevcPayloader::default().payload(1200, &annex_b(&[nalu]))?;
        assert_eq!(vec![Bytes::from_static(nalu)], payloads);
        assert_eq!(
            annex_b(&[nalu]),
            H265Packet::default().depacketize(&payloads[0])?
        );
    }
    assert!(
        H265Packet::default()
            .depacketize(&Bytes::from_static(&[0x48]))
            .is_err()
    );
    assert!(H265Packet::default().depacketize(&Bytes::new()).is_err());
    Ok(())
}

#[test]
fn an_aggregation_packet_is_split_into_its_nal_units_in_order() -> Result<()> {
    let payload = Bytes::from_static(&[
        0x60, 0x01, // PayloadHdr: type 48
        0x00, 0x04, 0x40, 0x01, 0x0C, 0x01, // VPS
        0x00, 0x05, 0x42, 0x01, 0x01, 0x02, 0x03, // SPS
        0x00, 0x03, 0x44, 0x01, 0xC1, // PPS
    ]);
    assert_eq!(
        annex_b(&[VPS, SPS, PPS]),
        H265Packet::default().depacketize(&payload)?
    );
    Ok(())
}

#[test]
fn fragmentation_units_are_reassembled_with_the_nal_unit_header_rebuilt() -> Result<()> {
    // LayerId 5 and TID 3 in the payload header, FuType 19: the NAL unit header is
    // (19 << 9) | (5 << 3) | 3 = 0x262B.
    let mut packet = H265Packet::default();
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x2B, 0x93, 1, 2]))?
            .is_empty()
    );
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x2B, 0x13, 3]))?
            .is_empty()
    );
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x26, 0x2B, 1, 2, 3, 4, 5]),
        packet.depacketize(&Bytes::from_static(&[0x62, 0x2B, 0x53, 4, 5]))?
    );
    Ok(())
}

#[test]
fn a_fragment_whose_start_was_lost_is_dropped() -> Result<()> {
    let mut packet = H265Packet::default();
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x01, 0x13, 3]))?
            .is_empty()
    );
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x01, 0x53, 4]))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn a_lost_middle_fragment_discards_the_nal_unit_when_sequence_numbers_are_given() -> Result<()> {
    // The audit's reproduction (bug 4), for the depacketizer: fragments 1, 2 and 4.
    let idr = big_idr(180);
    let fragments = HevcPayloader::default().payload(50, &annex_b(&[&idr]))?;
    assert_eq!(4, fragments.len());

    let mut packet = H265Packet::default();
    let mut out = BytesMut::new();
    for (sequence_number, fragment) in [(7u16, 0usize), (8, 1), (10, 3)] {
        out.put(packet.depacketize_with_sequence_number(sequence_number, &fragments[fragment])?);
    }
    assert!(out.is_empty(), "no NAL unit with a hole in it");

    let mut out = BytesMut::new();
    for (i, fragment) in fragments.iter().enumerate() {
        out.put(
            packet.depacketize_with_sequence_number(65535u16.wrapping_add(i as u16), fragment)?,
        );
    }
    assert_eq!(annex_b(&[&idr]), out.freeze());
    Ok(())
}

#[test]
fn fragment_reassembly_is_bounded() {
    let mut packet = H265Packet::default();
    let fragment = |fu_header: u8| {
        let mut payload = vec![0x62, 0x01, fu_header];
        payload.extend_from_slice(&[0xAA; 60_000]);
        Bytes::from(payload)
    };
    packet.depacketize(&fragment(0x93)).unwrap();
    let mut refused = false;
    for _ in 0..(MAX_H265_FU_NALU_SIZE / 60_000 + 10) {
        refused |= packet.depacketize(&fragment(0x13)).is_err();
        assert!(
            packet
                .fu_buffer
                .as_ref()
                .is_none_or(|buffer| buffer.len() <= MAX_H265_FU_NALU_SIZE)
        );
    }
    assert!(refused);
    // What follows the dropped NAL unit is not spliced onto anything.
    assert!(packet.depacketize(&fragment(0x53)).unwrap().is_empty());
}

#[test]
fn nothing_of_type_48_to_63_is_passed_on() -> Result<()> {
    // Section 6: NAL-unit-like structures of types 48 to 63 are not for the decoder.
    let mut packet = H265Packet::default();
    for reserved in 51..=63u8 {
        let payload = Bytes::from(vec![reserved << 1, 0x01, 1, 2, 3]);
        assert!(packet.depacketize(&payload)?.is_empty(), "type {reserved}");
    }
    // An aggregation packet holding an aggregation packet and a fragment: only the NAL unit.
    let payload = Bytes::from_static(&[
        0x60, 0x01, 0x00, 0x03, 0x60, 0x01, 0x00, 0x00, 0x03, 0x44, 0x01, 0xC1, 0x00, 0x04, 0x62,
        0x01, 0x93, 0x07,
    ]);
    assert_eq!(annex_b(&[PPS]), packet.depacketize(&payload)?);
    // A fragmented aggregation packet.
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x01, 0x80 | 48, 1]))?
            .is_empty()
    );
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x62, 0x01, 0x40 | 48, 2]))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn malformed_payloads_are_errors() {
    for payload in [
        &[0x60u8, 0x01][..],                         // an AP with nothing in it
        &[0x60, 0x01, 0x00, 0x03, 0x44, 0x01, 0xC1], // an AP with one unit
        &[0x60, 0x01, 0x00, 0x09, 0x44, 0x01],       // a unit longer than the packet
        &[0x62, 0x01],                               // an FU without its header
        &[0x62, 0x01, 0x93],                         // an FU with an empty payload
        &[0x64, 0x01, 0x00],                         // a PACI cut short
        &[0x64, 0x01, 0x00, 0x30, 0xCA],             // a PACI shorter than its PHSsize
        &[0xA6, 0x01, 0x00],                         // F bit set
    ] {
        assert!(
            H265Packet::default()
                .depacketize(&Bytes::copy_from_slice(payload))
                .is_err(),
            "{payload:02x?}"
        );
    }
}

// --- PACI and TSCI (4.4.4, 4.5) ---

#[test]
fn a_paci_packet_yields_the_nal_unit_it_carries() -> Result<()> {
    // PayloadHdr type 50, LayerId 0, TID 1; A=0, cType=19, PHSsize=3, F0=1; a TSCI; then the
    // IDR's payload. The NAL unit header is rebuilt from cType, LayerId and TID.
    let payload = Bytes::from_static(&[0x64, 0x01, 0x26, 0x38, 0xCA, 0xFE, 0x80, 0xAF, 0x08, 0x40]);
    let mut packet = H265Packet::default();
    assert_eq!(annex_b(&[IDR]), packet.depacketize(&payload)?);
    assert!(matches!(packet.payload(), H265Payload::H265PACIPacket(_)));
    Ok(())
}

#[test]
fn a_paci_packet_can_carry_fragments_and_an_aggregate() -> Result<()> {
    let mut packet = H265Packet::default();
    // cType 49 (FU), no PHES: bytes 2 and 3 are 0x62 0x00.
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x64, 0x01, 0x62, 0x00, 0x93, 1, 2]))?
            .is_empty()
    );
    assert_eq!(
        Bytes::from_static(&[0, 0, 0, 1, 0x26, 0x01, 1, 2, 3]),
        packet.depacketize(&Bytes::from_static(&[0x64, 0x01, 0x62, 0x00, 0x53, 3]))?
    );
    // cType 48 (AP).
    let payload = Bytes::from_static(&[
        0x64, 0x01, 0x60, 0x00, 0x00, 0x03, 0x44, 0x01, 0xC1, 0x00, 0x02, 0x48, 0x01,
    ]);
    assert_eq!(annex_b(&[PPS, EOS]), packet.depacketize(&payload)?);
    // A PACI in a PACI carries nothing a decoder may get.
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[
                0x64, 0x01, 0x64, 0x00, 0x26, 0x01, 0x07
            ]))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn the_reserved_paci_flags_and_their_extensions_are_ignored() -> Result<()> {
    // F0, F1, F2 and Y all set, PHSsize 5: three octets of TSCI and two a receiver does not
    // know. The carried NAL unit is the same.
    let payload = Bytes::from_static(&[
        0x64, 0x01, 0x26, 0x5F, 0xCA, 0xFE, 0x80, 0x99, 0x98, 0xAF, 0x08, 0x40,
    ]);
    let mut packet = H265Packet::default();
    assert_eq!(annex_b(&[IDR]), packet.depacketize(&payload)?);
    let H265Payload::H265PACIPacket(paci) = packet.payload() else {
        panic!("a PACI packet");
    };
    assert!(paci.f1() && paci.f2() && paci.y());
    assert_eq!(5, paci.phs_size());
    let tsci = paci.tsci().expect("F0 is set");
    assert_eq!(0xCA, tsci.tl0picidx());
    assert_eq!(0xFE, tsci.irap_pic_id());
    Ok(())
}

#[test]
fn the_tsci_is_read_from_the_first_three_octets_of_the_phes() -> Result<()> {
    // The audit's reproduction (bug 2): TL0PICIDX 0xCA, IrapPicID 0xFE, S=1 read as
    // TL0PICIDX 0, IrapPicID 0xCA.
    let mut packet = H265Packet::default();
    packet.depacketize(&Bytes::from_static(&[
        0x64, 0x01, 0x00, 0x38, 0xCA, 0xFE, 0x80, 0x02, 0x01, 0x07,
    ]))?;
    let H265Payload::H265PACIPacket(paci) = packet.payload() else {
        panic!("a PACI packet");
    };
    let tsci = paci.tsci().expect("F0 is set and PHSsize is 3");
    assert_eq!(0xCA, tsci.tl0picidx());
    assert_eq!(0xFE, tsci.irap_pic_id());
    assert!(tsci.s());
    assert!(!tsci.e());
    assert_eq!(0, tsci.res());

    // S=0, E=1, RES=0x2A in the third octet.
    packet.depacketize(&Bytes::from_static(&[
        0x64, 0x01, 0x00, 0x38, 0x01, 0x02, 0x6A, 0x02, 0x01, 0x07,
    ]))?;
    let H265Payload::H265PACIPacket(paci) = packet.payload() else {
        panic!("a PACI packet");
    };
    let tsci = paci.tsci().expect("F0 is set and PHSsize is 3");
    assert_eq!((1, 2), (tsci.tl0picidx(), tsci.irap_pic_id()));
    assert!(!tsci.s() && tsci.e());
    assert_eq!(0x2A, tsci.res());
    Ok(())
}

// --- The payloader (4.4, 5) ---

#[test]
fn start_codes_of_three_and_four_bytes_both_delimit_nal_units() -> Result<()> {
    // The audit's reproduction (bug 5): a four-byte code first and three-byte codes after
    // gave one "NAL unit" holding all three.
    let mut stream = vec![0, 0, 0, 1];
    stream.extend_from_slice(VPS);
    stream.extend_from_slice(&[0, 0, 1]);
    stream.extend_from_slice(SPS);
    stream.extend_from_slice(&[0, 0, 1]);
    stream.extend_from_slice(IDR);
    let payloads = HevcPayloader::default().payload(1200, &Bytes::from(stream))?;
    let mut packet = H265Packet::default();
    assert_eq!(
        annex_b(&[VPS, SPS, IDR]),
        depacketize_all(&mut packet, &payloads)?
    );
    Ok(())
}

#[test]
fn the_ap_header_has_the_or_of_the_f_bits_and_the_lowest_layer_id_and_tid() -> Result<()> {
    // LayerId 3 TID 4, and LayerId 2 TID 6 with F set.
    let a: &[u8] = &[0x40, (3 << 3) | 4, 0xAA];
    let b: &[u8] = &[0xC2, (2 << 3) | 6, 0xBB];
    let payloads = HevcPayloader::default().payload(1200, &annex_b(&[a, b]))?;
    assert_eq!(1, payloads.len());
    let header = H265NALUHeader::new(payloads[0][0], payloads[0][1]);
    assert!(header.f());
    assert_eq!(48, header.nalu_type());
    assert_eq!(2, header.layer_id());
    assert_eq!(4, header.tid());
    Ok(())
}

#[test]
fn an_ap_fills_the_mtu_and_no_further() -> Result<()> {
    // VPS (4), SPS (5), PPS (3): 2 + 6 + 7 + 5 = 20 bytes.
    let access_unit = annex_b(&[VPS, SPS, PPS]);
    let payloads = HevcPayloader::default().payload(20, &access_unit)?;
    assert_eq!(
        vec![20],
        payloads.iter().map(Bytes::len).collect::<Vec<_>>()
    );
    let payloads = HevcPayloader::default().payload(19, &access_unit)?;
    assert_eq!(
        vec![15, 3],
        payloads.iter().map(Bytes::len).collect::<Vec<_>>(),
        "AP(VPS, SPS), then the PPS as a single NAL unit packet"
    );
    Ok(())
}

#[test]
fn packet_type_nal_units_are_not_sent() -> Result<()> {
    // Types 48 to 50 as input would be nested aggregates, fragments or PACIs.
    for nalu_type in [48u8, 49, 50, 55, 63] {
        let mut small = vec![nalu_type << 1, 0x01, 1, 2];
        let payloads = HevcPayloader::default().payload(100, &annex_b(&[&small, IDR]))?;
        assert_eq!(vec![Bytes::from_static(IDR)], payloads, "type {nalu_type}");
        small.extend_from_slice(&[0; 300]);
        assert!(
            HevcPayloader::default()
                .payload(100, &annex_b(&[&small]))?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn fragments_carry_f_layer_id_tid_and_s_and_e_once_each() -> Result<()> {
    let mut nalu = vec![0xA6, (7 << 3) | 2];
    nalu.extend((0..200).map(|i| i as u8));
    let payloads = HevcPayloader::default().payload(60, &annex_b(&[&nalu]))?;
    assert!(payloads.len() >= 2);
    let last = payloads.len() - 1;
    for (i, payload) in payloads.iter().enumerate() {
        let header = H265NALUHeader::new(payload[0], payload[1]);
        assert!(header.f());
        assert_eq!(49, header.nalu_type());
        assert_eq!(7, header.layer_id());
        assert_eq!(2, header.tid());
        assert_eq!(i == 0, payload[2] & 0x80 != 0);
        assert_eq!(i == last, payload[2] & 0x40 != 0);
        assert_eq!(19, payload[2] & 0x3F);
        assert!(payload.len() > 3 && payload.len() <= 60);
    }
    Ok(())
}

// --- Decoding order numbers (4.4.1 to 4.4.3, 4.6, 6) ---

#[test]
fn without_donl_no_packet_carries_a_decoding_order_number() -> Result<()> {
    // sprop-max-don-diff 0: DONL and DOND are absent.
    let payloads = HevcPayloader::default().payload(1200, &annex_b(&[VPS, SPS]))?;
    assert_eq!(
        &[
            0x60, 0x01, 0, 4, 0x40, 0x01, 0x0C, 0x01, 0, 5, 0x42, 0x01, 0x01, 0x02, 0x03
        ],
        &payloads[0][..]
    );
    let mut packet = H265Packet::default();
    let units = packet.nal_units(&payloads[0])?;
    assert!(units.iter().all(|unit| unit.don.is_none()));
    Ok(())
}

#[test]
fn with_donl_every_packet_form_carries_its_decoding_order_number() -> Result<()> {
    let idr = big_idr(100);
    let mut payloader = HevcPayloader::with_donl(65534);
    let payloads = payloader.payload(40, &annex_b(&[VPS, SPS, &idr, PPS]))?;

    // AP: DONL of the first unit, DOND 0 for the next (DON = previous + DOND + 1).
    assert_eq!(
        &[
            0x60, 0x01, 0xFF, 0xFE, 0, 4, 0x40, 0x01, 0x0C, 0x01, 0x00, 0, 5, 0x42, 0x01, 0x01,
            0x02, 0x03
        ],
        &payloads[0][..]
    );
    // FU: DONL in the first fragment only.
    assert_eq!(&[0x62, 0x01, 0x93, 0x00, 0x00], &payloads[1][..5]);
    assert_eq!(
        &[0x62, 0x01, 0x13, 0x23],
        &payloads[2][..4],
        "no DONL after the first"
    );
    // Single NAL unit packet: the DONL after the payload header.
    let last = payloads.len() - 1;
    assert_eq!(&[0x44, 0x01, 0x00, 0x01, 0xC1], &payloads[last][..]);
    assert!(payloads.iter().all(|payload| payload.len() <= 40));

    let mut packet = H265Packet::default();
    packet.with_donl(true);
    let mut units = vec![];
    for payload in &payloads {
        units.extend(packet.nal_units(payload)?);
    }
    assert_eq!(
        vec![Some(65534), Some(65535), Some(0), Some(1)],
        units.iter().map(|unit| unit.don).collect::<Vec<_>>()
    );
    assert_eq!(
        vec![
            Bytes::from_static(VPS),
            Bytes::from_static(SPS),
            Bytes::from(idr),
            Bytes::from_static(PPS)
        ],
        units.into_iter().map(|unit| unit.data).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn with_donl_a_nal_unit_is_never_sent_in_one_fragment() -> Result<()> {
    // Too large for a single NAL unit packet with its DONL, small enough for one FU.
    for len in [37usize, 38, 39, 40, 41] {
        let idr = big_idr(len - 2);
        let payloads = HevcPayloader::with_donl(9).payload(40, &annex_b(&[&idr]))?;
        if payloads.len() == 1 {
            assert_eq!(len + 2, payloads[0].len(), "a single NAL unit packet");
            continue;
        }
        assert_eq!(0x93, payloads[0][2], "S without E");
        assert_eq!(0x53, payloads[payloads.len() - 1][2], "E without S");
        let mut packet = H265Packet::default();
        packet.with_donl(true);
        let mut units = vec![];
        for payload in &payloads {
            assert!(payload.len() <= 40);
            units.extend(packet.nal_units(payload)?);
        }
        assert_eq!(
            vec![H265NalUnit {
                data: Bytes::from(idr),
                don: Some(9)
            }],
            units
        );
    }
    Ok(())
}

#[test]
fn dond_gives_each_aggregated_unit_its_don() -> Result<()> {
    // DONL 65530; DOND 4 and 0: 65530, 65535, 0.
    let payload = Bytes::from_static(&[
        0x60, 0x01, 0xFF, 0xFA, 0x00, 0x02, 0x48, 0x01, 0x04, 0x00, 0x02, 0x4A, 0x01, 0x00, 0x00,
        0x03, 0x44, 0x01, 0xC1,
    ]);
    let mut packet = H265Packet::default();
    packet.with_donl(true);
    let units = packet.nal_units(&payload)?;
    assert_eq!(
        vec![Some(65530), Some(65535), Some(0)],
        units.iter().map(|unit| unit.don).collect::<Vec<_>>()
    );
    Ok(())
}

fn numbered(don: u16) -> H265NalUnit {
    H265NalUnit {
        data: Bytes::from(vec![0x02, 0x01, don as u8]),
        don: Some(don),
    }
}

fn dons(units: &[H265NalUnit]) -> Vec<u16> {
    units.iter().filter_map(|unit| unit.don).collect()
}

#[test]
fn the_depacketization_buffer_passes_nal_units_on_by_abs_don() {
    // Condition A: a spread of sprop-max-don-diff (3) or more releases the smallest.
    let mut buffer = H265DepacketizationBuffer::new(3, 100);
    let mut out = vec![];
    for don in [2u16, 0, 1, 4, 3, 6, 5] {
        out.extend(buffer.push(numbered(don)));
    }
    assert_eq!(vec![0, 1, 2, 3], dons(&out));
    assert_eq!(vec![4, 5, 6], dons(&buffer.flush()));
    assert!(buffer.is_empty());
}

#[test]
fn the_depacketization_buffer_holds_no_more_than_sprop_depack_buf_nalus() {
    // Condition B: more than two NAL units in the buffer releases the smallest.
    let mut buffer = H265DepacketizationBuffer::new(1000, 2);
    let mut out = vec![];
    for don in [3u16, 1, 2, 0, 5, 4] {
        out.extend(buffer.push(numbered(don)));
        assert!(buffer.len() <= 2);
    }
    // 0 arrived after 1 had left: it is the smallest in the buffer, so it leaves next.
    assert_eq!(vec![1, 0, 2, 3], dons(&out));
}

#[test]
fn abs_don_orders_across_the_don_wrap() {
    let mut buffer = H265DepacketizationBuffer::new(2, 100);
    let mut out = vec![];
    for don in [65534u16, 0, 65535, 2, 1] {
        out.extend(buffer.push(numbered(don)));
    }
    out.extend(buffer.flush());
    assert_eq!(vec![65534, 65535, 0, 1, 2], dons(&out));
}

#[test]
fn the_depacketization_buffer_is_bounded() {
    let mut buffer = H265DepacketizationBuffer::new(32767, 32767);
    for don in 0..(MAX_DEPACKETIZATION_NAL_UNITS as u16 + 100) {
        buffer.push(numbered(don));
        assert!(buffer.len() <= MAX_DEPACKETIZATION_NAL_UNITS);
    }
}

#[test]
fn a_stream_with_decoding_order_numbers_is_received_in_decoding_order() -> Result<()> {
    // Single NAL unit packets with DONL, sent out of decoding order.
    let mut receiver = H265Packet::default();
    receiver.with_depacketization_buffer(H265DepacketizationBuffer::new(2, 10));
    let mut out = BytesMut::new();
    for don in [1u16, 0, 3, 2, 4] {
        let payload = Bytes::from(vec![0x02, 0x01, 0x00, don as u8, 0xD0 | don as u8]);
        out.put(receiver.depacketize(&payload)?);
    }
    out.put(receiver.flush_depacketization_buffer());
    let expected: Vec<Vec<u8>> = (0..5u8).map(|don| vec![0x02, 0x01, 0xD0 | don]).collect();
    let expected: Vec<&[u8]> = expected.iter().map(|nalu| &nalu[..]).collect();
    assert_eq!(annex_b(&expected), out.freeze());
    Ok(())
}

// --- Several RTP streams of one bitstream: MRST and MRMT (4.3, 4.6, 6) ---

/// A single NAL unit packet of layer `layer` (type 1, TID 1) with DONL `don`; the NAL unit's
/// one octet of payload is `mark`.
fn layered_with_donl(layer: u8, don: u16, mark: u8) -> Bytes {
    let [high, low] = don.to_be_bytes();
    Bytes::from(vec![0x02, (layer << 3) | 1, high, low, mark])
}

/// The same packet without DONL.
fn layered(layer: u8, mark: u8) -> Bytes {
    Bytes::from(vec![0x02, (layer << 3) | 1, mark])
}

fn marks(units: &[H265NalUnit]) -> Vec<u8> {
    units.iter().map(|unit| unit.data[2]).collect()
}

/// RFC 7798 section 4.3: "Receivers MUST support all of SRST, MRST, and MRMT"; section 6:
/// with `sprop-max-don-diff` above 0 the NAL units of all the RTP streams of a bitstream go
/// into one de-packetization buffer and leave by AbsDon (section 4.6, derived along each
/// stream), whenever condition A holds. A base layer stream carries the even decoding order
/// numbers and an enhancement layer stream the odd ones, across the DON wrap, and each
/// enhancement packet arrives before the base packet that precedes it in decoding order.
#[test]
fn nal_units_of_several_rtp_streams_are_passed_on_in_cross_stream_decoding_order() -> Result<()> {
    const BASE: u32 = 0x1000;
    const ENHANCEMENT: u32 = 0x2000;
    let mut receiver = H265MultiStreamDepacketizer::new(100);
    receiver.add_stream(BASE, 2);
    receiver.add_stream(ENHANCEMENT, 2);

    let arrivals: [(u32, u8, u16, u16); 8] = [
        (ENHANCEMENT, 1, 10, 65535),
        (BASE, 0, 20, 65534),
        (ENHANCEMENT, 1, 11, 1),
        (BASE, 0, 21, 0),
        (ENHANCEMENT, 1, 12, 3),
        (BASE, 0, 22, 2),
        (ENHANCEMENT, 1, 13, 5),
        (BASE, 0, 23, 4),
    ];
    let mut out = vec![];
    let mut released_while_receiving = 0;
    for (stream, layer, sequence_number, don) in arrivals {
        let units = receiver.push(
            stream,
            sequence_number,
            0,
            &layered_with_donl(layer, don, don as u8),
        )?;
        released_while_receiving += units.len();
        out.extend(units);
    }
    assert!(
        released_while_receiving >= 4,
        "condition A passes NAL units on while the streams play, not only at the end"
    );
    out.extend(receiver.flush());
    let expected: Vec<u8> = [65534u16, 65535, 0, 1, 2, 3, 4, 5]
        .iter()
        .map(|don| *don as u8)
        .collect();
    assert_eq!(expected, marks(&out));
    // Each NAL unit keeps the layer of the stream it came in.
    assert!(
        out.iter()
            .all(|unit| (unit.data[1] >> 3 == 1) == (unit.don.unwrap() % 2 == 1))
    );
    Ok(())
}

/// RFC 7798 section 6, `sprop-max-don-diff` 0 for every stream: "the NAL units carried in the
/// multiple RTP streams are passed to the decoder in their NTP timestamp order", of the same
/// timestamp the dependee stream's first, one stream's in transmission order. Duplicated and
/// outdated packets are removed. The enhancement stream's packet of each access unit arrives
/// first.
#[test]
fn without_decoding_order_numbers_several_streams_are_ordered_by_ntp_timestamp_and_dependency()
-> Result<()> {
    const BASE: u32 = 1;
    const ENHANCEMENT: u32 = 2;
    let mut receiver = H265MultiStreamDepacketizer::new(0);
    receiver.add_stream(BASE, 0);
    receiver.add_stream(ENHANCEMENT, 0);

    // (stream, layer, sequence number, NTP timestamp, mark): mark 0xA_ is the base layer's
    // NAL unit of access unit _, 0xB_ the enhancement layer's.
    let arrivals: [(u32, u8, u16, u64, u8); 9] = [
        (ENHANCEMENT, 1, 500, 100, 0xB1),
        (BASE, 0, 7, 100, 0xA1),
        (ENHANCEMENT, 1, 501, 200, 0xB2),
        (BASE, 0, 8, 200, 0xA2),
        // A duplicate and an outdated packet.
        (BASE, 0, 8, 200, 0xA2),
        (ENHANCEMENT, 1, 500, 100, 0xB1),
        (BASE, 0, 9, 300, 0xA3),
        (BASE, 0, 10, 300, 0xA4),
        (ENHANCEMENT, 1, 502, 300, 0xB3),
    ];
    let mut out = vec![];
    for (stream, layer, sequence_number, ntp, mark) in arrivals {
        out.extend(receiver.push(stream, sequence_number, ntp, &layered(layer, mark))?);
    }
    out.extend(receiver.flush());
    assert_eq!(vec![0xA1, 0xB1, 0xA2, 0xB2, 0xA3, 0xA4, 0xB3], marks(&out));
    Ok(())
}

/// A packet of a stream that was not added gives nothing, and the buffer stays bounded however
/// long a dependee stays silent.
#[test]
fn the_multi_stream_receiver_is_bounded() -> Result<()> {
    let mut receiver = H265MultiStreamDepacketizer::new(0);
    receiver.add_stream(1, 0);
    receiver.add_stream(2, 0);
    assert!(receiver.push(9, 0, 0, &layered(0, 1))?.is_empty());
    for n in 0..(MAX_DEPACKETIZATION_NAL_UNITS as u16 + 100) {
        receiver.push(2, n, u64::from(n), &layered(1, 1))?;
        assert!(receiver.len() <= MAX_DEPACKETIZATION_NAL_UNITS);
    }
    Ok(())
}
