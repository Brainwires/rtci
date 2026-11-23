//! RFC 6184 interleaved mode (`packetization-mode=2`): STAP-B, MTAP16, MTAP24, FU-B, decoding
//! order numbers and the de-interleaving buffer.

use super::*;

const SPS: &[u8] = &[0x67, 0x42, 0xC0, 0x1F];
const PPS: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];
const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33];

fn annex_b(nalus: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for nalu in nalus {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nalu);
    }
    Bytes::from(out)
}

fn slice(tag: u8) -> Bytes {
    Bytes::from(vec![0x41, tag])
}

fn unit(don: u16, data: Bytes) -> H264NalUnit {
    H264NalUnit {
        data,
        don: Some(don),
        timestamp_offset: None,
    }
}

fn tags(units: &[H264NalUnit]) -> Vec<u8> {
    units.iter().map(|unit| unit.data[1]).collect()
}

// --- don_diff (5.5) ---

#[test]
fn don_diff_follows_the_five_cases_of_section_5_5() {
    assert_eq!(0, don_diff(7, 7));
    assert_eq!(3, don_diff(7, 10));
    assert_eq!(32767, don_diff(0, 32767));
    // DON(m) > DON(n) and DON(m) - DON(n) >= 32768: n is after the wrap.
    assert_eq!(6, don_diff(65533, 3));
    assert_eq!(32768, don_diff(32768, 0));
    // DON(m) < DON(n) and DON(n) - DON(m) >= 32768: n is before the wrap.
    assert_eq!(-6, don_diff(3, 65533));
    assert_eq!(-32768, don_diff(0, 32768));
    // DON(m) > DON(n) and DON(m) - DON(n) < 32768.
    assert_eq!(-3, don_diff(10, 7));
}

// --- The payloader in mode 2 (6.4, 5.7.1, 5.8) ---

#[test]
fn mode_2_sends_stap_b_and_fu_b_only_and_numbers_nal_units_in_order() -> Result<()> {
    let mut big = vec![0x65];
    big.extend((0..300).map(|i| i as u8));
    let mut payloader = H264Payloader::with_packetization_mode(2).with_initial_don(65534);
    let payloads = payloader.payload(100, &annex_b(&[SPS, PPS, &big, IDR]))?;

    // STAP-B(SPS, PPS) with DON 65534; FU-B + FU-As with DON 0; STAP-B(IDR) with DON 1.
    assert_eq!(
        &[
            0x79, 0xFF, 0xFE, 0, 4, 0x67, 0x42, 0xC0, 0x1F, 0, 4, 0x68, 0xCE, 0x3C, 0x80
        ],
        &payloads[0][..]
    );
    assert_eq!(
        &[0x7D, 0x85, 0x00, 0x00],
        &payloads[1][..4],
        "FU-B: S, type 5, DON 0"
    );
    let last = payloads.len() - 1;
    for payload in &payloads[2..last] {
        assert_eq!(0x7C, payload[0], "the fragments after the first are FU-As");
    }
    assert_eq!(FU_END_BITMASK | 5, payloads[last - 1][1]);
    assert_eq!(&[0x79, 0x00, 0x01, 0, 5], &payloads[last][..5]);
    for payload in &payloads {
        assert!(payload.len() <= 100);
        let packet_type = payload[0] & NALU_TYPE_BITMASK;
        assert!(
            [STAPB_NALU_TYPE, FUB_NALU_TYPE, FUA_NALU_TYPE].contains(&packet_type),
            "no single NAL unit packet and no STAP-A in mode 2: type {packet_type}"
        );
    }

    // The receiver gets each NAL unit with its DON: consecutive, across the wrap.
    let mut packet = H264Packet::default();
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
            Bytes::from_static(SPS),
            Bytes::from_static(PPS),
            Bytes::from(big),
            Bytes::from_static(IDR)
        ],
        units.into_iter().map(|unit| unit.data).collect::<Vec<_>>()
    );

    // The numbering goes on in the next access unit.
    let next = payloader.payload(100, &annex_b(&[IDR]))?;
    assert_eq!(&[0x79, 0x00, 0x02], &next[0][..3]);
    Ok(())
}

#[test]
fn mode_2_never_sends_a_nal_unit_in_one_fragment() -> Result<()> {
    // Too large for a STAP-B (3 + 2 + len > mtu) and small enough for one FU-B.
    for len in [16usize, 17, 18, 19, 20, 60] {
        let mut nalu = vec![0x65];
        nalu.extend((0..len - 1).map(|i| i as u8));
        let payloads = H264Payloader::with_packetization_mode(2).payload(20, &annex_b(&[&nalu]))?;
        assert!(payloads.len() >= 2, "len {len}");
        assert_eq!(FUB_NALU_TYPE, payloads[0][0] & NALU_TYPE_BITMASK);
        assert_eq!(FU_START_BITMASK | 5, payloads[0][1], "S without E");
        assert_eq!(
            FU_END_BITMASK | 5,
            payloads[payloads.len() - 1][1],
            "E without S"
        );
        assert!(payloads.iter().all(|payload| payload.len() <= 20));

        let mut packet = H264Packet::default();
        let mut units = vec![];
        for payload in &payloads {
            units.extend(packet.nal_units(payload)?);
        }
        assert_eq!(vec![unit(0, Bytes::from(nalu))], units);
    }
    Ok(())
}

// --- STAP-B (5.7.1) ---

#[test]
fn stap_b_units_take_consecutive_dons() -> Result<()> {
    let payload = stap_b(
        65535,
        &[
            Bytes::from_static(SPS),
            Bytes::from_static(PPS),
            Bytes::from_static(IDR),
        ],
    )?;
    assert_eq!(0x79, payload[0], "NRI 3, type 25");
    assert_eq!(&[0xFF, 0xFF], &payload[1..3]);
    let units = H264Packet::default().nal_units(&payload)?;
    assert_eq!(
        vec![
            unit(65535, Bytes::from_static(SPS)),
            unit(0, Bytes::from_static(PPS)),
            unit(1, Bytes::from_static(IDR)),
        ],
        units
    );
    // Without a de-interleaving buffer the NAL units come out in the packet's order.
    assert_eq!(
        annex_b(&[SPS, PPS, IDR]),
        H264Packet::default().depacketize(&payload)?
    );
    Ok(())
}

// --- MTAP (5.7.2) ---

#[test]
fn an_mtap16_carries_don_base_dond_and_timestamp_offsets() -> Result<()> {
    let units = [
        MtapUnit {
            don: 12,
            timestamp: 93_000,
            nalu: slice(0xB),
        },
        MtapUnit {
            don: 10,
            timestamp: 90_000,
            nalu: slice(0xA),
        },
    ];
    let (payload, timestamp) = mtap(MtapKind::Mtap16, &units)?;
    assert_eq!(90_000, timestamp, "the earliest NALU-time");
    assert_eq!(
        &[
            0x5A, // NRI 2, type 26
            0x00, 0x0A, // DONB: the DON of the first NAL unit in decoding order
            0x00, 0x02, 0x02, 0x0B, 0xB8, 0x41, 0x0B, // size 2, DOND 2, TS offset 3000
            0x00, 0x02, 0x00, 0x00, 0x00, 0x41, 0x0A, // size 2, DOND 0, TS offset 0
        ],
        &payload[..]
    );
    let parsed = H264Packet::default().nal_units(&payload)?;
    assert_eq!(
        vec![
            H264NalUnit {
                data: slice(0xB),
                don: Some(12),
                timestamp_offset: Some(3000),
            },
            H264NalUnit {
                data: slice(0xA),
                don: Some(10),
                timestamp_offset: Some(0),
            },
        ],
        parsed
    );
    Ok(())
}

#[test]
fn an_mtap24_has_three_byte_offsets_and_wraps_don_and_timestamp() -> Result<()> {
    let units = [
        MtapUnit {
            don: 65535,
            timestamp: u32::MAX - 999,
            nalu: slice(1),
        },
        MtapUnit {
            don: 1,
            timestamp: 99_000,
            nalu: slice(2),
        },
    ];
    let (payload, timestamp) = mtap(MtapKind::Mtap24, &units)?;
    assert_eq!(u32::MAX - 999, timestamp);
    assert_eq!(0x5B, payload[0], "type 27");
    assert_eq!(&[0xFF, 0xFF], &payload[1..3], "DONB 65535");
    // Second unit: DOND 2 (65535 -> 1), offset 100000 = 0x0186A0.
    assert_eq!(
        &[0x00, 0x02, 0x02, 0x01, 0x86, 0xA0, 0x41, 0x02],
        &payload[11..]
    );
    let parsed = H264Packet::default().nal_units(&payload)?;
    assert_eq!(
        vec![Some(65535), Some(1)],
        parsed.iter().map(|u| u.don).collect::<Vec<_>>()
    );
    assert_eq!(
        vec![Some(0), Some(100_000)],
        parsed
            .iter()
            .map(|u| u.timestamp_offset)
            .collect::<Vec<_>>()
    );
    // NALU-time is the packet's timestamp plus the offset, modulo 2^32.
    assert_eq!(99_000, timestamp.wrapping_add(100_000));
    Ok(())
}

#[test]
fn an_mtap_refuses_what_its_fields_cannot_express() {
    let two = |don_b: u16, timestamp_b: u32| {
        [
            MtapUnit {
                don: 0,
                timestamp: 0,
                nalu: slice(1),
            },
            MtapUnit {
                don: don_b,
                timestamp: timestamp_b,
                nalu: slice(2),
            },
        ]
    };
    assert!(mtap(MtapKind::Mtap16, &two(255, 65535)).is_ok());
    assert!(
        mtap(MtapKind::Mtap16, &two(256, 0)).is_err(),
        "DOND is 8 bits"
    );
    assert!(
        mtap(MtapKind::Mtap16, &two(1, 65536)).is_err(),
        "16-bit offset"
    );
    assert!(mtap(MtapKind::Mtap24, &two(1, 65536)).is_ok());
    assert!(
        mtap(MtapKind::Mtap24, &two(1, 1 << 24)).is_err(),
        "24-bit offset"
    );
    assert!(mtap(MtapKind::Mtap16, &[]).is_err());
}

// --- FU-B (5.8) ---

#[test]
fn a_nal_unit_whose_first_fragment_is_an_fu_b_has_its_don() -> Result<()> {
    let mut packet = H264Packet::default();
    assert!(
        packet
            .nal_units(&Bytes::from_static(&[0x7D, 0x85, 0x12, 0x34, 1, 2]))?
            .is_empty()
    );
    assert!(
        packet
            .nal_units(&Bytes::from_static(&[0x7C, 0x05, 3]))?
            .is_empty()
    );
    assert_eq!(
        vec![unit(0x1234, Bytes::from_static(&[0x65, 1, 2, 3, 4]))],
        packet.nal_units(&Bytes::from_static(&[0x7C, 0x45, 4]))?
    );
    // A NAL unit that starts with an FU-A afterwards has none.
    assert!(
        packet
            .nal_units(&Bytes::from_static(&[0x7C, 0x85, 1]))?
            .is_empty()
    );
    let units = packet.nal_units(&Bytes::from_static(&[0x7C, 0x45, 2]))?;
    assert_eq!(None, units[0].don);
    Ok(())
}

// --- The de-interleaving buffer (7.2.2) ---

#[test]
fn nal_units_leave_the_buffer_in_decoding_order() {
    // sprop-interleaving-depth 2: the buffer holds two VCL NAL units and passes on the third.
    let mut buffer = H264DeinterleavingBuffer::new(2, None);
    let mut out = vec![];
    for (don, tag) in [(2u16, 2u8), (1, 1), (4, 4), (3, 3), (6, 6), (5, 5)] {
        out.extend(buffer.push(unit(don, slice(tag))));
        assert!(buffer.len() <= 2);
    }
    assert_eq!(vec![1, 2, 3, 4], tags(&out));
    assert_eq!(vec![5, 6], tags(&buffer.flush()));
    assert!(buffer.is_empty());
}

#[test]
fn a_depth_of_zero_passes_each_vcl_nal_unit_straight_on() {
    let mut buffer = H264DeinterleavingBuffer::new(0, None);
    assert_eq!(vec![1], tags(&buffer.push(unit(1, slice(1)))));
    assert_eq!(vec![2], tags(&buffer.push(unit(2, slice(2)))));
}

#[test]
fn only_vcl_nal_units_count_towards_the_depth() {
    let mut buffer = H264DeinterleavingBuffer::new(1, None);
    let sps = unit(1, Bytes::from_static(SPS));
    let pps = unit(2, Bytes::from_static(PPS));
    assert!(buffer.push(pps.clone()).is_empty());
    assert!(buffer.push(sps.clone()).is_empty());
    assert!(
        buffer.push(unit(3, slice(3))).is_empty(),
        "one VCL NAL unit: N - 1"
    );
    // The second VCL NAL unit makes N: NAL units leave, in DON order, until N - 1 are left.
    let out = buffer.push(unit(4, slice(4)));
    assert_eq!(vec![sps, pps, unit(3, slice(3))], out);
    assert_eq!(1, buffer.len());
}

#[test]
fn the_buffer_orders_across_the_don_wrap() {
    let mut buffer = H264DeinterleavingBuffer::new(1, None);
    let mut out = vec![];
    for (don, tag) in [(65534u16, 1u8), (65535, 2), (1, 4), (0, 3), (2, 5)] {
        out.extend(buffer.push(unit(don, slice(tag))));
    }
    out.extend(buffer.flush());
    assert_eq!(vec![1, 2, 3, 4, 5], tags(&out));
}

#[test]
fn sprop_max_don_diff_releases_nal_units_too_far_behind_the_latest() {
    // A deep buffer that would hold everything, and a DON spread limit of 3.
    let mut buffer = H264DeinterleavingBuffer::new(100, Some(3));
    assert!(buffer.push(unit(10, slice(10))).is_empty());
    assert!(buffer.push(unit(12, slice(12))).is_empty());
    assert!(
        buffer.push(unit(13, slice(13))).is_empty(),
        "13 - 10 = 3: not greater"
    );
    assert_eq!(vec![10], tags(&buffer.push(unit(14, slice(14)))));
    // 20 is more than 3 after 12, 13 and 14: they leave in order.
    assert_eq!(vec![12, 13, 14], tags(&buffer.push(unit(20, slice(20)))));
    assert_eq!(1, buffer.len());
}

/// RFC 6184 section 7.2.2 and 8.1: initial buffering lasts `sprop-init-buf-time` (90 kHz
/// ticks) from the first NAL unit, unless the depth is reached first.
#[test]
fn initial_buffering_lasts_the_signalled_init_buf_time() {
    let start = std::time::Instant::now();
    let ms = std::time::Duration::from_millis;
    // 9000 ticks: 100 ms; a depth the two NAL units do not reach.
    let mut buffer = H264DeinterleavingBuffer::new(4, None).with_init_buf_time(9_000);
    assert!(buffer.is_initial_buffering(start));
    assert!(buffer.push_at(start, unit(2, slice(2))).is_empty());
    assert!(buffer.push_at(start + ms(40), unit(1, slice(1))).is_empty());
    assert!(buffer.is_initial_buffering(start + ms(99)));
    assert!(!buffer.is_initial_buffering(start + ms(100)));
}

/// Initial buffering ends as soon as the buffer holds N VCL NAL units, before the time; and
/// without `sprop-init-buf-time` only the depth (or the DON spread) ends it.
#[test]
fn initial_buffering_ends_at_the_depth_before_the_time() {
    let start = std::time::Instant::now();
    let later = start + std::time::Duration::from_secs(5);
    let mut timed = H264DeinterleavingBuffer::new(1, None).with_init_buf_time(900_000);
    let mut untimed = H264DeinterleavingBuffer::new(1, None);
    for buffer in [&mut timed, &mut untimed] {
        assert!(buffer.push_at(start, unit(1, slice(1))).is_empty());
        assert!(
            buffer.is_initial_buffering(later),
            "10 s not passed, depth not reached"
        );
        assert_eq!(vec![1], tags(&buffer.push_at(start, unit(2, slice(2)))));
        assert!(!buffer.is_initial_buffering(start));
    }
}

#[test]
fn the_buffer_is_bounded_whatever_the_parameters_say() {
    let mut buffer = H264DeinterleavingBuffer::new(32767, None);
    let mut released = 0;
    for don in 0..(MAX_DEINTERLEAVING_NAL_UNITS as u16 + 50) {
        released += buffer.push(unit(don, slice(0))).len();
        assert!(buffer.len() <= MAX_DEINTERLEAVING_NAL_UNITS);
    }
    assert_eq!(50, released);
}

#[test]
fn a_nal_unit_without_a_don_passes_through_the_buffer() {
    let mut buffer = H264DeinterleavingBuffer::new(5, None);
    let plain = H264NalUnit {
        data: slice(9),
        don: None,
        timestamp_offset: None,
    };
    assert_eq!(vec![plain.clone()], buffer.push(plain));
    assert!(buffer.is_empty());
}

#[test]
fn an_interleaved_stream_is_received_in_decoding_order() -> Result<()> {
    // Six slices, DON 0 to 5, sent as STAP-Bs in the order 1, 0, 3, 2, 5, 4.
    let mut receiver =
        H264Packet::default().with_deinterleaving(H264DeinterleavingBuffer::new(2, None));
    let mut out = BytesMut::new();
    for don in [1u16, 0, 3, 2, 5, 4] {
        let payload = stap_b(don, &[slice(don as u8)])?;
        out.put(receiver.depacketize(&payload)?);
    }
    out.put(receiver.flush_deinterleaving());
    let expected: Vec<Bytes> = (0..6u8).map(slice).collect();
    let expected: Vec<&[u8]> = expected.iter().map(|b| &b[..]).collect();
    assert_eq!(annex_b(&expected), out.freeze());
    Ok(())
}
