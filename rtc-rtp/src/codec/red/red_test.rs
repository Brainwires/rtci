use super::*;

fn b(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

fn filled(len: usize, value: u8) -> Bytes {
    Bytes::from(vec![value; len])
}

// ---- format ------------------------------------------------------------------------------

#[test]
fn rfc2198_section7_example_dvi4_primary_with_lpc_redundancy() {
    // DVI4 primary (PT 5, 84 bytes) and one LPC redundant block (PT 7, 14 bytes), both 20 ms
    // at 8 kHz, so the redundancy is 160 timestamp units old.
    let lpc = filled(14, 0x11);
    let dvi = filled(84, 0x22);
    let packet = RedPacket::new(5, dvi.clone(), [(7, 160, lpc.clone())]).unwrap();
    let raw = packet.marshal().unwrap();
    // F=1 PT=7 | offset 160 | length 14, then F=0 PT=5.
    assert_eq!(&raw[..5], &[0x87, 0x02, 0x80, 0x0E, 0x05]);
    assert_eq!(&raw[5..19], lpc.as_ref());
    assert_eq!(&raw[19..], dvi.as_ref());
    assert_eq!(raw.len(), 5 + 14 + 84);

    let parsed = RedPacket::parse(&raw.freeze()).unwrap();
    assert_eq!(parsed, packet);
    assert_eq!(
        parsed.redundant(),
        &[RedBlock {
            payload_type: 7,
            timestamp_offset: 160,
            data: lpc,
            primary: false
        }]
    );
    assert_eq!(parsed.primary(), &RedBlock::primary(5, dvi));
}

#[test]
fn rfc4733_figure5_tone_primary_with_event_redundancy() {
    // RFC 4733 Figure 5: RED PT 102, timestamp 12800; redundant telephone-event block (PT 100,
    // offset 1600, 4 bytes), primary tone block (PT 101).
    let raw: [u8; 17] = [
        0xE4, 0x19, 0x00, 0x04, 0x65, // headers
        0x01, 0x94, 0x06, 0xE0, // event 1, E, volume 20, duration 1760
        0x00, 0x14, 0x00, 0xA0, 0x02, 0xB9, 0x04, 0xB9, // tone 697 + 1209 Hz, duration 160
    ];
    let parsed = RedPacket::parse(&Bytes::copy_from_slice(&raw)).unwrap();
    assert_eq!(parsed.blocks().len(), 2);
    let event = &parsed.redundant()[0];
    assert_eq!(
        (
            event.payload_type,
            event.timestamp_offset,
            event.data.as_ref()
        ),
        (100, 1600, &raw[5..9])
    );
    assert_eq!(event.timestamp(12800), 11200);
    let tone = parsed.primary();
    assert_eq!((tone.payload_type, tone.data.as_ref()), (101, &raw[9..]));
    assert_eq!(tone.timestamp(12800), 12800);
    assert_eq!(parsed.marshal().unwrap().as_ref(), &raw);
}

#[test]
fn primary_only_payload_is_one_header_byte() {
    let packet = RedPacket::new(111, b(&[1, 2, 3]), []).unwrap();
    let raw = packet.marshal().unwrap();
    assert_eq!(raw.as_ref(), &[111, 1, 2, 3]);
    assert_eq!(RedPacket::parse(&raw.freeze()).unwrap(), packet);
}

#[test]
fn an_empty_primary_is_accepted() {
    let raw = Bytes::from_static(&[0x80 | 111, 0x00, 0x0C, 0x02, 111, 0xAA, 0xBB]);
    let parsed = RedPacket::parse(&raw).unwrap();
    assert!(parsed.primary().data.is_empty());
    assert_eq!(parsed.redundant()[0].data.as_ref(), &[0xAA, 0xBB]);
    assert_eq!(parsed.redundant()[0].timestamp_offset, 3);
    assert_eq!(parsed.marshal().unwrap().freeze(), raw);
}

#[test]
fn data_blocks_follow_the_headers_in_order_without_padding() {
    let packet = RedPacket::new(
        3,
        b(&[0xC0]),
        [(1, 0x3FFF, b(&[0xA0, 0xA1])), (2, 7, b(&[0xB0]))],
    )
    .unwrap();
    let raw = packet.marshal().unwrap();
    assert_eq!(
        raw.as_ref(),
        &[
            0x81, 0xFF, 0xFC, 0x02, // PT 1, offset 0x3FFF, len 2
            0x82, 0x00, 0x1C, 0x01, // PT 2, offset 7, len 1
            0x03, // primary PT 3
            0xA0, 0xA1, 0xB0, 0xC0
        ]
    );
    assert_eq!(RedPacket::parse(&raw.freeze()).unwrap(), packet);
}

#[test]
fn round_trip_with_maximum_fields() {
    let packet = RedPacket::new(
        127,
        filled(2000, 9),
        [(
            127,
            RED_MAX_TIMESTAMP_OFFSET,
            filled(RED_MAX_BLOCK_LENGTH, 7),
        )],
    )
    .unwrap();
    let raw = packet.marshal().unwrap().freeze();
    assert_eq!(RedPacket::parse(&raw).unwrap(), packet);
    assert_eq!(RedPacket::unmarshal(&mut raw.clone()).unwrap(), packet);
}

#[test]
fn block_timestamps_wrap_around_zero() {
    let block = RedBlock::redundant(0, 960, Bytes::new());
    assert_eq!(block.timestamp(100), 100u32.wrapping_sub(960));
    assert_eq!(block.timestamp(100), u32::MAX - 859);
}

// ---- malformed input ---------------------------------------------------------------------

#[test]
fn an_empty_payload_is_rejected() {
    assert_eq!(RedPacket::parse(&Bytes::new()), Err(Error::ErrShortPacket));
}

#[test]
fn a_truncated_redundant_header_is_rejected() {
    for raw in [
        &[0x80][..],
        &[0x80, 0, 0],
        &[0x87, 0x02, 0x80, 0x0E, 0x85, 0x00],
    ] {
        assert_eq!(
            RedPacket::parse(&b(raw)),
            Err(Error::ErrShortPacket),
            "{raw:?}"
        );
    }
}

#[test]
fn a_payload_without_a_primary_header_is_rejected() {
    // Two complete redundant headers and nothing after them.
    let raw = [0x80, 0, 0, 0, 0x80, 0, 0, 0];
    assert!(RedPacket::parse(&b(&raw)).is_err());
}

#[test]
fn block_lengths_beyond_the_payload_are_rejected() {
    // Header says 14 bytes of redundancy; only 13 follow.
    let mut raw = vec![0x87, 0x02, 0x80, 0x0E, 0x05];
    raw.extend(vec![0; 13]);
    assert_eq!(RedPacket::parse(&b(&raw)), Err(Error::ErrShortPacket));
    // Exactly 14: legal, with an empty primary.
    raw.push(0);
    assert!(
        RedPacket::parse(&b(&raw))
            .unwrap()
            .primary()
            .data
            .is_empty()
    );
}

#[test]
fn too_many_blocks_are_rejected() {
    let header = [0x80u8, 0, 0x04, 0];
    let mut ok = header.repeat(RED_MAX_BLOCKS - 1);
    ok.push(0);
    assert_eq!(
        RedPacket::parse(&b(&ok)).unwrap().blocks().len(),
        RED_MAX_BLOCKS
    );
    let mut too_many = header.repeat(RED_MAX_BLOCKS);
    too_many.push(0);
    assert!(RedPacket::parse(&b(&too_many)).is_err());
}

#[test]
fn writer_rejects_out_of_range_fields() {
    assert!(RedPacket::new(128, Bytes::new(), []).is_err());
    assert!(RedPacket::new(0, Bytes::new(), [(128, 1, Bytes::new())]).is_err());
    assert!(RedPacket::new(0, Bytes::new(), [(1, 0x4000, Bytes::new())]).is_err());
    assert!(RedPacket::new(0, Bytes::new(), [(1, 1, filled(0x400, 0))]).is_err());
    let too_many = (0..RED_MAX_BLOCKS).map(|_| (1u8, 1u16, Bytes::new()));
    assert!(RedPacket::new(0, Bytes::new(), too_many).is_err());
}

#[test]
fn from_blocks_requires_exactly_one_primary_last() {
    assert!(RedPacket::from_blocks(vec![]).is_err());
    assert!(RedPacket::from_blocks(vec![RedBlock::redundant(1, 1, Bytes::new())]).is_err());
    assert!(
        RedPacket::from_blocks(vec![
            RedBlock::primary(1, Bytes::new()),
            RedBlock::primary(1, Bytes::new())
        ])
        .is_err()
    );
    let mut bad = RedBlock::primary(1, Bytes::new());
    bad.timestamp_offset = 5;
    assert!(RedPacket::from_blocks(vec![bad]).is_err());
    assert!(
        RedPacket::from_blocks(vec![
            RedBlock::redundant(1, 1, Bytes::new()),
            RedBlock::primary(1, Bytes::new())
        ])
        .is_ok()
    );
}

#[test]
fn marshal_into_a_short_buffer_fails() {
    let packet = RedPacket::new(1, b(&[1, 2]), []).unwrap();
    let mut buf = [0u8; 2];
    assert_eq!(packet.marshal_to(&mut buf), Err(Error::ErrBufferTooSmall));
}

// ---- encoder -----------------------------------------------------------------------------

#[test]
fn encoder_with_redundancy_1_carries_the_previous_primary() {
    let mut enc = RedEncoder::new(1, 1200);
    let first = enc.encode_packet(111, 1000, b(&[1])).unwrap();
    assert!(first.redundant().is_empty());
    let second = enc.encode_packet(111, 1960, b(&[2])).unwrap();
    assert_eq!(
        second.redundant(),
        &[RedBlock::redundant(111, 960, b(&[1]))]
    );
    assert_eq!(second.primary(), &RedBlock::primary(111, b(&[2])));
    let third = enc.encode_packet(111, 2920, b(&[3])).unwrap();
    assert_eq!(third.redundant(), &[RedBlock::redundant(111, 960, b(&[2]))]);
}

#[test]
fn encoder_with_redundancy_2_orders_blocks_oldest_first_primary_last() {
    let mut enc = RedEncoder::new(2, 1200);
    enc.encode(111, 0, b(&[1])).unwrap();
    enc.encode(111, 960, b(&[2])).unwrap();
    let raw = enc.encode(111, 1920, b(&[3])).unwrap();
    let packet = RedPacket::parse(&raw).unwrap();
    assert_eq!(
        packet.blocks(),
        &[
            RedBlock::redundant(111, 1920, b(&[1])),
            RedBlock::redundant(111, 960, b(&[2])),
            RedBlock::primary(111, b(&[3]))
        ]
    );
    // The fourth drops the oldest.
    let packet = enc.encode_packet(111, 2880, b(&[4])).unwrap();
    assert_eq!(
        packet
            .redundant()
            .iter()
            .map(|b| b.data[0])
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn encoder_drops_redundancy_beyond_the_14_bit_offset() {
    let mut enc = RedEncoder::new(2, 1200);
    enc.encode(111, 0, b(&[1])).unwrap();
    enc.encode(111, 10_000, b(&[2])).unwrap();
    // 0x3FFF + 1 after the first: it no longer fits, the second does.
    let packet = enc.encode_packet(111, 0x4000, b(&[3])).unwrap();
    assert_eq!(
        packet.redundant(),
        &[RedBlock::redundant(111, 0x4000 - 10_000, b(&[2]))]
    );
}

#[test]
fn encoder_drops_redundancy_longer_than_10_bits() {
    let mut enc = RedEncoder::new(1, 4000);
    enc.encode(111, 0, filled(0x400, 1)).unwrap();
    let packet = enc.encode_packet(111, 960, b(&[2])).unwrap();
    assert!(packet.redundant().is_empty());
    enc.encode(111, 1920, filled(0x3FF, 3)).unwrap();
    let packet = enc.encode_packet(111, 2880, b(&[4])).unwrap();
    assert_eq!(packet.redundant()[0].data.len(), 0x3FF);
}

#[test]
fn encoder_drops_oldest_redundancy_first_to_fit_the_size_budget() {
    // Budget: primary (1 + 10) + one redundant block (4 + 10) = 25.
    let mut enc = RedEncoder::new(2, 25);
    enc.encode(111, 0, filled(10, 1)).unwrap();
    enc.encode(111, 960, filled(10, 2)).unwrap();
    let packet = enc.encode_packet(111, 1920, filled(10, 3)).unwrap();
    assert_eq!(packet.redundant().len(), 1);
    assert_eq!(packet.redundant()[0].data[0], 2);
    assert!(packet.marshal_size() <= 25);
}

#[test]
fn encoder_rejects_a_primary_that_alone_exceeds_the_budget() {
    let mut enc = RedEncoder::new(1, 10);
    assert_eq!(
        enc.encode(111, 0, filled(10, 0)),
        Err(Error::ErrPacketTooBig)
    );
    assert!(enc.encode(128, 0, b(&[1])).is_err());
    // Nothing was remembered.
    let packet = enc.encode_packet(111, 960, b(&[1])).unwrap();
    assert!(packet.redundant().is_empty());
}

#[test]
fn encoder_offsets_wrap_around_the_timestamp() {
    let mut enc = RedEncoder::new(1, 1200);
    enc.encode(111, u32::MAX - 479, b(&[1])).unwrap();
    let packet = enc.encode_packet(111, 480, b(&[2])).unwrap();
    assert_eq!(packet.redundant()[0].timestamp_offset, 960);
    assert_eq!(packet.redundant()[0].timestamp(480), u32::MAX - 479);
}

#[test]
fn encoder_skips_a_previous_primary_with_the_same_or_a_later_timestamp() {
    let mut enc = RedEncoder::new(2, 1200);
    enc.encode(111, 960, b(&[1])).unwrap();
    // Same timestamp: offset 0 describes the same interval as the primary.
    assert!(
        enc.encode_packet(111, 960, b(&[2]))
            .unwrap()
            .redundant()
            .is_empty()
    );
    // Earlier timestamp: the offset would be negative.
    assert!(
        enc.encode_packet(111, 0, b(&[3]))
            .unwrap()
            .redundant()
            .is_empty()
    );
}

#[test]
fn encoder_with_redundancy_0_sends_only_the_primary_and_reset_forgets() {
    let mut enc = RedEncoder::new(0, 1200);
    enc.encode(111, 0, b(&[1])).unwrap();
    assert_eq!(enc.encode(111, 960, b(&[2])).unwrap().as_ref(), &[111, 2]);
    let mut enc = RedEncoder::new(1, 1200);
    enc.encode(111, 0, b(&[1])).unwrap();
    enc.reset();
    assert!(
        enc.encode_packet(111, 960, b(&[2]))
            .unwrap()
            .redundant()
            .is_empty()
    );
    assert_eq!(RedEncoder::new(1000, 1200).redundancy(), RED_MAX_BLOCKS - 1);
}

// ---- decoder -----------------------------------------------------------------------------

fn primaries(out: &[RecoveredBlock]) -> Vec<(u32, u8, bool)> {
    out.iter()
        .map(|r| (r.timestamp, r.data[0], r.primary))
        .collect()
}

#[test]
fn decoder_recovers_a_lost_primary_from_the_next_packet() {
    let mut enc = RedEncoder::new(1, 1200);
    let p1 = enc.encode(111, 0, b(&[1])).unwrap();
    let _lost = enc.encode(111, 960, b(&[2])).unwrap();
    let p3 = enc.encode(111, 1920, b(&[3])).unwrap();
    let mut dec = RedDecoder::default();
    assert_eq!(
        primaries(&dec.decode(1, 0, &p1).unwrap()),
        vec![(0, 1, true)]
    );
    let out = dec.decode(3, 1920, &p3).unwrap();
    assert_eq!(primaries(&out), vec![(960, 2, false), (1920, 3, true)]);
    assert_eq!(out[0].payload_type, 111);
}

#[test]
fn decoder_does_not_deliver_duplicates() {
    let mut enc = RedEncoder::new(2, 1200);
    let packets: Vec<_> = (0..4u32)
        .map(|i| enc.encode(111, i * 960, b(&[i as u8])).unwrap())
        .collect();
    let mut dec = RedDecoder::default();
    let mut delivered = vec![];
    for (i, p) in packets.iter().enumerate() {
        delivered.extend(primaries(&dec.decode(i as u16, i as u32 * 960, p).unwrap()));
    }
    assert_eq!(
        delivered,
        vec![
            (0, 0, true),
            (960, 1, true),
            (1920, 2, true),
            (2880, 3, true)
        ]
    );
    // A duplicated packet delivers nothing.
    assert!(dec.decode(3, 2880, &packets[3]).unwrap().is_empty());
}

#[test]
fn decoder_recovers_two_lost_primaries_in_timestamp_order() {
    let mut enc = RedEncoder::new(2, 1200);
    let p0 = enc.encode(111, 0, b(&[0])).unwrap();
    enc.encode(111, 960, b(&[1])).unwrap();
    enc.encode(111, 1920, b(&[2])).unwrap();
    let p3 = enc.encode(111, 2880, b(&[3])).unwrap();
    let mut dec = RedDecoder::default();
    dec.decode(0, 0, &p0).unwrap();
    assert_eq!(
        primaries(&dec.decode(3, 2880, &p3).unwrap()),
        vec![(960, 1, false), (1920, 2, false), (2880, 3, true)]
    );
}

#[test]
fn decoder_orders_recoveries_by_timestamp_whatever_the_header_order() {
    let packet = RedPacket::new(111, b(&[9]), [(111, 960, b(&[2])), (111, 1920, b(&[1]))]).unwrap();
    let mut dec = RedDecoder::default();
    let out = dec
        .decode(5, 10_000, &packet.marshal().unwrap().freeze())
        .unwrap();
    assert_eq!(
        primaries(&out),
        vec![(8080, 1, false), (9040, 2, false), (10_000, 9, true)]
    );
}

#[test]
fn a_late_original_after_its_recovery_is_not_delivered_again() {
    let mut enc = RedEncoder::new(1, 1200);
    let p1 = enc.encode(111, 960, b(&[1])).unwrap();
    let p2 = enc.encode(111, 1920, b(&[2])).unwrap();
    let mut dec = RedDecoder::default();
    dec.decode(2, 1920, &p2).unwrap();
    assert!(dec.decode(1, 960, &p1).unwrap().is_empty());
}

#[test]
fn primaries_sharing_a_timestamp_are_all_delivered() {
    // Video carried in RED: several packets of one frame share the timestamp.
    let mut dec = RedDecoder::default();
    for seq in 0..3u16 {
        let raw = RedPacket::new(96, b(&[seq as u8]), [])
            .unwrap()
            .marshal()
            .unwrap();
        assert_eq!(dec.decode(seq, 3000, &raw.freeze()).unwrap().len(), 1);
    }
}

#[test]
fn decoder_recovers_across_a_timestamp_wrap() {
    let mut enc = RedEncoder::new(1, 1200);
    enc.encode(111, u32::MAX - 479, b(&[1])).unwrap();
    let p = enc.encode(111, 480, b(&[2])).unwrap();
    let mut dec = RedDecoder::default();
    assert_eq!(
        primaries(&dec.decode(7, 480, &p).unwrap()),
        vec![(u32::MAX - 479, 1, false), (480, 2, true)]
    );
}

#[test]
fn decoder_duplicate_window_is_bounded() {
    let mut dec = RedDecoder::new(2);
    let raw = |v: u8| {
        RedPacket::new(0, b(&[v]), [])
            .unwrap()
            .marshal()
            .unwrap()
            .freeze()
    };
    dec.decode(1, 10, &raw(1)).unwrap();
    dec.decode(2, 20, &raw(2)).unwrap();
    dec.decode(3, 30, &raw(3)).unwrap();
    // Sequence 1 fell out of the 2-entry window, 3 did not.
    assert_eq!(dec.decode(1, 10, &raw(1)).unwrap().len(), 1);
    assert!(dec.decode(3, 30, &raw(3)).unwrap().is_empty());
    for seq in 0..10_000u16 {
        dec.decode(seq, u32::from(seq), &raw(0)).unwrap();
    }
    assert!(dec.sequence_numbers.len() <= 2 && dec.timestamps.len() <= 2);
}

#[test]
fn decoder_rejects_malformed_payloads() {
    let mut dec = RedDecoder::default();
    assert!(dec.decode(0, 0, &Bytes::new()).is_err());
    assert!(dec.decode(0, 0, &b(&[0x80, 0, 0])).is_err());
}

#[test]
fn depacketizer_returns_the_primary_data() {
    let mut d = RedDepacketizer;
    let raw = RedPacket::new(5, b(&[7, 8]), [(7, 160, b(&[1]))])
        .unwrap()
        .marshal()
        .unwrap()
        .freeze();
    assert_eq!(d.depacketize(&raw).unwrap().as_ref(), &[7, 8]);
    assert!(d.depacketize(&Bytes::new()).is_err());
    assert!(d.is_partition_head(&raw) && d.is_partition_tail(false, &raw));
}

// ---- fmtp --------------------------------------------------------------------------------

#[test]
fn red_fmtp_parses_and_formats_slash_lists() {
    assert_eq!(parse_red_fmtp("111/111").unwrap(), vec![111, 111]);
    assert_eq!(parse_red_fmtp("0/5").unwrap(), vec![0, 5]);
    assert_eq!(parse_red_fmtp("101/101/101").unwrap(), vec![101, 101, 101]);
    assert_eq!(parse_red_fmtp("96").unwrap(), vec![96]);
    assert_eq!(format_red_fmtp(&[111, 111]), "111/111");
    assert_eq!(format_red_fmtp(&[0, 5]), "0/5");
    assert_eq!(
        parse_red_fmtp(&format_red_fmtp(&[1, 2, 127])).unwrap(),
        vec![1, 2, 127]
    );
}

#[test]
fn red_fmtp_rejects_bad_entries() {
    for bad in [
        "", "/", "111/", "/111", "111//111", "a/1", "128", "1/256", " 1", "1 /2", "+1", "-1",
        "0x10", "1000",
    ] {
        assert!(parse_red_fmtp(bad).is_err(), "{bad:?}");
    }
    let long = vec!["1"; RED_MAX_BLOCKS + 1].join("/");
    assert!(parse_red_fmtp(&long).is_err());
    let max = vec!["1"; RED_MAX_BLOCKS].join("/");
    assert_eq!(parse_red_fmtp(&max).unwrap().len(), RED_MAX_BLOCKS);
}
