//! The reference time and the padding of transport-wide feedback
//! (draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1).
use super::*;
use bytes::Bytes;

fn feedback(reference_time: u32) -> TransportLayerCc {
    TransportLayerCc {
        sender_ssrc: 1,
        media_ssrc: 2,
        base_sequence_number: 100,
        packet_status_count: 2,
        reference_time,
        fb_pkt_count: 0,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketNotReceived,
            run_length: 2,
        })],
        recv_deltas: vec![],
    }
}

// "reference time: 24 bits Signed integer indicating an absolute reference time in some
// (unknown) time base ... in multiples of 64ms."
#[test]
fn the_reference_time_is_a_24_bit_signed_value() {
    for (wire, signed) in [
        (0x000000u32, 0i32),
        (0x000001, 1),
        (0x7fffff, 8_388_607),
        (0x800000, -8_388_608),
        (0xffffff, -1),
    ] {
        assert_eq!(signed, feedback(wire).reference_time_signed(), "{wire:#x}");
    }

    // A negative value goes out as its 24 bits and comes back as them.
    let negative = feedback(-2i32 as u32);
    let raw = negative.marshal().unwrap();
    assert_eq!(&[0xff, 0xff, 0xfe], &raw[16..19]);
    let parsed = TransportLayerCc::unmarshal(&mut raw.freeze()).unwrap();
    assert_eq!(0xfffffe, parsed.reference_time);
    assert_eq!(-2, parsed.reference_time_signed());
}

// The audit's reproduction (T5): two feedback packets 64 ms apart, with reference times
// 0xFFFFFF and 0x000000, are one tick apart and not 12.4 days.
#[test]
fn the_reference_time_is_followed_across_its_wrap() {
    let mut unwrapper = ReferenceTimeUnwrapper::new();
    assert_eq!(-2, unwrapper.unwrap(0xfffffe));
    assert_eq!(-1, unwrapper.unwrap(0xffffff));
    assert_eq!(0, unwrapper.unwrap(0x000000));
    assert_eq!(1, unwrapper.unwrap(0x000001));

    let mut unwrapper = ReferenceTimeUnwrapper::new();
    let before = unwrapper.unwrap_millis(0xffffff);
    let after = unwrapper.unwrap_millis(0x000000);
    assert_eq!(TYPE_TCC_REFERENCE_TIME_TICK_MILLIS, after - before);

    // The other wrap, from the largest positive value to the most negative one.
    let mut unwrapper = ReferenceTimeUnwrapper::new();
    assert_eq!(8_388_607, unwrapper.unwrap(0x7fffff));
    assert_eq!(8_388_608, unwrapper.unwrap(0x800000));
    assert_eq!(8_388_609, unwrapper.unwrap(0x800001));
}

#[test]
fn the_unwrapped_reference_time_keeps_counting_over_several_wraps() {
    let mut unwrapper = ReferenceTimeUnwrapper::new();
    let mut wire = 5u32;
    let mut want = 5i64;
    assert_eq!(want, unwrapper.unwrap(wire));

    // Three times round the 24-bit space in steps of a quarter of it (about 3 days each).
    for _ in 0..12 {
        wire = (wire + 0x400000) & 0xffffff;
        want += 0x400000;
        assert_eq!(want, unwrapper.unwrap(wire));
    }
    assert_eq!(5 + 3 * (1 << 24), want);
}

// Feedback packets can be reordered: one that is a little behind the last steps back by that
// little, it does not jump a whole wrap forward.
#[test]
fn a_reference_time_behind_the_last_one_steps_back() {
    let mut unwrapper = ReferenceTimeUnwrapper::new();
    assert_eq!(10, unwrapper.unwrap(10));
    assert_eq!(7, unwrapper.unwrap(7));
    assert_eq!(-3, unwrapper.unwrap(0xfffffd));
    assert_eq!(2, unwrapper.unwrap(2));
    // Bits above the 24 are not part of the field.
    assert_eq!(3, unwrapper.unwrap(0xab000003));
}

// "P: padding. If set, the padding octets ... are included in the length of the packet":
// they come after the deltas and are not chunks or deltas.
#[test]
fn padding_is_not_read_as_chunks_or_deltas() {
    // One packet received, one small delta, one octet of padding.
    let mut raw = Bytes::from_static(&[
        0xaf, 0xcd, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x07, 0x20, 0x01, 0x04, 0x01,
    ]);
    let twcc = TransportLayerCc::unmarshal(&mut raw).unwrap();
    assert_eq!(1, twcc.recv_deltas.len());

    // Two packets claimed, one delta present: the second "delta" would be the padding count.
    let mut raw = Bytes::from_static(&[
        0xaf, 0xcd, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x64, 0x00, 0x02, 0x00, 0x00, 0x01,
        0x07, 0x20, 0x02, 0x04, 0x01,
    ]);
    assert_eq!(
        Err(Error::PacketTooShort),
        TransportLayerCc::unmarshal(&mut raw)
    );

    // A status count that needs a second chunk where the padding is.
    let mut raw = Bytes::from_static(&[
        0xaf, 0xcd, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x64, 0x00, 0x09, 0x00, 0x00, 0x01,
        0x07, 0x00, 0x01, 0x00, 0x02,
    ]);
    assert_eq!(
        Err(Error::PacketTooShort),
        TransportLayerCc::unmarshal(&mut raw)
    );

    // A padding count of zero, and one larger than the packet.
    for last in [0u8, 0x15] {
        let mut raw = vec![
            0xaf, 0xcd, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00,
            0x01, 0x07, 0x20, 0x01, 0x04,
        ];
        raw.push(last);
        assert_eq!(
            Err(Error::WrongPadding),
            TransportLayerCc::unmarshal(&mut Bytes::from(raw))
        );
    }
}

// A report on packets that were not received has chunks and no delta: whatever the number of
// chunks, the last one may end the packet (the audit's T3).
#[test]
fn feedback_without_deltas_parses_with_any_number_of_chunks() {
    for chunks in 1..=5u16 {
        let twcc = TransportLayerCc {
            packet_status_count: chunks * 3,
            packet_chunks: (0..chunks)
                .map(|_| {
                    PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                        type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                        packet_status_symbol: SymbolTypeTcc::PacketNotReceived,
                        run_length: 3,
                    })
                })
                .collect(),
            ..feedback(1)
        };
        let raw = twcc.marshal().unwrap();
        assert_eq!(
            twcc,
            TransportLayerCc::unmarshal(&mut raw.freeze()).unwrap(),
            "{chunks} chunks"
        );
    }
}

// The status count ends the list (the audit's T4): a one-bit vector describes 14 packets,
// and with a count of 3 only the first three symbols are packets.
#[test]
fn a_status_vector_is_cut_at_the_status_count() {
    let mut raw = Bytes::from_static(&[
        0xaf, 0xcd, 0x00, 0x06, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x64, 0x00, 0x03, 0x00, 0x00, 0x01,
        0x07, //
        0xbf, 0xff, // one-bit vector, all fourteen symbols "received"
        0x04, 0x08, 0x0c, // three deltas
        0x00, 0x00, 0x03, // padding
    ]);
    let twcc = TransportLayerCc::unmarshal(&mut raw).unwrap();
    assert_eq!(
        vec![1000, 2000, 3000],
        twcc.recv_deltas.iter().map(|d| d.delta).collect::<Vec<_>>()
    );
}
