//! SDES items and chunk framing: RFC 3550 6.5, RFC 7941 and RFC 8852.
use super::*;
use crate::packet;

fn item(sdes_type: SdesType, text: &'static [u8]) -> SourceDescriptionItem {
    SourceDescriptionItem {
        sdes_type,
        text: Bytes::from_static(text),
    }
}

fn sdes(items: Vec<SourceDescriptionItem>) -> SourceDescription {
    SourceDescription {
        chunks: vec![SourceDescriptionChunk {
            source: 0x01020304,
            items,
        }],
    }
}

// RFC 8852 3.1 / 3.2 (RtpStreamId = 12, RepairedRtpStreamId = 13) and RFC 8843 15.1 (MID = 15),
// carried in RTCP SDES as RFC 7941 describes: plain text, not null terminated.
#[test]
fn mid_rid_and_repaired_rid_items_are_parsed_and_written() {
    let packet = sdes(vec![
        item(SdesType::SdesCname, b"c"),
        item(SdesType::SdesRtpStreamId, b"hi"),
        item(SdesType::SdesRepairedRtpStreamId, b"lo"),
        item(SdesType::SdesMid, b"0"),
    ]);
    let raw = packet.marshal().unwrap();
    assert_eq!(
        &[
            0x81, 0xca, 0x00, 0x05, // v=2, p=0, count=1, SDES, len=5
            0x01, 0x02, 0x03, 0x04, // ssrc
            0x01, 0x01, b'c', // CNAME
            0x0c, 0x02, b'h', b'i', // RtpStreamId
            0x0d, 0x02, b'l', b'o', // RepairedRtpStreamId
            0x0f, 0x01, b'0', // MID
            0x00, 0x00, // END + padding
        ][..],
        &raw[..]
    );
    assert_eq!(
        packet,
        SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
    );
}

// RFC 3550 6.5: the item types are a registry; an item a receiver does not know is passed
// over by its length, and the items after it are read.
#[test]
fn an_item_of_an_unregistered_type_is_skipped_by_its_length() {
    let mut raw = Bytes::from_static(&[
        0x81, 0xca, 0x00, 0x04, // v=2, p=0, count=1, SDES, len=4
        0x01, 0x02, 0x03, 0x04, // ssrc
        0xc8, 0x03, 0xde, 0xad, 0x00, // type 200, three octets, one of them null
        0x01, 0x02, b'a', b'b', // CNAME
        0x00, 0x00, 0x00, // END + padding
    ]);
    let packet = SourceDescription::unmarshal(&mut raw).unwrap();

    assert_eq!(
        sdes(vec![
            item(SdesType::Other(200), &[0xde, 0xad, 0x00]),
            item(SdesType::SdesCname, b"ab"),
        ]),
        packet
    );
    // And it is written back as it came.
    assert_eq!(0xc8, packet.marshal().unwrap()[8]);
}

#[test]
fn every_item_type_octet_survives_a_round_trip() {
    for octet in 0..=u8::MAX {
        assert_eq!(octet, u8::from(SdesType::from(octet)));
    }
    assert_eq!(SdesType::SdesEnd, SdesType::from(0));
    assert_eq!(SdesType::SdesRtpStreamId, SdesType::from(12));
    assert_eq!(SdesType::SdesRepairedRtpStreamId, SdesType::from(13));
    assert_eq!(SdesType::SdesMid, SdesType::from(15));
    assert_eq!(SdesType::Other(9), SdesType::from(9));
    assert_eq!("MID", SdesType::SdesMid.to_string());
    assert_eq!("SDES9", SdesType::Other(9).to_string());
}

// RFC 3550 6.5.1 - 6.5.8.
#[test]
fn all_the_items_of_rfc3550_round_trip_in_one_chunk() {
    let packet = sdes(vec![
        item(SdesType::SdesCname, b"user@host.example"),
        item(SdesType::SdesName, b"A. User"),
        item(SdesType::SdesEmail, b"user@example.com"),
        item(SdesType::SdesPhone, b"+1 908 555 1212"),
        item(SdesType::SdesLocation, b"Murray Hill, New Jersey"),
        item(SdesType::SdesTool, b"videotool 1.2"),
        item(SdesType::SdesNote, b"on the phone"),
        SourceDescriptionItem::private(b"ext", b"value").unwrap(),
    ]);
    let raw = packet.marshal().unwrap();
    assert!(raw.len().is_multiple_of(4));
    assert_eq!(0, raw[0] & 0x20, "an SDES packet needs no RTCP padding");
    assert_eq!(
        packet,
        SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
    );
}

// RFC 3550 6.5.8: prefix length, prefix string, value string.
#[test]
fn a_priv_item_is_a_prefix_and_a_value() {
    let priv_item = SourceDescriptionItem::private(b"ext", b"value").unwrap();
    assert_eq!(SdesType::SdesPrivate, priv_item.sdes_type);
    assert_eq!(&b"\x03extvalue"[..], &priv_item.text[..]);
    assert_eq!(
        Some((Bytes::from_static(b"ext"), Bytes::from_static(b"value"))),
        priv_item.as_private()
    );

    // The prefix and the value share 254 octets.
    assert!(SourceDescriptionItem::private(&[b'p'; 100], &[b'v'; 154]).is_ok());
    assert_eq!(
        Err(Error::SdesTextTooLong),
        SourceDescriptionItem::private(&[b'p'; 100], &[b'v'; 155])
    );

    // A prefix length that runs past the item, an empty item, and another item type.
    assert_eq!(None, item(SdesType::SdesPrivate, b"\x09ext").as_private());
    assert_eq!(None, item(SdesType::SdesPrivate, b"").as_private());
    assert_eq!(None, item(SdesType::SdesCname, b"\x01ab").as_private());
}

// RFC 3550 6.5: "The list of items in each chunk MUST be terminated by one or more null
// octets ... additional null octets MUST be included if needed to pad until the next 32-bit
// boundary." Items that end on the boundary get a whole word of nulls.
#[test]
fn a_chunk_is_terminated_and_padded_with_one_to_four_null_octets() {
    for (text, nulls) in [
        (&b""[..], 2),
        (&b"a"[..], 1),
        (&b"ab"[..], 4),
        (&b"abc"[..], 3),
        (&b"abcd"[..], 2),
    ] {
        let packet = sdes(vec![SourceDescriptionItem {
            sdes_type: SdesType::SdesCname,
            text: Bytes::copy_from_slice(text),
        }]);
        let raw = packet.marshal().unwrap();

        assert_eq!(8 + 2 + text.len() + nulls, raw.len(), "text {text:?}");
        assert!(raw.len().is_multiple_of(4));
        assert!(raw[raw.len() - nulls..].iter().all(|b| *b == 0));
        assert_eq!((raw.len() / 4 - 1) as u8, raw[3]);
        assert_eq!(
            packet,
            SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
        );
    }

    // A chunk without items is four null octets after the source.
    let empty = sdes(vec![]);
    let raw = empty.marshal().unwrap();
    assert_eq!(&[0x81, 0xca, 0, 2, 1, 2, 3, 4, 0, 0, 0, 0][..], &raw[..]);
    assert_eq!(
        empty,
        SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
    );
}

#[test]
fn several_chunks_are_read_by_the_source_count() {
    let packet = SourceDescription {
        chunks: vec![
            SourceDescriptionChunk {
                source: 1,
                items: vec![item(SdesType::SdesCname, b"A")],
            },
            SourceDescriptionChunk {
                source: 2,
                items: vec![
                    item(SdesType::SdesCname, b"BCD"),
                    item(SdesType::SdesMid, b"video"),
                ],
            },
            SourceDescriptionChunk {
                source: 3,
                items: vec![],
            },
        ],
    };
    let raw = packet.marshal().unwrap();
    assert_eq!(0x83, raw[0]);
    assert_eq!(
        packet,
        SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
    );
    assert_eq!(vec![1, 2, 3], packet.destination_ssrc());

    // No chunk at all is a legal, empty SDES.
    let none = SourceDescription::default();
    let raw = none.marshal().unwrap();
    assert_eq!(&[0x80, 0xca, 0, 0][..], &raw[..]);
    assert_eq!(
        none,
        SourceDescription::unmarshal(&mut raw.freeze()).unwrap()
    );
}

#[test]
fn malformed_sdes_packets_are_refused() {
    let cases: Vec<(&str, &'static [u8], Error)> = vec![
        (
            "the items run to the end of the packet without a null octet",
            &[0x81, 0xca, 0, 2, 0, 0, 0, 1, 0x01, 0x02, b'a', b'b'],
            Error::PacketTooShort,
        ),
        (
            "an item is longer than what is left of the packet",
            &[0x81, 0xca, 0, 2, 0, 0, 0, 1, 0x01, 0x09, b'a', 0x00],
            Error::PacketTooShort,
        ),
        (
            "an item type without a length octet",
            &[0x81, 0xca, 0, 2, 0, 0, 0, 1, 0x01, 0x01, b'a', 0x01],
            Error::PacketTooShort,
        ),
        (
            "an unknown item type is no excuse for running past the packet",
            &[0x81, 0xca, 0, 2, 0, 0, 0, 1, 0x0f, 0x05, b'a', 0x00],
            Error::PacketTooShort,
        ),
        (
            "the source count says two chunks and there is one",
            &[0x82, 0xca, 0, 2, 0, 0, 0, 1, 0x00, 0x00, 0x00, 0x00],
            Error::PacketTooShort,
        ),
        (
            "the source count says one chunk and there are two",
            &[
                0x81, 0xca, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
            ],
            Error::InvalidHeader,
        ),
        (
            "a chunk with a source and nothing else",
            &[0x81, 0xca, 0, 1, 0, 0, 0, 1],
            Error::PacketTooShort,
        ),
        (
            "the length says more than the datagram holds",
            &[0x81, 0xca, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0],
            Error::PacketTooShort,
        ),
        (
            "another packet type",
            &[0x81, 0xcb, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0],
            Error::WrongType,
        ),
    ];

    for (name, raw, want) in cases {
        assert_eq!(
            Err(want),
            SourceDescription::unmarshal(&mut Bytes::from_static(raw)),
            "{name}"
        );
    }
}

#[test]
fn items_and_packets_that_do_not_fit_the_format_are_not_marshalled() {
    // Type zero ends the list; it is not an item.
    assert_eq!(
        Err(Error::SdesMissingType),
        sdes(vec![item(SdesType::SdesEnd, b"x")]).marshal()
    );
    assert_eq!(
        Err(Error::SdesMissingType),
        sdes(vec![item(SdesType::Other(0), b"x")]).marshal()
    );
    // The length is one octet.
    let long = SourceDescriptionItem {
        sdes_type: SdesType::SdesCname,
        text: Bytes::from(vec![b'x'; 256]),
    };
    assert_eq!(Err(Error::SdesTextTooLong), sdes(vec![long]).marshal());
    let longest = SourceDescriptionItem {
        sdes_type: SdesType::SdesCname,
        text: Bytes::from(vec![b'x'; 255]),
    };
    assert!(sdes(vec![longest]).marshal().is_ok());
    // The source count is five bits.
    let many = SourceDescription {
        chunks: vec![SourceDescriptionChunk::default(); 32],
    };
    assert_eq!(Err(Error::TooManyChunks), many.marshal());
}

// RFC 3550 6.4.1: padding the P bit announces is not part of the chunks.
#[test]
fn rtcp_padding_after_the_chunks_is_not_a_chunk() {
    let mut raw = Bytes::from_static(&[
        0xa1, 0xca, 0x00, 0x03, // v=2, p=1, count=1, SDES, len=3
        0x01, 0x02, 0x03, 0x04, // ssrc
        0x01, 0x01, b'c', 0x00, // CNAME, END
        0x00, 0x00, 0x00, 0x04, // four padding octets
    ]);
    assert_eq!(
        sdes(vec![item(SdesType::SdesCname, b"c")]),
        SourceDescription::unmarshal(&mut raw).unwrap()
    );
}

// The audit's reproduction (rfc3550.md B2): the report that shares the datagram is delivered.
#[test]
fn a_sender_report_survives_an_sdes_with_a_mid_item_next_to_it() {
    let mut datagram = Bytes::from_static(&[
        0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, // RR
        0x81, 0xca, 0x00, 0x03, 0, 0, 0, 1, 0x01, 0x01, b'a', 0x0f, 0x01, b'0', 0x00, 0x00,
    ]);
    let packets = packet::unmarshal(&mut datagram).unwrap();
    assert_eq!(2, packets.len());
    let sdes = packets[1]
        .as_any()
        .downcast_ref::<SourceDescription>()
        .unwrap();
    assert_eq!(
        vec![
            item(SdesType::SdesCname, b"a"),
            item(SdesType::SdesMid, b"0")
        ],
        sdes.chunks[0].items
    );
}
