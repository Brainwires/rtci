use super::*;
use crate::packet;

// RFC 3550 6.7: subtype in the count field, SSRC, a four-character name, data in whole words.
#[test]
fn app_round_trips_with_the_wire_layout_of_rfc3550() {
    let app = ApplicationDefined {
        subtype: 5,
        ssrc: 0x01020304,
        name: *b"NAME",
        data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
    };
    let raw = app.marshal().unwrap();
    assert_eq!(
        &[
            0x85, 0xcc, 0x00, 0x03, // v=2, p=0, subtype=5, APP, len=3
            0x01, 0x02, 0x03, 0x04, // ssrc
            b'N', b'A', b'M', b'E', // name
            0xde, 0xad, 0xbe, 0xef, // data
        ][..],
        &raw[..]
    );
    assert_eq!(
        app,
        ApplicationDefined::unmarshal(&mut raw.freeze()).unwrap()
    );
    assert_eq!(Some("NAME"), app.name_str());
    assert_eq!(vec![0x01020304], app.destination_ssrc());
    assert_eq!(PacketType::ApplicationDefined, app.header().packet_type);
    assert_eq!(5, app.header().count);
}

#[test]
fn app_without_data_is_twelve_octets() {
    let app = ApplicationDefined {
        subtype: 0,
        ssrc: 1,
        name: *b"abcd",
        data: Bytes::new(),
    };
    let raw = app.marshal().unwrap();
    assert_eq!(
        &[0x80, 0xcc, 0, 2, 0, 0, 0, 1, b'a', b'b', b'c', b'd'][..],
        &raw[..]
    );
    assert_eq!(
        app,
        ApplicationDefined::unmarshal(&mut raw.freeze()).unwrap()
    );
}

// RFC 3550 6.7: "must be a multiple of 32 bits long"; the subtype is five bits; the name is
// ASCII.
#[test]
fn app_that_does_not_fit_the_format_is_not_marshalled() {
    let ok = ApplicationDefined {
        subtype: 31,
        ssrc: 1,
        name: *b"abcd",
        data: Bytes::from_static(&[1, 2, 3, 4]),
    };
    assert!(ok.marshal().is_ok());

    let odd = ApplicationDefined {
        data: Bytes::from_static(&[1, 2, 3]),
        ..ok.clone()
    };
    assert_eq!(Err(Error::WrongMarshalSize), odd.marshal());
    let subtype = ApplicationDefined {
        subtype: 32,
        ..ok.clone()
    };
    assert_eq!(Err(Error::InvalidHeader), subtype.marshal());
    let name = ApplicationDefined {
        name: [0xff, b'b', b'c', b'd'],
        ..ok
    };
    assert_eq!(Err(Error::InvalidHeader), name.marshal());
}

#[test]
fn malformed_app_packets_are_refused() {
    // No name.
    let mut raw = Bytes::from_static(&[0x80, 0xcc, 0, 1, 0, 0, 0, 1]);
    assert_eq!(
        Err(Error::PacketTooShort),
        ApplicationDefined::unmarshal(&mut raw)
    );
    // The length says more than there is.
    let mut raw = Bytes::from_static(&[0x80, 0xcc, 0, 3, 0, 0, 0, 1, b'a', b'b', b'c', b'd']);
    assert_eq!(
        Err(Error::PacketTooShort),
        ApplicationDefined::unmarshal(&mut raw)
    );
    // Not an APP packet.
    let mut raw = Bytes::from_static(&[0x80, 0xcb, 0, 2, 0, 0, 0, 1, b'a', b'b', b'c', b'd']);
    assert_eq!(
        Err(Error::WrongType),
        ApplicationDefined::unmarshal(&mut raw)
    );
    // Padding that says it is longer than the packet.
    let mut raw = Bytes::from_static(&[0xa0, 0xcc, 0, 2, 0, 0, 0, 1, b'a', b'b', b'c', 9]);
    assert_eq!(
        Err(Error::WrongPadding),
        ApplicationDefined::unmarshal(&mut raw)
    );
}

// RFC 3550 6.4.1: padding is not part of the packet's data.
#[test]
fn padding_is_not_application_data() {
    let mut raw = Bytes::from_static(&[
        0xa0, 0xcc, 0, 4, 0, 0, 0, 1, b'a', b'b', b'c', b'd', 1, 2, 3, 4, 0, 0, 0, 4,
    ]);
    let app = ApplicationDefined::unmarshal(&mut raw).unwrap();
    assert_eq!(&[1, 2, 3, 4][..], &app.data[..]);
}

// RFC 3550 6.7: a receiver ignores a name it does not know; the datagram still parses, and
// the packet is there for an application that does know it.
#[test]
fn an_app_packet_with_any_name_parses_inside_a_datagram() {
    let mut datagram = Bytes::from_static(&[
        0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, // RR
        0x9f, 0xcc, 0x00, 0x02, 0, 0, 0, 1, 0xff, 0x00, 0x01, 0x02, // APP, a name not ASCII
    ]);
    let packets = packet::unmarshal(&mut datagram).unwrap();
    assert_eq!(2, packets.len());
    let app = packets[1]
        .as_any()
        .downcast_ref::<ApplicationDefined>()
        .expect("an APP packet");
    assert_eq!(31, app.subtype);
    assert_eq!(None, app.name_str());
}
