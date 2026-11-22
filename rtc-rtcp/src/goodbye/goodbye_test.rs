use super::*;

#[test]
fn test_goodbye_unmarshal() {
    let tests = vec![
        (
            "valid",
            Bytes::from_static(&[
                0x81, 0xcb, 0x00, 0x02, // v=2, p=0, count=1, BYE, len=2 (12 octets)
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
                0x03, 0x46, 0x4f, 0x4f, // len=3, text=FOO
            ]),
            Goodbye {
                sources: vec![0x902f9e2e],
                reason: Bytes::from_static(b"FOO"),
            },
            None,
        ),
        (
            "invalid octet count",
            Bytes::from_static(&[
                0x81, 0xcb, 0x00, 0x02, // v=2, p=0, count=1, BYE, len=2 (12 octets)
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
                0x04, 0x46, 0x4f, 0x4f, // len=4, text=FOO
            ]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            Some(Error::PacketTooShort),
        ),
        (
            "wrong type",
            Bytes::from_static(&[
                0x81, 0xca, 0x00, 0x02, // v=2, p=0, count=1, SDES, len=2 (12 octets)
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
                0x03, 0x46, 0x4f, 0x4f, // len=3, text=FOO
            ]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            Some(Error::WrongType),
        ),
        (
            "short reason",
            Bytes::from_static(&[
                0x81, 0xcb, 0x00, 0x02, // v=2, p=0, count=1, BYE, len=2 (12 octets)
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
                0x01, 0x46, 0x00, 0x00, // len=3, text=F + padding
            ]),
            Goodbye {
                sources: vec![0x902f9e2e],
                reason: Bytes::from_static(b"F"),
            },
            None,
        ),
        (
            "not byte aligned",
            Bytes::from_static(&[
                0x81, 0xcb, 0x00, 0x02, // v=2, p=0, count=1, BYE, len=2, two octets missing
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
                0x01, 0x46, // len=1, text=F
            ]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            Some(Error::PacketTooShort),
        ),
        (
            "bad count in header",
            Bytes::from_static(&[
                0x82, 0xcb, 0x00, 0x01, // v=2, p=0, count=2, BYE, len=1 (8 octets)
                0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
            ]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            Some(Error::PacketTooShort),
        ),
        (
            "empty packet",
            Bytes::from_static(&[
                // v=2, p=0, count=0, BYE, len=0 (4 octets)
                0x80, 0xcb, 0x00, 0x00,
            ]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            None,
        ),
        (
            "nil",
            Bytes::from_static(&[]),
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b""),
            },
            Some(Error::PacketTooShort),
        ),
    ];

    for (name, mut data, want, want_error) in tests {
        let got = Goodbye::unmarshal(&mut data);

        assert_eq!(
            got.is_err(),
            want_error.is_some(),
            "Unmarshal {name} bye: err = {got:?}, want {want_error:?}"
        );

        if let Some(err) = want_error {
            let got_err = got.err().unwrap();
            assert_eq!(
                err, got_err,
                "Unmarshal {name} rr: err = {got_err:?}, want {err:?}",
            );
        } else {
            let actual = got.unwrap();
            assert_eq!(
                actual, want,
                "Unmarshal {name} rr: got {actual:?}, want {want:?}"
            );
        }
    }
}

#[test]
fn test_goodbye_round_trip() {
    let too_many_sources = vec![0u32; 1 << 5];

    let mut too_long_text = String::new();
    for _ in 0..1 << 8 {
        too_long_text.push('x');
    }

    let tests = vec![
        (
            "empty",
            Goodbye {
                sources: vec![],
                ..Default::default()
            },
            None,
        ),
        (
            "valid",
            Goodbye {
                sources: vec![0x01020304, 0x05060708],
                reason: Bytes::from_static(b"because"),
            },
            None,
        ),
        (
            "empty reason",
            Goodbye {
                sources: vec![0x01020304],
                reason: Bytes::from_static(b""),
            },
            None,
        ),
        (
            "reason no source",
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b"foo"),
            },
            None,
        ),
        (
            "short reason",
            Goodbye {
                sources: vec![],
                reason: Bytes::from_static(b"f"),
            },
            None,
        ),
        (
            "count overflow",
            Goodbye {
                sources: too_many_sources,
                reason: Bytes::from_static(b""),
            },
            Some(Error::TooManySources),
        ),
        (
            "reason too long",
            Goodbye {
                sources: vec![],
                reason: Bytes::copy_from_slice(too_long_text.as_bytes()),
            },
            Some(Error::ReasonTooLong),
        ),
    ];

    for (name, want, want_error) in tests {
        let got = want.marshal();

        assert_eq!(
            got.is_ok(),
            want_error.is_none(),
            "Marshal {name}: err = {got:?}, want {want_error:?}"
        );

        if let Some(err) = want_error {
            let got_err = got.err().unwrap();
            assert_eq!(
                err, got_err,
                "Unmarshal {name} rr: err = {got_err:?}, want {err:?}",
            );
        } else {
            let mut data = got.ok().unwrap();
            let actual =
                Goodbye::unmarshal(&mut data).unwrap_or_else(|_| panic!("Unmarshal {name}"));

            assert_eq!(
                actual, want,
                "{name} round trip: got {actual:?}, want {want:?}"
            )
        }
    }
}

// RFC 3550 6.6: the reason is a length octet and text; "if the string fills the packet to the
// next 32-bit boundary, the string is not null terminated. If not, the BYE packet MUST be
// padded with null octets", which "is separate from that indicated by the P bit".
#[test]
fn a_reason_is_padded_with_null_octets_without_the_padding_bit() {
    for (reason, size) in [
        (&b"a"[..], 12),
        (&b"ab"[..], 12),
        (&b"abc"[..], 12),
        (&b"abcd"[..], 16),
        (&b"abcdefg"[..], 16),
    ] {
        let bye = Goodbye {
            sources: vec![0x01020304],
            reason: Bytes::copy_from_slice(reason),
        };
        let raw = bye.marshal().unwrap();

        assert_eq!(size, raw.len(), "reason {reason:?}");
        assert_eq!(0x81, raw[0], "P is clear");
        assert_eq!((size / 4 - 1) as u8, raw[3]);
        assert_eq!(reason.len() as u8, raw[8]);
        assert_eq!(reason, &raw[9..9 + reason.len()]);
        assert!(raw[9 + reason.len()..].iter().all(|b| *b == 0));
        assert_eq!(bye, Goodbye::unmarshal(&mut raw.freeze()).unwrap());
    }
}

// RFC 3550 6.6: the reason is optional. Without one the packet is the header and the sources.
#[test]
fn a_goodbye_without_a_reason_has_no_length_octet() {
    let none = Goodbye::default();
    assert_eq!(&[0x80, 0xcb, 0x00, 0x00][..], &none.marshal().unwrap()[..]);

    let two = Goodbye {
        sources: vec![1, 2],
        reason: Bytes::new(),
    };
    let raw = two.marshal().unwrap();
    assert_eq!(
        &[0x82, 0xcb, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2][..],
        &raw[..]
    );
    assert_eq!(two, Goodbye::unmarshal(&mut raw.freeze()).unwrap());

    let most = Goodbye {
        sources: (0..31).collect(),
        reason: Bytes::new(),
    };
    let raw = most.marshal().unwrap();
    assert_eq!(4 + 31 * 4, raw.len());
    assert_eq!(most, Goodbye::unmarshal(&mut raw.freeze()).unwrap());
}

// What this crate wrote before: a zero length octet and three octets of P-bit padding. The
// padding is cut, the empty reason read.
#[test]
fn a_goodbye_with_an_empty_reason_and_rtcp_padding_still_parses() {
    let mut raw = Bytes::from_static(&[
        0xa1, 0xcb, 0x00, 0x02, // v=2, p=1, count=1, BYE, len=2
        0x01, 0x02, 0x03, 0x04, // ssrc
        0x00, 0x00, 0x00, 0x03, // empty reason, three padding octets
    ]);
    assert_eq!(
        Goodbye {
            sources: vec![0x01020304],
            reason: Bytes::new(),
        },
        Goodbye::unmarshal(&mut raw).unwrap()
    );
}

#[test]
fn a_goodbye_that_contradicts_its_own_lengths_is_refused() {
    // The count says three sources, the length holds two.
    let mut raw = Bytes::from_static(&[0x83, 0xcb, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
    assert_eq!(Err(Error::PacketTooShort), Goodbye::unmarshal(&mut raw));
    // The reason says nine octets, three follow.
    let mut raw = Bytes::from_static(&[0x81, 0xcb, 0, 2, 0, 0, 0, 1, 9, b'a', b'b', b'c']);
    assert_eq!(Err(Error::PacketTooShort), Goodbye::unmarshal(&mut raw));
    // The length runs past the datagram.
    let mut raw = Bytes::from_static(&[0x81, 0xcb, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(Err(Error::PacketTooShort), Goodbye::unmarshal(&mut raw));
    // A padding count of zero is not a count.
    let mut raw = Bytes::from_static(&[0xa1, 0xcb, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(Err(Error::WrongPadding), Goodbye::unmarshal(&mut raw));
}
