use super::*;
use crate::xoraddr::*;

use crate::fingerprint::FINGERPRINT;
use crate::integrity::MessageIntegrity;
use crate::textattrs::TextAttribute;
use std::io::{BufReader, BufWriter};

#[test]
fn test_message_buffer() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(m.raw.as_slice());
    m_decoded.read_from(&mut reader)?;

    assert_eq!(m_decoded, m, "{m_decoded} != {m}");

    Ok(())
}

#[test]
fn test_message_type_value() -> Result<()> {
    let tests = vec![
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_REQUEST,
            },
            0x0001,
        ),
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_SUCCESS_RESPONSE,
            },
            0x0101,
        ),
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_ERROR_RESPONSE,
            },
            0x0111,
        ),
        (
            MessageType {
                method: Method(0xb6d),
                class: MessageClass(0x3),
            },
            0x2ddd,
        ),
    ];

    for (input, output) in tests {
        let b = input.value();
        assert_eq!(b, output, "Value({input}) -> {b}, want {output}");
    }

    Ok(())
}

#[test]
fn test_message_type_read_value() -> Result<()> {
    let tests = vec![
        (
            0x0001,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_REQUEST,
            },
        ),
        (
            0x0101,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_SUCCESS_RESPONSE,
            },
        ),
        (
            0x0111,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_ERROR_RESPONSE,
            },
        ),
    ];

    for (input, output) in tests {
        let mut m = MessageType::default();
        m.read_value(input);
        assert_eq!(m, output, "ReadValue({input}) -> {m}, want {output}");
    }

    Ok(())
}

#[test]
fn test_message_type_read_write_value() -> Result<()> {
    let tests = vec![
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_REQUEST,
        },
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_SUCCESS_RESPONSE,
        },
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_ERROR_RESPONSE,
        },
        MessageType {
            method: Method(0x12),
            class: CLASS_ERROR_RESPONSE,
        },
    ];

    for test in tests {
        let mut m = MessageType::default();
        let v = test.value();
        m.read_value(v);
        assert_eq!(m, test, "ReadValue({test} -> {v}) = {m}, should be {test}");
    }

    Ok(())
}

#[test]
fn test_message_write_to() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();
    let mut buf = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(buf.as_mut());
        m.write_to(&mut writer)?;
    }

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    m_decoded.read_from(&mut reader)?;
    assert_eq!(m_decoded, m, "{m_decoded} != {m}");

    Ok(())
}

#[test]
fn test_message_cookie() -> Result<()> {
    let buf = vec![0; 20];
    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_length_less_header_size() -> Result<()> {
    let buf = vec![0; 8];
    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_bad_length() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let mut m = Message {
        typ: m_type,
        length: 4,
        transaction_id: TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        ..Default::default()
    };
    m.add(AttrType(0x1), &[1, 2]);
    m.write_header();
    m.raw[20 + 3] = 10; // set attr length = 10

    let mut m_decoded = Message::new();
    let result = m_decoded.write(&m.raw);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_attr_length_less_than_header() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let message_attribute = RawAttribute {
        length: 2,
        value: vec![1, 2],
        typ: AttrType(0x1),
    };
    let message_attributes = Attributes(vec![message_attribute]);
    let mut m = Message {
        typ: m_type,
        transaction_id: TransactionId::new(),
        attributes: message_attributes,
        ..Default::default()
    };
    m.encode();

    let mut m_decoded = Message::new();
    m.raw[3] = 2; // rewrite to bad length

    let mut reader = BufReader::new(&m.raw[..20 + 2]);
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_attr_size_less_than_length() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let message_attribute = RawAttribute {
        length: 4,
        value: vec![1, 2, 3, 4],
        typ: AttrType(0x1),
    };
    let message_attributes = Attributes(vec![message_attribute]);
    let mut m = Message {
        typ: m_type,
        transaction_id: TransactionId::new(),
        attributes: message_attributes,
        ..Default::default()
    };
    m.write_attributes();
    m.write_header();
    m.raw[3] = 5; // rewrite to bad length

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(&m.raw[..20 + 5]);
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_read_from_error() -> Result<()> {
    let mut m_decoded = Message::new();
    let buf = vec![];
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_class_string() -> Result<()> {
    let v = vec![
        CLASS_REQUEST,
        CLASS_ERROR_RESPONSE,
        CLASS_SUCCESS_RESPONSE,
        CLASS_INDICATION,
    ];

    for k in v {
        if k.to_string() == *"unknown message class" {
            panic!("bad stringer {k}");
        }
    }

    // should panic
    let p = MessageClass(0x05).to_string();
    assert_eq!(p, "unknown message class", "should be error {p}");

    Ok(())
}

#[test]
fn test_attr_type_string() -> Result<()> {
    let v = vec![
        ATTR_MAPPED_ADDRESS,
        ATTR_USERNAME,
        ATTR_ERROR_CODE,
        ATTR_MESSAGE_INTEGRITY,
        ATTR_UNKNOWN_ATTRIBUTES,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_XORMAPPED_ADDRESS,
        ATTR_SOFTWARE,
        ATTR_ALTERNATE_SERVER,
        ATTR_FINGERPRINT,
    ];
    for k in v {
        assert!(!k.to_string().starts_with("0x"), "bad stringer");
    }

    let v_non_standard = AttrType(0x512);
    assert!(
        v_non_standard.to_string().starts_with("0x512"),
        "bad prefix"
    );

    Ok(())
}

#[test]
fn test_method_string() -> Result<()> {
    assert_eq!(
        METHOD_BINDING.to_string(),
        "Binding".to_owned(),
        "binding is not binding!"
    );
    assert_eq!(
        Method(0x616).to_string(),
        "0x616".to_owned(),
        "Bad stringer {}",
        Method(0x616)
    );

    Ok(())
}

#[test]
fn test_attribute_equal() -> Result<()> {
    let a = RawAttribute {
        length: 2,
        value: vec![0x1, 0x2],
        ..Default::default()
    };
    let b = RawAttribute {
        length: 2,
        value: vec![0x1, 0x2],
        ..Default::default()
    };
    assert_eq!(a, b, "should equal");

    assert_ne!(
        a,
        RawAttribute {
            typ: AttrType(0x2),
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x2,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x3,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x2,
            value: vec![0x1, 0x3],
            ..Default::default()
        },
        "should not equal"
    );

    Ok(())
}

#[test]
fn test_message_equal() -> Result<()> {
    let attr = RawAttribute {
        length: 2,
        value: vec![0x1, 0x2],
        typ: AttrType(0x1),
    };
    let attrs = Attributes(vec![attr]);
    let a = Message {
        attributes: attrs.clone(),
        length: 4 + 2,
        ..Default::default()
    };
    let b = Message {
        attributes: attrs.clone(),
        length: 4 + 2,
        ..Default::default()
    };
    assert_eq!(a, b, "should equal");
    assert_ne!(
        a,
        Message {
            typ: MessageType {
                class: MessageClass(128),
                ..Default::default()
            },
            ..Default::default()
        },
        "should not equal"
    );

    let t_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    assert_ne!(
        a,
        Message {
            transaction_id: t_id,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        Message {
            length: 3,
            ..Default::default()
        },
        "should not equal"
    );

    let t_attrs = Attributes(vec![RawAttribute {
        length: 1,
        value: vec![0x1],
        typ: AttrType(0x1),
    }]);
    assert_ne!(
        a,
        Message {
            attributes: t_attrs,
            length: 4 + 2,
            ..Default::default()
        },
        "should not equal"
    );

    let t_attrs = Attributes(vec![RawAttribute {
        length: 2,
        value: vec![0x1, 0x1],
        typ: AttrType(0x2),
    }]);
    assert_ne!(
        a,
        Message {
            attributes: t_attrs,
            length: 4 + 2,
            ..Default::default()
        },
        "should not equal"
    );

    //"Nil attributes"
    {
        let a = Message {
            length: 4 + 2,
            ..Default::default()
        };
        let mut b = Message {
            attributes: attrs,
            length: 4 + 2,
            ..Default::default()
        };

        assert_ne!(a, b, "should not equal");
        assert_ne!(b, a, "should not equal");
        b.attributes = Attributes::default();
        assert_eq!(a, b, "should equal");
    }

    //"Attributes length"
    {
        let attr = RawAttribute {
            length: 2,
            value: vec![0x1, 0x2],
            typ: AttrType(0x1),
        };
        let attr1 = RawAttribute {
            length: 2,
            value: vec![0x1, 0x2],
            typ: AttrType(0x1),
        };
        let a = Message {
            attributes: Attributes(vec![attr.clone()]),
            length: 4 + 2,
            ..Default::default()
        };
        let b = Message {
            attributes: Attributes(vec![attr, attr1]),
            length: 4 + 2,
            ..Default::default()
        };
        assert_ne!(a, b, "should not equal");
    }

    //"Attributes values"
    {
        let attr = RawAttribute {
            length: 2,
            value: vec![0x1, 0x2],
            typ: AttrType(0x1),
        };
        let attr1 = RawAttribute {
            length: 2,
            value: vec![0x1, 0x1],
            typ: AttrType(0x1),
        };
        let a = Message {
            attributes: Attributes(vec![attr.clone(), attr.clone()]),
            length: 4 + 2,
            ..Default::default()
        };
        let b = Message {
            attributes: Attributes(vec![attr, attr1]),
            length: 4 + 2,
            ..Default::default()
        };
        assert_ne!(a, b, "should not equal");
    }

    Ok(())
}

#[test]
fn test_message_grow() -> Result<()> {
    let mut m = Message::new();
    m.grow(512, false);
    assert_eq!(m.raw.len(), 512, "Bad length {}", m.raw.len());

    Ok(())
}

#[test]
fn test_message_grow_smaller() -> Result<()> {
    let mut m = Message::new();
    m.grow(2, false);
    assert!(m.raw.capacity() >= 20, "Bad capacity {}", m.raw.capacity());

    assert!(m.raw.len() >= 20, "Bad length {}", m.raw.len());

    Ok(())
}

#[test]
fn test_message_string() -> Result<()> {
    let m = Message::new();
    assert_ne!(m.to_string(), "", "bad string");

    Ok(())
}

#[test]
fn test_is_message() -> Result<()> {
    let mut m = Message::new();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;
    m.write_header();

    let tests = vec![
        (vec![], false),                           // 0
        (vec![1, 2, 3], false),                    // 1
        (vec![1, 2, 4], false),                    // 2
        (vec![1, 2, 4, 5, 6, 7, 8, 9, 20], false), // 3
        (m.raw.to_vec(), true),                    // 5
        (
            vec![
                0, 0, 0, 0, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            true,
        ), // 6
    ];

    for (input, output) in tests {
        let got = is_stun_message(&input);
        assert_eq!(got, output, "IsMessage({input:?}) {got} != {output}");
    }

    Ok(())
}

#[test]
fn test_message_contains() -> Result<()> {
    let mut m = Message::new();
    m.add(ATTR_SOFTWARE, "value".as_bytes());

    assert!(m.contains(ATTR_SOFTWARE), "message should contain software");
    assert!(!m.contains(ATTR_NONCE), "message should not contain nonce");

    Ok(())
}

#[test]
fn test_message_full_size() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "webrtc-rs/stun".to_owned(),
        )),
        Box::new(MessageIntegrity::new_long_term_integrity_with_provider(
            "username".to_owned(),
            "realm".to_owned(),
            "password".to_owned(),
            crypto::default_provider()
                .expect("a built-in provider is enabled for tests")
                .crypto(),
        )?),
        Box::new(FINGERPRINT),
    ])?;
    let l = m.raw.len();
    m.raw = m.raw[..l - 10].to_vec();

    let mut decoder = Message::new();
    let l = m.raw.len();
    decoder.raw = m.raw[..l - 10].to_vec();
    let result = decoder.decode();
    assert!(result.is_err(), "decode on truncated buffer should error");

    Ok(())
}

#[test]
fn test_message_clone_to() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "webrtc-rs/stun".to_owned(),
        )),
        Box::new(MessageIntegrity::new_long_term_integrity_with_provider(
            "username".to_owned(),
            "realm".to_owned(),
            "password".to_owned(),
            crypto::default_provider()
                .expect("a built-in provider is enabled for tests")
                .crypto(),
        )?),
        Box::new(FINGERPRINT),
    ])?;
    m.encode();

    let mut b = Message::new();
    m.clone_to(&mut b)?;
    assert_eq!(b, m, "not equal");

    //TODO: Corrupting m and checking that b is not corrupted.
    /*let (mut s, ok) = b.attributes.get(ATTR_SOFTWARE);
    assert!(ok, "no software attribute");
    s.value[0] = b'k';
    s.add_to(&mut b)?;
    assert_ne!(b, m, "should not be equal");*/

    Ok(())
}

#[test]
fn test_message_add_to() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(FINGERPRINT),
    ])?;
    m.encode();

    let mut b = Message::new();
    m.clone_to(&mut b)?;

    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 2, 0]);
    assert_ne!(b, m, "should not be equal");

    m.add_to(&mut b)?;
    assert_eq!(b, m, "should be equal");

    Ok(())
}

#[test]
fn test_decode() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();

    let mut m_decoded = Message::new();
    m_decoded.raw.clear();
    m_decoded.raw.extend_from_slice(&m.raw);
    m_decoded.decode()?;
    assert_eq!(
        m_decoded, m,
        "decoded result is not equal to encoded message"
    );

    Ok(())
}

#[test]
fn test_message_marshal_binary() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "software".to_owned())),
        Box::new(XorMappedAddress {
            ip: "213.1.223.5".parse().unwrap(),
            port: 0,
        }),
    ])?;

    let mut data = m.marshal_binary()?;
    // Reset m.Raw to check retention.
    for i in 0..m.raw.len() {
        m.raw[i] = 0;
    }
    m.unmarshal_binary(&data)?;

    // Reset data to check retention.
    #[allow(clippy::needless_range_loop)]
    data.fill(0);

    m.decode()?;

    Ok(())
}

fn encoded_binding_request() -> Vec<u8> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([7; TRANSACTION_ID_SIZE])),
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "abc".to_owned())),
    ])
    .unwrap();
    m.raw
}

/// RFC 8489 section 6.3: the first two bits of a STUN message are zero.
#[test]
fn test_a_message_whose_first_two_bits_are_set_is_not_stun() {
    for top in [0x40u8, 0x80, 0xc0] {
        let mut raw = encoded_binding_request();
        raw[0] |= top;
        assert!(!is_stun_message(&raw), "first byte {:#x}", raw[0]);
        let mut m = Message::new();
        assert!(
            m.unmarshal_binary(&raw).is_err(),
            "first byte {:#x}",
            raw[0]
        );
    }
    let raw = encoded_binding_request();
    assert!(is_stun_message(&raw));
    assert!(Message::new().unmarshal_binary(&raw).is_ok());
}

/// RFC 8489 section 6.3: the message length must be sensible: a multiple of four (section 5)
/// that describes the whole datagram.
#[test]
fn test_a_message_whose_length_is_not_the_datagram_is_refused() {
    // Bytes after the message the header describes.
    let mut trailing = encoded_binding_request();
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert!(Message::new().unmarshal_binary(&trailing).is_err());

    // A length that is not a multiple of four: an attribute of 3 bytes with no padding.
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([7; TRANSACTION_ID_SIZE])),
    ])
    .unwrap();
    let mut unpadded = m.raw.clone();
    unpadded.extend_from_slice(&[0x80, 0x22, 0x00, 0x03, b'a', b'b', b'c']);
    unpadded[3] = 7;
    assert!(Message::new().unmarshal_binary(&unpadded).is_err());
}

/// RFC 8489 section 14: the padding of an attribute is zero when sent, also in a buffer that
/// held something else before.
#[test]
fn test_attribute_padding_is_zero_when_sent() {
    let mut m = Message::new();
    m.write_header();
    m.add(ATTR_SOFTWARE, &[0xff; 16]);
    m.reset();
    m.write_header();
    for (value, padding) in [(&b"a"[..], 3), (b"ab", 2), (b"abc", 1), (b"abcd", 0)] {
        m.add(ATTR_SOFTWARE, value);
        let end = m.raw.len();
        assert!(end.is_multiple_of(4));
        assert_eq!(&m.raw[end - padding - value.len()..end - padding], value);
        assert!(m.raw[end - padding..].iter().all(|b| *b == 0), "{value:?}");
        // The attribute's length field is the value's length without the padding.
        let header = end - padding - value.len() - ATTRIBUTE_HEADER_SIZE;
        assert_eq!(&m.raw[header + 2..header + 4], &[0, value.len() as u8]);
    }
}

/// RFC 8489 section 14: the padding of an attribute is ignored when received, whatever it
/// holds.
#[test]
fn test_attribute_padding_is_ignored_when_received() -> Result<()> {
    let mut raw = encoded_binding_request();
    // SOFTWARE "abc" is the last attribute: its fourth byte is padding.
    let end = raw.len() - 1;
    assert_eq!(raw[end], 0);
    raw[end] = 0xa5;
    let mut m = Message::new();
    m.unmarshal_binary(&raw)?;
    assert_eq!(m.get(ATTR_SOFTWARE)?, b"abc");
    assert_eq!(TextAttribute::get_from_as(&m, ATTR_SOFTWARE)?.text, "abc");
    Ok(())
}

/// RFC 8489 section 14: when an attribute appears more than once, the first one is the one
/// that is processed.
#[test]
fn test_first_of_duplicate_attributes_is_used() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(TransactionId([7; TRANSACTION_ID_SIZE])),
        Box::new(XorMappedAddress {
            ip: "192.0.2.1".parse().unwrap(),
            port: 1111,
        }),
        Box::new(XorMappedAddress {
            ip: "192.0.2.2".parse().unwrap(),
            port: 2222,
        }),
    ])?;
    let mut decoded = Message::new();
    decoded.unmarshal_binary(&m.raw)?;
    assert_eq!(decoded.attributes.0.len(), 2);
    let mut got = XorMappedAddress::default();
    got.get_from(&decoded)?;
    assert_eq!(got.to_string(), "192.0.2.1:1111");
    Ok(())
}

/// RFC 8489 section 5: transaction ids are random over all 96 bits. Over 256 ids, no two are
/// equal and every bit takes both values (a fixed or counted bit would fail; a random one
/// fails once in 2^248 runs).
#[test]
fn test_transaction_ids_are_random_in_every_bit() {
    let mut ids: Vec<TransactionId> = (0..128).map(|_| TransactionId::new()).collect();
    for _ in 0..128 {
        let mut m = Message::new();
        m.write_header();
        m.new_transaction_id().unwrap();
        assert_eq!(
            &m.raw[8..20],
            &m.transaction_id.0,
            "the id is in the header"
        );
        ids.push(m.transaction_id);
    }
    let mut ones = [0u8; TRANSACTION_ID_SIZE];
    let mut zeros = [0u8; TRANSACTION_ID_SIZE];
    for id in &ids {
        for (i, byte) in id.0.iter().enumerate() {
            ones[i] |= byte;
            zeros[i] |= !byte;
        }
    }
    assert_eq!(ones, [0xff; TRANSACTION_ID_SIZE]);
    assert_eq!(zeros, [0xff; TRANSACTION_ID_SIZE]);
    let distinct: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len());
}

/// A message is read from a reader whole, whatever its length.
#[test]
fn test_read_from_reads_a_message_longer_than_the_initial_buffer() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([7; TRANSACTION_ID_SIZE])),
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "s".repeat(100))),
        Box::new(TextAttribute::new(ATTR_USERNAME, "u".repeat(400))),
    ])?;
    assert!(m.raw.len() > 500);
    let mut got = Message::new();
    let n = got.read_from(&mut BufReader::new(m.raw.as_slice()))?;
    assert_eq!(n, m.raw.len());
    assert_eq!(got, m);
    Ok(())
}

/// RFC 8489 section 6.3: the comprehension-required attributes a usage does not know are
/// found; comprehension-optional ones never are.
#[test]
fn test_unknown_required_attributes_are_listed_in_order() {
    let mut m = Message::new();
    m.write_header();
    m.add(ATTR_USERNAME, b"user");
    m.add(AttrType(0x7ffe), &[]);
    m.add(ATTR_PRIORITY, &[0; 4]);
    m.add(AttrType(0x8000), &[]);
    m.add(AttrType(0x7ffe), &[]);
    m.add(AttrType(0xffff), &[]);
    assert_eq!(
        m.unknown_required_attributes(&STUN_ATTRIBUTES),
        vec![AttrType(0x7ffe), ATTR_PRIORITY]
    );
    let with_ice = [&STUN_ATTRIBUTES[..], &[ATTR_PRIORITY]].concat();
    assert_eq!(
        m.unknown_required_attributes(&with_ice),
        vec![AttrType(0x7ffe)]
    );
    assert!(STUN_ATTRIBUTES.iter().all(|a| a.required()));
}
