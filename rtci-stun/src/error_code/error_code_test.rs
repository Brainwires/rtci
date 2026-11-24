use super::*;

#[test]
fn test_display_valid_utf8() {
    let code = ErrorCodeAttribute {
        code: ErrorCode(401),
        reason: b"Unauthorized".to_vec(),
    };
    assert_eq!(format!("{}", code), "401: Unauthorized");
}

#[test]
fn test_display_invalid_utf8_does_not_panic() {
    let code = ErrorCodeAttribute {
        code: ErrorCode(401),
        reason: vec![0xc0, 0xaf],
    };
    let result = format!("{}", code);
    assert_eq!(result, "401: \u{FFFD}\u{FFFD}");
}

fn message_with_error_code(value: &[u8]) -> Message {
    let mut m = Message::new();
    m.write_header();
    m.add(ATTR_ERROR_CODE, value);
    m
}

/// RFC 8489 section 14.8: the 21 reserved bits are ignored by a receiver; the class is the 3
/// bits after them.
#[test]
fn test_reserved_bits_next_to_the_class_are_ignored() {
    let m = message_with_error_code(&[0xff, 0xff, 0xfc, 38]);
    let mut got = ErrorCodeAttribute::default();
    got.get_from(&m).expect("the attribute decodes");
    assert!(got.code == CODE_STALE_NONCE, "decoded {}", got.code.0);
}

/// RFC 8489 sections 6.3.1.1 and 14.8: ERROR-CODE on the wire is 21 reserved zero bits, the
/// class (hundreds digit) in 3 bits, the number (code modulo 100) in a byte, and the reason
/// phrase; it reads back as the code and phrase that were sent.
#[test]
fn test_error_code_wire_format() -> Result<()> {
    let mut m = Message::new();
    m.write_header();
    CODE_ROLE_CONFLICT.add_to(&mut m)?;
    let mut expected = vec![0x00, 0x00, 0x04, 87];
    expected.extend_from_slice(b"Role Conflict");
    assert_eq!(m.get(ATTR_ERROR_CODE)?, expected);

    let mut decoded = Message::new();
    decoded.unmarshal_binary(&m.raw)?;
    let mut got = ErrorCodeAttribute::default();
    got.get_from(&decoded)?;
    assert_eq!(got.code, CODE_ROLE_CONFLICT);
    assert_eq!(got.reason, b"Role Conflict");

    // An error response without the attribute has no code.
    let empty = Message::new();
    assert_eq!(got.get_from(&empty), Err(Error::ErrAttributeNotFound));
    Ok(())
}

/// RFC 8489 section 14.8 and the IANA registry: each error code the RFC defines has its
/// recommended reason phrase.
#[test]
fn test_rfc8489_error_codes_have_their_recommended_reason() {
    for (code, reason) in [
        (300, "Try Alternate"),
        (400, "Bad Request"),
        (401, "Unauthenticated"),
        (420, "Unknown Attribute"),
        (438, "Stale Nonce"),
        (500, "Server Error"),
    ] {
        let mut m = Message::new();
        m.write_header();
        ErrorCode(code).add_to(&mut m).unwrap();
        let mut got = ErrorCodeAttribute::default();
        got.get_from(&m).unwrap();
        assert_eq!(got.to_string(), format!("{code}: {reason}"));
    }
    assert!(CODE_UNAUTHENTICATED == CODE_UNAUTHORIZED);
}

/// RFC 8489 section 14.8: the class is 3 to 6 and the number 0 to 99, when sent and when
/// received.
#[test]
fn test_error_code_outside_300_to_699_is_refused() {
    for code in [0, 99, 299, 700, 1000, u16::MAX] {
        let mut m = Message::new();
        m.write_header();
        let attr = ErrorCodeAttribute {
            code: ErrorCode(code),
            reason: b"reason".to_vec(),
        };
        assert!(attr.add_to(&mut m).is_err(), "{code} was encoded");
    }
    for code in [300, 399, 487, 699] {
        let mut m = Message::new();
        m.write_header();
        let attr = ErrorCodeAttribute {
            code: ErrorCode(code),
            reason: vec![],
        };
        attr.add_to(&mut m).unwrap();
        let mut got = ErrorCodeAttribute::default();
        got.get_from(&m).unwrap();
        assert_eq!(got.code.0, code);
    }
    for value in [
        &[0, 0, 2, 0][..],
        &[0, 0, 7, 0],
        &[0, 0, 0, 0],
        &[0, 0, 4, 100],
        &[0, 0, 4, 255],
        &[0, 0, 4],
    ] {
        let m = message_with_error_code(value);
        let mut got = ErrorCodeAttribute::default();
        assert!(got.get_from(&m).is_err(), "{value:?} decoded");
    }
}

/// RFC 8489 section 14.8: the reason phrase is UTF-8 of fewer than 128 characters, which is
/// at most 509 bytes when sent; a longer one from the wire is still read.
#[test]
fn test_reason_phrase_is_utf8_of_fewer_than_128_characters() {
    let attr = |reason: Vec<u8>| ErrorCodeAttribute {
        code: CODE_BAD_REQUEST,
        reason,
    };
    let add = |reason: Vec<u8>| {
        let mut m = Message::new();
        m.write_header();
        attr(reason).add_to(&mut m)
    };
    assert!(add("r".repeat(127).into_bytes()).is_ok());
    assert!(add("r".repeat(128).into_bytes()).is_err());
    // 127 characters of four bytes each: 508 bytes.
    assert!(add("\u{1f600}".repeat(127).into_bytes()).is_ok());
    assert!(add("\u{1f600}".repeat(128).into_bytes()).is_err());
    assert!(add(vec![0xff, 0xfe]).is_err(), "not UTF-8");

    let mut value = vec![0, 0, 4, 0];
    value.extend_from_slice("r".repeat(763).as_bytes());
    let mut got = ErrorCodeAttribute::default();
    got.get_from(&message_with_error_code(&value)).unwrap();
    assert_eq!(got.reason.len(), 763);
}
