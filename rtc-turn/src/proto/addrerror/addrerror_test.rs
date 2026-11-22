use super::*;
use stun::error_code::{CODE_ADDR_FAMILY_NOT_SUPPORTED, CODE_INSUFFICIENT_CAPACITY};

#[test]
fn test_address_error_code_round_trip() -> Result<()> {
    for (family, code, reason) in [
        (
            REQUESTED_FAMILY_IPV6,
            CODE_ADDR_FAMILY_NOT_SUPPORTED,
            "Address Family not Supported",
        ),
        (
            REQUESTED_FAMILY_IPV4,
            CODE_INSUFFICIENT_CAPACITY,
            "Insufficient Capacity",
        ),
    ] {
        let attr = AddressErrorCode {
            family: RequestedAddressFamily(family.0),
            code,
            reason: reason.as_bytes().to_vec(),
        };
        let mut m = Message::new();
        attr.add_to(&mut m)?;
        m.write_header();

        let v = m.get(ATTR_ADDRESS_ERROR_CODE)?;
        assert_eq!(v[0], family.0, "the family is the first byte");
        assert_eq!(v[1], 0, "reserved");
        assert_eq!(
            u16::from(v[2]),
            code.0 / 100,
            "the class, reserved bits zero"
        );
        assert_eq!(u16::from(v[3]), code.0 % 100, "the number");
        assert_eq!(&v[4..], reason.as_bytes());

        let mut decoded = Message::new();
        decoded.write(&m.raw)?;
        let mut got = AddressErrorCode::default();
        got.get_from(&decoded)?;
        assert!(got == attr, "{got:?}");
    }
    Ok(())
}

/// RFC 8656 §18.12: the 13 reserved bits "MUST be ignored by the client".
#[test]
fn test_address_error_code_decoding_ignores_the_reserved_bits() -> Result<()> {
    let mut m = Message::new();
    // Family IPv6, every reserved bit set, class 4, number 40.
    m.add(
        ATTR_ADDRESS_ERROR_CODE,
        &[0x02, 0xff, 0xf8 | 0x04, 40, b'n', b'o'],
    );
    let mut got = AddressErrorCode::default();
    got.get_from(&m)?;
    assert_eq!(got.family, REQUESTED_FAMILY_IPV6);
    assert!(got.code == CODE_ADDR_FAMILY_NOT_SUPPORTED, "{got:?}");
    assert_eq!(got.reason, b"no");
    assert_eq!(got.to_string(), "IPv6: 440 no");
    Ok(())
}

#[test]
fn test_address_error_code_refuses_malformed_values() {
    let mut short = Message::new();
    short.add(ATTR_ADDRESS_ERROR_CODE, &[0x02, 0, 4]);
    assert_eq!(
        AddressErrorCode::default().get_from(&short),
        Err(Error::ErrUnexpectedEof)
    );

    let mut family = Message::new();
    family.add(ATTR_ADDRESS_ERROR_CODE, &[0x07, 0, 4, 40]);
    assert_eq!(
        AddressErrorCode::default().get_from(&family),
        Err(Error::ErrInvalidRequestedFamilyValue)
    );

    let mut m = Message::new();
    assert!(
        AddressErrorCode {
            family: RequestedAddressFamily(0x09),
            code: CODE_ADDR_FAMILY_NOT_SUPPORTED,
            reason: vec![],
        }
        .add_to(&mut m)
        .is_err()
    );
    assert!(
        AddressErrorCode {
            family: RequestedAddressFamily(0x02),
            code: ErrorCode(99),
            reason: vec![],
        }
        .add_to(&mut m)
        .is_err()
    );
}
