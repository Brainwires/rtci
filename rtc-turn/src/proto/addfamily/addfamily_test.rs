use super::*;

#[test]
fn test_additional_address_family_is_ipv6_with_zero_reserved_bytes() -> Result<()> {
    let mut m = Message::new();
    AdditionalAddressFamily::default().add_to(&mut m)?;
    m.write_header();
    assert_eq!(
        m.get(ATTR_ADDITIONAL_ADDRESS_FAMILY)?,
        vec![0x02, 0, 0, 0],
        "RFC 8656 §7.1: the value is 0x02 (IPv6); the rest is reserved"
    );

    let mut decoded = Message::new();
    decoded.write(&m.raw)?;
    let mut got = AdditionalAddressFamily(REQUESTED_FAMILY_IPV4);
    got.get_from(&decoded)?;
    assert_eq!(got, AdditionalAddressFamily(REQUESTED_FAMILY_IPV6));
    Ok(())
}

#[test]
fn test_additional_address_family_refuses_any_other_family() {
    let mut m = Message::new();
    assert_eq!(
        AdditionalAddressFamily(REQUESTED_FAMILY_IPV4).add_to(&mut m),
        Err(Error::ErrInvalidRequestedFamilyValue)
    );
    assert!(!m.contains(ATTR_ADDITIONAL_ADDRESS_FAMILY));
}

#[test]
fn test_additional_address_family_decoding_ignores_the_reserved_bytes() -> Result<()> {
    let mut m = Message::new();
    m.add(ATTR_ADDITIONAL_ADDRESS_FAMILY, &[0x02, 0xff, 0xff, 0xff]);
    let mut got = AdditionalAddressFamily(REQUESTED_FAMILY_IPV4);
    got.get_from(&m)?;
    assert_eq!(got.0, REQUESTED_FAMILY_IPV6);

    let mut bad_size = Message::new();
    bad_size.add(ATTR_ADDITIONAL_ADDRESS_FAMILY, &[0x02, 0, 0]);
    assert!(
        AdditionalAddressFamily::default()
            .get_from(&bad_size)
            .is_err()
    );

    let mut bad_family = Message::new();
    bad_family.add(ATTR_ADDITIONAL_ADDRESS_FAMILY, &[0x03, 0, 0, 0]);
    assert!(
        AdditionalAddressFamily::default()
            .get_from(&bad_family)
            .is_err()
    );
    Ok(())
}
