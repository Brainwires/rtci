use super::*;
use shared::error::*;
use std::net::IpAddr;

#[test]
fn test_mapped_address() -> Result<()> {
    let mut m = Message::new();
    let addr = MappedAddress {
        ip: "122.12.34.5".parse().unwrap(),
        port: 5412,
    };
    assert_eq!(addr.to_string(), "122.12.34.5:5412", "bad string {addr}");

    //"add_to"
    {
        addr.add_to(&mut m)?;

        //"GetFrom"
        {
            let mut got = MappedAddress::default();
            got.get_from(&m)?;
            assert_eq!(got.ip, addr.ip, "got bad IP: {}", got.ip);

            //"Not found"
            {
                let message = Message::new();
                let result = got.get_from(&message);
                if let Err(err) = result {
                    assert_eq!(
                        Error::ErrAttributeNotFound,
                        err,
                        "should be not found: {err}"
                    );
                } else {
                    panic!("expected error, but got ok");
                }
            }
            //"Bad family"
            {
                let (mut v, _) = m.attributes.get(ATTR_MAPPED_ADDRESS);
                v.value[0] = 32;
                got.get_from(&m)?
            }
            //"Bad length"
            {
                let mut message = Message::new();
                message.add(ATTR_MAPPED_ADDRESS, &[1, 2, 3]);
                let result = got.get_from(&message);
                if let Err(err) = result {
                    assert_eq!(
                        Error::ErrUnexpectedEof,
                        err,
                        "<{}> should be <{}>",
                        err,
                        Error::ErrUnexpectedEof
                    );
                } else {
                    panic!("expected error, but got ok");
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_mapped_address_v6() -> Result<()> {
    let mut m = Message::new();
    let addr = MappedAddress {
        ip: "::".parse().unwrap(),
        port: 5412,
    };

    //"add_to"
    {
        addr.add_to(&mut m)?;

        //"GetFrom"
        {
            let mut got = MappedAddress::default();
            got.get_from(&m)?;
            assert_eq!(got.ip, addr.ip, "got bad IP: {}", got.ip);

            //"Not found"
            {
                let message = Message::new();
                let result = got.get_from(&message);
                if let Err(err) = result {
                    assert_eq!(
                        Error::ErrAttributeNotFound,
                        err,
                        "<{}> should be <{}>",
                        err,
                        Error::ErrAttributeNotFound,
                    );
                } else {
                    panic!("expected error, but got ok");
                }
            }
        }
    }
    Ok(())
}

/// The value of a MAPPED-ADDRESS for `ip` and `port`.
fn mapped_address_value(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut m = Message::new();
    m.write_header();
    MappedAddress { ip, port }.add_to(&mut m).unwrap();
    m.get(ATTR_MAPPED_ADDRESS).unwrap()
}

/// RFC 8489 section 14.15: ALTERNATE-SERVER is encoded as MAPPED-ADDRESS, under its own
/// attribute type (0x8023).
#[test]
fn test_alternate_server() -> Result<()> {
    let ip: IpAddr = "122.12.34.5".parse().unwrap();
    let port = 5412;
    let mut m = Message::new();
    m.write_header();
    AlternateServer { ip, port }.add_to(&mut m)?;
    assert_eq!(ATTR_ALTERNATE_SERVER.value(), 0x8023);
    assert!(!m.contains(ATTR_MAPPED_ADDRESS));
    assert_eq!(
        m.get(ATTR_ALTERNATE_SERVER)?,
        mapped_address_value(ip, port)
    );

    let mut decoded = Message::new();
    decoded.unmarshal_binary(&m.raw)?;
    let mut got = AlternateServer::default();
    got.get_from(&decoded)?;
    assert_eq!(got, AlternateServer { ip, port });
    assert_eq!(got.to_string(), "122.12.34.5:5412");

    // "Not found": neither an empty message nor a MAPPED-ADDRESS is an ALTERNATE-SERVER.
    let mut mapped = Message::new();
    mapped.write_header();
    MappedAddress { ip, port }.add_to(&mut mapped)?;
    for message in [Message::new(), mapped] {
        assert_eq!(got.get_from(&message), Err(Error::ErrAttributeNotFound));
    }
    Ok(())
}

/// RFC 5780 sections 7.3 and 7.4: RESPONSE-ORIGIN (0x802b) and OTHER-ADDRESS (0x802c) are
/// encoded as MAPPED-ADDRESS, each under its own attribute type.
#[test]
fn test_other_address() -> Result<()> {
    let ip: IpAddr = "2001:db8::68".parse().unwrap();
    let port = 5412;
    let mut m = Message::new();
    m.write_header();
    OtherAddress { ip, port }.add_to(&mut m)?;
    ResponseOrigin { ip, port: 3478 }.add_to(&mut m)?;
    assert_eq!(ATTR_OTHER_ADDRESS.value(), 0x802c);
    assert_eq!(ATTR_RESPONSE_ORIGIN.value(), 0x802b);
    assert!(!m.contains(ATTR_MAPPED_ADDRESS));
    assert_eq!(m.get(ATTR_OTHER_ADDRESS)?, mapped_address_value(ip, port));
    assert_eq!(m.get(ATTR_RESPONSE_ORIGIN)?, mapped_address_value(ip, 3478));

    let mut decoded = Message::new();
    decoded.unmarshal_binary(&m.raw)?;
    let mut other = OtherAddress::default();
    other.get_from(&decoded)?;
    assert_eq!(other, OtherAddress { ip, port });
    let mut origin = ResponseOrigin::default();
    origin.get_from(&decoded)?;
    assert_eq!(origin, ResponseOrigin { ip, port: 3478 });

    // "Not found"
    assert_eq!(
        other.get_from(&Message::new()),
        Err(Error::ErrAttributeNotFound)
    );
    Ok(())
}

fn message_with_attribute(t: AttrType, value: &[u8]) -> Message {
    let mut m = Message::new();
    m.write_header();
    m.add(t, value);
    m
}

/// RFC 8489 section 14.1: the address is 32 bits for IPv4 and 128 bits for IPv6, never less
/// and never more.
#[test]
fn test_mapped_address_of_the_wrong_length_is_refused() {
    let mut v6 = vec![0x00, 0x02, 0x12, 0x34];
    v6.extend_from_slice(&[0xaa; 6]);
    let mut v4_long = vec![0x00, 0x01, 0x12, 0x34];
    v4_long.extend_from_slice(&[0xaa; 16]);
    let v4_short = vec![0x00, 0x01, 0x12, 0x34, 0xaa, 0xaa];
    for value in [v6, v4_long, v4_short] {
        let m = message_with_attribute(ATTR_MAPPED_ADDRESS, &value);
        let mut got = MappedAddress::default();
        assert!(got.get_from(&m).is_err(), "{value:02x?} decoded as {got}");
    }
}

/// RFC 8489 section 14.1: the first 8 bits are ignored by a receiver.
#[test]
fn test_mapped_address_ignores_its_first_byte() -> Result<()> {
    let m = message_with_attribute(ATTR_MAPPED_ADDRESS, &[0xff, 0x01, 0x12, 0x34, 192, 0, 2, 1]);
    let mut got = MappedAddress::default();
    got.get_from(&m)?;
    assert_eq!(got.to_string(), "192.0.2.1:4660");
    Ok(())
}
