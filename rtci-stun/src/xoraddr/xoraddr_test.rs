use super::*;
use crate::checks::*;
use base64::prelude::*;

use std::io::BufReader;

#[test]
fn test_xor_safe() -> Result<()> {
    let mut dst = vec![0; 8];
    let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let b = vec![8, 7, 7, 6, 6, 3, 4, 1];
    safe_xor_bytes(&mut dst, &a, &b);
    let c = dst.clone();
    safe_xor_bytes(&mut dst, &c, &a);
    for i in 0..dst.len() {
        assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
    }

    Ok(())
}

#[test]
fn test_xor_safe_bsmaller() -> Result<()> {
    let mut dst = vec![0; 5];
    let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let b = vec![8, 7, 7, 6, 6];
    safe_xor_bytes(&mut dst, &a, &b);
    let c = dst.clone();
    safe_xor_bytes(&mut dst, &c, &a);
    for i in 0..dst.len() {
        assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
    }

    Ok(())
}

#[test]
fn test_xormapped_address_get_from() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let addr_value = vec![0x00, 0x01, 0x9c, 0xd5, 0xf4, 0x9f, 0x38, 0xae];
    m.add(ATTR_XORMAPPED_ADDRESS, &addr_value);
    let mut addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    addr.get_from(&m)?;
    assert_eq!(
        addr.ip.to_string(),
        "213.141.156.236",
        "bad IP {} != 213.141.156.236",
        addr.ip
    );
    assert_eq!(addr.port, 48583, "bad Port {} != 48583", addr.port);

    //"UnexpectedEOF"
    {
        let mut m = Message::new();
        // {0, 1} is correct addr family.
        m.add(ATTR_XORMAPPED_ADDRESS, &[0, 1, 3, 4]);
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        let result = addr.get_from(&m);
        if let Err(err) = result {
            assert_eq!(
                Error::ErrUnexpectedEof,
                err,
                "len(v) = 4 should render <{}> error, got <{}>",
                Error::ErrUnexpectedEof,
                err
            );
        } else {
            panic!("expected error, got ok");
        }
    }
    //"AttrOverflowErr"
    {
        let mut m = Message::new();
        // {0, 1} is correct addr family.
        m.add(
            ATTR_XORMAPPED_ADDRESS,
            &[0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4],
        );
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        let result = addr.get_from(&m);
        if let Err(err) = result {
            assert!(
                is_attr_size_overflow(&err),
                "AddTo should return AttrOverflowErr, got: {err}"
            );
        } else {
            panic!("expected error, got ok");
        }
    }

    Ok(())
}

#[test]
fn test_xormapped_address_get_from_invalid() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
    let expected_port = 21254u16;
    let mut addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    let result = addr.get_from(&m);
    assert!(result.is_err(), "should be error");

    addr.ip = expected_ip;
    addr.port = expected_port;
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    m.raw[20 + 4 + 1] = 0x21;
    m.decode()?;
    let mut reader = BufReader::new(m.raw.as_slice());
    m_res.read_from(&mut reader)?;
    let result = addr.get_from(&m);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_xormapped_address_add_to() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
    let expected_port = 21254u16;
    let mut addr = XorMappedAddress {
        ip: "213.141.156.236".parse().unwrap(),
        port: expected_port,
    };
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    m_res.write(&m.raw)?;
    addr.get_from(&m_res)?;
    assert_eq!(
        addr.ip, expected_ip,
        "{} (got) != {} (expected)",
        addr.ip, expected_ip
    );

    assert_eq!(
        addr.port, expected_port,
        "bad Port {} != {}",
        addr.port, expected_port
    );

    Ok(())
}

#[test]
fn test_xormapped_address_add_to_ipv6() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "fe80::dc2b:44ff:fe20:6009".parse().unwrap();
    let expected_port = 21254u16;
    let addr = XorMappedAddress {
        ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
        port: 21254,
    };
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    let mut reader = BufReader::new(m.raw.as_slice());
    m_res.read_from(&mut reader)?;

    let mut got_addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    got_addr.get_from(&m)?;

    assert_eq!(
        got_addr.ip, expected_ip,
        "bad IP {} != {}",
        got_addr.ip, expected_ip
    );
    assert_eq!(
        got_addr.port, expected_port,
        "bad Port {} != {}",
        got_addr.port, expected_port
    );

    Ok(())
}

/// Port of pion's `TestXORMappedAddress_AddTo_Invalid`, which hands `AddTo` an 8-byte IP and
/// expects `ErrBadIPLength`. An `IpAddr` cannot hold an address of the wrong length, so encoding
/// cannot fail that way here: every address is written with its own family's length. The check
/// that remains is on the wire, where a value longer than its family allows is refused.
#[test]
fn test_xormapped_address_add_to_invalid() -> Result<()> {
    for (ip, value_len) in [
        ("1.2.3.4", 4 + IPV4LEN),
        ("fe80::dc2b:44ff:fe20:6009", 4 + IPV6LEN),
    ] {
        let mut m = Message::new();
        m.transaction_id = TransactionId::new();
        let addr = XorMappedAddress {
            ip: ip.parse().unwrap(),
            port: 21254,
        };
        addr.add_to(&mut m)?;
        assert_eq!(m.get(ATTR_XORMAPPED_ADDRESS)?.len(), value_len, "{ip}");

        let mut got = XorMappedAddress::default();
        got.get_from(&m)?;
        assert_eq!(got.ip, addr.ip);
        assert_eq!(got.port, addr.port);
    }

    // An IPv4 family with an IPv6-sized address.
    let mut m = Message::new();
    let mut value = vec![0u8; 4 + IPV6LEN];
    value[0..2].copy_from_slice(&FAMILY_IPV4.to_be_bytes());
    m.add(ATTR_XORMAPPED_ADDRESS, &value);
    let mut got = XorMappedAddress::default();
    let err = got
        .get_from(&m)
        .expect_err("an address longer than its family allows is refused");
    assert!(is_attr_size_overflow(&err), "{err}");

    Ok(())
}

#[test]
fn test_xormapped_address_string() -> Result<()> {
    let tests = vec![
        (
            // 0
            XorMappedAddress {
                ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
                port: 124,
            },
            "[fe80::dc2b:44ff:fe20:6009]:124",
        ),
        (
            // 1
            XorMappedAddress {
                ip: "213.141.156.236".parse().unwrap(),
                port: 8147,
            },
            "213.141.156.236:8147",
        ),
    ];

    for (addr, ip) in tests {
        assert_eq!(
            addr.to_string(),
            ip,
            " XORMappesAddres.String() {addr} (got) != {ip} (expected)",
        );
    }

    Ok(())
}

fn message_with_attribute(t: AttrType, value: &[u8]) -> Message {
    let mut m = Message::new();
    m.write_header();
    m.add(t, value);
    m
}

/// RFC 8489 section 14.2: an X-Address is 32 bits for IPv4 and 128 bits for IPv6; a shorter
/// value is not an address.
#[test]
fn test_xormapped_address_of_the_wrong_length_is_refused() {
    let mut v6 = vec![0x00, 0x02, 0x12, 0x34];
    v6.extend_from_slice(&[0xaa; 6]);
    let v4_short = vec![0x00, 0x01, 0x12, 0x34, 0xaa, 0xaa];
    let mut v4_long = vec![0x00, 0x01, 0x12, 0x34];
    v4_long.extend_from_slice(&[0xaa; 16]);
    for value in [v6, v4_short, v4_long] {
        let m = message_with_attribute(ATTR_XORMAPPED_ADDRESS, &value);
        let mut got = XorMappedAddress::default();
        assert!(got.get_from(&m).is_err(), "{value:02x?} decoded as {got}");
    }
}

/// RFC 8489 section 14.2: the first 8 bits are ignored by a receiver.
#[test]
fn test_xormapped_address_ignores_its_first_byte() -> Result<()> {
    let mut expected = Message::new();
    expected.write_header();
    XorMappedAddress {
        ip: "192.0.2.1".parse().unwrap(),
        port: 4660,
    }
    .add_to(&mut expected)?;
    let mut value = expected.attributes.0[0].value.clone();
    value[0] = 0xff;

    let m = message_with_attribute(ATTR_XORMAPPED_ADDRESS, &value);
    let mut got = XorMappedAddress::default();
    got.get_from(&m)?;
    assert_eq!(got.to_string(), "192.0.2.1:4660");
    Ok(())
}
