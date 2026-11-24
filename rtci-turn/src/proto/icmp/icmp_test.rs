use super::*;

#[test]
fn test_icmp_round_trip() -> Result<()> {
    // ICMPv4 Destination Unreachable, fragmentation needed and DF set, next-hop MTU 1400;
    // and the largest values the fields hold.
    for attr in [
        Icmp {
            icmp_type: 3,
            code: 4,
            error_data: 1400,
        },
        Icmp {
            icmp_type: 0x7f,
            code: 0x1ff,
            error_data: u32::MAX,
        },
        Icmp::default(),
    ] {
        let mut m = Message::new();
        attr.add_to(&mut m)?;
        m.write_header();
        let v = m.get(ATTR_ICMP)?;
        assert_eq!(v.len(), 8);
        assert_eq!(&v[..2], &[0, 0], "the reserved field is zero when sent");

        let mut decoded = Message::new();
        decoded.write(&m.raw)?;
        let mut got = Icmp::default();
        got.get_from(&decoded)?;
        assert_eq!(got, attr);
    }
    Ok(())
}

/// The layout of RFC 8656 Figure 11: 16 reserved bits, a 7-bit type, a 9-bit code, 32 bits of
/// error data.
#[test]
fn test_icmp_wire_layout() -> Result<()> {
    let mut m = Message::new();
    Icmp {
        icmp_type: 3,
        code: 4,
        error_data: 0x0102_0304,
    }
    .add_to(&mut m)?;
    assert_eq!(
        m.get(ATTR_ICMP)?,
        vec![0, 0, 3 << 1, 4, 1, 2, 3, 4],
        "the type takes the upper seven bits of the third byte"
    );
    Ok(())
}

/// RFC 8656 §18.13: the reserved field "MUST be ignored when received".
#[test]
fn test_icmp_decoding_ignores_the_reserved_field() -> Result<()> {
    let mut m = Message::new();
    m.add(ATTR_ICMP, &[0xff, 0xff, 3 << 1, 4, 0, 0, 5, 120]);
    let mut got = Icmp::default();
    got.get_from(&m)?;
    assert_eq!(
        got,
        Icmp {
            icmp_type: 3,
            code: 4,
            error_data: 1400,
        }
    );
    assert_eq!(got.to_string(), "ICMP type 3 code 4 data 1400");
    Ok(())
}

#[test]
fn test_icmp_refuses_values_that_do_not_fit_and_a_wrong_size() {
    let mut m = Message::new();
    assert!(
        Icmp {
            icmp_type: 0x80,
            code: 0,
            error_data: 0,
        }
        .add_to(&mut m)
        .is_err()
    );
    assert!(
        Icmp {
            icmp_type: 0,
            code: 0x200,
            error_data: 0,
        }
        .add_to(&mut m)
        .is_err()
    );
    assert!(!m.contains(ATTR_ICMP));

    let mut short = Message::new();
    short.add(ATTR_ICMP, &[0, 0, 6, 4]);
    assert!(Icmp::default().get_from(&short).is_err());
}
