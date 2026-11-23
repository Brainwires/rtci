use super::*;
use bytes::Bytes;

/// RFC 6051 Figure 5: Variant A carries the 64-bit NTP timestamp as it is, seconds first.
#[test]
fn the_64_bit_variant_is_the_ntp_timestamp_in_network_order() -> Result<()> {
    let extension = Ntp64Extension {
        ntp_time: 0xE5A1_B2C3_8000_0001,
    };
    let raw = extension.marshal()?;
    assert_eq!(&raw[..], &[0xE5, 0xA1, 0xB2, 0xC3, 0x80, 0x00, 0x00, 0x01]);
    assert_eq!(extension, Ntp64Extension::unmarshal(&mut raw.clone())?);
    assert!(Ntp64Extension::unmarshal(&mut Bytes::from_static(&[0; 7])).is_err());
    Ok(())
}

/// RFC 6051 Figure 6: Variant B carries bits 8 to 31 of the seconds and the whole fraction;
/// the upper eight bits come from the source's RTCP sender reports, also when the timestamp
/// and the report sit on two sides of a 2^24-second boundary.
#[test]
fn the_56_bit_variant_takes_its_upper_seconds_from_a_sender_report() -> Result<()> {
    let ntp = 0xE5A1_B2C3_8000_0001;
    let extension = Ntp56Extension::new(ntp);
    let raw = extension.marshal()?;
    assert_eq!(&raw[..], &[0xA1, 0xB2, 0xC3, 0x80, 0x00, 0x00, 0x01]);
    let read = Ntp56Extension::unmarshal(&mut raw.clone())?;
    assert_eq!(
        ntp,
        read.ntp_time(ntp - (3 << 32)),
        "an SR three seconds before"
    );
    // An SR just before a boundary, the timestamp just after it.
    let after = 0xE600_0000_1000_0000;
    let report = 0xE5FF_FFFF_F000_0000;
    assert_eq!(after, Ntp56Extension::new(after).ntp_time(report));
    // And the other way round.
    assert_eq!(report, Ntp56Extension::new(report).ntp_time(after));
    Ok(())
}
