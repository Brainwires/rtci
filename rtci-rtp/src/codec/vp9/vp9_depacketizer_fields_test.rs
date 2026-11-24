//! RFC 9628 4.2: three reference indices are allowed, and G is one bit of the SS header.

use super::*;
use bytes::Bytes;

#[test]
fn three_reference_indices_are_accepted() -> Result<()> {
    // I=1 P=1 F=1, 7-bit picture id 2, then three P_DIFFs (1, 2 and 3) with N set on the first two.
    let mut packet = Vp9Packet::default();
    let payload = packet.depacketize(&Bytes::from_static(&[0xD0, 0x02, 0x03, 0x05, 0x06, 0xAA]))?;
    assert_eq!(vec![1, 2, 3], packet.pdiff);
    assert_eq!(&[0xAA], &payload[..]);
    Ok(())
}

#[test]
fn reserved_bits_of_the_ss_header_are_not_the_g_bit() -> Result<()> {
    // V=1 (SS present), B=1, E=1; SS header N_S=0, Y=0, G=0 with the three reserved bits set.
    let mut packet = Vp9Packet::default();
    packet.depacketize(&Bytes::from_static(&[0x0E, 0x07, 0xAA]))?;
    assert!(packet.v);
    assert!(!packet.g, "the reserved bits must not read as G");
    assert_eq!(0, packet.ng);
    Ok(())
}

#[test]
fn the_g_bit_announces_a_picture_group() -> Result<()> {
    // SS header with G=1, then N_G=1 and one picture-group entry: TID 0, U=0, R=1, P_DIFF 1.
    let mut packet = Vp9Packet::default();
    packet.depacketize(&Bytes::from_static(&[0x0E, 0x08, 0x01, 0x04, 0x01, 0xAA]))?;
    assert!(packet.g);
    assert_eq!(1, packet.ng);
    assert_eq!(vec![vec![1u8]], packet.pgpdiff);
    Ok(())
}
