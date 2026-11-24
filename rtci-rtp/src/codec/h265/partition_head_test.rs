//! RFC 7798 4.4.3: only a fragmentation unit with its start bit clear continues a NAL unit.

use super::*;
use bytes::Bytes;

#[test]
fn a_single_nal_unit_is_a_head() {
    // Type 1 (TRAIL_R), then payload.
    let packet = H265Packet::default();
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x02, 0x01, 0xAA])));
}

#[test]
fn an_aggregation_packet_is_a_head() {
    // Type 48 (AP).
    let packet = H265Packet::default();
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x60, 0x01, 0x00, 0x02])));
}

#[test]
fn only_the_first_fragment_is_a_head() {
    let packet = H265Packet::default();
    // Type 49 (FU): 0x62 0x01, then the FU header.
    let start = Bytes::from_static(&[0x62, 0x01, 0x80 | 19, 0xAA]);
    let middle = Bytes::from_static(&[0x62, 0x01, 19, 0xBB]);
    let end = Bytes::from_static(&[0x62, 0x01, 0x40 | 19, 0xCC]);

    assert!(packet.is_partition_head(&start));
    assert!(!packet.is_partition_head(&middle));
    assert!(!packet.is_partition_head(&end));
}

#[test]
fn a_truncated_payload_is_not_a_head() {
    let packet = H265Packet::default();
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x62])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x62, 0x01])));
}
