use super::*;

/// A unit larger than the MTU is split, unparsed, behind the S / E flags, and comes back
/// whole; head and tail come from the flags, not the marker.
#[test]
fn a_unit_is_split_and_reassembled_unparsed() {
    let unit: Bytes = (0..=255u8).cycle().take(1000).collect::<Vec<_>>().into();
    let mut payloader = OpaquePayloader;
    let payloads = payloader.payload(300, &unit).unwrap();
    assert_eq!(
        payloads.len(),
        4,
        "999 bytes per 299-byte chunk, then the rest"
    );
    assert!(payloads.iter().all(|p| p.len() <= 300));
    assert_eq!(payloads[0][0], OPAQUE_START);
    assert_eq!(payloads[1][0], 0);
    assert_eq!(payloads[3][0], OPAQUE_END);
    let mut depacketizer = OpaqueDepacketizer::default();
    assert!(depacketizer.is_partition_head(&payloads[0]));
    assert!(!depacketizer.is_partition_head(&payloads[1]));
    assert!(depacketizer.is_partition_tail(false, &payloads[3]));
    let mut out = Bytes::new();
    for p in &payloads {
        out = depacketizer.depacketize(p).unwrap();
    }
    assert_eq!(out, unit);
}

/// A unit that fits is one payload with both flags; an empty one too.
#[test]
fn a_small_unit_is_one_payload_with_both_flags() {
    let mut payloader = OpaquePayloader;
    let one = payloader
        .payload(1200, &Bytes::from_static(b"abc"))
        .unwrap();
    assert_eq!(one, vec![Bytes::from_static(b"\xC0abc")]);
    let empty = payloader.payload(1200, &Bytes::new()).unwrap();
    assert_eq!(empty, vec![Bytes::from_static(b"\xC0")]);
    assert!(payloader.payload(1, &Bytes::from_static(b"x")).is_err());
}

/// A payload whose unit start was lost is dropped with the unit, not returned as one.
#[test]
fn a_unit_missing_its_start_is_dropped_whole() {
    let mut payloader = OpaquePayloader;
    let payloads = payloader
        .payload(4, &Bytes::from_static(b"abcdefg"))
        .unwrap();
    let mut depacketizer = OpaqueDepacketizer::default();
    for p in &payloads[1..] {
        assert!(depacketizer.depacketize(p).unwrap().is_empty());
    }
    // The next unit is whole again.
    let next = payloader.payload(4, &Bytes::from_static(b"xyz")).unwrap();
    assert_eq!(
        depacketizer.depacketize(&next[0]).unwrap(),
        Bytes::from_static(b"xyz")
    );
}
