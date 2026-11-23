use super::*;
use bytes::{Bytes, BytesMut};

/// The libwebrtc layout: B and the sequence index in the first byte, the standard deviation,
/// the luma and chroma thresholds in one byte, then the samples; round trip.
#[test]
fn a_full_message_parses_field_by_field_and_round_trips() -> Result<()> {
    let raw = Bytes::from_static(&[0x80 | 0x05, 0xff, 0x3a, 10, 20, 30]);
    let parsed = CorruptionDetectionExtension::unmarshal(&mut raw.clone())?;
    assert!(parsed.interpret_sequence_index_as_most_significant_bits);
    assert_eq!(parsed.sequence_index, 5);
    assert_eq!(parsed.std_dev, 0xff);
    assert!((parsed.std_dev() - 40.0).abs() < 1e-9);
    assert_eq!(parsed.luma_error_threshold, 3);
    assert_eq!(parsed.chroma_error_threshold, 0xa);
    assert_eq!(parsed.sample_values, vec![10, 20, 30]);
    assert!(!parsed.synchronization);
    assert_eq!(parsed.full_sequence_index(1234), 5 << 7);

    let mut out = BytesMut::with_capacity(parsed.marshal_size());
    out.resize(parsed.marshal_size(), 0);
    parsed.marshal_to(&mut out)?;
    assert_eq!(out.freeze(), raw);
    Ok(())
}

/// A synchronization message is one byte; two bytes and more than thirteen samples are not
/// messages.
#[test]
fn a_synchronization_message_is_one_byte_and_bad_lengths_are_refused() -> Result<()> {
    let sync = CorruptionDetectionExtension::unmarshal(&mut Bytes::from_static(&[0x7f]))?;
    assert!(sync.synchronization);
    assert_eq!(sync.sequence_index, 0x7f);
    assert!(sync.sample_values.is_empty());
    assert_eq!(sync.marshal_size(), 1);
    assert!(CorruptionDetectionExtension::unmarshal(&mut Bytes::from_static(&[1, 2])).is_err());
    assert!(CorruptionDetectionExtension::unmarshal(&mut Bytes::from(vec![0u8; 17])).is_err());
    assert!(CorruptionDetectionExtension::unmarshal(&mut Bytes::new()).is_err());
    Ok(())
}

/// Without B the 7 bits are the low bits of the 14-bit index; the high ones come from the
/// receiver's last index, carried forward when the low bits wrapped, and the index wraps at
/// 2^14.
#[test]
fn the_low_bits_of_the_sequence_index_extend_the_last_one() {
    let low = |bits: u8| CorruptionDetectionExtension {
        sequence_index: bits,
        ..Default::default()
    };
    assert_eq!(low(0x10).full_sequence_index(0x0105), 0x0110);
    assert_eq!(
        low(0x02).full_sequence_index(0x017e),
        0x0182,
        "wrapped low bits"
    );
    assert_eq!(
        low(0x01).full_sequence_index(0x3fff),
        0x0001,
        "the 14-bit wrap"
    );
}
