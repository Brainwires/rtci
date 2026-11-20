use super::*;
use shared::error::Error;

#[test]
fn test_channel_number_string() -> Result<()> {
    let n = ChannelNumber(112);
    assert_eq!(n.to_string(), "112", "bad string {n}, expected 112");
    Ok(())
}

/// Port of pion's `TestChannelNumber_NoAlloc`, which counts heap allocations with Go's
/// `testing.AllocsPerRun`. The Rust test harness has no allocation counter, and `Message::add`
/// does copy each value into its attribute list, so what carries over is the property the Go test
/// protects: adding CHANNEL-NUMBER to a message and resetting it reuses the message's buffer
/// instead of growing a new one, whether the number lives on the stack or on the heap.
#[test]
fn test_channel_number_no_alloc() -> Result<()> {
    let mut m = Message::new();
    let capacity = m.raw.capacity();

    // Case with ChannelNumber on stack.
    let n = ChannelNumber(6);
    n.add_to(&mut m)?;
    assert_eq!(m.raw.capacity(), capacity, "adding grew the buffer");
    m.reset();
    assert_eq!(m.raw.capacity(), capacity, "resetting dropped the buffer");

    // On heap.
    let n = Box::new(ChannelNumber(12));
    n.add_to(&mut m)?;
    assert_eq!(m.raw.capacity(), capacity, "adding grew the buffer");
    m.reset();
    assert_eq!(m.raw.capacity(), capacity, "resetting dropped the buffer");

    Ok(())
}

#[test]
fn test_channel_number_add_to() -> Result<()> {
    let mut m = Message::new();
    let n = ChannelNumber(6);
    n.add_to(&mut m)?;
    m.write_header();

    //"GetFrom"
    {
        let mut decoded = Message::new();
        decoded.write(&m.raw)?;

        let mut num_decoded = ChannelNumber::default();
        num_decoded.get_from(&decoded)?;
        assert_eq!(num_decoded, n, "Decoded {num_decoded}, expected {n}");

        //"HandleErr"
        {
            let mut m = Message::new();
            let mut n_handle = ChannelNumber::default();
            if let Err(err) = n_handle.get_from(&m) {
                assert_eq!(
                    Error::ErrAttributeNotFound,
                    err,
                    "{err} should be not found"
                );
            } else {
                panic!("expected error, but got ok");
            }

            m.add(ATTR_CHANNEL_NUMBER, &[1, 2, 3]);

            if let Err(err) = n_handle.get_from(&m) {
                assert!(
                    is_attr_size_invalid(&err),
                    "IsAttrSizeInvalid should be true"
                );
            } else {
                panic!("expected error, but got ok");
            }
        }
    }

    Ok(())
}

#[test]
fn rfc8656_channel_number_boundaries() {
    assert!(!ChannelNumber(0x3fff).valid());
    assert!(ChannelNumber(0x4000).valid());
    assert!(ChannelNumber(0x4fff).valid());
    assert!(!ChannelNumber(0x5000).valid());
    assert!(!ChannelNumber(0x7fff).valid());
}
