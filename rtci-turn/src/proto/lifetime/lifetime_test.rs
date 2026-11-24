use super::*;
use shared::error::Error;

#[test]
fn test_lifetime_string() -> Result<()> {
    let l = Lifetime(Duration::from_secs(10));
    assert_eq!(l.to_string(), "10s", "bad string {l}, expected 10s");

    Ok(())
}

#[test]
fn test_lifetime_add_to() -> Result<()> {
    let mut m = Message::new();
    let l = Lifetime(Duration::from_secs(10));
    l.add_to(&mut m)?;
    m.write_header();

    //"GetFrom"
    {
        let mut decoded = Message::new();
        decoded.write(&m.raw)?;

        let mut life = Lifetime::default();
        life.get_from(&decoded)?;
        assert_eq!(life, l, "Decoded {life}, expected {l}");

        //"HandleErr"
        {
            let mut m = Message::new();
            let mut n_handle = Lifetime::default();
            if let Err(err) = n_handle.get_from(&m) {
                assert_eq!(
                    Error::ErrAttributeNotFound,
                    err,
                    "{err} should be not found"
                );
            } else {
                panic!("expected error, but got ok");
            }
            m.add(ATTR_LIFETIME, &[1, 2, 3]);

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

/// RFC 8656 §18.2: LIFETIME is a 32-bit count of seconds. A longer duration is the longest
/// it can say, not its low 32 bits.
#[test]
fn test_lifetime_longer_than_32_bits_saturates() -> Result<()> {
    for (secs, expected) in [
        (u64::from(u32::MAX), u32::MAX),
        (u64::from(u32::MAX) + 1, u32::MAX),
        (u64::from(u32::MAX) + 600, u32::MAX),
        (3600, 3600),
    ] {
        let mut m = Message::new();
        Lifetime(Duration::from_secs(secs)).add_to(&mut m)?;
        assert_eq!(m.get(ATTR_LIFETIME)?, expected.to_be_bytes().to_vec());
    }
    Ok(())
}
