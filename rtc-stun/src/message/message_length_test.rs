//! The 16-bit message length (RFC 8489 §5) is never wrapped: a message whose attributes do not
//! fit it is refused by `build`, and the header written meanwhile saturates.
use super::*;
use crate::fingerprint::FINGERPRINT;

/// A SOFTWARE attribute of that many zero bytes, added raw.
struct Filler(usize);

impl Setter for Filler {
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_SOFTWARE, &vec![0; self.0]);
        Ok(())
    }
}

fn header_length(m: &Message) -> u16 {
    u16::from_be_bytes([m.raw[2], m.raw[3]])
}

#[test]
fn test_build_accepts_a_message_at_the_length_limit() -> Result<()> {
    // 4 bytes of attribute header and 65,528 of value: 65,532 bytes of attributes.
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Filler(65_528)),
    ])?;
    assert_eq!(m.length, 65_532);
    assert_eq!(header_length(&m), 65_532);

    let mut decoded = Message::new();
    decoded.write(&m.raw)?;
    assert_eq!(decoded.length, 65_532);
    Ok(())
}

#[test]
fn test_build_refuses_a_message_past_the_length_limit() {
    // 65,536 bytes of attributes: one more than the length field holds.
    let mut m = Message::new();
    let result = m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Filler(65_532)),
        Box::new(FINGERPRINT),
    ]);
    assert_eq!(result, Err(Error::ErrPacketTooBig));
}

/// Without `build`, the header still never claims a short length for a long message: it
/// saturates instead of keeping the low 16 bits (70,004 would have read as 4,468).
#[test]
fn test_write_length_saturates() {
    let mut m = Message::new();
    m.add(ATTR_SOFTWARE, &vec![0; 70_000]);
    assert_eq!(m.length, 70_004);
    assert_eq!(header_length(&m), u16::MAX);
    assert_eq!(
        u16::from_be_bytes([
            m.raw[MESSAGE_HEADER_SIZE + 2],
            m.raw[MESSAGE_HEADER_SIZE + 3]
        ]),
        u16::MAX,
        "the attribute's own length field saturates too"
    );
}
