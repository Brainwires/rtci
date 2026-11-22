use super::*;
use shared::error::Error;

/// RFC 6062 §6.2.1: CONNECTION-ID (0x002a) is a 32-bit unsigned value in network order.
#[test]
fn test_connection_id_round_trip() -> Result<()> {
    for id in [0u32, 1, 0x0102_0304, u32::MAX] {
        let mut m = Message::new();
        ConnectionId(id).add_to(&mut m)?;
        m.write_header();
        assert_eq!(ATTR_CONNECTION_ID.value(), 0x002a);
        assert_eq!(m.get(ATTR_CONNECTION_ID)?, id.to_be_bytes().to_vec());

        let mut decoded = Message::new();
        decoded.write(&m.raw)?;
        let mut got = ConnectionId::default();
        got.get_from(&decoded)?;
        assert_eq!(got, ConnectionId(id));
        assert_eq!(got.to_string(), id.to_string());
    }
    Ok(())
}

#[test]
fn test_connection_id_refuses_a_missing_or_wrong_sized_value() {
    let m = Message::new();
    assert_eq!(
        ConnectionId::default().get_from(&m),
        Err(Error::ErrAttributeNotFound)
    );
    for bad in [&[1u8, 2, 3][..], &[1, 2, 3, 4, 5]] {
        let mut m = Message::new();
        m.add(ATTR_CONNECTION_ID, bad);
        assert!(ConnectionId::default().get_from(&m).is_err(), "{bad:?}");
    }
}
