//! RFC 3550 5.1: a packet re-marshals with the padding it arrived with.

use super::*;
use bytes::Bytes;

fn padded(padding: &[u8]) -> Bytes {
    // V=2, P=1, PT 96, seq 1, ts 2, SSRC 3, a 1-byte payload, then the padding.
    let mut raw = vec![
        0xA0, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0xAB,
    ];
    raw.extend_from_slice(padding);
    Bytes::from(raw)
}

#[test]
fn the_padding_size_survives_a_round_trip() -> Result<()> {
    // Seven padding octets: not what marshal would choose for a 1-byte payload (3).
    let raw = padded(&[0, 0, 0, 0, 0, 0, 7]);
    let packet = Packet::unmarshal(&mut raw.clone())?;

    assert!(packet.header.padding);
    assert_eq!(7, packet.header.padding_size);
    assert_eq!(&[0xAB], &packet.payload[..]);
    assert_eq!(raw.len(), packet.marshal_size());
    assert_eq!(raw, packet.marshal()?.freeze());
    Ok(())
}

#[test]
fn without_a_padding_size_marshal_pads_to_32_bits() -> Result<()> {
    let packet = Packet {
        header: Header {
            version: 2,
            padding: true,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 2,
            ssrc: 3,
            ..Default::default()
        },
        payload: Bytes::from_static(&[0xAB]),
    };

    assert_eq!(padded(&[0, 0, 3]), packet.marshal()?.freeze());
    Ok(())
}
