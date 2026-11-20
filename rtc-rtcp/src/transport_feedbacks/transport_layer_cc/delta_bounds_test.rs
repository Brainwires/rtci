//! Status chunks that call for more receive deltas than the packet carries are refused before
//! any delta is queued (draft-holmer-rmcat-transport-wide-cc-extensions-01 3.1.5: every packet
//! reported received with a small or large delta has a one- or two-byte delta after the chunks).

use super::*;
use bytes::Bytes;

/// The fixed part of a TWCC packet: header (length 5 = 24 bytes in all), sender and media SSRC,
/// base sequence number 0, the given packet status count, reference time 0, feedback count 0.
fn twcc(packet_status_count: u16, rest: &[u8]) -> Bytes {
    let mut raw = vec![
        0x8F, 0xCD, 0x00, 0x05, // V=2, FMT=15, PT=205, length 5
        0x00, 0x00, 0x00, 0x01, // sender SSRC
        0x00, 0x00, 0x00, 0x02, // media SSRC
        0x00, 0x00, // base sequence number
    ];
    raw.extend_from_slice(&packet_status_count.to_be_bytes());
    raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reference time, fb_pkt_count
    raw.extend_from_slice(rest);
    Bytes::from(raw)
}

#[test]
fn a_run_claiming_more_deltas_than_the_packet_holds_is_refused() {
    // One run-length chunk: received with a small delta, run 8191; then two bytes. The packet
    // has room for two deltas, not 8191.
    let mut raw = twcc(8191, &[0x3F, 0xFF, 0x04, 0x08]);
    assert_eq!(
        Err(Error::PacketTooShort),
        TransportLayerCc::unmarshal(&mut raw)
    );
}

#[test]
fn a_large_delta_run_needs_two_bytes_each() {
    // Run of 2 large deltas (S=10): four bytes needed, two present.
    let mut raw = twcc(2, &[0x40, 0x02, 0x00, 0x04]);
    assert_eq!(
        Err(Error::PacketTooShort),
        TransportLayerCc::unmarshal(&mut raw)
    );
}

#[test]
fn deltas_that_fill_the_packet_exactly_are_accepted() {
    // Run of 2 small deltas, then exactly the two delta bytes.
    let mut raw = twcc(2, &[0x20, 0x02, 0x04, 0x08]);
    let feedback = TransportLayerCc::unmarshal(&mut raw).expect("a well-formed packet");
    assert_eq!(2, feedback.packet_status_count);
    assert_eq!(2, feedback.recv_deltas.len());
    assert_eq!(
        vec![
            0x04 * TYPE_TCC_DELTA_SCALE_FACTOR,
            0x08 * TYPE_TCC_DELTA_SCALE_FACTOR
        ],
        feedback
            .recv_deltas
            .iter()
            .map(|delta| delta.delta)
            .collect::<Vec<_>>()
    );
}
