//! RFC 3550 Appendix A.1: the header validity checks.

use super::*;

/// V=2, PT 96, seq 1, ts 2, SSRC 3.
const FIXED: [u8; 12] = [
    0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
];

fn packet(first: u8, tail: &[u8]) -> Vec<u8> {
    let mut raw = FIXED.to_vec();
    raw[0] = first;
    raw.extend_from_slice(tail);
    raw
}

#[test]
fn a_plain_packet_is_valid_and_its_parts_are_located() {
    let raw = packet(0x80, &[1, 2, 3]);
    assert_eq!(
        Ok(RtpLayout {
            payload_type: 96,
            header_len: 12,
            payload_len: 3,
            padding_len: 0,
        }),
        check_rtp_validity(&raw, |_| true)
    );
}

#[test]
fn a_version_other_than_2_is_invalid() {
    for first in [0x00, 0x40, 0xC0] {
        assert_eq!(
            Err(Error::BadVersion),
            check_rtp_validity(&packet(first, &[1]), |_| true)
        );
    }
}

#[test]
fn an_unknown_payload_type_is_invalid() {
    let raw = packet(0x80, &[1]);
    assert_eq!(
        Err(Error::WrongPayloadType),
        check_rtp_validity(&raw, |pt| pt != 96)
    );
    assert!(check_rtp_validity(&raw, |pt| pt == 96).is_ok());
}

#[test]
fn an_rtcp_sender_or_receiver_report_is_not_rtp() {
    for second in [200u8, 201] {
        let mut raw = packet(0x80, &[1]);
        raw[1] = second;
        assert_eq!(
            Err(Error::WrongPayloadType),
            check_rtp_validity(&raw, |_| true)
        );
    }
    // PT 72 without the marker is an ordinary payload type.
    let mut raw = packet(0x80, &[1]);
    raw[1] = 72;
    assert!(check_rtp_validity(&raw, |_| true).is_ok());
}

#[test]
fn the_length_must_cover_the_csrc_list() {
    assert_eq!(
        Err(Error::ErrHeaderSizeInsufficient),
        check_rtp_validity(&FIXED[..11], |_| true)
    );
    // CC = 2: eight more bytes are needed.
    assert_eq!(
        Err(Error::ErrHeaderSizeInsufficient),
        check_rtp_validity(&packet(0x82, &[0; 7]), |_| true)
    );
    assert_eq!(
        Ok(RtpLayout {
            payload_type: 96,
            header_len: 20,
            payload_len: 0,
            padding_len: 0,
        }),
        check_rtp_validity(&packet(0x82, &[0; 8]), |_| true)
    );
}

#[test]
fn the_extension_length_must_fit_the_packet() {
    // X=1, block header says two words, one is there.
    let short = packet(0x90, &[0xBE, 0xDE, 0x00, 0x02, 0x10, 0xAA, 0x00, 0x00]);
    assert_eq!(
        Err(Error::ErrHeaderSizeInsufficientForExtension),
        check_rtp_validity(&short, |_| true)
    );
    // X=1 and not even the block header.
    assert_eq!(
        Err(Error::ErrHeaderSizeInsufficientForExtension),
        check_rtp_validity(&packet(0x90, &[0xBE, 0xDE]), |_| true)
    );
    let whole = packet(
        0x90,
        &[0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x00, 0x00, 7, 7],
    );
    assert_eq!(
        Ok(RtpLayout {
            payload_type: 96,
            header_len: 20,
            payload_len: 2,
            padding_len: 0,
        }),
        check_rtp_validity(&whole, |_| true)
    );
}

#[test]
fn a_padding_count_must_be_non_zero_and_fit_what_follows_the_header() {
    // P=1: one payload byte and three padding bytes.
    assert_eq!(
        Ok(RtpLayout {
            payload_type: 96,
            header_len: 12,
            payload_len: 1,
            padding_len: 3,
        }),
        check_rtp_validity(&packet(0xA0, &[0xAB, 0, 0, 3]), |_| true)
    );
    // The whole of what follows the header may be padding.
    assert!(check_rtp_validity(&packet(0xA0, &[0, 0, 0, 4]), |_| true).is_ok());
    // A count that reaches into the header.
    assert_eq!(
        Err(Error::ErrShortPacket),
        check_rtp_validity(&packet(0xA0, &[0, 0, 0, 5]), |_| true)
    );
    // A count of zero is not a padding count.
    assert_eq!(
        Err(Error::ErrShortPacket),
        check_rtp_validity(&packet(0xA0, &[0xAB, 0]), |_| true)
    );
    // P=1 with nothing after the header: the "count" would be a header octet.
    assert_eq!(
        Err(Error::ErrShortPacket),
        check_rtp_validity(&FIXED.map(|b| if b == 0x80 { 0xA0 } else { b }), |_| true)
    );
}

#[test]
fn what_the_check_accepts_the_parser_accepts() {
    use crate::packet::Packet;
    use shared::marshal::Unmarshal;

    let samples: Vec<Vec<u8>> = vec![
        packet(0x80, &[1, 2, 3]),
        packet(0x82, &[0; 8]),
        packet(
            0x90,
            &[0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x00, 0x00, 7, 7],
        ),
        packet(0xA0, &[0xAB, 0, 0, 3]),
    ];
    for raw in samples {
        let layout = check_rtp_validity(&raw, |_| true).unwrap();
        let parsed = Packet::unmarshal(&mut &raw[..]).unwrap();
        assert_eq!(layout.payload_len, parsed.payload.len());
        assert_eq!(layout.padding_len, usize::from(parsed.header.padding_size));
        assert_eq!(layout.payload_type, parsed.header.payload_type);
    }
}
