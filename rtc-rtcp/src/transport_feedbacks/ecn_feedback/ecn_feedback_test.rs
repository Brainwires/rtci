use super::*;
use crate::packet::unmarshal;
use bytes::Bytes;

/// RFC 6679 section 5.1, Figure 2, built by hand: FMT 8, PT 205, length 7.
const WIRE: [u8; 32] = [
    0x88, 0xcd, 0x00, 0x07, // V=2, FMT=8, RTPFB, length 7
    0x00, 0x00, 0x00, 0x01, // sender SSRC
    0x00, 0x00, 0x00, 0x02, // media SSRC
    0x00, 0x01, 0x00, 0x10, // extended highest sequence number 65552
    0x00, 0x00, 0x00, 0x03, // ECT(0) 3
    0x00, 0x00, 0x01, 0x00, // ECT(1) 256
    0x00, 0x05, 0x00, 0x06, // ECN-CE 5, not-ECT 6
    0x00, 0x07, 0x00, 0x08, // lost 7, duplicates 8
];

fn report() -> EcnFeedback {
    EcnFeedback {
        sender_ssrc: 1,
        media_ssrc: 2,
        extended_highest_sequence_number: 65552,
        counters: EcnCounters {
            ect0: 3,
            ect1: 256,
            ce: 5,
            not_ect: 6,
            lost: 7,
            duplicates: 8,
        },
    }
}

#[test]
fn an_ecn_feedback_report_has_the_wire_image_of_rfc_6679_figure_2() {
    assert_eq!(report().marshal().unwrap().as_ref(), &WIRE[..]);
    let parsed = EcnFeedback::unmarshal(&mut Bytes::from_static(&WIRE)).unwrap();
    assert_eq!(parsed, report());
}

#[test]
fn an_rtpfb_packet_with_fmt_8_is_dispatched_as_ecn_feedback() {
    let packets = unmarshal(&mut Bytes::from_static(&WIRE)).unwrap();
    assert_eq!(packets.len(), 1);
    let parsed = packets[0]
        .as_any()
        .downcast_ref::<EcnFeedback>()
        .expect("an EcnFeedback");
    assert_eq!(parsed, &report());
    assert_eq!(packets[0].destination_ssrc(), vec![2]);
}

/// "Each ECN Feedback Report corresponds to a single RTP source": an FCI that is not one
/// 20-octet report is refused.
#[test]
fn an_ecn_feedback_whose_fci_is_not_one_report_is_refused() {
    let mut short = WIRE.to_vec();
    short.truncate(28);
    short[3] = 0x06;
    assert!(EcnFeedback::unmarshal(&mut Bytes::from(short)).is_err());

    let mut long = WIRE.to_vec();
    long.extend_from_slice(&[0, 0, 0, 0]);
    long[3] = 0x08;
    assert!(EcnFeedback::unmarshal(&mut Bytes::from(long)).is_err());
}
