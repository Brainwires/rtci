//! The length, padding and FCI rules of the feedback messages of RFC 4585, RFC 5104, RFC 6051
//! and RFC 8888, on the messages that existed before those rules were enforced.
use crate::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
use crate::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use crate::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use crate::payload_feedbacks::slice_loss_indication::{SliEntry, SliceLossIndication};
use crate::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use crate::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use crate::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use bytes::Bytes;
use shared::error::Error;
use shared::marshal::{Marshal, Unmarshal};

fn parse<T: Unmarshal>(raw: &'static [u8]) -> Result<T, Error> {
    T::unmarshal(&mut Bytes::from_static(raw))
}

// RFC 4585 6.3.1.2: "PLI does not require parameters. Therefore, the length field MUST be 2,
// and there MUST NOT be any Feedback Control Information."
#[test]
fn a_picture_loss_indication_is_exactly_twelve_octets() {
    let pli = PictureLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
    };
    assert_eq!(
        &[0x81, 0xce, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2][..],
        &pli.marshal().unwrap()[..]
    );

    // With FCI.
    assert_eq!(
        Err(Error::InvalidHeader),
        parse::<PictureLossIndication>(&[
            0x81, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0
        ])
    );
    // Without the media source.
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<PictureLossIndication>(&[0x81, 0xce, 0x00, 0x01, 0, 0, 0, 1])
    );
    // A length that runs past the datagram.
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<PictureLossIndication>(&[0x81, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2])
    );
    // RTCP padding is not FCI.
    assert_eq!(
        Ok(pli),
        parse::<PictureLossIndication>(&[
            0xa1, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4
        ])
    );
}

// RFC 6051 3.2: "The length field in the RTCP header MUST be 2, and there MUST NOT be any
// Feedback Control Information."
#[test]
fn a_rapid_resynchronisation_request_is_exactly_twelve_octets() {
    let rrr = RapidResynchronizationRequest {
        sender_ssrc: 1,
        media_ssrc: 2,
    };
    assert_eq!(
        &[0x85, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2][..],
        &rrr.marshal().unwrap()[..]
    );
    assert_eq!(
        Err(Error::InvalidHeader),
        parse::<RapidResynchronizationRequest>(&[
            0x85, 0xcd, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0
        ])
    );
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<RapidResynchronizationRequest>(&[0x85, 0xcd, 0x00, 0x01, 0, 0, 0, 1])
    );
    assert_eq!(
        Err(Error::WrongType),
        parse::<RapidResynchronizationRequest>(&[0x81, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2])
    );
}

// RFC 4585 6.2.1: "The FCI field MUST contain at least one and MAY contain more than one
// Generic NACK." The length is 2 + n.
#[test]
fn a_generic_nack_carries_at_least_one_pid_and_blp_pair() {
    let empty = TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: 2,
        nacks: vec![],
    };
    assert_eq!(Err(Error::PacketTooShort), empty.marshal());
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<TransportLayerNack>(&[0x81, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2])
    );

    let two = TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: 2,
        nacks: vec![
            NackPair {
                packet_id: 0x0102,
                lost_packets: 0x8001,
            },
            NackPair {
                packet_id: 0x0203,
                lost_packets: 0,
            },
        ],
    };
    let raw = two.marshal().unwrap();
    assert_eq!(
        &[
            0x81, 0xcd, 0x00, 0x04, // v=2, FMT=1, RTPFB, len = 2 + 2
            0, 0, 0, 1, 0, 0, 0, 2, // sender, media source
            0x01, 0x02, 0x80, 0x01, // PID, BLP
            0x02, 0x03, 0x00, 0x00,
        ][..],
        &raw[..]
    );
    assert_eq!(Ok(two), TransportLayerNack::unmarshal(&mut raw.freeze()));

    // Padding of two octets leaves half a pair.
    assert_eq!(
        Err(Error::WrongPadding),
        parse::<TransportLayerNack>(&[
            0xa1, 0xcd, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0x01, 0x02, 0x00, 0x02
        ])
    );
    // Padding of a word after one pair is fine.
    let padded = parse::<TransportLayerNack>(&[
        0xa1, 0xcd, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 2, 0x01, 0x02, 0x00, 0x00, 0, 0, 0, 4,
    ])
    .unwrap();
    assert_eq!(1, padded.nacks.len());
}

// RFC 4585 6.3.2: "The FCI field MUST contain at least one SLI."
#[test]
fn a_slice_loss_indication_carries_at_least_one_entry() {
    let empty = SliceLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
        sli_entries: vec![],
    };
    assert_eq!(Err(Error::PacketTooShort), empty.marshal());
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<SliceLossIndication>(&[0x82, 0xce, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2])
    );

    let one = SliceLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
        sli_entries: vec![SliEntry {
            first: 0x1fff,
            number: 1,
            picture: 0x3f,
        }],
    };
    let raw = one.marshal().unwrap();
    // First (13 bits), Number (13 bits), PictureID (6 bits).
    assert_eq!(&[0xff, 0xf8, 0x00, 0x7f][..], &raw[12..]);
    assert_eq!(Ok(one), SliceLossIndication::unmarshal(&mut raw.freeze()));

    // More entries than the 16-bit length field can count are refused, not truncated.
    let too_many = SliceLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
        sli_entries: vec![SliEntry::default(); 65534],
    };
    assert_eq!(Err(Error::TooManyReports), too_many.marshal());
}

// RFC 5104 4.3.1.1: one or more entries, the length is 2 + 2 * N, reserved bits are ignored.
// 4.3.1.2: the "SSRC of media source" is not used and SHALL be set to 0.
#[test]
fn a_full_intra_request_follows_the_format_of_rfc5104() {
    let fir = FullIntraRequest {
        sender_ssrc: 1,
        media_ssrc: 0x55555555,
        fir: vec![FirEntry {
            ssrc: 2,
            sequence_number: 7,
        }],
    };
    let raw = fir.marshal().unwrap();
    assert_eq!(
        &[
            0x84, 0xce, 0x00, 0x04, // v=2, FMT=4, PSFB, len = 2 + 2
            0, 0, 0, 1, // sender
            0, 0, 0, 0, // media source: zero, whatever the field holds
            0, 0, 0, 2, 7, 0, 0, 0, // ssrc, seq nr, reserved
        ][..],
        &raw[..]
    );

    // What a peer wrote in the unused field and in the reserved bits changes nothing.
    let parsed = parse::<FullIntraRequest>(&[
        0x84, 0xce, 0x00, 0x04, 0, 0, 0, 1, 0x55, 0x55, 0x55, 0x55, 0, 0, 0, 2, 7, 0xff, 0xff, 0xff,
    ])
    .unwrap();
    assert_eq!(fir, parsed);
    assert_eq!(vec![2], crate::packet::Packet::destination_ssrc(&parsed));

    assert_eq!(
        Err(Error::PacketTooShort),
        FullIntraRequest {
            sender_ssrc: 1,
            media_ssrc: 0,
            fir: vec![],
        }
        .marshal()
    );
    // Half an entry.
    assert_eq!(
        Err(Error::InvalidHeader),
        parse::<FullIntraRequest>(&[
            0x84, 0xce, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 7, 0, 0, 0, 0, 0, 0, 3,
        ])
    );
}

// draft-alvestrand-rmcat-remb-03 2.2: Num SSRC says how many SSRC entries follow.
#[test]
fn a_remb_has_as_many_ssrc_entries_as_it_says() {
    let remb = ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 1,
        bitrate: 8927168.0,
        ssrcs: vec![0x12345678, 0x9abcdef0],
    };
    let raw = remb.marshal().unwrap().freeze();
    assert_eq!(
        Ok(remb),
        ReceiverEstimatedMaximumBitrate::unmarshal(&mut raw.clone())
    );

    // One entry more than Num SSRC says.
    let mut more = raw.to_vec();
    more[3] += 1;
    more.extend_from_slice(&[0, 0, 0, 9]);
    assert_eq!(
        Err(Error::SsrcNumAndLengthMismatch),
        ReceiverEstimatedMaximumBitrate::unmarshal(&mut Bytes::from(more))
    );
    // One entry fewer.
    let mut fewer = raw[..raw.len() - 4].to_vec();
    fewer[3] -= 1;
    assert_eq!(
        Err(Error::SsrcNumAndLengthMismatch),
        ReceiverEstimatedMaximumBitrate::unmarshal(&mut Bytes::from(fewer))
    );
    // Cut inside the fixed part.
    assert_eq!(
        Err(Error::PacketTooShort),
        parse::<ReceiverEstimatedMaximumBitrate>(&[
            0x8f, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 0, b'R', b'E', b'M', b'B'
        ])
    );
    // Num SSRC is one octet.
    let too_many = ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 1,
        bitrate: 1000.0,
        ssrcs: vec![0; 256],
    };
    assert_eq!(Err(Error::TooManySources), too_many.marshal());
}

// draft-alvestrand-rmcat-remb-03 2.2: the bit rate is mantissa * 2^exp, so a mantissa of
// zero is zero bits per second.
#[test]
fn a_remb_with_a_zero_mantissa_is_a_bit_rate_of_zero() {
    for exp in [0u8, 1, 63] {
        let raw = [
            0x8f,
            0xce,
            0x00,
            0x04,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            b'R',
            b'E',
            b'M',
            b'B',
            0,
            exp << 2,
            0,
            0,
        ];
        let remb =
            ReceiverEstimatedMaximumBitrate::unmarshal(&mut Bytes::copy_from_slice(&raw)).unwrap();
        assert_eq!(0.0, remb.bitrate, "exp {exp}");
    }

    let zero = ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 1,
        bitrate: 0.0,
        ssrcs: vec![],
    };
    let raw = zero.marshal().unwrap();
    assert_eq!(&[0, 0, 0, 0][..], &raw[16..]);
    assert_eq!(
        Ok(zero),
        ReceiverEstimatedMaximumBitrate::unmarshal(&mut raw.freeze())
    );
}

// RFC 8888 3.1: "V, P, PT, length" are as RFC 3550 defines them. Padding the P bit announces
// comes after the report timestamp and is not it.
#[test]
fn a_padded_congestion_control_feedback_report_keeps_its_timestamp() {
    let ccfb = CcFeedbackReport {
        sender_ssrc: 1,
        report_blocks: vec![],
        report_timestamp: 0x12345678,
    };
    let mut raw = ccfb.marshal().unwrap().to_vec();
    assert_eq!(12, raw.len());
    raw[0] |= 0x20;
    raw[3] += 2;
    raw.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);

    assert_eq!(Ok(ccfb), CcFeedbackReport::unmarshal(&mut Bytes::from(raw)));

    // A padding count larger than the packet.
    assert_eq!(
        Err(Error::WrongPadding),
        parse::<CcFeedbackReport>(&[0xab, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0x12, 0x34, 0x56, 99])
    );
}
