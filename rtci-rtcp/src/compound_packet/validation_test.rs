//! The validity checks of RFC 3550 Appendix A.2 and §6.1, and what RFC 5506 leaves of them.
use super::*;
use crate::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use crate::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};

const RR: &[u8] = &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1];
const SDES: &[u8] = &[0x81, 0xca, 0x00, 0x02, 0, 0, 0, 1, 0x01, 0x01, b'c', 0x00];
const PLI: &[u8] = &[0x81, 0xce, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2];
/// A PLI with four octets of padding and the P bit.
const PADDED_PLI: &[u8] = &[0xa1, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4];

fn datagram(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// RFC 3550 6.1: SR or RR first, then an SDES with a CNAME, then anything.
#[test]
fn a_report_an_sdes_with_a_cname_and_feedback_is_a_compound_packet() {
    for raw in [
        datagram(&[RR, SDES]),
        datagram(&[RR, SDES, PLI]),
        datagram(&[RR, RR, SDES, PLI, PLI]),
    ] {
        assert_eq!(Ok(()), validate_compound(&raw));
        // A compound packet is acceptable where reduced-size RTCP is.
        assert_eq!(Ok(()), validate_reduced_size(&raw));
    }
}

// RFC 5506 4.1: one or more RTCP packets of any type, no report in front, no SDES. RFC 3550
// Appendix A.2 refuses exactly that: "The payload type field of the first RTCP packet in a
// compound packet must be equal to SR or RR."
#[test]
fn feedback_on_its_own_is_reduced_size_and_not_compound() {
    for raw in [
        datagram(&[PLI]),
        datagram(&[PLI, PLI]),
        datagram(&[SDES, RR]),
    ] {
        assert_eq!(Ok(()), validate_reduced_size(&raw));
        assert_eq!(Err(Error::BadFirstPacket), validate_compound(&raw));
    }
}

// RFC 3550 6.1: "An SDES packet containing a CNAME item MUST be included in each compound
// RTCP packet".
#[test]
fn a_compound_packet_without_a_cname_is_refused() {
    let sdes_without_cname: &[u8] = &[0x81, 0xca, 0x00, 0x02, 0, 0, 0, 1, 0x02, 0x01, b'n', 0x00];

    assert_eq!(
        Err(Error::MissingCname),
        validate_compound(&datagram(&[RR]))
    );
    assert_eq!(
        Err(Error::MissingCname),
        validate_compound(&datagram(&[RR, sdes_without_cname]))
    );
    assert_eq!(
        Err(Error::PacketBeforeCname),
        validate_compound(&datagram(&[RR, PLI, SDES]))
    );
    // None of that concerns a reduced-size packet.
    assert_eq!(Ok(()), validate_reduced_size(&datagram(&[RR, PLI, SDES])));
}

// RFC 3550 6.4.1: "padding MUST only be added to the last individual packet, and if padding
// is added to that packet, the padding bit MUST be set only on that packet." Appendix A.2:
// "The padding bit (P) should be zero for the first packet of a compound RTCP packet".
#[test]
fn only_the_last_packet_of_a_datagram_may_be_padded() {
    let padded_rr: &[u8] = &[0xa0, 0xc9, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 4];

    // On the last packet: fine, compound or reduced-size.
    assert_eq!(
        Ok(()),
        validate_compound(&datagram(&[RR, SDES, PADDED_PLI]))
    );
    assert_eq!(Ok(()), validate_reduced_size(&datagram(&[PLI, PADDED_PLI])));
    assert_eq!(Ok(()), validate_reduced_size(&datagram(&[PADDED_PLI])));

    // On the first packet of a compound packet.
    assert_eq!(
        Err(Error::WrongPadding),
        validate_compound(&datagram(&[padded_rr, SDES]))
    );
    assert_eq!(
        Err(Error::WrongPadding),
        validate_compound(&datagram(&[padded_rr]))
    );
    // In the middle.
    assert_eq!(
        Err(Error::WrongPadding),
        validate_compound(&datagram(&[RR, SDES, PADDED_PLI, PLI]))
    );
    assert_eq!(
        Err(Error::WrongPadding),
        validate_reduced_size(&datagram(&[PADDED_PLI, PLI]))
    );
}

// RFC 3550 6.4.1: "The last octet of the padding is a count of how many padding octets
// should be ignored, including itself".
#[test]
fn a_padding_count_that_cannot_be_true_is_refused() {
    let count_zero: &[u8] = &[0xa1, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0];
    let count_too_large: &[u8] = &[0xa1, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 13];
    let count_whole_body: &[u8] = &[0xa0, 0xd0, 0x00, 0x01, 0, 0, 0, 4];

    for raw in [count_zero, count_too_large] {
        assert_eq!(Err(Error::WrongPadding), validate_reduced_size(raw));
        assert_eq!(
            Err(Error::WrongPadding),
            validate_compound(&datagram(&[RR, SDES, raw]))
        );
    }
    assert_eq!(Ok(()), validate_reduced_size(count_whole_body));
}

// RFC 3550 Appendix A.2: "RTP version field must equal 2" and "The length fields of the
// individual RTCP packets must add up to the overall length of the compound RTCP packet as
// received."
#[test]
fn version_and_lengths_are_checked_on_every_packet() {
    let version_one_sdes: &[u8] = &[0x41, 0xca, 0x00, 0x02, 0, 0, 0, 1, 0x01, 0x01, b'c', 0x00];

    for validate in [validate_compound, validate_reduced_size] {
        assert_eq!(Err(Error::EmptyCompound), validate(&[]));
        assert_eq!(
            Err(Error::BadVersion),
            validate(&datagram(&[RR, version_one_sdes]))
        );
        assert_eq!(
            Err(Error::BadVersion),
            validate(&[0x00, 0xc9, 0x00, 0x01, 0, 0, 0, 1])
        );
        // A stray octet after the last packet.
        assert_eq!(
            Err(Error::PacketTooShort),
            validate(&datagram(&[RR, SDES, &[0x80]]))
        );
        // The last packet says it is longer than what is left.
        assert_eq!(
            Err(Error::PacketTooShort),
            validate(&datagram(&[RR, SDES, &PLI[..8]]))
        );
    }
}

// RFC 5506 3.4.2: with any packet type allowed in front, the best check left is that it is
// an RTCP packet type at all: 192 to 223 (RFC 5761 4).
#[test]
fn a_reduced_size_datagram_starts_with_an_rtcp_packet_type() {
    for packet_type in [0u8, 96, 127, 191, 224, 255] {
        let raw = [0x80, packet_type, 0x00, 0x01, 0, 0, 0, 1];
        assert_eq!(
            Err(Error::BadFirstPacket),
            validate_reduced_size(&raw),
            "{packet_type}"
        );
    }
    for packet_type in [192u8, 200, 204, 205, 206, 207, 208, 223] {
        let raw = [0x80, packet_type, 0x00, 0x01, 0, 0, 0, 1];
        assert_eq!(Ok(()), validate_reduced_size(&raw), "{packet_type}");
    }
}

fn padded_transport_cc() -> TransportLayerCc {
    TransportLayerCc {
        sender_ssrc: 1,
        media_ssrc: 2,
        base_sequence_number: 7,
        packet_status_count: 1,
        reference_time: 5,
        fb_pkt_count: 1,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
            run_length: 1,
        })],
        recv_deltas: vec![RecvDelta {
            type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
            delta: 1000,
        }],
    }
}

fn report_and_cname() -> Vec<Box<dyn Packet>> {
    vec![
        Box::new(ReceiverReport {
            ssrc: 1,
            ..Default::default()
        }),
        Box::new(SourceDescription {
            chunks: vec![SourceDescriptionChunk {
                source: 1,
                items: vec![SourceDescriptionItem {
                    sdes_type: SdesType::SdesCname,
                    text: Bytes::from_static(b"c"),
                }],
            }],
        }),
    ]
}

// The same rule on the sending side: a compound packet is not marshalled with a padded packet
// anywhere but at its end.
#[test]
fn a_compound_packet_is_marshalled_with_padding_on_its_last_packet_only() {
    let pli = PictureLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
    };
    assert!(padded_transport_cc().header().padding);

    let mut in_the_middle = report_and_cname();
    in_the_middle.push(Box::new(padded_transport_cc()));
    in_the_middle.push(Box::new(pli.clone()));
    assert_eq!(
        Err(Error::WrongPadding),
        CompoundPacket(in_the_middle).marshal()
    );

    let mut at_the_end = report_and_cname();
    at_the_end.push(Box::new(pli));
    at_the_end.push(Box::new(padded_transport_cc()));
    let compound = CompoundPacket(at_the_end);
    let raw = compound.marshal().unwrap();
    assert_eq!(Ok(()), validate_compound(&raw));
    assert_eq!(
        compound,
        CompoundPacket::unmarshal(&mut raw.freeze()).unwrap()
    );
}

// `CompoundPacket::unmarshal` is the strict reader: it applies the header checks before it
// parses anything.
#[test]
fn the_compound_reader_applies_the_header_checks() {
    assert_eq!(
        Some(Error::BadFirstPacket),
        CompoundPacket::unmarshal(&mut &datagram(&[PLI, RR, SDES])[..]).err()
    );
    assert_eq!(
        Some(Error::WrongPadding),
        CompoundPacket::unmarshal(&mut &datagram(&[RR, SDES, PADDED_PLI, PLI])[..]).err()
    );
    let compound = CompoundPacket::unmarshal(&mut &datagram(&[RR, SDES, PADDED_PLI])[..]).unwrap();
    assert_eq!(3, compound.0.len());
    assert_eq!(Ok(Bytes::from_static(b"c")), compound.cname());
}
