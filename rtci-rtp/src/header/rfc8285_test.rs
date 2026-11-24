//! RFC 8285: the one-byte and two-byte header-extension forms, and RFC 3550 5.1's version.

use super::*;
use shared::error::Error;
use shared::marshal::{Marshal, Unmarshal};

/// V=2, X=1, PT 96, seq 1, ts 2, SSRC 3, then an extension block with this profile and body
/// (the body's length must be a multiple of four).
fn packet_with_block(profile: u16, block: &[u8]) -> Bytes {
    assert_eq!(0, block.len() % 4);
    let mut raw = vec![
        0x90, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    ];
    raw.extend_from_slice(&profile.to_be_bytes());
    raw.extend_from_slice(&((block.len() / 4) as u16).to_be_bytes());
    raw.extend_from_slice(block);
    Bytes::from(raw)
}

fn parse(raw: &Bytes) -> shared::error::Result<Header> {
    Header::unmarshal(&mut raw.clone())
}

fn marshal(header: &Header) -> shared::error::Result<Bytes> {
    Ok(header.marshal()?.freeze())
}

// --- RFC 8285 4.3: appbits ---

#[test]
fn a_two_byte_block_is_parsed_whatever_its_appbits() -> shared::error::Result<()> {
    // The audit's reproduction (H1): profile 0x1001, one element with ID 5.
    for appbits in 0..=0xFu16 {
        let raw = packet_with_block(0x1000 | appbits, &[0x05, 0x01, 0xAA, 0x00]);
        let header = parse(&raw)?;
        assert_eq!(Some(ExtensionForm::TwoByte), header.extension_form());
        assert_eq!(vec![5], header.get_extension_ids());
        assert_eq!(Some(Bytes::from_static(&[0xAA])), header.get_extension(5));
        // The appbits the packet arrived with are kept, so it re-marshals as it was.
        assert_eq!(0x1000 | appbits, header.extension_profile);
        assert_eq!(raw, marshal(&header)?);
    }
    Ok(())
}

#[test]
fn a_profile_next_to_the_two_byte_range_is_an_rfc3550_extension() -> shared::error::Result<()> {
    for profile in [0x0FFFu16, 0x1010, 0x2000, 0xBEDF] {
        let raw = packet_with_block(profile, &[0x05, 0x01, 0xAA, 0x00]);
        let header = parse(&raw)?;
        assert_eq!(Some(ExtensionForm::Rfc3550), header.extension_form());
        assert_eq!(
            Some(Bytes::from_static(&[0x05, 0x01, 0xAA, 0x00])),
            header.get_extension(0)
        );
        assert_eq!(raw, marshal(&header)?);
    }
    Ok(())
}

#[test]
fn an_element_set_on_a_header_with_appbits_keeps_the_two_byte_form() -> shared::error::Result<()> {
    let raw = packet_with_block(0x100A, &[0x05, 0x01, 0xAA, 0x00]);
    let mut header = parse(&raw)?;
    header.set_extension(200, Bytes::from_static(&[1, 2, 3]))?;
    let reparsed = parse(&marshal(&header)?)?;
    assert_eq!(vec![5, 200], reparsed.get_extension_ids());
    assert_eq!(0x100A, reparsed.extension_profile);
    Ok(())
}

// --- RFC 8285 4.1.2: ID 0 with a length ---

#[test]
fn id_zero_with_a_length_ends_the_one_byte_block_and_keeps_what_came_before()
-> shared::error::Result<()> {
    // The audit's reproduction (H2): element ID 1, then 0x02 (ID 0, length nibble 2).
    let raw = packet_with_block(0xBEDE, &[0x10, 0xAA, 0x02, 0x01, 0x02, 0x03, 0x00, 0x00]);
    let header = parse(&raw)?;
    assert_eq!(vec![1], header.get_extension_ids());
    assert_eq!(Some(Bytes::from_static(&[0xAA])), header.get_extension(1));
    assert_eq!(None, header.get_extension(0));
    // The header can be sent again, and is as long as it was.
    assert_eq!(raw.len(), header.marshal_size());
    let again = parse(&marshal(&header)?)?;
    assert_eq!(vec![1], again.get_extension_ids());
    Ok(())
}

#[test]
fn id_zero_with_a_length_that_runs_past_the_block_is_not_an_error() -> shared::error::Result<()> {
    // The length of an ID 0 element is ignored, so it cannot make the packet invalid.
    let raw = packet_with_block(0xBEDE, &[0x10, 0xAA, 0x0F, 0x00]);
    let header = parse(&raw)?;
    assert_eq!(vec![1], header.get_extension_ids());
    Ok(())
}

// --- RFC 8285 4.2 / 4.1.2: the form `set_extension` chooses ---

#[test]
fn an_id_above_14_on_a_header_without_extensions_takes_the_two_byte_form()
-> shared::error::Result<()> {
    // The audit's reproduction (H3): it was Ok with profile 0xBEDE, and marshal then failed.
    let mut header = Header::default();
    header.set_extension(20, Bytes::from_static(&[0x12, 0x34]))?;
    assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    let raw = marshal(&header)?;
    let parsed = parse(&raw)?;
    assert_eq!(
        Some(Bytes::from_static(&[0x12, 0x34])),
        parsed.get_extension(20)
    );
    Ok(())
}

#[test]
fn an_empty_element_on_a_header_without_extensions_takes_the_two_byte_form()
-> shared::error::Result<()> {
    // The one-byte form cannot carry a zero-length element (its length field is len - 1).
    let mut header = Header::default();
    header.set_extension(3, Bytes::new())?;
    assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    let parsed = parse(&marshal(&header)?)?;
    assert_eq!(Some(Bytes::new()), parsed.get_extension(3));
    Ok(())
}

#[test]
fn an_element_that_fits_the_one_byte_form_is_not_sent_in_the_two_byte_form() {
    for (id, len) in [(1u8, 1usize), (14, 16), (7, 3)] {
        let mut header = Header::default();
        header
            .set_extension(id, Bytes::from(vec![0xAB; len]))
            .unwrap();
        assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);
    }
}

#[test]
fn id_zero_and_oversized_elements_are_refused_on_a_header_without_extensions() {
    let mut header = Header::default();
    assert_eq!(
        Err(Error::ErrRfc8285oneByteHeaderIdrange),
        header.set_extension(0, Bytes::from_static(&[1]))
    );
    assert_eq!(
        Err(Error::ErrRfc8285twoByteHeaderSize),
        header.set_extension(1, Bytes::from(vec![0; 256]))
    );
    // A refused element leaves the header without an extension block.
    assert!(!header.extension);
    assert!(marshal(&header).is_ok());
}

#[test]
fn a_one_byte_header_refuses_an_element_that_needs_the_two_byte_form() {
    // A stream carries one form unless mixing was negotiated (RFC 8285 4.1.2), so the plain
    // setter does not change the form of a header that has elements.
    let mut header = Header::default();
    header.set_extension(1, Bytes::from_static(&[1])).unwrap();
    assert_eq!(
        Err(Error::ErrRfc8285oneByteHeaderIdrange),
        header.set_extension(15, Bytes::from_static(&[1]))
    );
    assert_eq!(
        Err(Error::ErrRfc8285oneByteHeaderSize),
        header.set_extension(2, Bytes::from(vec![0; 17]))
    );
    assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);
    assert_eq!(vec![1], header.get_extension_ids());
}

#[test]
fn the_upgrading_setter_converts_a_one_byte_header_when_the_element_needs_it()
-> shared::error::Result<()> {
    let mut header = Header::default();
    header.set_extension(1, Bytes::from_static(&[0xA1]))?;
    header.set_extension(14, Bytes::from(vec![0xE0; 16]))?;
    assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);

    header.set_extension_upgrading(20, Bytes::from_static(&[0x12, 0x34]))?;
    assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);

    // Every element is still there after a trip over the wire, under the same id.
    let parsed = parse(&marshal(&header)?)?;
    assert_eq!(Some(ExtensionForm::TwoByte), parsed.extension_form());
    assert_eq!(Some(Bytes::from_static(&[0xA1])), parsed.get_extension(1));
    assert_eq!(Some(Bytes::from(vec![0xE0; 16])), parsed.get_extension(14));
    assert_eq!(
        Some(Bytes::from_static(&[0x12, 0x34])),
        parsed.get_extension(20)
    );
    assert_eq!(header.marshal_size(), marshal(&header)?.len());
    Ok(())
}

#[test]
fn the_upgrading_setter_keeps_the_one_byte_form_when_the_element_fits() -> shared::error::Result<()>
{
    let mut header = Header::default();
    header.set_extension(1, Bytes::from_static(&[0xA1]))?;
    header.set_extension_upgrading(2, Bytes::from_static(&[0xB2]))?;
    assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);
    Ok(())
}

#[test]
fn the_upgrading_setter_refuses_what_no_form_carries() {
    let mut header = Header::default();
    header
        .set_extension(1, Bytes::from_static(&[0xA1]))
        .unwrap();
    assert!(
        header
            .set_extension_upgrading(0, Bytes::from_static(&[1]))
            .is_err()
    );
    assert!(
        header
            .set_extension_upgrading(2, Bytes::from(vec![0; 256]))
            .is_err()
    );
    assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);
}

#[test]
fn upgrade_to_two_byte_keeps_every_element_and_is_idempotent() -> shared::error::Result<()> {
    let mut header = Header::default();
    header.upgrade_to_two_byte()?;
    assert!(!header.extension, "nothing to convert");

    header.set_extension(3, Bytes::from_static(&[1, 2, 3]))?;
    header.upgrade_to_two_byte()?;
    header.upgrade_to_two_byte()?;
    let raw = marshal(&header)?;
    assert_eq!(header.marshal_size(), raw.len());
    // 12 fixed + 4 block header + (2 + 3) element + 3 padding.
    assert_eq!(24, raw.len());
    assert_eq!(
        &[0x10, 0x00, 0x00, 0x02, 0x03, 0x03, 1, 2, 3, 0, 0, 0],
        &raw[12..]
    );

    let mut generic = parse(&packet_with_block(0x1234, &[1, 2, 3, 4]))?;
    assert_eq!(
        Err(Error::ErrRfc3550headerIdrange),
        generic.upgrade_to_two_byte()
    );
    Ok(())
}

// --- RFC 8285 4.3: one id space for both forms ---

#[test]
fn an_id_reads_the_same_through_either_form() -> shared::error::Result<()> {
    let one_byte = parse(&packet_with_block(0xBEDE, &[0x51, 0xCA, 0xFE, 0x00]))?;
    let two_byte = parse(&packet_with_block(0x1000, &[0x05, 0x02, 0xCA, 0xFE]))?;
    assert_eq!(one_byte.get_extension(5), two_byte.get_extension(5));
    assert_eq!(
        Some(Bytes::from_static(&[0xCA, 0xFE])),
        one_byte.get_extension(5)
    );
    Ok(())
}

// --- RFC 8285 4.1.1: no empty extension block ---

#[test]
fn deleting_the_last_element_removes_the_extension_block() -> shared::error::Result<()> {
    let mut header = Header::default();
    header.set_extension(1, Bytes::from_static(&[0xAA]))?;
    header.set_extension(2, Bytes::from_static(&[0xBB]))?;
    header.del_extension(1)?;
    assert!(header.extension, "one element is left");
    header.del_extension(2)?;
    assert!(!header.extension);
    let raw = marshal(&header)?;
    assert_eq!(12, raw.len());
    assert_eq!(0, raw[0] & 0x10, "X is clear");
    // And the header takes a new element in whatever form fits it.
    header.set_extension(30, Bytes::from_static(&[1]))?;
    assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    Ok(())
}

// --- RFC 3550 5.3.1: a zero-length extension ---

#[test]
fn an_extension_block_of_length_zero_is_valid() -> shared::error::Result<()> {
    for profile in [0xBEDEu16, 0x1000, 0x4321] {
        let raw = packet_with_block(profile, &[]);
        let header = parse(&raw)?;
        assert!(header.extension);
        assert_eq!(raw.len(), header.marshal_size());
        assert_eq!(raw, marshal(&header)?);
    }
    Ok(())
}

// --- RFC 3550 5.1: version ---

#[test]
fn a_default_header_is_version_2_on_the_wire() -> shared::error::Result<()> {
    // The audit's reproduction (B7): a header built from `Default` went out as version 0.
    let header = Header {
        ssrc: 7,
        payload_type: 96,
        ..Default::default()
    };
    let raw = marshal(&header)?;
    assert_eq!(0x80, raw[0]);
    Ok(())
}

#[test]
fn a_header_of_another_version_is_not_marshalled() {
    for version in [0u8, 1, 3, 4, 6] {
        let header = Header {
            version,
            ..Default::default()
        };
        assert_eq!(Err(Error::BadVersion), header.marshal().map(|_| ()));
    }
}

#[test]
fn a_packet_of_another_version_is_not_parsed_as_rtp() {
    for first in [0x00u8, 0x40, 0xC0, 0x17, 0xFF] {
        let raw = Bytes::from(vec![
            first, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
        ]);
        assert_eq!(Err(Error::BadVersion), parse(&raw).map(|_| ()));
    }
}

#[test]
fn a_payload_type_that_does_not_fit_seven_bits_is_not_marshalled() {
    let header = Header {
        payload_type: 0x80,
        ..Default::default()
    };
    assert_eq!(Err(Error::WrongPayloadType), header.marshal().map(|_| ()));
}

// --- RFC 3550 5.1: the CSRC list ---

#[test]
fn the_csrc_list_and_an_extension_survive_a_round_trip_together() -> shared::error::Result<()> {
    let mut header = Header {
        csrc: (1..=15).collect(),
        ..Default::default()
    };
    header.set_extension(4, Bytes::from_static(&[9, 9]))?;
    let raw = marshal(&header)?;
    assert_eq!(0x9F, raw[0], "V=2, X=1, CC=15");
    assert_eq!(12 + 15 * 4 + 4 + 4, raw.len());
    let parsed = parse(&raw)?;
    assert_eq!((1..=15).collect::<Vec<u32>>(), parsed.csrc);
    assert_eq!(Some(Bytes::from_static(&[9, 9])), parsed.get_extension(4));
    Ok(())
}

#[test]
fn a_csrc_count_larger_than_the_packet_is_refused() {
    // CC = 2 with room for one CSRC only.
    let raw = Bytes::from_static(&[
        0x82, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0, 0, 0, 1,
    ]);
    assert_eq!(
        Err(Error::ErrHeaderSizeInsufficient),
        parse(&raw).map(|_| ())
    );
}
