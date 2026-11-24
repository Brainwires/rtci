use bytes::Bytes;

use super::*;

// generates a valid ogg file that can be used for tests
fn build_ogg_container() -> Vec<u8> {
    vec![
        0x4f, 0x67, 0x67, 0x53, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e,
        0x9b, 0x20, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x61, 0xee, 0x61, 0x17, 0x01, 0x13, 0x4f, 0x70,
        0x75, 0x73, 0x48, 0x65, 0x61, 0x64, 0x01, 0x02, 0x00, 0x0f, 0x80, 0xbb, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x4f, 0x67, 0x67, 0x53, 0x00, 0x00, 0xda, 0x93, 0xc2, 0xd9, 0x00, 0x00, 0x00,
        0x00, 0x8e, 0x9b, 0x20, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x49, 0x97, 0x03, 0x37, 0x01, 0x05,
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]
}

#[test]
fn test_ogg_reader_parse_valid_header() -> Result<()> {
    let ogg = build_ogg_container();
    let r = Cursor::new(&ogg);
    let (_reader, header) = OggReader::new(r, true)?;

    assert_eq!(header.channel_map, 0);
    assert_eq!(header.channels, 2);
    assert_eq!(header.output_gain, 0);
    assert_eq!(header.pre_skip, 0xf00);
    assert_eq!(header.sample_rate, 48000);
    assert_eq!(header.version, 1);

    Ok(())
}

#[test]
fn test_ogg_reader_parse_next_page() -> Result<()> {
    let ogg = build_ogg_container();
    let r = Cursor::new(&ogg);
    let (mut reader, _header) = OggReader::new(r, true)?;

    let (payload, _) = reader.parse_next_page()?;
    assert_eq!(payload, Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]));

    let result = reader.parse_next_page();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_ogg_reader_parse_errors() -> Result<()> {
    //"Invalid ID Page Header Signature"
    {
        let mut ogg = build_ogg_container();
        ogg[0] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageSignature);
        }
    }

    //"Invalid ID Page Header Type"
    {
        let mut ogg = build_ogg_container();
        ogg[5] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageType);
        }
    }

    //"Invalid ID Page Payload Length"
    {
        let mut ogg = build_ogg_container();
        ogg[27] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPageLength);
        }
    }

    //"Invalid ID Page Payload Length"
    {
        let mut ogg = build_ogg_container();
        ogg[35] = 0;

        let result = OggReader::new(Cursor::new(ogg), false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrBadIDPagePayloadSignature);
        }
    }

    //"Invalid Page Checksum"
    {
        let mut ogg = build_ogg_container();
        ogg[22] = 0;

        let result = OggReader::new(Cursor::new(ogg), true);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, Error::ErrChecksumMismatch);
        }
    }

    Ok(())
}

/// One Ogg page (checksum left zero: read with checksums off).
fn page(header_type: u8, segments: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = b"OggS".to_vec();
    out.push(0); // version
    out.push(header_type);
    out.extend_from_slice(&0u64.to_le_bytes()); // granule position
    out.extend_from_slice(&1u32.to_le_bytes()); // serial
    out.extend_from_slice(&0u32.to_le_bytes()); // page index
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum
    out.push(segments.len() as u8);
    out.extend_from_slice(segments);
    out.extend_from_slice(payload);
    out
}

/// RFC 3533 section 6: a page's segment table says where its packets end. The reader dropped
/// it, so a page holding several Opus packets could only be sent whole.
#[test]
fn test_ogg_reader_next_packet_splits_pages_by_the_segment_table() -> Result<()> {
    // Page 1: packets of 3 and 2 bytes, then the start (255 bytes) of a packet that
    // continues on page 2 with 10 more bytes, followed there by a 1-byte packet.
    let long: Vec<u8> = (0..265u32).map(|i| i as u8).collect();
    let mut payload1 = vec![1, 2, 3, 4, 5];
    payload1.extend_from_slice(&long[..255]);
    let mut payload2 = long[255..].to_vec();
    payload2.push(9);
    let mut stream = page(0, &[3, 2, 255], &payload1);
    stream.extend(page(PAGE_HEADER_FLAG_CONTINUED_PACKET, &[10, 1], &payload2));

    let mut reader = OggReader::new_with_options(Cursor::new(stream), false);
    let (p, header) = reader.next_packet()?;
    assert_eq!(&p[..], &[1, 2, 3]);
    assert_eq!(header.segment_table(), &[3, 2, 255]);
    assert_eq!(&reader.next_packet()?.0[..], &[4, 5]);
    let (p, header) = reader.next_packet()?;
    assert_eq!(&p[..], &long[..]);
    assert!(header.is_continued_packet());
    assert_eq!(&reader.next_packet()?.0[..], &[9]);
    assert!(reader.next_packet().is_err());
    Ok(())
}

#[test]
fn test_ogg_page_packets() {
    let header = OggPageHeader {
        granule_position: 0,
        serial: 0,
        header_type: 0,
        sig: *b"OggS",
        version: 0,
        index: 0,
        segments_count: 3,
        segment_table: vec![255, 0, 2],
    };
    let payload: Vec<u8> = (0..257u32).map(|i| i as u8).collect();
    let packets = header.packets(&payload);
    // A 255-byte packet ends with the 0 lacing value; then a 2-byte one.
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], (&payload[..255], true));
    assert_eq!(packets[1], (&payload[255..], true));
}
