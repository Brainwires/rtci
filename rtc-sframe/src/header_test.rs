use crate::header_vectors::RFC9605_C1_HEADERS;
use crate::test_util::hex;
use crate::{Error, ErrorKind, Header, MAX_HEADER_LEN};

#[test]
fn rfc9605_c1_every_header_vector_encodes_to_the_given_bytes() {
    assert_eq!(RFC9605_C1_HEADERS.len(), 289);
    for &(kid, ctr, encoded) in RFC9605_C1_HEADERS {
        let expected = hex(encoded);
        let header = Header::new(kid, ctr);

        let mut buffer = [0xaa; MAX_HEADER_LEN];
        let len = header.encode(&mut buffer);
        assert_eq!(&buffer[..len], expected, "kid {kid:#x} ctr {ctr:#x}");
        assert_eq!(header.encoded_len(), expected.len());

        let mut appended = vec![0x55];
        header.encode_to(&mut appended);
        assert_eq!(&appended[1..], expected);
    }
}

#[test]
fn rfc9605_c1_every_header_vector_decodes_to_the_given_values() {
    for &(kid, ctr, encoded) in RFC9605_C1_HEADERS {
        let bytes = hex(encoded);
        assert_eq!(
            Header::decode(&bytes),
            Ok((Header { kid, ctr }, bytes.len())),
            "header {encoded}"
        );
        assert_eq!(
            Header::decode_lenient(&bytes),
            Ok((Header { kid, ctr }, bytes.len()))
        );
    }
}

#[test]
fn header_decode_stops_at_the_end_of_the_header() {
    for &(kid, ctr, encoded) in RFC9605_C1_HEADERS {
        let mut bytes = hex(encoded);
        let header_len = bytes.len();
        bytes.extend_from_slice(&[0xff, 0x00, 0xff]);
        assert_eq!(
            Header::decode(&bytes),
            Ok((Header { kid, ctr }, header_len))
        );
    }
}

#[test]
fn header_decode_refuses_every_truncation() {
    assert_eq!(Header::decode(&[]), Err(Error::TruncatedHeader));
    assert_eq!(Header::decode_lenient(&[]), Err(Error::TruncatedHeader));
    for &(_, _, encoded) in RFC9605_C1_HEADERS {
        let bytes = hex(encoded);
        for len in 0..bytes.len() {
            assert_eq!(
                Header::decode(&bytes[..len]),
                Err(Error::TruncatedHeader),
                "header {encoded} cut to {len} bytes"
            );
            assert_eq!(
                Header::decode_lenient(&bytes[..len]),
                Err(Error::TruncatedHeader)
            );
        }
    }
    assert_eq!(Error::TruncatedHeader.kind(), Some(ErrorKind::Syntax));
}

#[test]
fn header_decode_refuses_values_not_in_their_shortest_form() {
    // (bytes, the KID and CTR they carry)
    let cases: &[(&[u8], u64, u64)] = &[
        // An extended KID below 8.
        (&[0x80, 0x05], 5, 0),
        // An extended CTR below 8.
        (&[0x08, 0x07], 0, 7),
        // A two-byte KID with a leading zero byte.
        (&[0x90, 0x00, 0x09], 9, 0),
        // An eight-byte CTR holding 0x0100.
        (&[0x0f, 0, 0, 0, 0, 0, 0, 0x01, 0x00], 0, 0x100),
        // A minimal KID with a padded CTR.
        (&[0x89, 0xff, 0x00, 0x08], 0xff, 8),
    ];
    for &(bytes, kid, ctr) in cases {
        assert_eq!(
            Header::decode(bytes),
            Err(Error::NonMinimalHeader),
            "{bytes:02x?}"
        );
        assert_eq!(
            Header::decode_lenient(bytes),
            Ok((Header { kid, ctr }, bytes.len()))
        );
    }
    assert_eq!(Error::NonMinimalHeader.kind(), Some(ErrorKind::Syntax));
}

#[test]
fn header_round_trips_at_every_length_boundary() {
    let mut values = vec![0u64, 1, 7, 8];
    for bytes in 1..=8u32 {
        let top = if bytes == 8 {
            u64::MAX
        } else {
            (1u64 << (8 * bytes)) - 1
        };
        values.extend([top, top.wrapping_add(1), top - 1]);
    }
    for &kid in &values {
        for &ctr in &values {
            let header = Header::new(kid, ctr);
            let mut buffer = [0; MAX_HEADER_LEN];
            let len = header.encode(&mut buffer);
            assert_eq!(Header::decode(&buffer[..len]), Ok((header, len)));
            // The fewest bytes: none below 8, else exactly what the value needs.
            let needed = |value: u64| match value {
                0..8 => 0,
                _ => (64 - value.leading_zeros()).div_ceil(8) as usize,
            };
            assert_eq!(len, 1 + needed(kid) + needed(ctr));
        }
    }
}
