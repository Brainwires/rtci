//! webrtc-rs `media` v0.17.1 `h264_reader` tests, ported to `H26xReader` (H.264 mode).

use super::*;
use std::io::Cursor;

fn reader(input: &[u8]) -> H26xReader<Cursor<Vec<u8>>> {
    H26xReader::new(Cursor::new(input.to_vec()), 1_048_576, false)
}

fn h264(nal: H26xNAL) -> H264NAL {
    match nal {
        H26xNAL::H264(nal) => nal,
        H26xNAL::H265(_) => panic!("expected an H.264 NAL unit"),
    }
}

#[test]
fn test_data_does_not_start_with_h264header() {
    for input in [&[2][..], &[0, 2], &[0, 0, 2], &[0, 0, 2, 0], &[0, 0, 0, 2]] {
        assert!(
            matches!(reader(input).next_nal(), Err(Error::ErrDataIsNotH264Stream)),
            "{input:?}"
        );
    }
}

#[test]
fn test_parse_header() -> Result<()> {
    let nal = h264(reader(&[0x0, 0x0, 0x1, 0xAB]).next_nal()?);

    assert_eq!(1, nal.data.len());
    assert!(nal.forbidden_zero_bit);
    assert_eq!(0, nal.picture_order_count);
    assert_eq!(1, nal.ref_idc);
    assert_eq!(H264NalUnitType::EndOfStream, nal.unit_type);
    Ok(())
}

#[test]
fn test_eof() {
    for input in [&[0, 0, 0, 1][..], &[0, 0, 1], &[]] {
        assert!(
            matches!(reader(input).next_nal(), Err(Error::ErrIoEOF)),
            "{input:?}"
        );
    }
}

#[test]
fn test_skip_sei() -> Result<()> {
    let mut reader = reader(&[
        0x0, 0x0, 0x0, 0x1, 0xAA, 0x0, 0x0, 0x0, 0x1, 0x6, // SEI
        0x0, 0x0, 0x0, 0x1, 0xAB,
    ]);

    assert_eq!(0xAA, h264(reader.next_nal()?).data[0]);
    assert_eq!(0xAB, h264(reader.next_nal()?).data[0]);
    Ok(())
}

#[test]
fn test_issue1734_next_nal() {
    for input in [
        &[0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01][..],
        &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01],
    ] {
        let mut reader = reader(input);
        // Just make sure it doesn't crash.
        while reader.next_nal().is_ok() {}
    }
}

#[test]
fn test_trailing01after_start_code() -> Result<()> {
    let mut reader = reader(&[0x0, 0x0, 0x0, 0x1, 0x01, 0x0, 0x0, 0x0, 0x1, 0x01]);
    for _ in 0..=1 {
        reader.next_nal()?;
    }
    Ok(())
}
