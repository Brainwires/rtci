//! A frame header claiming more bytes than the file holds is an error, read without first
//! allocating the declared size.

use super::*;
use std::io::Cursor;

const FILE_HEADER: [u8; 32] = [
    0x44, 0x4b, 0x49, 0x46, 0x00, 0x00, 0x20, 0x00, 0x56, 0x50, 0x38, 0x30, 0xb0, 0x00, 0x90, 0x00,
    0x30, 0x75, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn a_frame_claiming_4_gib_is_refused() {
    let mut file = FILE_HEADER.to_vec();
    file.extend_from_slice(&u32::MAX.to_le_bytes()); // frame size
    file.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    file.extend_from_slice(&[1, 2, 3]);

    let (mut reader, _) = IVFReader::new(Cursor::new(file)).expect("a valid file header");
    assert!(reader.parse_next_frame().is_err());
}

#[test]
fn a_whole_frame_still_reads() -> Result<()> {
    let mut file = FILE_HEADER.to_vec();
    file.extend_from_slice(&3u32.to_le_bytes());
    file.extend_from_slice(&7u64.to_le_bytes());
    file.extend_from_slice(&[1, 2, 3]);

    let (mut reader, _) = IVFReader::new(Cursor::new(file))?;
    let (payload, header) = reader.parse_next_frame()?;
    assert_eq!(&[1, 2, 3], &payload[..]);
    assert_eq!(7, header.timestamp);
    Ok(())
}
