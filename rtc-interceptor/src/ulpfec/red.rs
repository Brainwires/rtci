//! The part of the RED payload format (RFC 2198 section 3) that carries ULPFEC.
//!
//! ```text
//!  0                   1                    2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3  4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |F|   block PT  |  timestamp offset         |   block length    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Redundant blocks have that four-octet header with F = 1; the primary block's header is last,
//! one octet, F = 0 and the payload type. The data blocks follow in the order of their headers.

use super::UlpfecError;
use bytes::{BufMut, Bytes, BytesMut};

/// The longest redundant block: the block length field is 10 bits.
pub(crate) const MAX_REDUNDANT_BLOCK: usize = 0x3FF;

/// One block of a RED payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedBlock<'a> {
    pub payload_type: u8,
    /// Zero for the primary block.
    pub timestamp_offset: u16,
    pub data: &'a [u8],
}

/// Split a RED payload into its redundant blocks and its primary block.
pub(crate) fn parse(payload: &[u8]) -> Result<(Vec<RedBlock<'_>>, RedBlock<'_>), UlpfecError> {
    // Headers first: (payload type, timestamp offset, length) of each redundant block.
    let mut headers = Vec::new();
    let mut rest = payload;
    let primary_payload_type = loop {
        let Some(first) = rest.first().copied() else {
            return Err(UlpfecError::MalformedRed);
        };
        if first & 0x80 == 0 {
            rest = &rest[1..];
            break first & 0x7F;
        }
        if rest.len() < 4 {
            return Err(UlpfecError::MalformedRed);
        }
        let timestamp_offset = (u16::from(rest[1]) << 6) | u16::from(rest[2] >> 2);
        let length = (usize::from(rest[2] & 0x03) << 8) | usize::from(rest[3]);
        headers.push((first & 0x7F, timestamp_offset, length));
        rest = &rest[4..];
    };

    let mut redundant = Vec::with_capacity(headers.len());
    for (payload_type, timestamp_offset, length) in headers {
        if rest.len() < length {
            return Err(UlpfecError::MalformedRed);
        }
        redundant.push(RedBlock {
            payload_type,
            timestamp_offset,
            data: &rest[..length],
        });
        rest = &rest[length..];
    }
    Ok((
        redundant,
        RedBlock {
            payload_type: primary_payload_type,
            timestamp_offset: 0,
            data: rest,
        },
    ))
}

/// Build a RED payload: the redundant blocks (payload type, timestamp offset, data), then the
/// primary block.
pub(crate) fn write(
    redundant: &[(u8, u16, &[u8])],
    primary_payload_type: u8,
    primary: &[u8],
) -> Result<Bytes, UlpfecError> {
    let size = 1
        + primary.len()
        + redundant
            .iter()
            .map(|(_, _, data)| 4 + data.len())
            .sum::<usize>();
    let mut out = BytesMut::with_capacity(size);
    for (payload_type, timestamp_offset, data) in redundant {
        if data.len() > MAX_REDUNDANT_BLOCK {
            return Err(UlpfecError::RedBlockTooLong);
        }
        let timestamp_offset = timestamp_offset & 0x3FFF;
        out.put_u8(0x80 | (payload_type & 0x7F));
        out.put_u8((timestamp_offset >> 6) as u8);
        out.put_u8(((timestamp_offset << 2) as u8) | ((data.len() >> 8) as u8));
        out.put_u8(data.len() as u8);
    }
    out.put_u8(primary_payload_type & 0x7F);
    for (_, _, data) in redundant {
        out.put_slice(data);
    }
    out.put_slice(primary);
    Ok(out.freeze())
}

/// What a RED payload of a ULPFEC-protected stream holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedFecPayload {
    /// The FEC payloads: every block, redundant or primary, of the FEC payload type.
    pub fec: Vec<Bytes>,
    /// The primary block's payload type and data when it is media, `None` when the packet holds
    /// only FEC.
    pub primary: Option<(u8, Bytes)>,
}

/// Take a RED payload (RFC 2198) apart for ULPFEC (RFC 5109 14.2): the blocks of
/// `fec_payload_type` are FEC payloads, the primary block is the media.
///
/// Both forms in use are read: FEC as a redundant block ahead of a media primary (RFC 5109
/// 10.3), and a RED packet whose single block is the FEC payload (what libwebrtc sends).
/// Redundant blocks of any other payload type are redundant media, which is no business of the
/// FEC, and are skipped.
pub fn depacketize_red(payload: &[u8], fec_payload_type: u8) -> Result<RedFecPayload, UlpfecError> {
    let (redundant, primary) = parse(payload)?;
    let mut fec: Vec<Bytes> = redundant
        .iter()
        .filter(|block| block.payload_type == fec_payload_type)
        .map(|block| Bytes::copy_from_slice(block.data))
        .collect();
    let primary = if primary.payload_type == fec_payload_type {
        fec.push(Bytes::copy_from_slice(primary.data));
        None
    } else {
        Some((primary.payload_type, Bytes::copy_from_slice(primary.data)))
    };
    Ok(RedFecPayload { fec, primary })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5109 Figure 20: the primary block header of a RED packet carrying payload type 11.
    #[test]
    fn rfc_5109_figure_20_primary_block_header() {
        let payload = write(&[], 11, &[1, 2, 3]).unwrap();
        assert_eq!(&[0b0000_1011, 1, 2, 3], &payload[..]);
    }

    /// RFC 5109 Figure 22: the redundant block header for 354 octets of FEC, payload type 127,
    /// timestamp offset 0.
    #[test]
    fn rfc_5109_figure_22_redundant_block_header() {
        let fec = [0xEEu8; 354];
        let payload = write(&[(127, 0, &fec)], 11, &[9]).unwrap();
        assert_eq!(&[0xFF, 0x00, 0x01, 0x62], &payload[..4]);
        assert_eq!(0x0B, payload[4], "the primary block header comes last");
        assert_eq!(&fec[..], &payload[5..359], "then the data, in header order");
        assert_eq!(&[9], &payload[359..]);
    }

    #[test]
    fn blocks_round_trip_with_offsets_and_lengths() {
        let first = [1u8; 300];
        let second = [2u8; 5];
        let payload = write(&[(100, 0x3FFF, &first), (101, 1, &second)], 96, &[7, 8]).unwrap();
        let (redundant, primary) = parse(&payload).unwrap();
        assert_eq!(
            vec![
                RedBlock {
                    payload_type: 100,
                    timestamp_offset: 0x3FFF,
                    data: &first
                },
                RedBlock {
                    payload_type: 101,
                    timestamp_offset: 1,
                    data: &second
                },
            ],
            redundant
        );
        assert_eq!(96, primary.payload_type);
        assert_eq!(&[7, 8], primary.data);
    }

    #[test]
    fn a_block_longer_than_ten_bits_cannot_be_redundant() {
        let long = [0u8; 1024];
        assert_eq!(
            Err(UlpfecError::RedBlockTooLong),
            write(&[(127, 0, &long)], 96, &[])
        );
        assert!(write(&[(127, 0, &long[..1023])], 96, &[]).is_ok());
    }

    #[test]
    fn truncated_red_is_refused() {
        assert_eq!(Err(UlpfecError::MalformedRed), parse(&[]).map(|_| ()));
        // A redundant header cut short.
        assert_eq!(
            Err(UlpfecError::MalformedRed),
            parse(&[0xFF, 0x00]).map(|_| ())
        );
        // Redundant headers with no primary header after them.
        assert_eq!(
            Err(UlpfecError::MalformedRed),
            parse(&[0xFF, 0x00, 0x00, 0x01]).map(|_| ())
        );
        // A block length beyond the data.
        assert_eq!(
            Err(UlpfecError::MalformedRed),
            parse(&[0xFF, 0x00, 0x00, 0x05, 0x0B, 1, 2]).map(|_| ())
        );
    }

    #[test]
    fn an_empty_primary_block_is_valid() {
        let (redundant, primary) = parse(&[0x60]).unwrap();
        assert!(redundant.is_empty());
        assert_eq!(0x60, primary.payload_type);
        assert!(primary.data.is_empty());
    }

    #[test]
    fn fec_is_found_as_a_redundant_block_and_as_the_only_block() {
        let fec = [5u8; 20];
        let with_media = write(&[(127, 0, &fec)], 96, &[1, 2]).unwrap();
        let parsed = depacketize_red(&with_media, 127).unwrap();
        assert_eq!(vec![Bytes::copy_from_slice(&fec)], parsed.fec);
        assert_eq!(Some((96, Bytes::from_static(&[1, 2]))), parsed.primary);

        let alone = write(&[], 127, &fec).unwrap();
        let parsed = depacketize_red(&alone, 127).unwrap();
        assert_eq!(vec![Bytes::copy_from_slice(&fec)], parsed.fec);
        assert_eq!(None, parsed.primary);
    }

    #[test]
    fn redundant_media_blocks_are_not_fec() {
        let payload = write(&[(96, 960, &[3, 3])], 96, &[4, 4]).unwrap();
        let parsed = depacketize_red(&payload, 127).unwrap();
        assert!(parsed.fec.is_empty());
        assert_eq!(Some((96, Bytes::from_static(&[4, 4]))), parsed.primary);
    }
}
