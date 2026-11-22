//! AV1 RTP Depacketizer
//!
//! Reads AV1 RTP packets and outputs AV1 low overhead bitstream format.
//! Based on <https://aomediacodec.github.io/av1-rtp-spec/>

use bytes::{BufMut, Bytes, BytesMut};

use crate::codec::av1::leb128::read_leb128;
use crate::codec::av1::obu::{
    OBU_HAS_SIZE_BIT, OBU_TYPE_MASK, OBU_TYPE_REDUNDANT_FRAME_HEADER, OBU_TYPE_TEMPORAL_DELIMITER,
    OBU_TYPE_TILE_GROUP, OBU_TYPE_TILE_LIST,
};
use crate::packetizer::Depacketizer;
use shared::error::{Error, Result};

// AV1 Aggregation Header bit masks
const AV1_Z_MASK: u8 = 0b1000_0000;
const AV1_Y_MASK: u8 = 0b0100_0000;
const AV1_W_MASK: u8 = 0b0011_0000;
const AV1_N_MASK: u8 = 0b0000_1000;

/// Largest OBU reassembled across RTP packets. Far above any real one (a 4K key frame's tile
/// group is a few hundred KiB); a reassembly that would grow past it is dropped.
pub const MAX_AV1_OBU_SIZE: usize = 4 * 1024 * 1024;

/// AV1 RTP Depacketizer
///
/// Depacketizes AV1 RTP packets into low overhead bitstream format with obu_size fields.
#[derive(Default, Debug, Clone)]
pub struct Av1Depacketizer {
    /// Buffer for fragmented OBU from previous packet
    buffer: BytesMut,
    /// Z flag from aggregation header - first OBU is continuation
    pub z: bool,
    /// Y flag from aggregation header - last OBU will continue
    pub y: bool,
    /// N flag from aggregation header - new coded video sequence
    pub n: bool,
}

impl Av1Depacketizer {
    /// An AV1 depacketizer with no buffered fragments.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Av1Depacketizer {
    fn depacketize_payload(&mut self, payload: &Bytes) -> Result<Bytes> {
        if payload.len() <= 1 {
            return Err(Error::ErrShortPacket);
        }

        // Parse aggregation header
        // |Z|Y| W |N|-|-|-|
        let obu_z = (payload[0] & AV1_Z_MASK) != 0;
        let obu_y = (payload[0] & AV1_Y_MASK) != 0;
        let obu_count = ((payload[0] & AV1_W_MASK) >> 4) as usize;
        let obu_n = (payload[0] & AV1_N_MASK) != 0;

        self.z = obu_z;
        self.y = obu_y;
        self.n = obu_n;

        // Clear buffer on new coded video sequence
        if obu_n {
            self.buffer.clear();
        }

        // Clear buffer if Z is not set but we have buffered data
        if !obu_z && !self.buffer.is_empty() {
            self.buffer.clear();
        }

        let mut result = BytesMut::new();
        let mut offset = 1; // Skip aggregation header
        let mut elements = 0;

        while offset < payload.len() {
            let is_first = elements == 0;
            // With W = 1, 2 or 3 the last of the W elements has no length field: it is the rest
            // of the packet. Every other element, and every element with W = 0, has one.
            let length_field = if obu_count != 0 && elements == obu_count - 1 {
                payload.len() - offset
            } else {
                // A length that does not end, is longer than 8 bytes or does not fit 32 bits
                // is not a length (AV1 4.10.5).
                let (len, n) = read_leb128(&payload[offset..]).ok_or(Error::ErrShortPacket)?;
                offset += n;
                len as usize
            };
            if length_field > payload.len() - offset {
                return Err(Error::ErrShortPacket);
            }
            let fragment = payload.slice(offset..offset + length_field);
            offset += length_field;
            elements += 1;
            // The packet's last element continues in the next packet when Y is set.
            let continues = obu_y && offset == payload.len();

            // Build OBU buffer
            let obu_buffer = if is_first && obu_z {
                // Continuation of previous packet's OBU
                if self.buffer.is_empty() {
                    // Lost first fragment, skip this OBU
                    continue;
                }

                // Bounded: a peer that keeps setting Y must not grow this without limit.
                if self.buffer.len() + length_field > MAX_AV1_OBU_SIZE {
                    return Err(Error::ErrShortPacket);
                }
                // Appended in place, so a long fragment chain costs linear time; the buffer
                // used to be copied whole into a new one for every packet.
                self.buffer.extend_from_slice(&fragment);
                if continues {
                    // Still not complete: keep buffering.
                    continue;
                }
                std::mem::take(&mut self.buffer).freeze()
            } else {
                // If this is the last OBU and Y flag is set, buffer it for next packet
                if continues {
                    if length_field > MAX_AV1_OBU_SIZE {
                        return Err(Error::ErrShortPacket);
                    }
                    self.buffer = BytesMut::from(fragment.as_ref());
                    continue;
                }
                fragment
            };

            // Skip empty OBUs
            if obu_buffer.is_empty() {
                continue;
            }

            write_obu(&mut result, &obu_buffer)?;
        }

        // "W: ... MUST be set equal to 0 or equal to the number of OBU elements contained in
        // the packet" (AV1 RTP 4.4). The loop ends at the end of the packet, so fewer elements
        // than W means the last ones are not there.
        if obu_count != 0 && elements != obu_count {
            return Err(Error::ErrShortPacket);
        }

        Ok(result.freeze())
    }
}

/// Writes one whole OBU in low overhead format (with its `obu_size` field), unless it is one
/// a receiver ignores: a temporal delimiter or a tile list OBU (AV1 RTP 5).
fn write_obu(result: &mut BytesMut, obu_buffer: &[u8]) -> Result<()> {
    // Parse OBU header to check type
    let obu_type = (obu_buffer[0] & OBU_TYPE_MASK) >> 3;

    // Skip temporal delimiter and tile list OBUs
    if obu_type == OBU_TYPE_TEMPORAL_DELIMITER || obu_type == OBU_TYPE_TILE_LIST {
        return Ok(());
    }

    // Check if OBU has size field
    let has_size_field = (obu_buffer[0] & OBU_HAS_SIZE_BIT) != 0;
    let has_extension = (obu_buffer[0] & 0x04) != 0;
    let header_size = if has_extension { 2 } else { 1 };
    // A one-byte OBU that claims an extension header has no room for it.
    if obu_buffer.len() < header_size {
        return Err(Error::ErrShortPacket);
    }

    if has_size_field {
        // OBU already has size field, validate it against the whole OBU (reassembled, when
        // it came in fragments).
        let (obu_size, leb_size) =
            read_leb128(&obu_buffer[header_size..]).ok_or(Error::ErrShortPacket)?;
        if obu_buffer.len() != header_size + leb_size + obu_size as usize {
            return Err(Error::ErrShortPacket);
        }
        result.extend_from_slice(obu_buffer);
    } else {
        // Add size field to OBU
        // Set obu_has_size_field bit
        result.put_u8(obu_buffer[0] | OBU_HAS_SIZE_BIT);

        // Copy extension header if present
        if has_extension {
            result.put_u8(obu_buffer[1]);
        }

        // Write payload size as LEB128
        let payload_size = obu_buffer.len() - header_size;
        write_leb128(result, payload_size as u32);

        // Copy OBU payload
        result.extend_from_slice(&obu_buffer[header_size..]);
    }
    Ok(())
}

impl Depacketizer for Av1Depacketizer {
    /// Depacketize parses an AV1 RTP payload into OBU stream with obu_size_field.
    ///
    /// A malformed packet is an error and drops any OBU being reassembled: what follows it
    /// cannot be trusted to continue it.
    ///
    /// Reference: <https://aomediacodec.github.io/av1-rtp-spec/>
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        let result = self.depacketize_payload(payload);
        if result.is_err() {
            self.buffer.clear();
        }
        result
    }

    /// Whether the packet can start a temporal unit: Z is not set (its first OBU element is
    /// not the continuation of a fragment), and that first OBU is not one that only follows
    /// a frame header of the same unit (a tile group or a redundant frame header). Z = 0 alone
    /// used to count, so a unit whose first packet was lost was taken up from its second.
    ///
    /// This is as much as the payload says. A unit whose later frames each start a packet with
    /// their own frame header (spatial layers) still looks like a start there; the Dependency
    /// Descriptor's `start_of_frame` and the RTP timestamp tell those apart.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        let Some(&aggregation_header) = payload.first() else {
            return false;
        };
        if (aggregation_header & AV1_Z_MASK) != 0 {
            return false;
        }
        // With W = 1 the only element has no length field; otherwise the first one does.
        let mut offset = 1;
        if (aggregation_header & AV1_W_MASK) >> 4 != 1 {
            match read_leb128(&payload[offset..]) {
                Some((_, n)) => offset += n,
                None => return false,
            }
        }
        match payload.get(offset) {
            Some(obu_header) => !matches!(
                (obu_header & OBU_TYPE_MASK) >> 3,
                OBU_TYPE_TILE_GROUP | OBU_TYPE_REDUNDANT_FRAME_HEADER
            ),
            None => false,
        }
    }

    /// Returns true if marker bit is set (end of frame)
    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

/// Write LEB128 encoded value to buffer
fn write_leb128(buf: &mut BytesMut, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An OBU fragmented across packets (Y set, then Z and Y set on every following packet)
    /// is bounded at `MAX_AV1_OBU_SIZE`, and the buffer grows in place. It used to grow
    /// without limit, and was copied whole into a new buffer for every packet.
    #[test]
    fn fragment_chain_is_bounded() {
        let mut depacketizer = Av1Depacketizer::new();
        // Z=0, Y=1, W=1: one OBU, continued in the next packet.
        let mut first = vec![0x50, 0x30];
        first.extend_from_slice(&[0xab; 1200]);
        assert!(depacketizer.depacketize(&Bytes::from(first)).is_ok());

        // Z=1, Y=1, W=1: a middle fragment.
        let mut middle = vec![0xd0];
        middle.extend_from_slice(&[0xab; 1200]);
        let middle = Bytes::from(middle);
        let mut refused = false;
        for _ in 0..(MAX_AV1_OBU_SIZE / 1200 + 2) {
            if depacketizer.depacketize(&middle).is_err() {
                refused = true;
                break;
            }
            assert!(depacketizer.buffer.len() <= MAX_AV1_OBU_SIZE);
        }
        assert!(refused, "the reassembly passed MAX_AV1_OBU_SIZE");
        assert!(depacketizer.buffer.is_empty(), "the partial OBU is dropped");
    }

    /// A fragmented OBU still reassembles: start, middle and end fragments.
    #[test]
    fn fragment_chain_reassembles() {
        let mut depacketizer = Av1Depacketizer::new();
        // Z=0, Y=1, W=1; OBU header 0x30 (frame, no size field) and two payload bytes.
        assert!(
            depacketizer
                .depacketize(&Bytes::from_static(&[0x50, 0x30, 0x01, 0x02]))
                .unwrap()
                .is_empty()
        );
        // Z=1, Y=1, W=1.
        assert!(
            depacketizer
                .depacketize(&Bytes::from_static(&[0xd0, 0x03, 0x04]))
                .unwrap()
                .is_empty()
        );
        // Z=1, Y=0, W=1: the end.
        let obu = depacketizer
            .depacketize(&Bytes::from_static(&[0x90, 0x05]))
            .unwrap();
        assert_eq!(&obu[..], &[0x32, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    /// A one-byte OBU whose header sets the extension flag must be rejected, not sliced past its
    /// end (`[2..]` on a one-byte buffer) or underflow the payload-size computation.
    #[test]
    fn one_byte_obu_with_extension_flag_is_rejected() {
        for obu_header in [0x36u8, 0x34] {
            // W=1 (one OBU, no length field); a FRAME OBU header with the extension bit, with
            // and without the size-field bit.
            let payload = Bytes::from(vec![0x10, obu_header]);
            let mut depacketizer = Av1Depacketizer::new();
            assert!(depacketizer.depacketize(&payload).is_err());
        }
    }

    #[test]
    fn test_depacketizer_basic() {
        let mut depacketizer = Av1Depacketizer::new();

        // Simple packet with one OBU element (W=1)
        // Aggregation header: W=1, no Z, no Y, no N = 0x10
        // OBU header: type=6 (Frame), no extension, no size = 0x30
        // Total: aggregation header + OBU header + payload
        let payload = Bytes::from(vec![
            0x10, // Aggregation header: W=1
            0x30, // OBU header: type=6 (Frame), no ext, no size
            0x01, 0x02, 0x03, // OBU payload
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        assert!(!result.is_empty());
        // Should have size field added (OBU_HAS_SIZE_BIT = 0x02)
        assert_eq!(result[0] & OBU_HAS_SIZE_BIT, OBU_HAS_SIZE_BIT);
        // Size should be 3 (payload bytes)
        assert_eq!(result[1], 3);
        // Payload should follow
        assert_eq!(&result[2..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_depacketizer_with_w_zero() {
        let mut depacketizer = Av1Depacketizer::new();

        // Packet with W=0 means each OBU has length prefix
        // Aggregation header: W=0
        // Length field (LEB128): 4 bytes
        // OBU: header + payload
        let payload = Bytes::from(vec![
            0x00, // Aggregation header: W=0
            0x04, // Length field: 4 bytes
            0x30, // OBU header: type=6 (Frame), no ext, no size
            0x01, 0x02, 0x03, // OBU payload (3 bytes, total OBU = 4)
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        assert!(!result.is_empty());
        // Should have size field added
        assert_eq!(result[0] & OBU_HAS_SIZE_BIT, OBU_HAS_SIZE_BIT);
    }

    #[test]
    fn test_is_partition_head() {
        let depacketizer = Av1Depacketizer::new();

        // Z=0 means partition head
        let payload = Bytes::from(vec![0x10, 0x30]);
        assert!(depacketizer.is_partition_head(&payload));

        // Z=1 means continuation
        let payload = Bytes::from(vec![0x90, 0x30]);
        assert!(!depacketizer.is_partition_head(&payload));
    }

    #[test]
    fn test_write_leb128() {
        let mut buf = BytesMut::new();

        // Test small values
        write_leb128(&mut buf, 0);
        assert_eq!(buf.as_ref(), &[0x00]);

        buf.clear();
        write_leb128(&mut buf, 127);
        assert_eq!(buf.as_ref(), &[0x7f]);

        buf.clear();
        write_leb128(&mut buf, 128);
        assert_eq!(buf.as_ref(), &[0x80, 0x01]);

        buf.clear();
        write_leb128(&mut buf, 16383);
        assert_eq!(buf.as_ref(), &[0xff, 0x7f]);
    }

    #[test]
    fn test_skip_temporal_delimiter() {
        let mut depacketizer = Av1Depacketizer::new();

        // Packet with temporal delimiter OBU (type=2) which should be skipped
        let payload = Bytes::from(vec![
            0x10, // Aggregation header: W=1
            0x12, // OBU header: type=2 (Temporal Delimiter), no ext, with size
            0x00, // Size = 0
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        // Should be empty since temporal delimiter is skipped
        assert!(result.is_empty());
    }

    #[test]
    fn test_fragmented_obu_with_size_field() {
        let mut depacketizer = Av1Depacketizer::new();

        // Build a Frame OBU that already carries a low-overhead size field.
        let mut obu = BytesMut::new();
        obu.put_u8(0x32); // Frame OBU, no extension, has size field
        let payload = vec![0xAB; 500];
        write_leb128(&mut obu, payload.len() as u32);
        obu.extend_from_slice(&payload);
        let obu = obu.freeze();

        let first_fragment_size = 400;
        let p1 = Bytes::from_iter(
            std::iter::once(0x50) // Z=0, Y=1, W=1
                .chain(obu[..first_fragment_size].iter().copied()),
        );
        let p2 = Bytes::from_iter(
            std::iter::once(0x90) // Z=1, Y=0, W=1
                .chain(obu[first_fragment_size..].iter().copied()),
        );

        assert!(depacketizer.depacketize(&p1).unwrap().is_empty());
        let result = depacketizer.depacketize(&p2).unwrap();
        assert_eq!(result, obu);
    }
}
