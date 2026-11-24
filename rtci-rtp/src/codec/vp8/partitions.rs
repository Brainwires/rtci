//! The partitions of an encoded VP8 frame (RFC 6386 sections 9.1 to 9.5), so that the
//! payloader can start each one in a packet of its own (RFC 7741 sections 3, 4.2 and 4.4).
//!
//! A frame is a frame tag (3 octets, 10 on a key frame), the first partition (its size is in
//! the frame tag), the sizes of the DCT token partitions but the last (3 octets each,
//! little-endian), and the token partitions (1, 2, 4 or 8; the count is a field of the first
//! partition's bool-coded header). RFC 7741 section 4.4 places the partition sizes "at the end
//! of the first partition", so partition 0 here runs from the frame's first octet to the end
//! of the size table.

use std::ops::Range;

/// The most partitions a VP8 frame has: the first partition and 8 token partitions.
pub(crate) const VP8_MAX_PARTITIONS: usize = 9;

/// The RFC 6386 section 7 boolean decoder, reading `data` (zeros past its end, as libvpx
/// does). Only literals (probability 128) are read here.
struct BoolDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    value: u32,
    range: u32,
    bit_count: u32,
}

impl<'a> BoolDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut decoder = BoolDecoder {
            data,
            pos: 0,
            value: 0,
            range: 255,
            bit_count: 0,
        };
        decoder.value = (u32::from(decoder.next_byte()) << 8) | u32::from(decoder.next_byte());
        decoder
    }

    fn next_byte(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn read_bool(&mut self, probability: u32) -> bool {
        let split = 1 + (((self.range - 1) * probability) >> 8);
        let big_split = split << 8;
        let bit = if self.value >= big_split {
            self.range -= split;
            self.value -= big_split;
            true
        } else {
            self.range = split;
            false
        };
        while self.range < 128 {
            self.value <<= 1;
            self.range <<= 1;
            self.bit_count += 1;
            if self.bit_count == 8 {
                self.bit_count = 0;
                self.value |= u32::from(self.next_byte());
            }
        }
        bit
    }

    /// `L(n)`: an n-bit unsigned literal, most significant bit first.
    fn literal(&mut self, bits: u32) -> u32 {
        (0..bits).fold(0, |v, _| (v << 1) | u32::from(self.read_bool(128)))
    }

    /// A flag, and when it is set an n-bit value with (when `signed`) its sign bit.
    fn skip_optional(&mut self, bits: u32, signed: bool) {
        if self.read_bool(128) {
            self.literal(bits + u32::from(signed));
        }
    }
}

/// `log2_nbr_of_dct_partitions` from the frame header at the start of the first partition
/// (RFC 6386 sections 9.2 to 9.6, 19.2).
fn log2_token_partitions(first_partition: &[u8], key_frame: bool) -> u32 {
    let mut d = BoolDecoder::new(first_partition);
    if key_frame {
        d.literal(1); // color_space
        d.literal(1); // clamping_type
    }
    if d.read_bool(128) {
        // segmentation_enabled
        let update_map = d.read_bool(128);
        let update_data = d.read_bool(128);
        if update_data {
            d.literal(1); // segment_feature_mode
            for _ in 0..4 {
                d.skip_optional(7, true); // quantizer_update_value
            }
            for _ in 0..4 {
                d.skip_optional(6, true); // loop_filter_update_value
            }
        }
        if update_map {
            for _ in 0..3 {
                d.skip_optional(8, false); // segment_prob
            }
        }
    }
    d.literal(1); // filter_type
    d.literal(6); // loop_filter_level
    d.literal(3); // sharpness_level
    if d.read_bool(128) {
        // loop_filter_adj_enable
        if d.read_bool(128) {
            // mode_ref_lf_delta_update
            for _ in 0..8 {
                d.skip_optional(6, true); // ref_frame / mb_mode delta
            }
        }
    }
    d.literal(2)
}

/// The byte ranges of `frame`'s partitions, in order and covering the whole frame: partition 0
/// (frame tag, first partition and the token partition sizes), then the token partitions.
/// `None` when `frame` is not a VP8 frame whose sizes add up; the payloader then cuts the frame
/// without regard to partitions (RFC 7741 section 4.4).
pub(crate) fn vp8_partitions(frame: &[u8]) -> Option<Vec<Range<usize>>> {
    if frame.len() < 3 {
        return None;
    }
    let tag = u32::from(frame[0]) | (u32::from(frame[1]) << 8) | (u32::from(frame[2]) << 16);
    let key_frame = tag & 1 == 0;
    let first_partition_size = (tag >> 5) as usize;
    let header_size: usize = if key_frame {
        // The start code (RFC 6386 section 9.1) after the frame tag, then width and height.
        if frame.get(3..6) != Some(&[0x9d, 0x01, 0x2a][..]) {
            return None;
        }
        10
    } else {
        3
    };
    let first_end = header_size.checked_add(first_partition_size)?;
    if first_partition_size == 0 || first_end > frame.len() {
        return None;
    }
    let token_partitions =
        1usize << log2_token_partitions(&frame[header_size..first_end], key_frame);
    let sizes_end = first_end.checked_add(3 * (token_partitions - 1))?;
    if sizes_end > frame.len() {
        return None;
    }
    let mut partitions = Vec::with_capacity(token_partitions + 1);
    partitions.push(0..sizes_end);
    let mut start = sizes_end;
    for i in 0..token_partitions - 1 {
        let s = &frame[first_end + 3 * i..first_end + 3 * i + 3];
        let size = usize::from(s[0]) | (usize::from(s[1]) << 8) | (usize::from(s[2]) << 16);
        let end = start.checked_add(size)?;
        if end > frame.len() {
            return None;
        }
        partitions.push(start..end);
        start = end;
    }
    // The last token partition is the rest of the frame.
    partitions.push(start..frame.len());
    Some(partitions)
}
