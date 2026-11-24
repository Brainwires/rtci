//! The ULPFEC payload: FEC header, level headers and level payloads (RFC 5109 7.3, 7.4).

use super::UlpfecError;
use bytes::{BufMut, Bytes, BytesMut};

/// Octets of the FEC header (RFC 5109 7.3).
pub const FEC_HEADER_LENGTH: usize = 10;

/// Packets a short mask describes (L = 0).
pub const SHORT_MASK_BITS: usize = 16;

/// Packets a long mask describes (L = 1).
pub const LONG_MASK_BITS: usize = 48;

/// The most protection levels read from one FEC packet.
///
/// The RFC sets no limit; a level costs at least four octets, so without one a single packet could
/// declare several hundred empty levels and make every recovery pass walk them.
pub const MAX_LEVELS: usize = 32;

/// One protection level of a FEC packet: its mask and its payload (RFC 5109 7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlpfecLevel {
    /// Which packets the level protects: bit `i` (bit 0 the least significant) stands for the
    /// packet with sequence number `SN base + i`. On the wire the order is the reverse, `i = 0`
    /// being the most significant bit of the mask field.
    pub mask: u64,
    /// The level's payload; its length is the level's protection length.
    pub payload: Bytes,
}

impl UlpfecLevel {
    /// Whether the packet `SN base + offset` is protected at this level.
    pub fn protects(&self, offset: usize) -> bool {
        offset < LONG_MASK_BITS && self.mask & (1u64 << offset) != 0
    }

    /// The offsets from the SN base of the packets this level protects, ascending.
    pub fn offsets(&self) -> impl Iterator<Item = usize> + '_ {
        (0..LONG_MASK_BITS).filter(|offset| self.protects(*offset))
    }
}

/// A parsed ULPFEC payload: what follows the RTP header of a FEC packet, or what a RED block of
/// the FEC payload type holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlpfecPacket {
    /// The L bit: masks are 48 bits long instead of 16.
    pub long_mask: bool,
    /// P recovery.
    pub padding_recovery: bool,
    /// X recovery.
    pub extension_recovery: bool,
    /// CC recovery (4 bits).
    pub csrc_count_recovery: u8,
    /// M recovery.
    pub marker_recovery: bool,
    /// PT recovery (7 bits).
    pub payload_type_recovery: u8,
    /// The lowest sequence number protected at any level.
    pub sn_base: u16,
    /// TS recovery.
    pub timestamp_recovery: u32,
    /// Length recovery: the XOR of the protected packets' lengths after the fixed RTP header.
    pub length_recovery: u16,
    /// The levels, level 0 first. A packet that holds level `p` holds every level below it
    /// (RFC 5109 7.4 rule c), which the layout guarantees: levels are not numbered on the wire,
    /// they are counted.
    pub levels: Vec<UlpfecLevel>,
}

impl UlpfecPacket {
    /// Parse a ULPFEC payload.
    ///
    /// The E bit is ignored (7.3). Levels are read until the payload ends; a level whose payload
    /// is cut short, a level with an empty mask and trailing octets too few for a level header are
    /// all refused, because a packet that is wrong about its own layout cannot be trusted to name
    /// what it protects.
    pub fn parse(payload: &[u8]) -> Result<Self, UlpfecError> {
        if payload.len() < FEC_HEADER_LENGTH + 4 {
            return Err(UlpfecError::TooShort);
        }
        let long_mask = payload[0] & 0x40 != 0;
        let level_header_length = if long_mask { 8 } else { 4 };

        let mut levels = Vec::new();
        let mut rest = &payload[FEC_HEADER_LENGTH..];
        while !rest.is_empty() {
            if levels.len() == MAX_LEVELS {
                return Err(UlpfecError::TooManyLevels);
            }
            if rest.len() < level_header_length {
                return Err(UlpfecError::TooShort);
            }
            let protection_length = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let mask = read_mask(&rest[2..level_header_length]);
            if mask == 0 {
                return Err(UlpfecError::EmptyMask);
            }
            rest = &rest[level_header_length..];
            if rest.len() < protection_length {
                return Err(UlpfecError::TruncatedLevel);
            }
            levels.push(UlpfecLevel {
                mask,
                payload: Bytes::copy_from_slice(&rest[..protection_length]),
            });
            rest = &rest[protection_length..];
        }

        Ok(Self {
            long_mask,
            padding_recovery: payload[0] & 0x20 != 0,
            extension_recovery: payload[0] & 0x10 != 0,
            csrc_count_recovery: payload[0] & 0x0F,
            marker_recovery: payload[1] & 0x80 != 0,
            payload_type_recovery: payload[1] & 0x7F,
            sn_base: u16::from_be_bytes([payload[2], payload[3]]),
            timestamp_recovery: u32::from_be_bytes([
                payload[4], payload[5], payload[6], payload[7],
            ]),
            length_recovery: u16::from_be_bytes([payload[8], payload[9]]),
            levels,
        })
    }

    /// Serialise: the FEC header, then each level's header and payload.
    ///
    /// The E bit is written 0 (7.3). A short mask keeps offsets 0 to 15 only; the encoder sets
    /// [`long_mask`](Self::long_mask) whenever an offset beyond them is protected.
    pub fn marshal(&self) -> Bytes {
        let level_header_length = if self.long_mask { 8 } else { 4 };
        let size = FEC_HEADER_LENGTH
            + self
                .levels
                .iter()
                .map(|level| level_header_length + level.payload.len())
                .sum::<usize>();
        let mut out = BytesMut::with_capacity(size);
        out.put_u8(
            (u8::from(self.long_mask) << 6)
                | (u8::from(self.padding_recovery) << 5)
                | (u8::from(self.extension_recovery) << 4)
                | (self.csrc_count_recovery & 0x0F),
        );
        out.put_u8((u8::from(self.marker_recovery) << 7) | (self.payload_type_recovery & 0x7F));
        out.put_u16(self.sn_base);
        out.put_u32(self.timestamp_recovery);
        out.put_u16(self.length_recovery);
        for level in &self.levels {
            // A level payload longer than the field can say is not something the encoder builds;
            // saturating keeps a hand-built packet from wrapping to a short length.
            out.put_u16(u16::try_from(level.payload.len()).unwrap_or(u16::MAX));
            write_mask(&mut out, level.mask, self.long_mask);
            out.put_slice(&level.payload);
        }
        out.freeze()
    }

    /// The recovery bit string of the FEC header (RFC 5109 9.1 step 2), in the layout the
    /// protected bit string of a media packet has: the first eight octets of an RTP header, then
    /// the length. The version bits and the sequence number hold nothing.
    pub(crate) fn header_bit_string(&self) -> [u8; 10] {
        let mut bits = [0u8; 10];
        bits[0] = (u8::from(self.padding_recovery) << 5)
            | (u8::from(self.extension_recovery) << 4)
            | (self.csrc_count_recovery & 0x0F);
        bits[1] = (u8::from(self.marker_recovery) << 7) | (self.payload_type_recovery & 0x7F);
        bits[4..8].copy_from_slice(&self.timestamp_recovery.to_be_bytes());
        bits[8..10].copy_from_slice(&self.length_recovery.to_be_bytes());
        bits
    }

    /// Where level `index` starts in a protected packet, counted from the end of the fixed RTP
    /// header: the sum of the protection lengths of the levels below it (RFC 5109 8.2, `Sn`).
    pub(crate) fn level_offset(&self, index: usize) -> usize {
        self.levels[..index]
            .iter()
            .map(|level| level.payload.len())
            .sum()
    }
}

/// Wire mask (16 or 48 bits, offset 0 most significant) to offset bits.
fn read_mask(wire: &[u8]) -> u64 {
    let mut mask = 0u64;
    for (index, byte) in wire.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                mask |= 1u64 << (index * 8 + bit);
            }
        }
    }
    mask
}

/// Offset bits to the wire mask.
fn write_mask(out: &mut BytesMut, mask: u64, long_mask: bool) {
    let length = if long_mask { 6 } else { 2 };
    for index in 0..length {
        let mut byte = 0u8;
        for bit in 0..8 {
            if mask & (1u64 << (index * 8 + bit)) != 0 {
                byte |= 0x80 >> bit;
            }
        }
        out.put_u8(byte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(long_mask: bool, levels: Vec<UlpfecLevel>) -> UlpfecPacket {
        UlpfecPacket {
            long_mask,
            padding_recovery: true,
            extension_recovery: false,
            csrc_count_recovery: 0x0A,
            marker_recovery: true,
            payload_type_recovery: 0x55,
            sn_base: 0xFFFE,
            timestamp_recovery: 0x0102_0304,
            length_recovery: 0x0506,
            levels,
        }
    }

    #[test]
    fn the_fec_header_is_ten_octets_in_the_order_of_figure_3() {
        let wire = packet(
            false,
            vec![UlpfecLevel {
                mask: 0b101,
                payload: Bytes::from_static(&[9, 8, 7]),
            }],
        )
        .marshal();
        assert_eq!(
            &[
                0x2A, 0xD5, 0xFF, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // FEC header
                0x00, 0x03, 0xA0, 0x00, // level 0: length 3, packets base+0 and base+2
                9, 8, 7
            ],
            &wire[..]
        );
    }

    #[test]
    fn a_long_mask_sets_the_l_bit_and_takes_six_octets() {
        let original = packet(
            true,
            vec![UlpfecLevel {
                mask: (1 << 47) | (1 << 16) | 1,
                payload: Bytes::from_static(&[1]),
            }],
        );
        let wire = original.marshal();
        assert_eq!(0x40, wire[0] & 0x40, "L bit");
        assert_eq!(&[0x80, 0x00, 0x80, 0x00, 0x00, 0x01], &wire[12..18]);
        assert_eq!(FEC_HEADER_LENGTH + 8 + 1, wire.len());
        assert_eq!(original, UlpfecPacket::parse(&wire).unwrap());
    }

    #[test]
    fn the_e_bit_is_sent_as_zero() {
        let wire = packet(
            true,
            vec![UlpfecLevel {
                mask: 1,
                payload: Bytes::new(),
            }],
        )
        .marshal();
        assert_eq!(0, wire[0] & 0x80);
    }

    #[test]
    fn a_received_e_bit_is_ignored() {
        let original = packet(
            false,
            vec![UlpfecLevel {
                mask: 1,
                payload: Bytes::from_static(&[1, 2]),
            }],
        );
        let mut wire = original.marshal().to_vec();
        wire[0] |= 0x80;
        assert_eq!(original, UlpfecPacket::parse(&wire).unwrap());
    }

    #[test]
    fn several_levels_follow_each_other() {
        let original = packet(
            false,
            vec![
                UlpfecLevel {
                    mask: 0b0011,
                    payload: Bytes::from_static(&[1, 2, 3]),
                },
                UlpfecLevel {
                    mask: 0b1111,
                    payload: Bytes::from_static(&[4, 5]),
                },
            ],
        );
        let parsed = UlpfecPacket::parse(&original.marshal()).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(0, parsed.level_offset(0));
        assert_eq!(3, parsed.level_offset(1));
        assert_eq!(
            vec![0, 1, 2, 3],
            parsed.levels[1].offsets().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_level_cut_short_is_refused() {
        let wire = packet(
            false,
            vec![UlpfecLevel {
                mask: 1,
                payload: Bytes::from_static(&[1, 2, 3, 4]),
            }],
        )
        .marshal();
        assert_eq!(
            Err(UlpfecError::TruncatedLevel),
            UlpfecPacket::parse(&wire[..wire.len() - 1])
        );
    }

    #[test]
    fn a_packet_without_a_level_header_is_refused() {
        assert_eq!(Err(UlpfecError::TooShort), UlpfecPacket::parse(&[0u8; 10]));
        assert_eq!(Err(UlpfecError::TooShort), UlpfecPacket::parse(&[]));
        // L = 1 needs eight octets of level header.
        let mut wire = [0u8; 14];
        wire[0] = 0x40;
        assert_eq!(Err(UlpfecError::TooShort), UlpfecPacket::parse(&wire));
    }

    #[test]
    fn a_level_that_protects_nothing_is_refused() {
        let wire = [0u8; 14];
        assert_eq!(Err(UlpfecError::EmptyMask), UlpfecPacket::parse(&wire));
    }

    #[test]
    fn levels_beyond_the_limit_are_refused() {
        let levels = vec![
            UlpfecLevel {
                mask: 1,
                payload: Bytes::new(),
            };
            MAX_LEVELS + 1
        ];
        let wire = packet(false, levels).marshal();
        assert_eq!(Err(UlpfecError::TooManyLevels), UlpfecPacket::parse(&wire));
    }
}
