//! The RFC 8627 FEC header: the three variants of section 4.2.2, read and written.

use crate::flexfec::bit_array::BitArray;

/// Octets of RTP header a repair packet recovers from; the protected "payload" starts here.
pub(crate) const RTP_FIXED_HEADER_SIZE: usize = 12;

/// The recovery fields every R=0 header starts with: P, X, CC, M, PT recovery, length recovery
/// and TS recovery (Figures 12 and 13).
pub const FLEXFEC_RECOVERY_SIZE: usize = 8;

/// The most source packets a flexible mask can name: 15 + 31 + 64 bits (section 4.2.2.1).
pub const FLEXFEC_MAX_MASK_BITS: u32 = 110;

/// The most source streams one repair packet can protect: the CSRC count is four bits.
pub const FLEXFEC_MAX_PROTECTED_SSRCS: usize = 15;

const R_BIT: u8 = 0x80;
const F_BIT: u8 = 0x40;
const K_BIT: u8 = 0x80;

/// Why a repair packet's FEC header cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlexFecHeaderError {
    /// Shorter than the fields it claims to carry.
    Truncated,
    /// R=1 and F=1: reserved, MUST be ignored (section 4.2.2).
    ReservedVariant,
    /// An R=0 repair packet whose RTP header has no CSRC: it names no source stream
    /// (section 4.2.1).
    NoProtectedSsrc,
    /// L=0: with D=0 it is reserved and MUST be ignored (section 4.2.2.2); with any other D it
    /// describes no packet.
    ZeroColumns,
    /// No mask bit is set in any block: the packet protects nothing.
    ProtectsNothing,
    /// A retransmission whose payload is not an RTP packet (shorter than a fixed RTP header).
    NotARetransmittedPacket,
}

impl std::fmt::Display for FlexFecHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "FlexFEC header is truncated",
            Self::ReservedVariant => "FlexFEC header has R=1 and F=1, which is reserved",
            Self::NoProtectedSsrc => "FlexFEC repair packet has no CSRC naming a source stream",
            Self::ZeroColumns => "FlexFEC header has L=0",
            Self::ProtectsNothing => "FlexFEC repair packet protects no source packet",
            Self::NotARetransmittedPacket => "FlexFEC retransmission holds no RTP packet",
        })
    }
}

impl std::error::Error for FlexFecHeaderError {}

/// How one block of a repair packet names the source packets it protects.
///
/// Exhaustive: the one F bit selects between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexFecProtected {
    /// Flexible mask (R=0, F=0): bit *j* set means the packet `SN base + j` is protected, bit 0
    /// being the most significant (section 4.2.2.1). Up to 110 bits.
    Mask(BitArray),
    /// Fixed L columns and D rows (R=0, F=1; section 4.2.2.2, Figure 14):
    ///
    /// - `d <= 1`: row FEC over `SN base, SN base + 1, ..., SN base + (l - 1)` (`d == 1` says
    ///   column FEC follows, 2-D);
    /// - `d > 1`: column FEC over `SN base, SN base + l, ..., SN base + (d - 1) * l`.
    Fixed {
        /// L, the number of columns. Never 0 in a parsed header.
        l: u8,
        /// D, the number of rows.
        d: u8,
    },
}

/// One block of an R=0 FEC header: the source stream (taken from the repair packet's CSRC
/// list), its SN base, and the mask or L/D that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlexFecBlock {
    /// The source stream's SSRC: CSRC_i of the repair packet's RTP header.
    pub ssrc: u32,
    /// The lowest sequence number of this stream the repair packet protects.
    pub sn_base: u16,
    /// Which packets from there.
    pub protected: FlexFecProtected,
}

impl FlexFecBlock {
    /// The offsets from `sn_base` of the packets this block protects, ascending.
    ///
    /// At most 255 entries: a mask has 110 bits, a row L <= 255 packets, a column D <= 255.
    pub fn offsets(&self) -> Vec<u16> {
        match self.protected {
            FlexFecProtected::Mask(mask) => (0..FLEXFEC_MAX_MASK_BITS)
                .filter(|&bit| mask.bit(bit))
                .map(|bit| bit as u16)
                .collect(),
            FlexFecProtected::Fixed { l, d } if d <= 1 => (0..u16::from(l)).collect(),
            FlexFecProtected::Fixed { l, d } => {
                (0..u16::from(d)).map(|row| row * u16::from(l)).collect()
            }
        }
    }

    /// The distance from `sn_base` to the last packet protected, plus one: how many sequence
    /// numbers the block spans. 0 when it protects nothing.
    pub fn span(&self) -> u32 {
        self.offsets().last().map_or(0, |&last| u32::from(last) + 1)
    }

    /// The sequence numbers this block protects, in sending order.
    pub fn sequence_numbers(&self) -> Vec<u16> {
        self.offsets()
            .into_iter()
            .map(|offset| self.sn_base.wrapping_add(offset))
            .collect()
    }
}

/// A parsed FEC header (section 4.2.2).
///
/// Not exhaustive: R=1 F=1 is reserved for a future variant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlexFecHeader {
    /// R=0: a parity repair packet, with flexible masks (F=0) or fixed L/D (F=1).
    Repair {
        /// The first 8 octets as they are on the wire: R, F, then P, X, CC, M and PT recovery,
        /// length recovery, TS recovery.
        recovery: [u8; FLEXFEC_RECOVERY_SIZE],
        /// One block per CSRC of the repair packet, in CSRC order.
        blocks: Vec<FlexFecBlock>,
        /// Offset of the repair payload in the RTP payload.
        payload_offset: usize,
    },
    /// R=1, F=0: the RTP payload is one source packet, whole, with R and F where its version
    /// bits were (section 4.2.2.3, Figure 15).
    Retransmission,
}

impl FlexFecHeader {
    /// Parse the FEC header at the start of a repair packet's RTP `payload`.
    ///
    /// `csrc` is the CSRC list of the repair packet's RTP header, which names the protected
    /// source streams (section 4.2.1); there is one SN base block per entry.
    pub fn parse(csrc: &[u32], payload: &[u8]) -> Result<Self, FlexFecHeaderError> {
        let first = *payload.first().ok_or(FlexFecHeaderError::Truncated)?;
        let retransmission = first & R_BIT != 0;
        let fixed = first & F_BIT != 0;

        if retransmission {
            if fixed {
                return Err(FlexFecHeaderError::ReservedVariant);
            }
            if payload.len() < RTP_FIXED_HEADER_SIZE {
                return Err(FlexFecHeaderError::NotARetransmittedPacket);
            }
            return Ok(Self::Retransmission);
        }

        if csrc.is_empty() {
            return Err(FlexFecHeaderError::NoProtectedSsrc);
        }
        let recovery: [u8; FLEXFEC_RECOVERY_SIZE] = payload
            .get(..FLEXFEC_RECOVERY_SIZE)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(FlexFecHeaderError::Truncated)?;

        let mut offset = FLEXFEC_RECOVERY_SIZE;
        let mut blocks = Vec::with_capacity(csrc.len());
        for &ssrc in csrc {
            let word = payload
                .get(offset..offset + 4)
                .ok_or(FlexFecHeaderError::Truncated)?;
            let sn_base = u16::from_be_bytes([word[0], word[1]]);
            offset += 4;

            let protected = if fixed {
                let (l, d) = (word[2], word[3]);
                if l == 0 {
                    return Err(FlexFecHeaderError::ZeroColumns);
                }
                FlexFecProtected::Fixed { l, d }
            } else {
                let mut mask = BitArray::new();
                set_bits(
                    &mut mask,
                    0,
                    15,
                    u64::from(u16::from_be_bytes([word[2] & !K_BIT, word[3]])),
                );
                // k=1: another mask follows; k=0: this was the last (section 4.2.2.1).
                if word[2] & K_BIT != 0 {
                    let second = payload
                        .get(offset..offset + 4)
                        .ok_or(FlexFecHeaderError::Truncated)?;
                    offset += 4;
                    set_bits(
                        &mut mask,
                        15,
                        31,
                        u64::from(u32::from_be_bytes([
                            second[0] & !K_BIT,
                            second[1],
                            second[2],
                            second[3],
                        ])),
                    );
                    if second[0] & K_BIT != 0 {
                        // The third mask is 64 bits and has no k bit.
                        let third: [u8; 8] = payload
                            .get(offset..offset + 8)
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or(FlexFecHeaderError::Truncated)?;
                        offset += 8;
                        set_bits(&mut mask, 46, 64, u64::from_be_bytes(third));
                    }
                }
                FlexFecProtected::Mask(mask)
            };

            blocks.push(FlexFecBlock {
                ssrc,
                sn_base,
                protected,
            });
        }

        if blocks.iter().all(|block| block.span() == 0) {
            return Err(FlexFecHeaderError::ProtectsNothing);
        }

        Ok(Self::Repair {
            recovery,
            blocks,
            payload_offset: offset,
        })
    }
}

/// Set bits `first .. first + width` of `mask` from the low `width` bits of `value`, most
/// significant first.
fn set_bits(mask: &mut BitArray, first: u32, width: u32, value: u64) {
    for bit in 0..width {
        if (value >> (width - 1 - bit)) & 1 == 1 {
            mask.set_bit(first + bit);
        }
    }
}

/// Append the SN base and mask words of one flexible-mask block (Figure 12).
///
/// The mask is written at the smallest of the three sizes that holds its highest set bit: 15
/// bits, 46 bits or 110 bits, with k=1 on every word another one follows.
pub(crate) fn write_mask_block(out: &mut Vec<u8>, sn_base: u16, mask: &BitArray) {
    out.extend_from_slice(&sn_base.to_be_bytes());

    let (mask2, mask3) = (mask.mask2(), mask.mask3());
    let mut first = mask.mask1().to_be_bytes();
    if mask2 == 0 && mask3 == 0 {
        out.extend_from_slice(&first);
        return;
    }
    first[0] |= K_BIT;
    out.extend_from_slice(&first);

    let mut second = mask2.to_be_bytes();
    if mask3 == 0 {
        out.extend_from_slice(&second);
        return;
    }
    second[0] |= K_BIT;
    out.extend_from_slice(&second);
    out.extend_from_slice(&mask3.to_be_bytes());
}

/// Append the SN base, L and D of one fixed block (Figure 13).
pub(crate) fn write_fixed_block(out: &mut Vec<u8>, sn_base: u16, l: u8, d: u8) {
    out.extend_from_slice(&sn_base.to_be_bytes());
    out.push(l);
    out.push(d);
}

/// The R and F bits of a parity repair packet's first octet: R=0, F as given.
pub(crate) fn repair_variant_bits(fixed: bool) -> u8 {
    if fixed { F_BIT } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_of(bits: &[u32]) -> BitArray {
        let mut mask = BitArray::new();
        for &bit in bits {
            mask.set_bit(bit);
        }
        mask
    }

    fn mask_header(sn_base: u16, bits: &[u32]) -> Vec<u8> {
        let mut out = vec![0x00, 0x60, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44];
        write_mask_block(&mut out, sn_base, &mask_of(bits));
        out
    }

    /// Figure 12 with the 15-bit mask only: 8 octets of recovery fields, SN base, k=0 and the
    /// mask. 12 octets in all, where draft-03 has 20.
    #[test]
    fn a_fifteen_bit_mask_header_is_twelve_octets_with_k_clear() {
        let header = mask_header(0x1234, &[0, 2, 14]);

        assert_eq!(
            vec![
                0x00,
                0x60,
                0x00,
                0x10,
                0x11,
                0x22,
                0x33,
                0x44, // recovery fields
                0x12,
                0x34, // SN base
                0b0101_0000,
                0b0000_0001, // k=0, bits 0, 2 and 14
            ],
            header
        );
    }

    /// k=1 on the first word says the 31-bit mask follows; k=0 on that one ends the list. The
    /// polarity is the reverse of draft-03's.
    #[test]
    fn a_forty_six_bit_mask_sets_k_on_the_first_word_only() {
        let header = mask_header(7, &[0, 15, 45]);

        assert_eq!(16, header.len());
        assert_eq!([0b1100_0000, 0x00], header[10..12], "k=1, bit 0");
        assert_eq!(
            [0b0100_0000, 0x00, 0x00, 0x01],
            header[12..16],
            "k=0, bits 15 and 45"
        );
    }

    /// The third mask is a full 64 bits with no k bit: packets 46 to 109, 110 in all.
    #[test]
    fn a_hundred_and_ten_bit_mask_ends_with_sixty_four_bits_and_no_k_bit() {
        let header = mask_header(7, &[0, 46, 109]);

        assert_eq!(24, header.len());
        assert_ne!(0, header[10] & 0x80, "k=1");
        assert_ne!(0, header[12] & 0x80, "k=1");
        assert_eq!(
            [0x80, 0, 0, 0, 0, 0, 0, 0x01],
            header[16..24],
            "bit 46 is the first bit of the word, bit 109 the last"
        );
    }

    #[test]
    fn every_mask_width_parses_back_to_the_bits_written() {
        for bits in [
            vec![0u32],
            vec![0, 14],
            vec![0, 15],
            vec![3, 45],
            vec![0, 46],
            vec![0, 1, 2, 60, 109],
            (0..110).collect(),
        ] {
            let header = mask_header(65_530, &bits);
            let parsed = FlexFecHeader::parse(&[0xAABB_CCDD], &header).expect("parses");
            let FlexFecHeader::Repair {
                recovery,
                blocks,
                payload_offset,
            } = parsed
            else {
                panic!("a repair header");
            };
            assert_eq!(header[..8], recovery);
            assert_eq!(
                header.len(),
                payload_offset,
                "the payload follows the masks"
            );
            assert_eq!(1, blocks.len());
            assert_eq!(0xAABB_CCDD, blocks[0].ssrc);
            assert_eq!(65_530, blocks[0].sn_base);
            assert_eq!(
                bits.iter().map(|&bit| bit as u16).collect::<Vec<_>>(),
                blocks[0].offsets()
            );
        }
    }

    /// Sequence numbers wrap: SN base 65530 with bit 10 set is packet 4.
    #[test]
    fn protected_sequence_numbers_wrap() {
        let header = mask_header(65_530, &[0, 10]);
        let FlexFecHeader::Repair { blocks, .. } =
            FlexFecHeader::parse(&[1], &header).expect("parses")
        else {
            panic!("a repair header");
        };
        assert_eq!(vec![65_530, 4], blocks[0].sequence_numbers());
    }

    /// Section 4.2.2.1: with several CSRCs there is one SN base and mask block per CSRC, each of
    /// its own width.
    #[test]
    fn one_block_follows_per_csrc() {
        let mut header = vec![0u8; 8];
        write_mask_block(&mut header, 100, &mask_of(&[0, 1]));
        write_mask_block(&mut header, 9000, &mask_of(&[0, 20]));
        write_mask_block(&mut header, 5, &mask_of(&[0, 100]));
        assert_eq!(8 + 4 + 8 + 16, header.len());

        let FlexFecHeader::Repair {
            blocks,
            payload_offset,
            ..
        } = FlexFecHeader::parse(&[11, 22, 33], &header).expect("parses")
        else {
            panic!("a repair header");
        };
        assert_eq!(header.len(), payload_offset);
        assert_eq!(
            vec![
                (11, vec![100, 101]),
                (22, vec![9000, 9020]),
                (33, vec![5, 105])
            ],
            blocks
                .iter()
                .map(|block| (block.ssrc, block.sequence_numbers()))
                .collect::<Vec<_>>()
        );
    }

    /// Figure 13: F=1, then SN base, L and D per CSRC.
    #[test]
    fn a_fixed_header_carries_l_and_d() {
        let mut header = vec![repair_variant_bits(true) | 0x20, 0x60, 0, 9, 1, 2, 3, 4];
        write_fixed_block(&mut header, 0x0102, 4, 3);
        assert_eq!(vec![0x60, 0x60, 0, 9, 1, 2, 3, 4, 0x01, 0x02, 4, 3], header);

        let FlexFecHeader::Repair {
            blocks,
            payload_offset,
            ..
        } = FlexFecHeader::parse(&[9], &header).expect("parses")
        else {
            panic!("a repair header");
        };
        assert_eq!(12, payload_offset);
        assert_eq!(FlexFecProtected::Fixed { l: 4, d: 3 }, blocks[0].protected);
    }

    /// Figure 14: D of 0 or 1 is a row of L consecutive packets; D above 1 is a column of D
    /// packets, L apart.
    #[test]
    fn l_and_d_select_a_row_or_a_column() {
        let block = |l, d| FlexFecBlock {
            ssrc: 1,
            sn_base: 65_534,
            protected: FlexFecProtected::Fixed { l, d },
        };

        assert_eq!(vec![65_534, 65_535, 0, 1], block(4, 0).sequence_numbers());
        assert_eq!(vec![65_534, 65_535, 0, 1], block(4, 1).sequence_numbers());
        assert_eq!(vec![65_534, 2, 6], block(4, 3).sequence_numbers());
        assert_eq!(vec![65_534], block(1, 0).sequence_numbers(), "L=1 D=0");

        assert_eq!(4, block(4, 1).span());
        assert_eq!(9, block(4, 3).span());
        assert_eq!(254 * 255 + 1, block(255, 255).span());
    }

    /// Section 4.2.2.2: L=0 and D=0 MUST be ignored if received.
    #[test]
    fn l_zero_is_refused() {
        for d in [0u8, 1, 7] {
            let mut header = vec![repair_variant_bits(true), 0, 0, 0, 0, 0, 0, 0];
            write_fixed_block(&mut header, 100, 0, d);
            assert_eq!(
                Err(FlexFecHeaderError::ZeroColumns),
                FlexFecHeader::parse(&[1], &header),
                "L=0 D={d}"
            );
        }
    }

    /// Section 4.2.2: R=1 with F=1 is reserved; receivers MUST ignore these packets.
    #[test]
    fn r_and_f_both_set_is_refused() {
        let header = [0xC0u8; 32];
        assert_eq!(
            Err(FlexFecHeaderError::ReservedVariant),
            FlexFecHeader::parse(&[1], &header)
        );
        assert_eq!(
            Err(FlexFecHeaderError::ReservedVariant),
            FlexFecHeader::parse(&[], &header)
        );
    }

    /// Section 4.2.2.3: R=1 F=0 is a retransmission. The source SSRC is in the FEC header, so
    /// the CSRC list plays no part.
    #[test]
    fn r_set_alone_is_a_retransmission() {
        let payload = [0x80u8, 96, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0xAA];
        assert_eq!(
            Ok(FlexFecHeader::Retransmission),
            FlexFecHeader::parse(&[], &payload)
        );
        assert_eq!(
            Err(FlexFecHeaderError::NotARetransmittedPacket),
            FlexFecHeader::parse(&[], &payload[..11]),
            "shorter than an RTP header"
        );
    }

    /// Section 4.2.1: the CSRC list names the protected streams; a parity repair packet with
    /// none names nothing.
    #[test]
    fn a_repair_packet_without_a_csrc_is_refused() {
        assert_eq!(
            Err(FlexFecHeaderError::NoProtectedSsrc),
            FlexFecHeader::parse(&[], &mask_header(1, &[0]))
        );
    }

    #[test]
    fn a_header_cut_short_anywhere_is_refused() {
        let mut header = vec![0u8; 8];
        write_mask_block(&mut header, 1, &mask_of(&[0, 109]));
        write_mask_block(&mut header, 1, &mask_of(&[0, 20]));

        for length in 0..header.len() {
            assert_eq!(
                Err(FlexFecHeaderError::Truncated),
                FlexFecHeader::parse(&[1, 2], &header[..length]),
                "{length} of {} octets",
                header.len()
            );
        }
        assert!(FlexFecHeader::parse(&[1, 2], &header).is_ok());
    }

    #[test]
    fn a_mask_with_no_bit_set_protects_nothing() {
        assert_eq!(
            Err(FlexFecHeaderError::ProtectsNothing),
            FlexFecHeader::parse(&[1], &mask_header(1, &[]))
        );
    }
}
