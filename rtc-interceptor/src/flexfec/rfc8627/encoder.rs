//! RFC 8627 repair packet construction (section 6.2) and retransmission (section 4.2.2.3).

use super::header::{
    FLEXFEC_MAX_MASK_BITS, FLEXFEC_MAX_PROTECTED_SSRCS, FLEXFEC_RECOVERY_SIZE,
    RTP_FIXED_HEADER_SIZE, repair_variant_bits, write_fixed_block, write_mask_block,
};
use crate::flexfec::bit_array::BitArray;
use crate::flexfec::coverage::ProtectionCoverage;
use shared::marshal::{Marshal, MarshalSize};

/// How a repair packet names the source packets it protects.
///
/// Exhaustive: the one F bit selects between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexFecLayout {
    /// Flexible mask (R=0, F=0): any set of packets within 110 sequence numbers of the lowest.
    Mask,
    /// Fixed L columns and D rows (R=0, F=1). The source packets handed over must be exactly
    /// the row (`d <= 1`: L consecutive packets) or the column (`d > 1`: D packets, L apart)
    /// that L and D describe from the lowest sequence number.
    Fixed {
        /// L, the number of columns; not 0.
        l: u8,
        /// D, the number of rows.
        d: u8,
    },
}

/// The shape of the FEC a sender applies to each block of consecutive source packets
/// (RFC 8627 section 1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlexFecProtection {
    /// Flexible masks: blocks of `media_packets` packets, each protected by `fec_packets`
    /// interleaved repair packets (the first covers packets 0, n, 2n, ..., the second 1, n+1,
    /// ...). At most 110 packets per block.
    Mask {
        /// Source packets per block, 1 to 110.
        media_packets: u32,
        /// Repair packets per block.
        fec_packets: u32,
    },
    /// 1-D non-interleaved (row) FEC: one repair packet per `l` consecutive packets
    /// (section 1.1.1; sent as L=`l`, D=0). Recovers one loss per row.
    Row {
        /// L, packets per row; not 0.
        l: u8,
    },
    /// 1-D interleaved (column) FEC: blocks of `l * d` packets, one repair packet per column
    /// (section 1.1.2; sent as L=`l`, D=`d`). Recovers a burst of up to `l` packets.
    Column {
        /// L, the number of columns; not 0.
        l: u8,
        /// D, packets per column; at least 2.
        d: u8,
    },
    /// 2-D FEC: blocks of `l * d` packets, one repair packet per row (L=`l`, D=1) and one per
    /// column (L=`l`, D=`d`), rows first (section 1.1.4).
    RowAndColumn {
        /// L, the number of columns; not 0.
        l: u8,
        /// D, the number of rows; at least 2.
        d: u8,
    },
}

impl FlexFecProtection {
    /// How many consecutive source packets make one block; 0 when the shape is not usable.
    pub fn block_len(&self) -> usize {
        match *self {
            Self::Mask {
                media_packets,
                fec_packets,
            } => {
                if (1..=FLEXFEC_MAX_MASK_BITS).contains(&media_packets) && fec_packets > 0 {
                    media_packets as usize
                } else {
                    0
                }
            }
            Self::Row { l } => usize::from(l),
            Self::Column { l, d } | Self::RowAndColumn { l, d } => {
                if l == 0 || d < 2 {
                    0
                } else {
                    usize::from(l) * usize::from(d)
                }
            }
        }
    }

    /// How many repair packets one block yields.
    pub fn repair_packets_per_block(&self) -> usize {
        if self.block_len() == 0 {
            return 0;
        }
        match *self {
            Self::Mask {
                media_packets,
                fec_packets,
            } => fec_packets.min(media_packets) as usize,
            Self::Row { .. } => 1,
            Self::Column { l, .. } => usize::from(l),
            Self::RowAndColumn { l, d } => usize::from(l) + usize::from(d),
        }
    }
}

/// Why a repair packet could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlexFecEncodeError {
    /// No source packet was given.
    NothingToProtect,
    /// More than 15 source streams: the CSRC count is four bits (section 4.2.1).
    TooManySsrcs,
    /// A stream's packets span more than 110 sequence numbers, which no mask can name.
    MaskTooNarrow,
    /// The same sequence number of one stream was given twice.
    DuplicateSequenceNumber,
    /// The packets of a stream are not the row or column that L and D describe, or L is 0.
    NotTheFixedBlock,
    /// A source packet is longer than the 16-bit length recovery field can express.
    SourceTooLong,
    /// A source packet is not RTP version 2, the only version the format supports
    /// (section 6.2).
    NotVersion2,
    /// A source packet could not be serialized.
    Marshal,
}

impl std::fmt::Display for FlexFecEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NothingToProtect => "no source packet to protect",
            Self::TooManySsrcs => "more than 15 source streams in one repair packet",
            Self::MaskTooNarrow => "source packets span more than 110 sequence numbers",
            Self::DuplicateSequenceNumber => "a source packet was given twice",
            Self::NotTheFixedBlock => "source packets are not the row or column L and D describe",
            Self::SourceTooLong => "a source packet is too long for the length recovery field",
            Self::NotVersion2 => "a source packet is not RTP version 2",
            Self::Marshal => "a source packet could not be serialized",
        })
    }
}

impl std::error::Error for FlexFecEncodeError {}

/// The 80-bit FEC bit string header and the payload bit string of section 6.2, accumulated by
/// XOR over the source packets a repair packet protects.
#[derive(Debug, Default)]
pub(crate) struct Parity {
    /// First 16 bits of the RTP header, length recovery, TS recovery.
    pub(crate) recovery: [u8; FLEXFEC_RECOVERY_SIZE],
    /// Everything after the fixed 12-byte header, shorter packets padded with zeros at the end.
    pub(crate) payload: Vec<u8>,
}

impl Parity {
    /// XOR one source packet, as its wire octets, into the parity.
    ///
    /// `wire` is at least a fixed RTP header long; the caller checks.
    pub(crate) fn add(&mut self, wire: &[u8]) {
        let length = (wire.len() - RTP_FIXED_HEADER_SIZE) as u16;
        self.recovery[0] ^= wire[0];
        self.recovery[1] ^= wire[1];
        self.recovery[2] ^= (length >> 8) as u8;
        self.recovery[3] ^= length as u8;
        for (target, &octet) in self.recovery[4..8].iter_mut().zip(&wire[4..8]) {
            *target ^= octet;
        }

        let rest = &wire[RTP_FIXED_HEADER_SIZE..];
        if self.payload.len() < rest.len() {
            self.payload.resize(rest.len(), 0);
        }
        for (target, &source) in self.payload.iter_mut().zip(rest) {
            *target ^= source;
        }
    }
}

/// A source packet as it is on the wire.
fn wire_of(packet: &rtp::Packet) -> Result<Vec<u8>, FlexFecEncodeError> {
    if packet.header.version != 2 {
        return Err(FlexFecEncodeError::NotVersion2);
    }
    let size = packet.marshal_size();
    if size < RTP_FIXED_HEADER_SIZE || size - RTP_FIXED_HEADER_SIZE > usize::from(u16::MAX) {
        return Err(FlexFecEncodeError::SourceTooLong);
    }
    let mut wire = vec![0u8; size];
    packet
        .marshal_to(&mut wire)
        .map_err(|_| FlexFecEncodeError::Marshal)?;
    Ok(wire)
}

/// The lowest of `sequence_numbers` taking wrap-around into account: the one every other is
/// ahead of by less than half the sequence space.
fn lowest_sequence_number(sequence_numbers: &[u16]) -> u16 {
    let mut lowest = sequence_numbers[0];
    for &sequence_number in &sequence_numbers[1..] {
        if lowest.wrapping_sub(sequence_number) < 0x8000 {
            lowest = sequence_number;
        }
    }
    lowest
}

/// Builds RFC 8627 FlexFEC repair packets: the format negotiated as `flexfec` (`video/flexfec`
/// and the other three media types of RFC 8627 section 5.1), not `flexfec-03`.
///
/// One encoder is one repair stream: its own SSRC, payload type and sequence numbers. It may
/// protect several source streams (section 4.2.2.1), which it names in the CSRC list of each
/// repair packet.
#[derive(Debug)]
pub struct FlexFecEncoder {
    payload_type: u8,
    ssrc: u32,
    next_sequence_number: u16,
}

impl FlexFecEncoder {
    /// A repair-stream encoder sending `payload_type` on `ssrc`, its sequence numbers starting
    /// at 0 until [`with_base_sequence_number`](Self::with_base_sequence_number) says otherwise.
    pub fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            next_sequence_number: 0,
        }
    }

    /// Start the repair stream's sequence numbers at `sequence_number`. Section 4.2.1 wants the
    /// initial value random; the send interceptor draws one.
    pub fn with_base_sequence_number(mut self, sequence_number: u16) -> Self {
        self.next_sequence_number = sequence_number;
        self
    }

    /// The sequence number the next repair packet will carry.
    pub fn next_sequence_number(&self) -> u16 {
        self.next_sequence_number
    }

    /// The RTP header of the next packet of the repair stream (section 4.2.1): version 2, no
    /// marker, the CSRC list naming the protected streams, the caller's send-clock timestamp.
    fn repair_packet(&mut self, csrc: Vec<u32>, timestamp: u32, payload: Vec<u8>) -> rtp::Packet {
        let sequence_number = self.next_sequence_number;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: false,
                payload_type: self.payload_type,
                sequence_number,
                timestamp,
                ssrc: self.ssrc,
                csrc,
                ..Default::default()
            },
            payload: payload.into(),
        }
    }

    /// Build one parity repair packet protecting exactly `sources`, stamped with `timestamp`
    /// (the repair stream's RTP timestamp for the instant it is sent, section 4.2.1).
    ///
    /// `sources` may belong to several streams, up to 15: each gets a CSRC entry and its own SN
    /// base block, in order of first appearance. Order within a stream does not matter.
    pub fn encode(
        &mut self,
        layout: FlexFecLayout,
        sources: &[rtp::Packet],
        timestamp: u32,
    ) -> Result<rtp::Packet, FlexFecEncodeError> {
        if sources.is_empty() {
            return Err(FlexFecEncodeError::NothingToProtect);
        }

        // Group by stream, in order of first appearance.
        let mut streams: Vec<(u32, Vec<u16>)> = Vec::new();
        let mut parity = Parity::default();
        for packet in sources {
            let sequence_number = packet.header.sequence_number;
            match streams
                .iter_mut()
                .find(|(ssrc, _)| *ssrc == packet.header.ssrc)
            {
                Some((_, sequence_numbers)) => {
                    if sequence_numbers.contains(&sequence_number) {
                        return Err(FlexFecEncodeError::DuplicateSequenceNumber);
                    }
                    sequence_numbers.push(sequence_number);
                }
                None => {
                    if streams.len() == FLEXFEC_MAX_PROTECTED_SSRCS {
                        return Err(FlexFecEncodeError::TooManySsrcs);
                    }
                    streams.push((packet.header.ssrc, vec![sequence_number]));
                }
            }
            parity.add(&wire_of(packet)?);
        }

        let mut payload =
            Vec::with_capacity(FLEXFEC_RECOVERY_SIZE + streams.len() * 16 + parity.payload.len());
        // The version bits of the XOR are skipped; R and F take their place (section 6.2).
        parity.recovery[0] = (parity.recovery[0] & 0x3F)
            | repair_variant_bits(matches!(layout, FlexFecLayout::Fixed { .. }));
        payload.extend_from_slice(&parity.recovery);

        for (_, sequence_numbers) in &streams {
            // SN base: the lowest sequence number of this stream the packet protects.
            let sn_base = lowest_sequence_number(sequence_numbers);
            let mut offsets: Vec<u16> = sequence_numbers
                .iter()
                .map(|sequence_number| sequence_number.wrapping_sub(sn_base))
                .collect();
            offsets.sort_unstable();

            match layout {
                FlexFecLayout::Mask => {
                    let mut mask = BitArray::new();
                    for &offset in &offsets {
                        if u32::from(offset) >= FLEXFEC_MAX_MASK_BITS {
                            return Err(FlexFecEncodeError::MaskTooNarrow);
                        }
                        mask.set_bit(u32::from(offset));
                    }
                    write_mask_block(&mut payload, sn_base, &mask);
                }
                FlexFecLayout::Fixed { l, d } => {
                    let expected: Vec<u16> = if l == 0 {
                        // L=0 D=0 is reserved and MUST NOT be sent (section 4.2.2.2).
                        return Err(FlexFecEncodeError::NotTheFixedBlock);
                    } else if d <= 1 {
                        (0..u16::from(l)).collect()
                    } else {
                        (0..u16::from(d)).map(|row| row * u16::from(l)).collect()
                    };
                    if offsets != expected {
                        return Err(FlexFecEncodeError::NotTheFixedBlock);
                    }
                    write_fixed_block(&mut payload, sn_base, l, d);
                }
            }
        }
        payload.extend_from_slice(&parity.payload);

        let csrc = streams.iter().map(|(ssrc, _)| *ssrc).collect();
        Ok(self.repair_packet(csrc, timestamp, payload))
    }

    /// Protect one block of **consecutive** packets of one stream with `protection`, returning
    /// its repair packets in sending order (for 2-D, rows first, then columns: section
    /// 4.2.2.2).
    ///
    /// Returns nothing when `block` is not exactly [`FlexFecProtection::block_len`] consecutive
    /// packets of one stream: L and D describe positions from one base sequence number, so a
    /// gap would protect the wrong packets.
    pub fn encode_block(
        &mut self,
        protection: FlexFecProtection,
        block: &[rtp::Packet],
        timestamp: u32,
    ) -> Vec<rtp::Packet> {
        let block_len = protection.block_len();
        if block_len == 0 || block.len() != block_len {
            return Vec::new();
        }
        let consecutive = block.windows(2).all(|pair| {
            pair[1].header.ssrc == pair[0].header.ssrc
                && pair[1].header.sequence_number == pair[0].header.sequence_number.wrapping_add(1)
        });
        if !consecutive {
            return Vec::new();
        }

        // Each entry: the layout of one repair packet and the block positions it protects.
        let mut plan: Vec<(FlexFecLayout, Vec<usize>)> = Vec::new();
        let rows = |plan: &mut Vec<(FlexFecLayout, Vec<usize>)>, l: u8, d_field: u8| {
            let l = usize::from(l);
            for row in 0..block_len / l {
                plan.push((
                    FlexFecLayout::Fixed {
                        l: l as u8,
                        d: d_field,
                    },
                    (row * l..(row + 1) * l).collect(),
                ));
            }
        };
        let columns = |plan: &mut Vec<(FlexFecLayout, Vec<usize>)>, l: u8, d: u8| {
            for column in 0..usize::from(l) {
                plan.push((
                    FlexFecLayout::Fixed { l, d },
                    (0..usize::from(d))
                        .map(|row| column + row * usize::from(l))
                        .collect(),
                ));
            }
        };
        match protection {
            FlexFecProtection::Mask {
                media_packets,
                fec_packets,
            } => {
                let Some(coverage) = ProtectionCoverage::new(media_packets, fec_packets) else {
                    return Vec::new();
                };
                for fec_index in 0..coverage.num_fec_packets() {
                    let covered = coverage.covered_by(fec_index);
                    if !covered.is_empty() {
                        plan.push((
                            FlexFecLayout::Mask,
                            covered.into_iter().map(|index| index as usize).collect(),
                        ));
                    }
                }
            }
            // D=0: row FEC, and no column FEC will follow.
            FlexFecProtection::Row { l } => rows(&mut plan, l, 0),
            FlexFecProtection::Column { l, d } => columns(&mut plan, l, d),
            FlexFecProtection::RowAndColumn { l, d } => {
                // D=1: row FEC, and column FEC will follow.
                rows(&mut plan, l, 1);
                columns(&mut plan, l, d);
            }
        }

        let mut repair = Vec::with_capacity(plan.len());
        for (layout, positions) in plan {
            let sources: Vec<rtp::Packet> = positions
                .into_iter()
                .map(|position| block[position].clone())
                .collect();
            if let Ok(packet) = self.encode(layout, &sources, timestamp) {
                repair.push(packet);
            }
        }
        repair
    }

    /// Retransmit `source` on the repair stream (R=1, F=0; section 4.2.2.3): a new RTP header
    /// prepended to the source packet, whose version bits become R and F.
    pub fn retransmit(
        &mut self,
        source: &rtp::Packet,
        timestamp: u32,
    ) -> Result<rtp::Packet, FlexFecEncodeError> {
        // Version 2 is binary 10, which is R=1 F=0: the FEC header of a retransmission is the
        // source packet as it was sent.
        let payload = wire_of(source)?;
        Ok(self.repair_packet(Vec::new(), timestamp, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flexfec::rfc8627::header::{FlexFecHeader, FlexFecProtected};

    const MEDIA_SSRC: u32 = 0x0102_0304;
    const REPAIR_SSRC: u32 = 0x0A0B_0C0D;
    const REPAIR_PT: u8 = 98;

    fn source(ssrc: u32, sequence_number: u16, payload: &[u8]) -> rtp::Packet {
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: true,
                payload_type: 96,
                sequence_number,
                timestamp: 0x1000_0000 + u32::from(sequence_number),
                ssrc,
                ..Default::default()
            },
            payload: payload.to_vec().into(),
        }
    }

    fn run(first: u16, count: u16) -> Vec<rtp::Packet> {
        (0..count)
            .map(|offset| {
                source(
                    MEDIA_SSRC,
                    first.wrapping_add(offset),
                    &[offset as u8, 2, 3],
                )
            })
            .collect()
    }

    fn encoder() -> FlexFecEncoder {
        FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC)
    }

    fn blocks_of(packet: &rtp::Packet) -> Vec<(u32, Vec<u16>)> {
        match FlexFecHeader::parse(&packet.header.csrc, &packet.payload).expect("parses") {
            FlexFecHeader::Repair { blocks, .. } => blocks
                .iter()
                .map(|block| (block.ssrc, block.sequence_numbers()))
                .collect(),
            FlexFecHeader::Retransmission => panic!("a parity packet"),
        }
    }

    /// Sections 4.2.1, 4.2.2.1 and 6.2, byte for byte: the repair packet for two known source
    /// packets, computed here by hand.
    #[test]
    fn a_flexible_mask_repair_packet_is_laid_out_as_figure_12() {
        // Source 1: V=2, M=1, PT=96, SN=10, TS=0x00000100, payload AA BB CC.
        let first = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: true,
                payload_type: 96,
                sequence_number: 10,
                timestamp: 0x0000_0100,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            },
            payload: vec![0xAA, 0xBB, 0xCC].into(),
        };
        // Source 2: V=2, M=0, PT=97, SN=12, TS=0x00000301, payload 11 22 33 44 55.
        let second = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: false,
                payload_type: 97,
                sequence_number: 12,
                timestamp: 0x0000_0301,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            },
            payload: vec![0x11, 0x22, 0x33, 0x44, 0x55].into(),
        };

        let repair = encoder()
            .with_base_sequence_number(500)
            .encode(FlexFecLayout::Mask, &[first, second], 0xCAFE_F00D)
            .expect("encodes");

        let mut wire = vec![0u8; repair.marshal_size()];
        repair.marshal_to(&mut wire).expect("marshal");
        assert_eq!(
            vec![
                // RTP header: V=2, CC=1; M=0, PT=98; SN=500; TS; repair SSRC; CSRC = source SSRC.
                0x81,
                98,
                0x01,
                0xF4,
                0xCA,
                0xFE,
                0xF0,
                0x0D,
                0x0A,
                0x0B,
                0x0C,
                0x0D,
                0x01,
                0x02,
                0x03,
                0x04,
                // R=0 F=0, P/X/CC recovery 0; M recovery 1 ^ 0, PT recovery 96 ^ 97 = 1.
                0x00,
                0x81,
                // length recovery: 3 ^ 5.
                0x00,
                0x06,
                // TS recovery: 0x100 ^ 0x301.
                0x00,
                0x00,
                0x02,
                0x01,
                // SN base 10; k=0, mask bits 0 and 2.
                0x00,
                0x0A,
                0b0101_0000,
                0x00,
                // Repair payload: AA BB CC 00 00 ^ 11 22 33 44 55.
                0xBB,
                0x99,
                0xFF,
                0x44,
                0x55,
            ],
            wire
        );
    }

    /// Section 4.2.1: the marker is 0, the sequence number is one higher each packet, and the
    /// timestamp is what the caller's send clock says.
    #[test]
    fn repair_packets_form_their_own_stream() {
        let mut encoder = encoder().with_base_sequence_number(65_535);
        let first = encoder
            .encode(FlexFecLayout::Mask, &run(1, 3), 111)
            .expect("encodes");
        let second = encoder
            .encode(FlexFecLayout::Mask, &run(4, 3), 222)
            .expect("encodes");

        for packet in [&first, &second] {
            assert_eq!(2, packet.header.version);
            assert!(!packet.header.marker, "marker SHALL be 0");
            assert!(!packet.header.padding && !packet.header.extension);
            assert_eq!(REPAIR_PT, packet.header.payload_type);
            assert_eq!(REPAIR_SSRC, packet.header.ssrc);
            assert_eq!(vec![MEDIA_SSRC], packet.header.csrc, "the protected stream");
        }
        assert_eq!(65_535, first.header.sequence_number);
        assert_eq!(
            0, second.header.sequence_number,
            "one higher, across the wrap"
        );
        assert_eq!(
            (111, 222),
            (first.header.timestamp, second.header.timestamp)
        );
    }

    /// Section 4.2.2.1: SN base is the lowest sequence number protected, taking wrap-around
    /// into account, whatever order the packets were handed over in.
    #[test]
    fn sn_base_is_the_lowest_protected_sequence_number_across_the_wrap() {
        let sources = vec![
            source(MEDIA_SSRC, 2, &[1]),
            source(MEDIA_SSRC, 65_534, &[2]),
            source(MEDIA_SSRC, 0, &[3]),
        ];
        let repair = encoder()
            .encode(FlexFecLayout::Mask, &sources, 0)
            .expect("encodes");

        assert_eq!(
            vec![(MEDIA_SSRC, vec![65_534, 0, 2])],
            blocks_of(&repair),
            "base 65534, bits 0, 2 and 4"
        );
        assert_eq!([0xFF, 0xFE], repair.payload[8..10]);
    }

    /// Section 4.2.2.1: one SN base and mask block per protected stream, the streams named in
    /// the CSRC list in the same order.
    #[test]
    fn several_streams_get_a_csrc_and_a_block_each() {
        let sources = vec![
            source(0x11, 100, &[1]),
            source(0x22, 7000, &[2, 2]),
            source(0x11, 101, &[3]),
            source(0x22, 7050, &[4, 4, 4]),
        ];
        let repair = encoder()
            .encode(FlexFecLayout::Mask, &sources, 0)
            .expect("encodes");

        assert_eq!(vec![0x11, 0x22], repair.header.csrc);
        assert_eq!(
            vec![(0x11, vec![100, 101]), (0x22, vec![7000, 7050])],
            blocks_of(&repair)
        );
        // 8 recovery octets, a 4-octet block, a 16-octet block (bit 50 needs the third mask),
        // then a payload as long as the longest source.
        assert_eq!(8 + 4 + 16 + 3, repair.payload.len());
    }

    #[test]
    fn the_mask_grows_only_as_far_as_the_highest_packet_needs() {
        let length = |last: u16| {
            let sources = vec![source(MEDIA_SSRC, 0, &[]), source(MEDIA_SSRC, last, &[])];
            encoder()
                .encode(FlexFecLayout::Mask, &sources, 0)
                .expect("encodes")
                .payload
                .len()
        };
        assert_eq!(12, length(14), "15-bit mask");
        assert_eq!(16, length(15), "46-bit mask");
        assert_eq!(16, length(45));
        assert_eq!(24, length(46), "110-bit mask");
        assert_eq!(24, length(109));
    }

    #[test]
    fn what_no_header_can_name_is_refused() {
        let mut encoder = encoder();
        assert_eq!(
            Err(FlexFecEncodeError::NothingToProtect),
            encoder.encode(FlexFecLayout::Mask, &[], 0)
        );
        assert_eq!(
            Err(FlexFecEncodeError::MaskTooNarrow),
            encoder.encode(
                FlexFecLayout::Mask,
                &[source(1, 0, &[]), source(1, 110, &[])],
                0
            ),
            "the 111th sequence number"
        );
        assert_eq!(
            Err(FlexFecEncodeError::DuplicateSequenceNumber),
            encoder.encode(
                FlexFecLayout::Mask,
                &[source(1, 5, &[]), source(1, 5, &[])],
                0
            )
        );
        let sixteen: Vec<rtp::Packet> = (0..16).map(|ssrc| source(ssrc, 1, &[])).collect();
        assert_eq!(
            Err(FlexFecEncodeError::TooManySsrcs),
            encoder.encode(FlexFecLayout::Mask, &sixteen, 0)
        );
        let mut version_1 = source(1, 1, &[]);
        version_1.header.version = 1;
        assert_eq!(
            Err(FlexFecEncodeError::NotVersion2),
            encoder.encode(FlexFecLayout::Mask, &[version_1], 0)
        );
        assert_eq!(
            0,
            encoder.next_sequence_number(),
            "a refused packet uses no sequence number"
        );
    }

    /// Section 4.2.2.2: L=0 D=0 MUST NOT be sent, and L/D must describe the packets protected.
    #[test]
    fn a_fixed_layout_that_does_not_describe_the_packets_is_refused() {
        let mut encoder = encoder();
        for (l, d) in [(0u8, 0u8), (0, 3)] {
            assert_eq!(
                Err(FlexFecEncodeError::NotTheFixedBlock),
                encoder.encode(FlexFecLayout::Fixed { l, d }, &run(1, 4), 0),
                "L={l} D={d}"
            );
        }
        assert_eq!(
            Err(FlexFecEncodeError::NotTheFixedBlock),
            encoder.encode(FlexFecLayout::Fixed { l: 4, d: 0 }, &run(1, 3), 0),
            "three packets are not a row of four"
        );
        assert_eq!(
            Err(FlexFecEncodeError::NotTheFixedBlock),
            encoder.encode(FlexFecLayout::Fixed { l: 4, d: 3 }, &run(1, 3), 0),
            "three consecutive packets are not a column"
        );
        assert!(
            encoder
                .encode(FlexFecLayout::Fixed { l: 4, d: 1 }, &run(1, 4), 0)
                .is_ok()
        );
    }

    fn fixed_fields(packet: &rtp::Packet) -> (u16, u8, u8) {
        assert_eq!(0x40, packet.payload[0] & 0xC0, "R=0 F=1");
        (
            u16::from_be_bytes([packet.payload[8], packet.payload[9]]),
            packet.payload[10],
            packet.payload[11],
        )
    }

    /// Section 1.1.1 (Figure 2) and Figure 14: row FEC over L consecutive packets, sent with
    /// D=0 because no column FEC follows.
    #[test]
    fn row_protection_sends_one_repair_packet_per_row_with_d_zero() {
        let repair = encoder().encode_block(FlexFecProtection::Row { l: 4 }, &run(100, 4), 0);

        assert_eq!(1, repair.len());
        assert_eq!((100, 4, 0), fixed_fields(&repair[0]));
        assert_eq!(
            vec![(MEDIA_SSRC, vec![100, 101, 102, 103])],
            blocks_of(&repair[0])
        );
    }

    /// Section 1.1.2 (Figure 5): column FEC, one repair packet per column of an L by D block,
    /// each over D packets L apart, its SN base the column's first packet.
    #[test]
    fn column_protection_sends_one_repair_packet_per_column() {
        let repair =
            encoder().encode_block(FlexFecProtection::Column { l: 4, d: 3 }, &run(1, 12), 0);

        assert_eq!(4, repair.len());
        assert_eq!(
            vec![(1, 4, 3), (2, 4, 3), (3, 4, 3), (4, 4, 3)],
            repair.iter().map(fixed_fields).collect::<Vec<_>>()
        );
        assert_eq!(vec![(MEDIA_SSRC, vec![1, 5, 9])], blocks_of(&repair[0]));
        assert_eq!(vec![(MEDIA_SSRC, vec![4, 8, 12])], blocks_of(&repair[3]));
    }

    /// Section 1.1.4 (Figure 7) and Figure 14: 2-D FEC sends the row packets with D=1 ("column
    /// FEC will follow"), then the column packets.
    #[test]
    fn two_dimensional_protection_sends_rows_with_d_one_then_columns() {
        let repair = encoder().encode_block(
            FlexFecProtection::RowAndColumn { l: 4, d: 3 },
            &run(1, 12),
            0,
        );

        assert_eq!(
            vec![
                (1, 4, 1),
                (5, 4, 1),
                (9, 4, 1),
                (1, 4, 3),
                (2, 4, 3),
                (3, 4, 3),
                (4, 4, 3)
            ],
            repair.iter().map(fixed_fields).collect::<Vec<_>>()
        );
        for (offset, packet) in repair.iter().enumerate() {
            assert_eq!(offset as u16, packet.header.sequence_number);
        }
    }

    /// The flexible-mask shape interleaves, as the draft-03 coder does, and every repair
    /// packet's SN base is its own lowest packet.
    #[test]
    fn mask_protection_interleaves_with_a_base_per_repair_packet() {
        let repair = encoder().encode_block(
            FlexFecProtection::Mask {
                media_packets: 6,
                fec_packets: 2,
            },
            &run(100, 6),
            0,
        );

        assert_eq!(2, repair.len());
        assert_eq!(
            vec![(MEDIA_SSRC, vec![100, 102, 104])],
            blocks_of(&repair[0])
        );
        assert_eq!(
            vec![(MEDIA_SSRC, vec![101, 103, 105])],
            blocks_of(&repair[1])
        );
        for packet in &repair {
            assert_eq!(0, packet.payload[0] & 0xC0, "R=0 F=0");
            let FlexFecHeader::Repair { blocks, .. } =
                FlexFecHeader::parse(&packet.header.csrc, &packet.payload).expect("parses")
            else {
                panic!("a parity packet");
            };
            assert!(matches!(blocks[0].protected, FlexFecProtected::Mask(_)));
        }
    }

    /// A mask reaches 110 packets, one more than draft-03's.
    #[test]
    fn a_mask_block_of_110_packets_is_fully_named() {
        let repair = encoder().encode_block(
            FlexFecProtection::Mask {
                media_packets: 110,
                fec_packets: 1,
            },
            &run(65_500, 110),
            0,
        );
        assert_eq!(1, repair.len());
        let named = &blocks_of(&repair[0])[0].1;
        assert_eq!(110, named.len());
        assert_eq!(65_500u16.wrapping_add(109), named[109]);
    }

    #[test]
    fn a_block_that_is_not_the_shape_asked_for_yields_nothing() {
        let mut encoder = encoder();
        let column = FlexFecProtection::Column { l: 4, d: 3 };

        assert!(encoder.encode_block(column, &run(1, 11), 0).is_empty());
        let mut gapped = run(1, 12);
        gapped[7].header.sequence_number = 99;
        assert!(encoder.encode_block(column, &gapped, 0).is_empty());
        let mut other_stream = run(1, 12);
        other_stream[11].header.ssrc = 5;
        assert!(encoder.encode_block(column, &other_stream, 0).is_empty());

        for unusable in [
            FlexFecProtection::Row { l: 0 },
            FlexFecProtection::Column { l: 0, d: 3 },
            FlexFecProtection::Column { l: 4, d: 1 },
            FlexFecProtection::RowAndColumn { l: 4, d: 0 },
            FlexFecProtection::Mask {
                media_packets: 111,
                fec_packets: 1,
            },
            FlexFecProtection::Mask {
                media_packets: 5,
                fec_packets: 0,
            },
        ] {
            assert_eq!(0, unusable.block_len(), "{unusable:?}");
            assert_eq!(0, unusable.repair_packets_per_block(), "{unusable:?}");
        }
        assert_eq!(0, encoder.next_sequence_number());
    }

    /// Section 4.2.2.3, Figure 15: the retransmission payload is the source packet, RTP header
    /// first, and its first two bits read R=1 F=0. The source SSRC is in that header, not in
    /// the CSRC list.
    #[test]
    fn a_retransmission_is_the_source_packet_behind_a_new_rtp_header() {
        let mut lost = source(MEDIA_SSRC, 4321, &[9, 8, 7]);
        lost.header.csrc = vec![0xEEEE_0001];
        let mut wire = vec![0u8; lost.marshal_size()];
        lost.marshal_to(&mut wire).expect("marshal");

        let packet = encoder()
            .with_base_sequence_number(77)
            .retransmit(&lost, 9000)
            .expect("retransmits");

        assert_eq!(wire.as_slice(), &packet.payload[..]);
        assert_eq!(0x80, packet.payload[0] & 0xC0, "R=1 F=0");
        assert_eq!(MEDIA_SSRC.to_be_bytes(), packet.payload[8..12]);
        assert!(packet.header.csrc.is_empty());
        assert_eq!(
            (REPAIR_SSRC, REPAIR_PT, 77, 9000, false),
            (
                packet.header.ssrc,
                packet.header.payload_type,
                packet.header.sequence_number,
                packet.header.timestamp,
                packet.header.marker
            )
        );
        assert_eq!(
            Ok(FlexFecHeader::Retransmission),
            FlexFecHeader::parse(&packet.header.csrc, &packet.payload)
        );
    }
}
