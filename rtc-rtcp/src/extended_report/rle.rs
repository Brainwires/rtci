//! Loss and Duplicate RLE report blocks.
//!
//! Both blocks report per-packet status over a sequence-number range, run-length encoded: a
//! [`Chunk`](crate::extended_report::rle::Chunk) is either a run of identical values or an explicit 15-bit vector. That keeps a report
//! covering a long range compact while still describing individual packets.
//!
//! The same structure serves both blocks; [`RLEReportBlock::is_loss_rle`](crate::extended_report::rle::RLEReportBlock::is_loss_rle) selects which.
use super::*;

const RLE_REPORT_BLOCK_MIN_LENGTH: u16 = 8;

/// ChunkType enumerates the three kinds of chunks described in RFC 3611 section 4.1.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChunkType {
    /// A run-length chunk: a bit value repeated a stated number of times.
    RunLength = 0,
    /// A bit-vector chunk: 15 explicit per-packet bits.
    BitVector = 1,
    /// The terminating null chunk, which pads the block to a word boundary.
    TerminatingNull = 2,
}

/// Chunk as defined in RFC 3611, section 4.1. These represent information
/// about packet losses and packet duplication. They have three representations:
///
/// Run Length Chunk:
///
///   0                   1
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |C|R|        run length         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Bit Vector Chunk:
///
///   0                   1
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |C|        bit vector           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Terminating Null Chunk:
///
///   0                   1
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Chunk(pub u16);

impl fmt::Display for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.chunk_type() {
            ChunkType::RunLength => {
                let run_type = self.run_type().unwrap_or(0);
                write!(f, "[RunLength type={}, length={}]", run_type, self.value())
            }
            ChunkType::BitVector => write!(f, "[BitVector {:#b}", self.value()),
            ChunkType::TerminatingNull => write!(f, "[TerminatingNull]"),
        }
    }
}
impl Chunk {
    /// chunk_type returns the ChunkType that this Chunk represents
    pub fn chunk_type(&self) -> ChunkType {
        if self.0 == 0 {
            ChunkType::TerminatingNull
        } else if (self.0 >> 15) == 0 {
            ChunkType::RunLength
        } else {
            ChunkType::BitVector
        }
    }

    /// run_type returns the run_type that this Chunk represents. It is
    /// only valid if ChunkType is RunLengthChunkType.
    pub fn run_type(&self) -> Result<u8> {
        if self.chunk_type() != ChunkType::RunLength {
            Err(Error::WrongChunkType)
        } else {
            Ok((self.0 >> 14) as u8 & 0x01)
        }
    }

    /// value returns the value represented in this Chunk
    pub fn value(&self) -> u16 {
        match self.chunk_type() {
            ChunkType::RunLength => self.0 & 0x3FFF,
            ChunkType::BitVector => self.0 & 0x7FFF,
            ChunkType::TerminatingNull => 0,
        }
    }
}

/// RleReportBlock defines the common structure used by both
/// Loss RLE report blocks (RFC 3611 §4.1) and Duplicate RLE
/// report blocks (RFC 3611 §4.2).
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  BT = 1 or 2  | rsvd. |   t   |         block length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        ssrc of source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          begin_seq            |             end_seq           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          chunk 1              |             chunk 2           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                              ...                              :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          chunk n-1            |             chunk n           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct RLEReportBlock {
    //not included in marshal/unmarshal
    /// `true` for a Loss RLE block, `false` for a Duplicate RLE block.
    pub is_loss_rle: bool,
    /// The block's `T` field.
    pub t: u8,

    //marshal/unmarshal
    /// The SSRC whose packets are reported on.
    pub ssrc: u32,
    /// The first sequence number covered by this block.
    pub begin_seq: u16,
    /// One past the last sequence number covered.
    pub end_seq: u16,
    /// The run-length and bit-vector chunks encoding per-packet status.
    pub chunks: Vec<Chunk>,
}

/// LossRLEReportBlock is used to report information about packet
/// losses, as described in RFC 3611, section 4.1
/// make sure to set is_loss_rle = true
pub type LossRLEReportBlock = RLEReportBlock;

/// DuplicateRLEReportBlock is used to report information about packet
/// duplication, as described in RFC 3611, section 4.1
/// make sure to set is_loss_rle = false
pub type DuplicateRLEReportBlock = RLEReportBlock;

impl RLEReportBlock {
    /// Checks what RFC 3611 4.1 requires of the block's content.
    fn validate(&self) -> Result<()> {
        // "A report block MUST NOT report on a sequence number range of 65,534 or more."
        if self.end_seq.wrapping_sub(self.begin_seq) >= 65534 {
            return Err(Error::InvalidBlockSize);
        }
        for chunk in &self.chunks {
            // The terminating null chunk "MUST NOT appear anywhere else": it is not one of
            // the chunks here, it is added when the block is written and dropped when read.
            if chunk.0 == 0 {
                return Err(Error::WrongChunkType);
            }
            // A run length is "a value between 1 and 16,383". Zero with the run type 0 is
            // the null chunk; zero with the run type 1 is nothing at all.
            if chunk.chunk_type() == ChunkType::RunLength && chunk.value() == 0 {
                return Err(Error::WrongChunkType);
            }
        }
        Ok(())
    }

    /// The chunks on the wire: `chunks`, and a terminating null chunk when one is needed to
    /// round the block up to a 32-bit boundary.
    fn wire_chunks(&self) -> usize {
        self.chunks.len() + self.chunks.len() % 2
    }

    /// The XR block header describing this block's type and length.
    pub fn xr_header(&self) -> XRHeader {
        XRHeader {
            block_type: if self.is_loss_rle {
                BlockType::LossRLE
            } else {
                BlockType::DuplicateRLE
            },
            type_specific: self.t & 0x0F,
            block_length: (self.raw_size() / 4 - 1) as u16,
        }
    }
}

/// The longest run a run-length chunk holds (RFC 3611 section 4.1.1: 14 bits, 1 to 16,383).
pub const MAX_RUN_LENGTH: usize = 16_383;
/// The packets one bit-vector chunk describes (RFC 3611 section 4.1.2).
pub const BIT_VECTOR_LENGTH: usize = 15;

/// The sequence numbers of `begin_seq..end_seq` (modulo 2^16) a block with thinning `t`
/// reports on: those that are a multiple of 2^t (RFC 3611 section 4.1).
pub fn reported_sequence_numbers(begin_seq: u16, end_seq: u16, t: u8) -> Vec<u16> {
    let step = 1u32 << (t & 0x0F);
    let span = u32::from(end_seq.wrapping_sub(begin_seq));
    (0..span)
        .map(|offset| begin_seq.wrapping_add(offset as u16))
        .filter(|seq| u32::from(*seq) % step == 0)
        .collect()
}

impl RLEReportBlock {
    /// A block reporting `flags`, one per sequence number [`reported_sequence_numbers`] gives
    /// for `begin_seq..end_seq` and `t`: for a Loss RLE block `true` is "received", for a
    /// Duplicate RLE block `true` is "duplicated" (RFC 3611 sections 4.1, 4.2).
    ///
    /// A run of 15 equal values or more is a run-length chunk, anything shorter goes into
    /// bit vectors. The bits of a last bit vector past the end of the flags are zero (RFC 3611
    /// section 4.1: "the remaining bits ... MUST be set to zero").
    pub fn from_flags(
        is_loss_rle: bool,
        ssrc: u32,
        begin_seq: u16,
        end_seq: u16,
        t: u8,
        flags: &[bool],
    ) -> Self {
        let mut chunks = vec![];
        let mut i = 0;
        while i < flags.len() {
            let value = flags[i];
            let run = flags[i..].iter().take_while(|f| **f == value).count();
            if run >= BIT_VECTOR_LENGTH {
                let run = run.min(MAX_RUN_LENGTH);
                chunks.push(Chunk(((value as u16) << 14) | run as u16));
                i += run;
            } else {
                let mut vector = 0x8000u16;
                for (bit, flag) in flags[i..].iter().take(BIT_VECTOR_LENGTH).enumerate() {
                    if *flag {
                        vector |= 1 << (BIT_VECTOR_LENGTH - 1 - bit);
                    }
                }
                chunks.push(Chunk(vector));
                i += BIT_VECTOR_LENGTH;
            }
        }
        RLEReportBlock {
            is_loss_rle,
            t: t & 0x0F,
            ssrc,
            begin_seq,
            end_seq,
            chunks,
        }
    }

    /// The flag of each sequence number the block reports on, in order
    /// ([`reported_sequence_numbers`]): what the chunks say, cut to that many. Bits of a bit
    /// vector past the end of the range, and a terminating null chunk, are ignored (RFC 3611
    /// section 4.1). A block whose chunks say less than the range has `false` for the rest.
    pub fn flags(&self) -> Vec<bool> {
        let count = reported_sequence_numbers(self.begin_seq, self.end_seq, self.t).len();
        let mut flags = Vec::with_capacity(count);
        for chunk in &self.chunks {
            if flags.len() >= count {
                break;
            }
            match chunk.chunk_type() {
                ChunkType::RunLength => {
                    let value = chunk.run_type().unwrap_or(0) == 1;
                    let run = usize::from(chunk.value()).min(count - flags.len());
                    flags.extend(std::iter::repeat_n(value, run));
                }
                ChunkType::BitVector => {
                    for bit in 0..BIT_VECTOR_LENGTH {
                        if flags.len() >= count {
                            break;
                        }
                        flags.push(chunk.value() & (1 << (BIT_VECTOR_LENGTH - 1 - bit)) != 0);
                    }
                }
                ChunkType::TerminatingNull => break,
            }
        }
        flags.resize(count, false);
        flags
    }
}

impl fmt::Display for RLEReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Packet for RLEReportBlock {
    fn header(&self) -> Header {
        Header::default()
    }

    /// destination_ssrc returns an array of ssrc values that this report block refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.ssrc]
    }

    fn raw_size(&self) -> usize {
        XR_HEADER_LENGTH + RLE_REPORT_BLOCK_MIN_LENGTH as usize + self.wire_chunks() * 2
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<RLEReportBlock>() == Some(self)
    }
    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for RLEReportBlock {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for RLEReportBlock {
    /// marshal_to encodes the RLEReportBlock in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        self.validate()?;
        if self.raw_size() / 4 - 1 > u16::MAX as usize {
            return Err(Error::InvalidBlockSize);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.xr_header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.ssrc);
        buf.put_u16(self.begin_seq);
        buf.put_u16(self.end_seq);
        for chunk in &self.chunks {
            buf.put_u16(chunk.0);
        }
        if self.wire_chunks() != self.chunks.len() {
            // The terminating null chunk.
            buf.put_u16(0);
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for RLEReportBlock {
    /// Unmarshal decodes the RLEReportBlock from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < XR_HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let xr_header = XRHeader::unmarshal(raw_packet)?;
        let block_length = match xr_header.block_length.checked_mul(4) {
            Some(length) => length,
            None => return Err(Error::InvalidBlockSize),
        };
        if block_length < RLE_REPORT_BLOCK_MIN_LENGTH
            || !(block_length - RLE_REPORT_BLOCK_MIN_LENGTH).is_multiple_of(2)
            || raw_packet.remaining() < block_length as usize
        {
            return Err(Error::PacketTooShort);
        }

        if xr_header.block_type != BlockType::LossRLE
            && xr_header.block_type != BlockType::DuplicateRLE
        {
            return Err(Error::WrongType);
        }
        let is_loss_rle = xr_header.block_type == BlockType::LossRLE;
        let t = xr_header.type_specific & 0x0F;

        let ssrc = raw_packet.get_u32();
        let begin_seq = raw_packet.get_u16();
        let end_seq = raw_packet.get_u16();

        let remaining = block_length - RLE_REPORT_BLOCK_MIN_LENGTH;
        let mut chunks = vec![];
        for _ in 0..remaining / 2 {
            chunks.push(Chunk(raw_packet.get_u16()));
        }

        // "If the chunks do not end on a 32-bit boundary, a terminating null chunk is added":
        // it pads, and is not one of the block's chunks.
        while chunks.last() == Some(&Chunk(0)) {
            chunks.pop();
        }

        let block = RLEReportBlock {
            is_loss_rle,
            t,
            ssrc,
            begin_seq,
            end_seq,
            chunks,
        };
        block.validate()?;

        Ok(block)
    }
}
