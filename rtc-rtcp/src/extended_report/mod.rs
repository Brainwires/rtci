#[cfg(test)]
mod extended_report_test;
#[cfg(test)]
mod report_blocks_test;

/// Delay Since Last Receiver Report blocks, for round-trip time between receivers.
pub mod dlrr;
/// Packet Receipt Times blocks.
pub mod prt;
/// Loss and Duplicate RLE blocks, which run-length encode per-packet receipt.
pub mod rle;
/// Receiver Reference Time blocks, which anchor DLRR round-trip calculations.
pub mod rrt;
/// Statistics Summary blocks: loss, duplicate, jitter and TTL ranges.
pub mod ssr;
/// An unparsed block, for types this crate does not model.
pub mod unknown;
/// VoIP Metrics blocks, which carry call-quality estimates.
pub mod vm;

pub use dlrr::{DLRRReport, DLRRReportBlock};
pub use prt::PacketReceiptTimesReportBlock;
pub use rle::{Chunk, ChunkType, DuplicateRLEReportBlock, LossRLEReportBlock, RLEReportBlock};
pub use rrt::ReceiverReferenceTimeReportBlock;
pub use ssr::{StatisticsSummaryReportBlock, TTLorHopLimitType};
pub use unknown::UnknownReportBlock;
pub use vm::VoIPMetricsReportBlock;

use crate::Packet;
use crate::header::{HEADER_LENGTH, Header, PacketType, SSRC_LENGTH, read_packet};
use crate::util::get_padding_size;
use bytes::{Buf, BufMut, Bytes};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};
use std::any::Any;
use std::fmt;

const XR_HEADER_LENGTH: usize = 4;

/// BlockType specifies the type of report in a report block
/// Extended Report block types from RFC 3611.
///
/// The enum converts to and from the type octet with `u8::from` / `BlockType::from`. A type
/// that later documents define is kept as [`BlockType::Other`], so such a block is written
/// back as what it was.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockType {
    #[default]
    /// No block type: the type octet 0.
    Unknown,
    /// Loss RLE report block ([RFC 3611] §4.1).
    LossRLE, // 1, RFC 3611, section 4.1
    /// Duplicate RLE report block ([RFC 3611] §4.2).
    DuplicateRLE, // 2, RFC 3611, section 4.2
    /// Packet Receipt Times report block ([RFC 3611] §4.3).
    PacketReceiptTimes, // 3, RFC 3611, section 4.3
    /// Receiver Reference Time report block ([RFC 3611] §4.4).
    ReceiverReferenceTime, // 4, RFC 3611, section 4.4
    /// Delay Since Last Receiver Report block ([RFC 3611] §4.5).
    DLRR, // 5, RFC 3611, section 4.5
    /// Statistics Summary report block ([RFC 3611] §4.6).
    StatisticsSummary, // 6, RFC 3611, section 4.6
    /// VoIP Metrics report block ([RFC 3611] §4.7).
    VoIPMetrics, // 7, RFC 3611, section 4.7
    /// A block type this crate does not model, with its type octet.
    Other(u8),
}

impl From<u8> for BlockType {
    fn from(v: u8) -> Self {
        match v {
            0 => BlockType::Unknown,
            1 => BlockType::LossRLE,
            2 => BlockType::DuplicateRLE,
            3 => BlockType::PacketReceiptTimes,
            4 => BlockType::ReceiverReferenceTime,
            5 => BlockType::DLRR,
            6 => BlockType::StatisticsSummary,
            7 => BlockType::VoIPMetrics,
            other => BlockType::Other(other),
        }
    }
}

impl From<BlockType> for u8 {
    fn from(t: BlockType) -> Self {
        match t {
            BlockType::Unknown => 0,
            BlockType::LossRLE => 1,
            BlockType::DuplicateRLE => 2,
            BlockType::PacketReceiptTimes => 3,
            BlockType::ReceiverReferenceTime => 4,
            BlockType::DLRR => 5,
            BlockType::StatisticsSummary => 6,
            BlockType::VoIPMetrics => 7,
            BlockType::Other(other) => other,
        }
    }
}

/// converts the Extended report block types into readable strings
impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            BlockType::LossRLE => "LossRLEReportBlockType",
            BlockType::DuplicateRLE => "DuplicateRLEReportBlockType",
            BlockType::PacketReceiptTimes => "PacketReceiptTimesReportBlockType",
            BlockType::ReceiverReferenceTime => "ReceiverReferenceTimeReportBlockType",
            BlockType::DLRR => "DLRRReportBlockType",
            BlockType::StatisticsSummary => "StatisticsSummaryReportBlockType",
            BlockType::VoIPMetrics => "VoIPMetricsReportBlockType",
            _ => "UnknownReportBlockType",
        };
        write!(f, "{s}")
    }
}

/// TypeSpecificField as described in RFC 3611 section 4.5. In typical
/// cases, users of ExtendedReports shouldn't need to access this,
/// and should instead use the corresponding fields in the actual
/// report blocks themselves.
pub type TypeSpecificField = u8;

/// XRHeader defines the common fields that must appear at the start
/// of each report block. In typical cases, users of ExtendedReports
/// shouldn't need to access this. For locally-constructed report
/// blocks, these values will not be accurate until the corresponding
/// packet is marshaled.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct XRHeader {
    /// Which kind of report block follows.
    pub block_type: BlockType,
    /// Bits whose meaning depends on the block type.
    pub type_specific: TypeSpecificField,
    /// The block's length in 32-bit words, excluding this header.
    pub block_length: u16,
}

impl MarshalSize for XRHeader {
    fn marshal_size(&self) -> usize {
        XR_HEADER_LENGTH
    }
}

impl Marshal for XRHeader {
    /// marshal_to encodes the ExtendedReport in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < XR_HEADER_LENGTH {
            return Err(Error::BufferTooShort);
        }

        buf.put_u8(self.block_type.into());
        buf.put_u8(self.type_specific);
        buf.put_u16(self.block_length);

        Ok(XR_HEADER_LENGTH)
    }
}

impl Unmarshal for XRHeader {
    /// Unmarshal decodes the ExtendedReport from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < XR_HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let block_type: BlockType = raw_packet.get_u8().into();
        let type_specific = raw_packet.get_u8();
        let block_length = raw_packet.get_u16();

        Ok(XRHeader {
            block_type,
            type_specific,
            block_length,
        })
    }
}
/// The ExtendedReport packet is an Implementation of RTCP Extended
/// reports defined in RFC 3611. It is used to convey detailed
/// information about an RTP stream. Each packet contains one or
/// more report blocks, each of which conveys a different kind of
/// information.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|reserved |   PT=XR=207   |             length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ssrc                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                         report blocks                         :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq, Default, Clone)]
pub struct ExtendedReport {
    /// The SSRC of the sender of this extended report.
    pub sender_ssrc: u32,
    /// The report blocks this packet carries.
    pub reports: Vec<Box<dyn Packet>>,
}

impl fmt::Display for ExtendedReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Packet for ExtendedReport {
    /// Header returns the Header associated with this packet.
    fn header(&self) -> Header {
        Header {
            // Every report block is a whole number of 32-bit words (RFC 3611 3).
            padding: false,
            count: 0,
            packet_type: PacketType::ExtendedReport,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of ssrc values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        let mut ssrc = vec![];
        for p in &self.reports {
            ssrc.extend(p.destination_ssrc());
        }
        ssrc
    }

    fn raw_size(&self) -> usize {
        let mut reps_length = 0;
        for rep in &self.reports {
            reps_length += rep.marshal_size();
        }
        HEADER_LENGTH + SSRC_LENGTH + reps_length
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<ExtendedReport>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for ExtendedReport {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for ExtendedReport {
    /// marshal_to encodes the ExtendedReport in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.sender_ssrc);

        for report in &self.reports {
            let n = report.marshal_to(buf)?;
            buf = &mut buf[n..];
        }

        Ok(self.marshal_size())
    }
}

impl ExtendedReport {
    /// Parses one report block, `block` holding exactly that block.
    ///
    /// A block of a type this crate does not model, and a block of a known type that fails its
    /// own parse (a length its type does not allow, a value its type forbids), is kept as an
    /// [`UnknownReportBlock`] with its type and bytes: one such block costs neither the blocks
    /// around it nor the packets around this one (RFC 3611 4: a receiver skips what it cannot
    /// use by the block length).
    fn unmarshal_block(block_type: BlockType, block: Bytes) -> Result<Box<dyn Packet>> {
        let raw_block = &mut block.clone();
        let parsed: Result<Box<dyn Packet>> = match block_type {
            BlockType::LossRLE => {
                LossRLEReportBlock::unmarshal(raw_block).map(|b| Box::new(b) as Box<dyn Packet>)
            }
            BlockType::DuplicateRLE => DuplicateRLEReportBlock::unmarshal(raw_block)
                .map(|b| Box::new(b) as Box<dyn Packet>),
            BlockType::PacketReceiptTimes => PacketReceiptTimesReportBlock::unmarshal(raw_block)
                .map(|b| Box::new(b) as Box<dyn Packet>),
            BlockType::ReceiverReferenceTime => {
                ReceiverReferenceTimeReportBlock::unmarshal(raw_block)
                    .map(|b| Box::new(b) as Box<dyn Packet>)
            }
            BlockType::DLRR => {
                DLRRReportBlock::unmarshal(raw_block).map(|b| Box::new(b) as Box<dyn Packet>)
            }
            BlockType::StatisticsSummary => StatisticsSummaryReportBlock::unmarshal(raw_block)
                .map(|b| Box::new(b) as Box<dyn Packet>),
            BlockType::VoIPMetrics => {
                VoIPMetricsReportBlock::unmarshal(raw_block).map(|b| Box::new(b) as Box<dyn Packet>)
            }
            _ => Err(Error::WrongType),
        };

        match parsed {
            Ok(report) => Ok(report),
            Err(_) => Ok(Box::new(UnknownReportBlock::unmarshal(&mut block.clone())?)),
        }
    }
}

impl Unmarshal for ExtendedReport {
    /// Unmarshal decodes the ExtendedReport from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        // The padding the P bit announces ends the packet before the report blocks do. The
        // five reserved bits that share the first octet are ignored (RFC 3611 2).
        let (header, mut body) = read_packet(raw_packet)?;
        if header.packet_type != PacketType::ExtendedReport {
            return Err(Error::WrongType);
        }
        if body.len() < SSRC_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let sender_ssrc = body.get_u32();

        let mut reports = vec![];
        while body.has_remaining() {
            // Every block says how long it is, whatever its type, and that is what frames it.
            if body.len() < XR_HEADER_LENGTH {
                return Err(Error::PacketTooShort);
            }
            let block_length = u16::from_be_bytes([body[2], body[3]]) as usize * 4;
            if body.len() < XR_HEADER_LENGTH + block_length {
                return Err(Error::PacketTooShort);
            }
            let block_type: BlockType = body[0].into();
            let block = body.split_to(XR_HEADER_LENGTH + block_length);

            reports.push(Self::unmarshal_block(block_type, block)?);
        }

        Ok(ExtendedReport {
            sender_ssrc,
            reports,
        })
    }
}
