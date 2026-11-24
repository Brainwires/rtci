use super::*;
use crate::transport_feedbacks::ecn_feedback::{ECN_COUNTERS_LENGTH, EcnCounters};

/// One ECN Summary Report data block: an SSRC and its counters (RFC 6679 section 5.2,
/// Figure 4), five 32-bit words.
const ECN_SUMMARY_ENTRY_LENGTH: usize = SSRC_LENGTH + ECN_COUNTERS_LENGTH;

/// The counters of one media sender in an [`EcnSummaryReportBlock`].
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct EcnSummaryReport {
    /// The media sender the counters are about.
    pub ssrc: u32,
    /// Its cumulative counters, as in the ECN Feedback Report.
    pub counters: EcnCounters,
}

/// The RTCP XR ECN Summary Report block (RFC 6679 section 5.2): BT 13, one data block per
/// media sender. Negotiated with `a=rtcp-xr:ecn-sum` (section 6.3); an ECN-capable receiver
/// includes one in every regular compound RTCP packet (section 7.3.2), with no data block
/// when no SSRC counts as a sender (block length zero).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     BT=13     | Reserved      |         Block Length          |
/// | SSRC of Media Sender                                          |
/// | ECT (0) Counter                                               |
/// | ECT (1) Counter                                               |
/// | ECN-CE Counter                | not-ECT Counter               |
/// | Lost Packets Counter          | Duplication Counter           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct EcnSummaryReportBlock {
    /// One entry per media sender.
    pub reports: Vec<EcnSummaryReport>,
}

impl fmt::Display for EcnSummaryReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl EcnSummaryReportBlock {
    /// The XR block header: "Reserved: All bits SHALL be set to 0 on transmission"; the
    /// length is 5 × the number of data blocks.
    pub fn xr_header(&self) -> XRHeader {
        XRHeader {
            block_type: BlockType::EcnSummary,
            type_specific: 0,
            block_length: (self.raw_size() / 4 - 1) as u16,
        }
    }
}

impl Packet for EcnSummaryReportBlock {
    fn header(&self) -> Header {
        Header::default()
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        self.reports.iter().map(|r| r.ssrc).collect()
    }

    fn raw_size(&self) -> usize {
        XR_HEADER_LENGTH + self.reports.len() * ECN_SUMMARY_ENTRY_LENGTH
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<EcnSummaryReportBlock>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for EcnSummaryReportBlock {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for EcnSummaryReportBlock {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }
        if self.raw_size() / 4 - 1 > usize::from(u16::MAX) {
            return Err(Error::InvalidBlockSize);
        }
        let h = self.xr_header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];
        for report in &self.reports {
            buf.put_u32(report.ssrc);
            report.counters.put(&mut buf);
        }
        Ok(self.marshal_size())
    }
}

impl Unmarshal for EcnSummaryReportBlock {
    /// Decodes the block. "Receivers MUST discard reports where the block length is not a
    /// multiple of five, since these cannot be valid": such a block is refused (and kept as
    /// an unknown block by [`ExtendedReport`]); the reserved octet is ignored.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let xr_header = XRHeader::unmarshal(raw_packet)?;
        if xr_header.block_type != BlockType::EcnSummary {
            return Err(Error::WrongType);
        }
        if !xr_header.block_length.is_multiple_of(5) {
            return Err(Error::InvalidBlockSize);
        }
        let length = usize::from(xr_header.block_length) * 4;
        if raw_packet.remaining() < length {
            return Err(Error::PacketTooShort);
        }
        let mut reports = Vec::with_capacity(length / ECN_SUMMARY_ENTRY_LENGTH);
        for _ in 0..length / ECN_SUMMARY_ENTRY_LENGTH {
            let ssrc = raw_packet.get_u32();
            let counters = EcnCounters::get(raw_packet);
            reports.push(EcnSummaryReport { ssrc, counters });
        }
        Ok(EcnSummaryReportBlock { reports })
    }
}
