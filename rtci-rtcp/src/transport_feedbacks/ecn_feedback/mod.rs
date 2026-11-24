#[cfg(test)]
mod ecn_feedback_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::any::Any;
use std::fmt;

/// The octets of the counters an ECN Feedback Report and an ECN Summary Report data block
/// share (RFC 6679 sections 5.1 and 5.2): ECT(0), ECT(1), ECN-CE, not-ECT, lost, duplicates.
pub const ECN_COUNTERS_LENGTH: usize = 16;
/// The octets of an ECN Feedback Report (RFC 6679 section 5.1, Figure 2): the extended
/// highest sequence number and the counters.
pub const ECN_FEEDBACK_REPORT_LENGTH: usize = 4 + ECN_COUNTERS_LENGTH;

/// The cumulative ECN counters of one RTP source as a receiver keeps them (RFC 6679 section
/// 5.1). The two ECT counters are 32 bits on the wire, the others the 16 least significant bits
/// of the receiver's count ("the field will wrap if more than 65535 ... have been received").
/// "The counters SHALL be initiated to 0 for each new SSRC received."
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct EcnCounters {
    /// RTP packets received with ECT(0).
    pub ect0: u32,
    /// RTP packets received with ECT(1).
    pub ect1: u32,
    /// RTP packets received with ECN-CE, duplicates included.
    pub ce: u16,
    /// RTP packets received not-ECT.
    pub not_ect: u16,
    /// Packets expected minus packets received that are not duplicates; late packets are not
    /// lost.
    pub lost: u16,
    /// Packets received that duplicate one already received.
    pub duplicates: u16,
}

impl EcnCounters {
    pub(crate) fn put(&self, buf: &mut &mut [u8]) {
        buf.put_u32(self.ect0);
        buf.put_u32(self.ect1);
        buf.put_u16(self.ce);
        buf.put_u16(self.not_ect);
        buf.put_u16(self.lost);
        buf.put_u16(self.duplicates);
    }

    pub(crate) fn get<B: Buf>(buf: &mut B) -> Self {
        Self {
            ect0: buf.get_u32(),
            ect1: buf.get_u32(),
            ce: buf.get_u16(),
            not_ect: buf.get_u16(),
            lost: buf.get_u16(),
            duplicates: buf.get_u16(),
        }
    }
}

/// The RTP/AVPF transport-layer ECN Feedback packet (RFC 6679 section 5.1): RTPFB, FMT 8,
/// one ECN Feedback Report about one RTP source. Negotiated with `a=rtcp-fb:<pt> nack ecn`
/// (section 6.2); sent early or immediately when ECN-CE marks or losses need to reach the
/// sender quickly.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|  FMT=8  |  PT=RTPFB=205 |          length               |
/// |                  SSRC of packet sender                        |
/// |                  SSRC of media source                         |
/// | Extended Highest Sequence Number                              |
/// | ECT (0) Counter                                               |
/// | ECT (1) Counter                                               |
/// | ECN-CE Counter                | not-ECT Counter               |
/// | Lost Packets Counter          | Duplication Counter           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct EcnFeedback {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source the report is about.
    pub media_ssrc: u32,
    /// The 32-bit extended highest sequence number received (RFC 3550): the highest
    /// sequence number the report relates to.
    pub extended_highest_sequence_number: u32,
    /// The counters.
    pub counters: EcnCounters,
}

impl fmt::Display for EcnFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EcnFeedback {:x} {:x} {} {:?}",
            self.sender_ssrc, self.media_ssrc, self.extended_highest_sequence_number, self.counters
        )
    }
}

impl Packet for EcnFeedback {
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_ECN,
            packet_type: PacketType::TransportSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.media_ssrc]
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + SSRC_LENGTH * 2 + ECN_FEEDBACK_REPORT_LENGTH
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<EcnFeedback>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for EcnFeedback {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        l + get_padding_size(l)
    }
}

impl Marshal for EcnFeedback {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }
        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];
        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);
        buf.put_u32(self.extended_highest_sequence_number);
        self.counters.put(&mut buf);
        Ok(self.marshal_size())
    }
}

impl Unmarshal for EcnFeedback {
    /// Decodes the packet. Its FCI is one ECN Feedback Report ("Each ECN Feedback Report
    /// corresponds to a single RTP source"): an FCI of another length is refused.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, media_ssrc, mut fci) = read_feedback(
            raw_packet,
            PacketType::TransportSpecificFeedback,
            FORMAT_ECN,
        )?;
        if fci.len() != ECN_FEEDBACK_REPORT_LENGTH {
            return Err(Error::PacketTooShort);
        }
        let extended_highest_sequence_number = fci.get_u32();
        let counters = EcnCounters::get(&mut fci);
        Ok(EcnFeedback {
            sender_ssrc,
            media_ssrc,
            extended_highest_sequence_number,
            counters,
        })
    }
}
