#[cfg(test)]
mod full_intra_request_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::any::Any;
use std::fmt;

/// A FIREntry is a (ssrc, seqno) pair, as carried by FullIntraRequest.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct FirEntry {
    /// The SSRC being asked for an intra frame.
    pub ssrc: u32,
    /// A counter incremented per request, so a sender can ignore retransmitted duplicates.
    pub sequence_number: u8,
}

/// The FullIntraRequest packet is used to reliably request an Intra frame
/// in a video stream.  See RFC 5104 Section 3.5.1.  This is not for loss
/// recovery, which should use PictureLossIndication (PLI) instead.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct FullIntraRequest {
    /// The SSRC of the requesting receiver.
    pub sender_ssrc: u32,
    /// The "SSRC of media source" of the feedback header, as a peer wrote it. RFC 5104 §4.3.1.2
    /// does not use the field and has it sent as 0, so it is written as 0 whatever is here; the
    /// sources the request is for are the entries of `fir`.
    pub media_ssrc: u32,
    /// One entry per SSRC an intra frame is requested from.
    pub fir: Vec<FirEntry>,
}

const FIR_OFFSET: usize = 8;
const FIR_ENTRY_LENGTH: usize = 8;

impl fmt::Display for FullIntraRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = format!("FullIntraRequest {} {}", self.sender_ssrc, self.media_ssrc);
        for e in &self.fir {
            out += format!(" ({} {})", e.ssrc, e.sequence_number).as_str();
        }
        write!(f, "{out}")
    }
}

impl Packet for FullIntraRequest {
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_FIR,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of SSRC values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        let mut ssrcs: Vec<u32> = Vec::with_capacity(self.fir.len());
        for entry in &self.fir {
            ssrcs.push(entry.ssrc);
        }
        ssrcs
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + FIR_OFFSET + self.fir.len() * 8
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<FullIntraRequest>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for FullIntraRequest {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for FullIntraRequest {
    /// Marshal encodes the FullIntraRequest
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        // RFC 5104 4.3.1.1: "The FCI field MUST contain one or more FIR entries."
        if self.fir.is_empty() {
            return Err(Error::PacketTooShort);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = header_for(
            PacketType::PayloadSpecificFeedback,
            FORMAT_FIR,
            self.raw_size(),
        )?;
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.sender_ssrc);
        // RFC 5104 4.3.1.2: the "SSRC of media source" is not used and SHALL be set to 0; the
        // sources the request is for are in the FCI.
        buf.put_u32(0);

        for fir in self.fir.iter() {
            buf.put_u32(fir.ssrc);
            buf.put_u8(fir.sequence_number);
            buf.put_u8(0);
            buf.put_u16(0);
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for FullIntraRequest {
    /// Unmarshal decodes the FullIntraRequest
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < FIR_MIN_OCTET_COUNT {
            return Err(Error::PacketTooShort);
        }

        let (sender_ssrc, media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_FIR)?;
        // RFC 5104 4.3.1.1: one or more entries, the length being 2 + 2 * N.
        if fci.is_empty() {
            return Err(Error::PacketTooShort);
        }
        if !fci.len().is_multiple_of(FIR_ENTRY_LENGTH) {
            return Err(Error::InvalidHeader);
        }

        let mut fir = Vec::with_capacity(fci.len() / FIR_ENTRY_LENGTH);
        while fci.has_remaining() {
            fir.push(FirEntry {
                ssrc: fci.get_u32(),
                sequence_number: fci.get_u8(),
            });
            // 24 reserved bits, ignored on reception.
            fci.advance(3);
        }

        Ok(FullIntraRequest {
            sender_ssrc,
            media_ssrc,
            fir,
        })
    }
}
