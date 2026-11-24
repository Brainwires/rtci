#[cfg(test)]
mod pause_resume_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::any::Any;
use std::fmt;

/// The octets of an FCI entry before its type-specific field: the target SSRC, then the type,
/// the reserved bits, the parameter length and the PauseID (RFC 7728 section 7, Figure 6).
pub const PAUSE_RESUME_ENTRY_HEADER_LENGTH: usize = 8;

/// The pause feedback type of an FCI entry (RFC 7728 section 7, "Type (4 bits)").
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PauseResumeType {
    /// 0: PAUSE request.
    Pause,
    /// 1: RESUME request.
    Resume,
    /// 2: PAUSED indication.
    Paused,
    /// 3: REFUSED notification.
    Refused,
    /// 4 to 15: reserved. "FCI fields with these Type values SHALL be ignored on reception by
    /// receivers and MUST NOT be used by senders implementing this specification": decoded so
    /// that a packet carrying one still parses, and never written by the engine.
    Reserved(u8),
}

impl PauseResumeType {
    fn value(self) -> u8 {
        match self {
            Self::Pause => 0,
            Self::Resume => 1,
            Self::Paused => 2,
            Self::Refused => 3,
            Self::Reserved(value) => value & 0x0f,
        }
    }

    fn from_value(value: u8) -> Self {
        match value & 0x0f {
            0 => Self::Pause,
            1 => Self::Resume,
            2 => Self::Paused,
            3 => Self::Refused,
            other => Self::Reserved(other),
        }
    }
}

/// One FCI entry of a PAUSE-RESUME message (RFC 7728 section 7, Figure 6).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Target SSRC                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type  |  Res  | Parameter Len |           PauseID             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                         Type Specific                         :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PauseResumeEntry {
    /// The SSRC the request is for, or the one paused (PAUSED), or the target of the refused
    /// request (REFUSED).
    pub target_ssrc: u32,
    /// The pause feedback type.
    pub typ: PauseResumeType,
    /// The message sequence identification, scoped by the target SSRC (section 5.2).
    pub pause_id: u16,
    /// The type-specific field, a whole number of 32-bit words. PAUSED carries the extended
    /// sequence number of the last RTP packet sent before the pause in its first word
    /// (section 8.2; [`PauseResumeEntry::paused_extended_sequence_number`]); the others none.
    /// Unknown data is kept, so that it can be skipped and ignored ("A receiver ... MUST be
    /// able to skip and ignore any unknown Type Specific data").
    pub type_specific: Bytes,
}

impl PauseResumeEntry {
    /// A PAUSE request for `target_ssrc`.
    pub fn pause(target_ssrc: u32, pause_id: u16) -> Self {
        Self::without_parameters(target_ssrc, PauseResumeType::Pause, pause_id)
    }

    /// A RESUME request for `target_ssrc`.
    pub fn resume(target_ssrc: u32, pause_id: u16) -> Self {
        Self::without_parameters(target_ssrc, PauseResumeType::Resume, pause_id)
    }

    /// A REFUSED notification for `target_ssrc`.
    pub fn refused(target_ssrc: u32, pause_id: u16) -> Self {
        Self::without_parameters(target_ssrc, PauseResumeType::Refused, pause_id)
    }

    /// A PAUSED indication for `target_ssrc`, with the extended RTP sequence number of the
    /// last packet sent before the pause (section 8.2: "SHALL contain a fixed-length 32-bit
    /// parameter at the start of the Type Specific field").
    pub fn paused(target_ssrc: u32, pause_id: u16, extended_sequence_number: u32) -> Self {
        Self {
            target_ssrc,
            typ: PauseResumeType::Paused,
            pause_id,
            type_specific: Bytes::copy_from_slice(&extended_sequence_number.to_be_bytes()),
        }
    }

    fn without_parameters(target_ssrc: u32, typ: PauseResumeType, pause_id: u16) -> Self {
        Self {
            target_ssrc,
            typ,
            pause_id,
            type_specific: Bytes::new(),
        }
    }

    /// The extended sequence number a PAUSED indication carries; `None` for another type or
    /// a PAUSED without its parameter.
    pub fn paused_extended_sequence_number(&self) -> Option<u32> {
        if self.typ != PauseResumeType::Paused || self.type_specific.len() < 4 {
            return None;
        }
        let b = &self.type_specific;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn size(&self) -> usize {
        PAUSE_RESUME_ENTRY_HEADER_LENGTH + self.type_specific.len()
    }
}

/// The RTP/AVPF transport-layer PAUSE-RESUME message (RFC 7728 section 7): RTPFB, FMT 9,
/// one or more PAUSE, RESUME, PAUSED or REFUSED entries. "SSRC of media source: Not used;
/// SHALL be set to 0. The FCI identifies the SSRC the message is targeted for." Negotiated
/// with `a=rtcp-fb:<pt> ccm pause` (section 9).
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct PauseResume {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// The entries, in order.
    pub entries: Vec<PauseResumeEntry>,
}

impl fmt::Display for PauseResume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PauseResume from {:x}", self.sender_ssrc)?;
        for entry in &self.entries {
            write!(
                f,
                " {:?} {:x} id {}",
                entry.typ, entry.target_ssrc, entry.pause_id
            )?;
        }
        Ok(())
    }
}

impl Packet for PauseResume {
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_PAUSE_RESUME,
            packet_type: PacketType::TransportSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        let mut ssrcs: Vec<u32> = vec![];
        for entry in &self.entries {
            if !ssrcs.contains(&entry.target_ssrc) {
                ssrcs.push(entry.target_ssrc);
            }
        }
        ssrcs
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH
            + SSRC_LENGTH * 2
            + self
                .entries
                .iter()
                .map(PauseResumeEntry::size)
                .sum::<usize>()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<PauseResume>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for PauseResume {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        l + get_padding_size(l)
    }
}

impl Marshal for PauseResume {
    /// Writes the message. An entry whose type-specific field is not a whole number of
    /// 32-bit words, or longer than 255 words, cannot be described by its Parameter Len and
    /// is refused; so is a reserved type ("MUST NOT be used by senders").
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }
        for entry in &self.entries {
            if !entry.type_specific.len().is_multiple_of(4) || entry.type_specific.len() / 4 > 255 {
                return Err(Error::WrongMarshalSize);
            }
            if matches!(entry.typ, PauseResumeType::Reserved(_)) {
                return Err(Error::WrongType);
            }
        }
        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];
        buf.put_u32(self.sender_ssrc);
        // "SSRC of media source: Not used; SHALL be set to 0."
        buf.put_u32(0);
        for entry in &self.entries {
            buf.put_u32(entry.target_ssrc);
            // "Res: ... MUST be set to 0 by senders".
            buf.put_u8(entry.typ.value() << 4);
            buf.put_u8((entry.type_specific.len() / 4) as u8);
            buf.put_u16(entry.pause_id);
            buf.put_slice(&entry.type_specific);
        }
        Ok(self.marshal_size())
    }
}

impl Unmarshal for PauseResume {
    /// Decodes the message: the media source SSRC is ignored (it is "not used"), the
    /// reserved bits of each entry too, and each entry's type-specific field is taken by its
    /// Parameter Len whatever its type. An FCI that ends inside an entry is refused.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, _media_ssrc, mut fci) = read_feedback(
            raw_packet,
            PacketType::TransportSpecificFeedback,
            FORMAT_PAUSE_RESUME,
        )?;
        let mut entries = vec![];
        while fci.has_remaining() {
            if fci.remaining() < PAUSE_RESUME_ENTRY_HEADER_LENGTH {
                return Err(Error::PacketTooShort);
            }
            let target_ssrc = fci.get_u32();
            let typ = PauseResumeType::from_value(fci.get_u8() >> 4);
            let words = usize::from(fci.get_u8());
            let pause_id = fci.get_u16();
            if fci.remaining() < words * 4 {
                return Err(Error::PacketTooShort);
            }
            let type_specific = fci.copy_to_bytes(words * 4);
            entries.push(PauseResumeEntry {
                target_ssrc,
                typ,
                pause_id,
                type_specific,
            });
        }
        if entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        Ok(PauseResume {
            sender_ssrc,
            entries,
        })
    }
}
