#[cfg(test)]
mod slice_loss_indication_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::any::Any;
use std::fmt;

const SLI_LENGTH: usize = 2;
const SLI_OFFSET: usize = 8;

/// SLIEntry represents a single entry to the SLI packet's
/// list of lost slices.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct SliEntry {
    /// ID of first lost slice
    pub first: u16,
    /// Number of lost slices
    pub number: u16,
    /// ID of related picture
    pub picture: u8,
}

/// The SliceLossIndication packet informs the encoder about the loss of a picture slice
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct SliceLossIndication {
    /// SSRC of sender
    pub sender_ssrc: u32,
    /// SSRC of the media source
    pub media_ssrc: u32,

    /// The lost slices being reported.
    pub sli_entries: Vec<SliEntry>,
}

impl SliceLossIndication {
    /// An SLI for a VP8 frame (RFC 7741 section 5.2) that the receiver cannot say more of: the
    /// whole frame lost ("First ... 0, and the Number parameter to the total number of
    /// macroblocks per frame", for a frame of `width` by `height` pixels in 16 by 16
    /// macroblocks), in the picture whose VP8 PictureID is `picture_id`; a receiver whose
    /// current frame had none passes the last PictureID received plus one. The entry carries
    /// the six least significant bits. Number is cut to its 13 bits.
    pub fn vp8_frame(
        sender_ssrc: u32,
        media_ssrc: u32,
        picture_id: u16,
        width: u16,
        height: u16,
    ) -> Self {
        let macroblocks = u32::from(width).div_ceil(16) * u32::from(height).div_ceil(16);
        Self {
            sender_ssrc,
            media_ssrc,
            sli_entries: vec![SliEntry {
                first: 0,
                number: macroblocks.min(0x1fff) as u16,
                picture: (picture_id & 0x3f) as u8,
            }],
        }
    }
}

impl fmt::Display for SliceLossIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SliceLossIndication {:x} {:x} {:?}",
            self.sender_ssrc, self.media_ssrc, self.sli_entries,
        )
    }
}

impl Packet for SliceLossIndication {
    /// Header returns the Header associated with this packet.
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_SLI,
            // RFC 4585 §6.3.2: SLI is payload-specific feedback (PT=PSFB, FMT=2).
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of SSRC values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.media_ssrc]
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + SLI_OFFSET + self.sli_entries.len() * 4
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<SliceLossIndication>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for SliceLossIndication {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for SliceLossIndication {
    /// Marshal encodes the SliceLossIndication in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        // RFC 4585 6.3.2: "The FCI field MUST contain at least one SLI."
        if self.sli_entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        // The length field counts 32-bit words in 16 bits.
        if self.sli_entries.len() + SLI_LENGTH > u16::MAX as usize {
            return Err(Error::TooManyReports);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(self.media_ssrc);

        for s in &self.sli_entries {
            let sli = ((s.first as u32 & 0x1FFF) << 19)
                | ((s.number as u32 & 0x1FFF) << 6)
                | (s.picture as u32 & 0x3F);

            buf.put_u32(sli);
        }

        if h.padding {
            put_padding(buf, self.raw_size());
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for SliceLossIndication {
    /// Unmarshal decodes the SliceLossIndication from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_SLI)?;
        // RFC 4585 6.3.2: "The FCI field MUST contain at least one SLI."
        if fci.is_empty() {
            return Err(Error::PacketTooShort);
        }
        if !fci.len().is_multiple_of(4) {
            return Err(Error::WrongPadding);
        }

        let mut sli_entries = Vec::with_capacity(fci.len() / 4);
        while fci.has_remaining() {
            let sli = fci.get_u32();
            sli_entries.push(SliEntry {
                first: ((sli >> 19) & 0x1FFF) as u16,
                number: ((sli >> 6) & 0x1FFF) as u16,
                picture: (sli & 0x3F) as u8,
            });
        }

        Ok(SliceLossIndication {
            sender_ssrc,
            media_ssrc,
            sli_entries,
        })
    }
}
