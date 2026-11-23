#[cfg(test)]
mod compound_packet_test;
#[cfg(test)]
mod validation_test;

use crate::{
    header::*, packet::*, receiver_report::*, sender_report::*, source_description::*, util::*,
};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, Bytes};
use std::any::Any;
use std::fmt;

/// A CompoundPacket is a collection of RTCP packets transmitted as a single packet with
/// the underlying protocol (for example UDP).
///
/// To maximize the resolution of receiption statistics, the first Packet in a CompoundPacket
/// must always be either a SenderReport or a ReceiverReport.  This is true even if no data
/// has been sent or received, in which case an empty ReceiverReport must be sent, and even
/// if the only other RTCP packet in the compound packet is a Goodbye.
///
/// Next, a SourceDescription containing a CNAME item must be included in each CompoundPacket
/// to identify the source and to begin associating media for purposes such as lip-sync.
///
/// Other RTCP packet types may follow in any order. Packet types may appear more than once.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct CompoundPacket(pub Vec<Box<dyn Packet>>);

impl fmt::Display for CompoundPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Packet for CompoundPacket {
    fn header(&self) -> Header {
        Header::default()
    }

    /// destination_ssrc returns the synchronization sources associated with this
    /// CompoundPacket's reception report.
    fn destination_ssrc(&self) -> Vec<u32> {
        if self.0.is_empty() {
            vec![]
        } else {
            self.0[0].destination_ssrc()
        }
    }

    fn raw_size(&self) -> usize {
        let mut l = 0;
        for packet in &self.0 {
            l += packet.marshal_size();
        }
        l
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<CompoundPacket>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for CompoundPacket {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for CompoundPacket {
    /// Marshal encodes the CompoundPacket as binary.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        self.validate()?;

        for packet in &self.0 {
            let n = packet.marshal_to(buf)?;
            buf = &mut buf[n..];
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for CompoundPacket {
    /// Reads a datagram as the compound packet RFC 3550 defines, and nothing less: the header
    /// checks of Appendix A.2 ([`validate_compound`]), then every packet, then the rules of
    /// §6.1 ([`CompoundPacket::validate`]). A reduced-size datagram (RFC 5506) fails here; read
    /// one with [`crate::packet::unmarshal`].
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let mut raw = raw_packet.copy_to_bytes(raw_packet.remaining());
        validate_headers(&raw, Datagram::Compound)?;

        let mut packets = vec![];
        while raw.has_remaining() {
            let p = unmarshaller(&mut raw)?;
            packets.push(p);
        }

        let c = CompoundPacket(packets);
        c.validate()?;

        Ok(c)
    }
}

/// The two kinds of RTCP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Datagram {
    /// A compound packet, RFC 3550 §6.1.
    Compound,
    /// A reduced-size packet, RFC 5506 §4.1.
    ReducedSize,
}

/// Walks the headers of the packets in a datagram without parsing what they carry.
fn validate_headers(raw: &[u8], kind: Datagram) -> Result<()> {
    if raw.is_empty() {
        return Err(Error::EmptyCompound);
    }

    let mut rest = raw;
    let mut first = true;
    while !rest.is_empty() {
        // "The length fields of the individual RTCP packets must add up to the overall length
        // of the compound RTCP packet as received."
        if rest.len() < HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }
        // "RTP version field must equal 2", on every packet (the loop of the A.2 code).
        if (rest[0] >> VERSION_SHIFT) & VERSION_MASK != RTP_VERSION {
            return Err(Error::BadVersion);
        }
        let padding = (rest[0] >> PADDING_SHIFT) & PADDING_MASK != 0;
        let packet_type = rest[1];
        let length = u16::from_be_bytes([rest[2], rest[3]]) as usize * 4;
        if rest.len() < HEADER_LENGTH + length {
            return Err(Error::PacketTooShort);
        }
        let last = rest.len() == HEADER_LENGTH + length;

        if first {
            match kind {
                // "The payload type field of the first RTCP packet in a compound packet must
                // be equal to SR or RR."
                Datagram::Compound => {
                    if packet_type != u8::from(PacketType::SenderReport)
                        && packet_type != u8::from(PacketType::ReceiverReport)
                    {
                        return Err(Error::BadFirstPacket);
                    }
                    // "The padding bit (P) should be zero for the first packet of a compound
                    // RTCP packet", also when it is the only one.
                    if padding {
                        return Err(Error::WrongPadding);
                    }
                }
                // RFC 5506 3.4.2: any RTCP packet type may come first, which leaves little to
                // tell RTCP from anything else; "the best possible validation" left is that
                // the type is one RTCP can have next to RTP (RFC 5761 4).
                Datagram::ReducedSize => {
                    if !(192..=223).contains(&packet_type) {
                        return Err(Error::BadFirstPacket);
                    }
                }
            }
        }

        // RFC 3550 6.4.1: "padding MUST only be added to the last individual packet, and if
        // padding is added to that packet, the padding bit MUST be set only on that packet."
        if padding {
            if !last {
                return Err(Error::WrongPadding);
            }
            // The last octet counts the padding octets, itself included.
            let count = rest[HEADER_LENGTH + length - 1] as usize;
            if count == 0 || count > length {
                return Err(Error::WrongPadding);
            }
        }

        rest = &rest[HEADER_LENGTH + length..];
        first = false;
    }

    Ok(())
}

/// Checks that `raw`, one datagram, is a compound RTCP packet as RFC 3550 defines it.
///
/// Appendix A.2: every packet is version 2, the first is an SR or an RR with the padding bit
/// clear, and the lengths add up to the datagram. §6.4.1: only the last packet is padded.
/// §6.1: an SDES packet with a CNAME follows the reports.
///
/// A receiver that negotiated reduced-size RTCP (RFC 5506) does not apply this to what it
/// receives: see [`validate_reduced_size`].
pub fn validate_compound(raw: &[u8]) -> Result<()> {
    CompoundPacket::unmarshal(&mut &raw[..]).map(|_| ())
}

/// The header checks of RFC 3550 Appendix A.2 on `raw`, one datagram, as a compound packet:
/// every packet is version 2, the first is an SR or an RR with the padding bit clear, the
/// lengths add up to the datagram, and only the last packet is padded (section 6.4.1).
///
/// Unlike [`validate_compound`] it does not parse what the packets carry, so a packet of an
/// unknown type or one that does not parse is left to the caller (RFC 3550 section 6.1: such a
/// packet is ignored, the others processed).
pub fn validate_compound_headers(raw: &[u8]) -> Result<()> {
    validate_headers(raw, Datagram::Compound)
}

/// Checks that `raw`, one datagram, is acceptable as reduced-size RTCP (RFC 5506 §4.1): one
/// or more RTCP packets of any type, with no SR or RR in front and no SDES required.
///
/// What is left of the checks of RFC 3550 Appendix A.2 (RFC 5506 §3.4.2): every packet is
/// version 2, the lengths add up to the datagram, only the last packet is padded, and the
/// first packet's type is in the RTCP range 192 to 223. A compound packet passes too.
pub fn validate_reduced_size(raw: &[u8]) -> Result<()> {
    validate_headers(raw, Datagram::ReducedSize)
}

impl CompoundPacket {
    /// Validate returns an error if this is not an RFC-compliant CompoundPacket.
    pub fn validate(&self) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::EmptyCompound);
        }

        // SenderReport and ReceiverReport are the only types that
        // are allowed to be the first packet in a compound datagram
        if self.0[0].as_any().downcast_ref::<SenderReport>().is_none()
            && self.0[0]
                .as_any()
                .downcast_ref::<ReceiverReport>()
                .is_none()
        {
            return Err(Error::BadFirstPacket);
        }

        // RFC 3550 6.4.1: only the last packet of a compound packet is padded.
        if let Some((_, all_but_last)) = self.0.split_last()
            && all_but_last.iter().any(|pkt| pkt.header().padding)
        {
            return Err(Error::WrongPadding);
        }

        for pkt in &self.0[1..] {
            // If the number of RRs exceeds 31 additional ReceiverReports
            // can be included here.
            if pkt.as_any().downcast_ref::<ReceiverReport>().is_some() {
                continue;
            // A SourceDescription containing a CNAME must be included in every
            // CompoundPacket.
            } else if let Some(e) = pkt.as_any().downcast_ref::<SourceDescription>() {
                let mut has_cname = false;
                for c in &e.chunks {
                    for it in &c.items {
                        if it.sdes_type == SdesType::SdesCname {
                            has_cname = true
                        }
                    }
                }

                if !has_cname {
                    return Err(Error::MissingCname);
                }

                return Ok(());

            // Other packets are not permitted before the CNAME
            } else {
                return Err(Error::PacketBeforeCname);
            }
        }

        // CNAME never reached
        Err(Error::MissingCname)
    }

    /// CNAME returns the CNAME that *must* be present in every CompoundPacket
    pub fn cname(&self) -> Result<Bytes> {
        if self.0.is_empty() {
            return Err(Error::EmptyCompound);
        }

        for pkt in &self.0[1..] {
            if let Some(sdes) = pkt.as_any().downcast_ref::<SourceDescription>() {
                for c in &sdes.chunks {
                    for it in &c.items {
                        if it.sdes_type == SdesType::SdesCname {
                            return Ok(it.text.clone());
                        }
                    }
                }
            } else if pkt.as_any().downcast_ref::<ReceiverReport>().is_none() {
                return Err(Error::PacketBeforeCname);
            }
        }

        Err(Error::MissingCname)
    }
}
