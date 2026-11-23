//! The RTCP header.
//!
//! Four bytes on every packet: version and padding flags, a 5-bit count whose meaning depends on
//! the packet type, the [`PacketType`](crate::header::PacketType) itself, and a length in 32-bit words. The `*_SHIFT` and
//! `*_MASK` constants describe how the flags pack into the first octet.
//!
//! The length field is why RTCP is compound: several packets can be concatenated in one
//! datagram and walked by stepping over each header's length.
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};

/// PacketType specifies the type of an RTCP packet
/// RTCP packet types registered with IANA. See: <https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4>
///
/// The enum converts to and from the type octet with `u8::from` / `PacketType::from`; a value
/// this crate does not model is kept in [`PacketType::Other`], so a packet of an unknown type
/// is written back with the type it arrived with.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketType {
    #[default]
    /// No packet type: the type octet 0, and the value of a default header.
    Unsupported,
    /// Sender Report ([RFC 3550] §6.4.1): a sender's timing and packet counts.
    SenderReport, // 200, RFC 3550, 6.4.1
    /// Receiver Report ([RFC 3550] §6.4.2): reception quality from a receiver.
    ReceiverReport, // 201, RFC 3550, 6.4.2
    /// Source Description ([RFC 3550] §6.5): CNAME and other source metadata.
    SourceDescription, // 202, RFC 3550, 6.5
    /// BYE ([RFC 3550] §6.6): the source is leaving the session.
    Goodbye, // 203, RFC 3550, 6.6
    /// APP ([RFC 3550] §6.7): application-defined data.
    ApplicationDefined, // 204, RFC 3550, 6.7
    /// Transport-layer feedback ([RFC 4585]): NACK, TMMBR, TMMBN, transport-wide CC, CCFB.
    TransportSpecificFeedback, // 205, RFC 4585, 6.2
    /// Payload-specific feedback ([RFC 4585] §6.3): PLI, SLI, RPSI, FIR, TSTR, TSTN, VBCM, LRR,
    /// application-layer feedback (REMB).
    PayloadSpecificFeedback, // 206, RFC 4585, 6.3
    /// Extended Report ([RFC 3611]).
    ExtendedReport, // 207, RFC 3611
    /// A packet type this crate does not model, with its type octet.
    Other(u8),
}

// Transport and payload specific feedback messages overload the count field to act as a
// message type (FMT). Those are listed here.

/// FMT of the Slice Loss Indication (PSFB, RFC 4585 §6.3.2).
pub const FORMAT_SLI: u8 = 2;
/// FMT of the Picture Loss Indication (PSFB, RFC 4585 §6.3.1).
pub const FORMAT_PLI: u8 = 1;
/// FMT of the Reference Picture Selection Indication (PSFB, RFC 4585 §6.3.3).
pub const FORMAT_RPSI: u8 = 3;
/// FMT of the Full Intra Request (PSFB, RFC 5104 §4.3.1).
pub const FORMAT_FIR: u8 = 4;
/// FMT of the Temporal-Spatial Trade-off Request (PSFB, RFC 5104 §4.3.2).
pub const FORMAT_TSTR: u8 = 5;
/// FMT of the Temporal-Spatial Trade-off Notification (PSFB, RFC 5104 §4.3.3).
pub const FORMAT_TSTN: u8 = 6;
/// FMT of the Video Back Channel Message (PSFB, RFC 5104 §4.3.4).
pub const FORMAT_VBCM: u8 = 7;
/// FMT of the Layer Refresh Request (PSFB, RFC 9627 §3).
pub const FORMAT_LRR: u8 = 10;
/// FMT of application-layer feedback (PSFB, RFC 4585 §6.4), which REMB is one kind of.
pub const FORMAT_AFB: u8 = 15;
/// FMT of the generic NACK (RTPFB, RFC 4585 §6.2.1).
pub const FORMAT_TLN: u8 = 1;
/// FMT of the Temporary Maximum Media Stream Bit Rate Request (RTPFB, RFC 5104 §4.2.1).
pub const FORMAT_TMMBR: u8 = 3;
/// FMT of the Temporary Maximum Media Stream Bit Rate Notification (RTPFB, RFC 5104 §4.2.2).
pub const FORMAT_TMMBN: u8 = 4;
/// FMT of the Rapid Resynchronisation Request (RTPFB, RFC 6051 §3.2).
pub const FORMAT_RRR: u8 = 5;
/// FMT of REMB: application-layer feedback whose payload starts with `REMB`.
pub const FORMAT_REMB: u8 = 15;
/// FMT of transport-wide congestion control feedback (RTPFB).
/// <https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#page-5>
pub const FORMAT_TCC: u8 = 15;
/// FMT value for CCFB (Congestion Control Feedback) per RFC 8888
pub const FORMAT_CCFB: u8 = 11;
/// FMT value for the RTCP ECN Feedback packet (RFC 6679 section 5.1)
pub const FORMAT_ECN: u8 = 8;

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PacketType::Unsupported => "Unsupported",
            PacketType::Other(pt) => return write!(f, "PT{pt}"),
            PacketType::SenderReport => "SR",
            PacketType::ReceiverReport => "RR",
            PacketType::SourceDescription => "SDES",
            PacketType::Goodbye => "BYE",
            PacketType::ApplicationDefined => "APP",
            PacketType::TransportSpecificFeedback => "TSFB",
            PacketType::PayloadSpecificFeedback => "PSFB",
            PacketType::ExtendedReport => "XR",
        };
        write!(f, "{s}")
    }
}

impl From<u8> for PacketType {
    fn from(b: u8) -> Self {
        match b {
            0 => PacketType::Unsupported,
            200 => PacketType::SenderReport,       // RFC 3550, 6.4.1
            201 => PacketType::ReceiverReport,     // RFC 3550, 6.4.2
            202 => PacketType::SourceDescription,  // RFC 3550, 6.5
            203 => PacketType::Goodbye,            // RFC 3550, 6.6
            204 => PacketType::ApplicationDefined, // RFC 3550, 6.7
            205 => PacketType::TransportSpecificFeedback, // RFC 4585, 6.2
            206 => PacketType::PayloadSpecificFeedback, // RFC 4585, 6.3
            207 => PacketType::ExtendedReport,     // RFC 3611
            other => PacketType::Other(other),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(t: PacketType) -> Self {
        match t {
            PacketType::Unsupported => 0,
            PacketType::SenderReport => 200,
            PacketType::ReceiverReport => 201,
            PacketType::SourceDescription => 202,
            PacketType::Goodbye => 203,
            PacketType::ApplicationDefined => 204,
            PacketType::TransportSpecificFeedback => 205,
            PacketType::PayloadSpecificFeedback => 206,
            PacketType::ExtendedReport => 207,
            PacketType::Other(other) => other,
        }
    }
}

/// The RTP/RTCP version this crate speaks.
pub const RTP_VERSION: u8 = 2;
/// Bit offset of the version field in the first header octet.
pub const VERSION_SHIFT: u8 = 6;
/// Bit mask of the version field once shifted.
pub const VERSION_MASK: u8 = 0x3;
/// Bit offset of the padding flag.
pub const PADDING_SHIFT: u8 = 5;
/// Bit mask of the padding flag once shifted.
pub const PADDING_MASK: u8 = 0x1;
/// Bit offset of the report/source count field.
pub const COUNT_SHIFT: u8 = 0;
/// Bit mask of the report/source count field.
pub const COUNT_MASK: u8 = 0x1f;

/// Length of the RTCP header in bytes.
pub const HEADER_LENGTH: usize = 4;
/// The largest report count the 5-bit field can hold.
pub const COUNT_MAX: usize = (1 << 5) - 1;
/// Length of an SSRC in bytes.
pub const SSRC_LENGTH: usize = 4;
/// The longest SDES item value, bounded by its one-byte length field.
pub const SDES_MAX_OCTET_COUNT: usize = (1 << 8) - 1;

// https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.1
//
// The FCI field MUST contain one or more FIR entries.
//
// https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.1.1
//
// The length of the FIR feedback message MUST be set to
//    2+2*N, where N is the number of FCI entries.
/// The smallest valid FIR packet, in bytes.
pub const FIR_MIN_OCTET_COUNT: usize = 20;

/// A Header is the common header shared by all RTCP packets
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Header {
    /// If the padding bit is set, this individual RTCP packet contains
    /// some additional padding octets at the end which are not part of
    /// the control information but are included in the length field.
    pub padding: bool,
    /// The number of reception reports, sources contained or FMT in this packet (depending on the Type)
    pub count: u8,
    /// The RTCP packet type for this packet
    pub packet_type: PacketType,
    /// The length of this RTCP packet in 32-bit words minus one,
    /// including the header and any padding.
    pub length: u16,
}

/// Marshal encodes the Header in binary
impl MarshalSize for Header {
    fn marshal_size(&self) -> usize {
        HEADER_LENGTH
    }
}

impl Marshal for Header {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.count > 31 {
            return Err(Error::InvalidHeader);
        }
        if buf.remaining_mut() < HEADER_LENGTH {
            return Err(Error::BufferTooShort);
        }

        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|    RC   |   PT=SR=200   |             length            |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let b0 = (RTP_VERSION << VERSION_SHIFT)
            | ((self.padding as u8) << PADDING_SHIFT)
            | (self.count << COUNT_SHIFT);

        buf.put_u8(b0);
        buf.put_u8(self.packet_type.into());
        buf.put_u16(self.length);

        Ok(HEADER_LENGTH)
    }
}

impl Unmarshal for Header {
    /// Unmarshal decodes the Header from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|    RC   |      PT       |             length            |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let b0 = raw_packet.get_u8();
        let version = (b0 >> VERSION_SHIFT) & VERSION_MASK;
        if version != RTP_VERSION {
            return Err(Error::BadVersion);
        }

        let padding = ((b0 >> PADDING_SHIFT) & PADDING_MASK) > 0;
        let count = (b0 >> COUNT_SHIFT) & COUNT_MASK;
        let packet_type = PacketType::from(raw_packet.get_u8());
        let length = raw_packet.get_u16();

        Ok(Header {
            padding,
            count,
            packet_type,
            length,
        })
    }
}

/// Length of the part every feedback packet starts with after the header: the SSRC of the
/// packet sender and the SSRC of the media source (RFC 4585 §6.1).
pub(crate) const FEEDBACK_SSRCS_LENGTH: usize = 2 * SSRC_LENGTH;

/// Reads one RTCP packet off `raw`: its header, and its body without the padding the P bit
/// announces.
///
/// The body is exactly the `length` words the header declares; what follows them in `raw` is
/// the next packet of the datagram and is left there. RFC 3550 §6.4.1: with the P bit set the
/// last octet of the packet counts the padding octets, itself included, and those octets are
/// not control information.
pub(crate) fn read_packet<B>(raw: &mut B) -> Result<(Header, Bytes)>
where
    B: Buf,
{
    let header = Header::unmarshal(raw)?;
    let length = header.length as usize * 4;
    if raw.remaining() < length {
        return Err(Error::PacketTooShort);
    }
    let mut body = raw.copy_to_bytes(length);
    if header.padding {
        let padding = body.last().copied().unwrap_or(0) as usize;
        if padding == 0 || padding > body.len() {
            return Err(Error::WrongPadding);
        }
        body.truncate(body.len() - padding);
    }
    Ok((header, body))
}

/// Reads one feedback packet (RFC 4585 §6.1) of the given type and FMT off `raw` and returns
/// the SSRC of the packet sender, the SSRC of the media source and the FCI.
pub(crate) fn read_feedback<B>(
    raw: &mut B,
    packet_type: PacketType,
    format: u8,
) -> Result<(u32, u32, Bytes)>
where
    B: Buf,
{
    let (header, mut body) = read_packet(raw)?;
    if header.packet_type != packet_type || header.count != format {
        return Err(Error::WrongType);
    }
    if body.len() < FEEDBACK_SSRCS_LENGTH {
        return Err(Error::PacketTooShort);
    }
    let sender_ssrc = body.get_u32();
    let media_ssrc = body.get_u32();
    Ok((sender_ssrc, media_ssrc, body))
}

/// The header of a packet of `size` octets, `size` a multiple of four no larger than the 16-bit
/// length field can describe.
pub(crate) fn header_for(packet_type: PacketType, count: u8, size: usize) -> Result<Header> {
    if !size.is_multiple_of(4) || size < HEADER_LENGTH {
        return Err(Error::WrongMarshalSize);
    }
    let length = u16::try_from(size / 4 - 1).map_err(|_| Error::TooManyReports)?;
    Ok(Header {
        padding: false,
        count,
        packet_type,
        length,
    })
}

/// Writes the header and the two SSRCs of a feedback packet of `size` octets and returns the
/// rest of `buf`, where the FCI goes.
pub(crate) fn put_feedback_start(
    buf: &mut [u8],
    packet_type: PacketType,
    format: u8,
    size: usize,
    sender_ssrc: u32,
    media_ssrc: u32,
) -> Result<&mut [u8]> {
    if buf.len() < size {
        return Err(Error::BufferTooShort);
    }
    let n = header_for(packet_type, format, size)?.marshal_to(buf)?;
    let mut rest = &mut buf[n..];
    rest.put_u32(sender_ssrc);
    rest.put_u32(media_ssrc);
    Ok(rest)
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_header_unmarshal() {
        let tests = vec![
            (
                "valid",
                Bytes::from_static(&[
                    // v=2, p=0, count=1, RR, len=7
                    0x81u8, 0xc9, 0x00, 0x07,
                ]),
                Header {
                    padding: false,
                    count: 1,
                    packet_type: PacketType::ReceiverReport,
                    length: 7,
                },
                None,
            ),
            (
                "also valid",
                Bytes::from_static(&[
                    // v=2, p=1, count=1, BYE, len=7
                    0xa1, 0xcc, 0x00, 0x07,
                ]),
                Header {
                    padding: true,
                    count: 1,
                    packet_type: PacketType::ApplicationDefined,
                    length: 7,
                },
                None,
            ),
            (
                "bad version",
                Bytes::from_static(&[
                    // v=0, p=0, count=0, RR, len=4
                    0x00, 0xc9, 0x00, 0x04,
                ]),
                Header {
                    padding: false,
                    count: 0,
                    packet_type: PacketType::Unsupported,
                    length: 0,
                },
                Some(Error::BadVersion),
            ),
        ];

        for (name, data, want, want_error) in tests {
            let buf = &mut data.clone();
            let got = Header::unmarshal(buf);

            assert_eq!(
                got.is_err(),
                want_error.is_some(),
                "Unmarshal {name}: err = {got:?}, want {want_error:?}"
            );

            if let Some(want_error) = want_error {
                let got_err = got.err().unwrap();
                assert_eq!(
                    want_error, got_err,
                    "Unmarshal {name}: err = {got_err:?}, want {want_error:?}",
                );
            } else {
                let actual = got.unwrap();
                assert_eq!(
                    actual, want,
                    "Unmarshal {name}: got {actual:?}, want {want:?}"
                );
            }
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let tests = vec![
            (
                "valid",
                Header {
                    padding: true,
                    count: 31,
                    packet_type: PacketType::SenderReport,
                    length: 4,
                },
                None,
            ),
            (
                "also valid",
                Header {
                    padding: false,
                    count: 28,
                    packet_type: PacketType::ReceiverReport,
                    length: 65535,
                },
                None,
            ),
            (
                "invalid count",
                Header {
                    padding: false,
                    count: 40,
                    packet_type: PacketType::Unsupported,
                    length: 0,
                },
                Some(Error::InvalidHeader),
            ),
        ];

        for (name, want, want_error) in tests {
            let got = want.marshal();

            assert_eq!(
                got.is_ok(),
                want_error.is_none(),
                "Marshal {name}: err = {got:?}, want {want_error:?}"
            );

            if let Some(err) = want_error {
                let got_err = got.err().unwrap();
                assert_eq!(
                    err, got_err,
                    "Unmarshal {name} rr: err = {got_err:?}, want {err:?}",
                );
            } else {
                let data = got.ok().unwrap();
                let buf = &mut data.clone();
                let actual = Header::unmarshal(buf).unwrap_or_else(|_| panic!("Unmarshal {name}"));

                assert_eq!(
                    actual, want,
                    "{name} round trip: got {actual:?}, want {want:?}"
                )
            }
        }
    }
}
