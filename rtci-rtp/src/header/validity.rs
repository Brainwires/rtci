//! The RTP header validity checks of [RFC 3550] Appendix A.1.
//!
//! `check_rtp_validity` applies them to the bytes of a datagram before anything is parsed or
//! allocated, so a receiver can tell an RTP packet from garbage (the appendix's "weak validity
//! checks"). The checks that need more than one packet (a new source's probation, sequence
//! number jumps) are [`SourceSequence`](crate::sequence::SourceSequence).
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550#appendix-A.1

use shared::error::{Error, Result};

use super::{
    CC_MASK, CSRC_LENGTH, CSRC_OFFSET, EXTENSION_MASK, EXTENSION_SHIFT, HEADER_LENGTH,
    PADDING_MASK, PADDING_SHIFT, PT_MASK, RTP_VERSION, VERSION_MASK, VERSION_SHIFT,
};

/// The second octet of an RTCP sender report: an RTP packet with M=1 and PT 72.
const RTCP_SR: u8 = 200;
/// The second octet of an RTCP receiver report: an RTP packet with M=1 and PT 73.
const RTCP_RR: u8 = 201;

/// Where the parts of a valid RTP packet lie.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RtpLayout {
    /// The payload type.
    pub payload_type: u8,
    /// Bytes of header: the fixed header, the CSRC list and the extension block.
    pub header_len: usize,
    /// Bytes of payload, padding excluded.
    pub payload_len: usize,
    /// Bytes of padding after the payload, the count octet included; 0 without the P bit.
    pub padding_len: usize,
}

/// Applies the header validity checks of RFC 3550 Appendix A.1 to a datagram.
///
/// * the version is 2;
/// * the payload type is known (`payload_type_known`), and the second octet is not that of an
///   RTCP SR or RR;
/// * the packet is long enough for its CSRC count;
/// * with the X bit, the extension block fits the packet;
/// * with the P bit, the last octet is a padding count that is not zero and not larger than
///   what follows the header.
///
/// `payload_type_known` is the profile's part: the appendix has a receiver that does not know
/// a payload type ignore the packet (RFC 3550 section 5.1). Pass `|_| true` to check the
/// structure alone.
///
/// # Errors
///
/// [`Error::ErrHeaderSizeInsufficient`], [`Error::BadVersion`], [`Error::WrongPayloadType`],
/// [`Error::ErrHeaderSizeInsufficientForExtension`] or [`Error::ErrShortPacket`] (padding),
/// in the order of the checks above.
pub fn check_rtp_validity(
    packet: &[u8],
    payload_type_known: impl FnOnce(u8) -> bool,
) -> Result<RtpLayout> {
    if packet.len() < CSRC_OFFSET {
        return Err(Error::ErrHeaderSizeInsufficient);
    }
    let b0 = packet[0];
    if b0 >> VERSION_SHIFT & VERSION_MASK != RTP_VERSION {
        return Err(Error::BadVersion);
    }
    let b1 = packet[1];
    let payload_type = b1 & PT_MASK;
    if b1 == RTCP_SR || b1 == RTCP_RR || !payload_type_known(payload_type) {
        return Err(Error::WrongPayloadType);
    }

    let mut header_len = CSRC_OFFSET + usize::from(b0 & CC_MASK) * CSRC_LENGTH;
    if packet.len() < header_len {
        return Err(Error::ErrHeaderSizeInsufficient);
    }
    if b0 >> EXTENSION_SHIFT & EXTENSION_MASK != 0 {
        if packet.len() < header_len + HEADER_LENGTH {
            return Err(Error::ErrHeaderSizeInsufficientForExtension);
        }
        let words = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
        header_len += HEADER_LENGTH + usize::from(words) * 4;
        if packet.len() < header_len {
            return Err(Error::ErrHeaderSizeInsufficientForExtension);
        }
    }

    let after_header = packet.len() - header_len;
    let padding_len = if b0 >> PADDING_SHIFT & PADDING_MASK != 0 {
        let count = packet.last().map_or(0, |&count| usize::from(count));
        if count == 0 || count > after_header {
            return Err(Error::ErrShortPacket);
        }
        count
    } else {
        0
    };

    Ok(RtpLayout {
        payload_type,
        header_len,
        payload_len: after_header - padding_len,
        padding_len,
    })
}

#[cfg(test)]
#[path = "validity_test.rs"]
mod validity_test;
