//! ULPFEC: generic forward error correction with uneven level protection (RFC 5109).
//!
//! A FEC packet is the XOR of a set of media packets, named by a mask relative to a base sequence
//! number. Protection is organised in **levels**: level 0 covers the RTP header fields and the
//! first `L0` octets after the fixed header, level 1 the next `L1` octets, and so on, each level
//! with its own mask. One level whose length is the longest packet is the plain parity code of
//! RFC 2733; several levels protect the start of a packet more strongly than its end.
//!
//! # What is here
//!
//! - [`UlpfecPacket`]: the FEC header and the level headers (RFC 5109 7.3, 7.4), read and written.
//! - [`UlpfecEncoder`]: the protection operation (section 8), for any mask and any levels, with
//!   the mask rules of 7.4 checked for one packet and, by [`validate_scheme`], across the FEC
//!   packets of a group.
//! - [`UlpfecDecoder`]: recovery (section 9), level by level, iterated until nothing more can be
//!   rebuilt, over a bounded window of media and FEC packets.
//! - Two carriages (section 14), as a pair of interceptors:
//!   [`UlpfecSendInterceptor`] / [`UlpfecReceiveInterceptor`].
//!
//! # The two carriages
//!
//! **Redundant encoding (14.2), what browsers negotiate for video** (`video/red` with
//! `video/ulpfec`). Every packet of the stream is a RED packet (RFC 2198) on the media SSRC, in
//! the media stream's sequence number space. A media packet is one primary block. FEC data is
//! either a RED packet of its own whose only block is the FEC payload type (libwebrtc's form,
//! [`RedPlacement::OwnPacket`]), or a redundant block ahead of the next media packet's primary
//! block (the form of RFC 5109 10.3, [`RedPlacement::WithNextMedia`]). The FEC protects the
//! *virtual* RTP packets: the RED packets with the block header removed and the payload type
//! replaced by the primary's.
//!
//! **Separate stream (14.1).** FEC packets carry the FEC payload type and their own sequence
//! numbers. The RFC puts that stream in a second RTP session with the media stream's SSRC; a
//! WebRTC transport is one session, where two sequence spaces under one SSRC cannot coexist
//! (SRTP keys its replay state on the SSRC). The interceptors therefore send and expect the FEC
//! stream on the repair SSRC of [`StreamInfo::ssrc_fec`](crate::StreamInfo::ssrc_fec).
//! [`UlpfecStreamPacketizer`] builds the RFC's own form, FEC packets on the media SSRC, for an
//! application that does carry them to a separate session.
//!
//! **Separate RTP session (14.1), the RFC's own form.** A stream bound with
//! [`StreamInfo::fec_session`](crate::StreamInfo::fec_session) has its FEC in a second RTP
//! session, on a transport of its own, whatever carriage the builder names. Inside the chain
//! that FEC stream has the SSRC the field gives; on the FEC session's transport it has the
//! media stream's SSRC (section 7.2), which whoever drives the chain puts there with
//! [`FecSessionSsrcMap`](crate::FecSessionSsrcMap). `rtci`'s peer connection does both for a
//! FEC m= section grouped with the media's.
//!
//! # RED
//!
//! The RED block reader and writer in this module are the part of RFC 2198 the FEC carriage
//! needs, kept private apart from [`depacketize_red`]. A general RED codec belongs to `rtci-rtp`.

pub(crate) mod decoder;
pub(crate) mod encoder;
pub(crate) mod header;
pub(crate) mod receiver;
pub(crate) mod red;
pub(crate) mod sender;

/// Why ULPFEC data was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UlpfecError {
    /// Fewer octets than the 10-octet FEC header and one level header.
    TooShort,
    /// A level header says more payload follows than the packet holds.
    TruncatedLevel,
    /// A level protects no packet at all.
    EmptyMask,
    /// More protection levels than the decoder accepts.
    TooManyLevels,
    /// More than one level in a stream that signalled `onelevelonly=1`.
    MoreThanOneLevel,
    /// The encoder was given no level, or a level with no packet.
    NothingToProtect,
    /// A sequence number named by a level is not among the media packets given.
    UnknownSequenceNumber,
    /// The protected packets span more than 48 sequence numbers.
    SpanTooWide,
    /// A media packet is longer than the 16-bit length recovery field can describe, or could not
    /// be serialised.
    PacketTooLarge,
    /// A media packet is protected twice at a level above 0, or twice at level 0 with different
    /// protection lengths (RFC 5109 7.4 rule a).
    ProtectedTwice,
    /// A media packet is protected at a level without being protected at the level below
    /// (RFC 5109 7.4 rule b).
    LevelBelowMissing,
    /// A RED payload whose block headers do not fit the data.
    MalformedRed,
    /// A RED block longer than the 10-bit block length allows.
    RedBlockTooLong,
    /// The FEC packet names sequence numbers outside the decoder's window.
    OutsideWindow,
}

impl std::fmt::Display for UlpfecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::TooShort => "ULPFEC packet shorter than its headers",
            Self::TruncatedLevel => "ULPFEC level payload is truncated",
            Self::EmptyMask => "ULPFEC level protects no packet",
            Self::TooManyLevels => "ULPFEC packet has too many levels",
            Self::MoreThanOneLevel => "more than one ULPFEC level with onelevelonly=1",
            Self::NothingToProtect => "no packet to protect",
            Self::UnknownSequenceNumber => "protected sequence number is not among the packets",
            Self::SpanTooWide => "protected packets span more than 48 sequence numbers",
            Self::PacketTooLarge => "media packet too large to protect",
            Self::ProtectedTwice => "media packet protected twice at one level",
            Self::LevelBelowMissing => "media packet not protected at the level below",
            Self::MalformedRed => "malformed RED payload",
            Self::RedBlockTooLong => "RED block longer than 1023 octets",
            Self::OutsideWindow => "ULPFEC packet outside the decoder window",
        };
        f.write_str(text)
    }
}

impl std::error::Error for UlpfecError {}

/// The value of the `onelevelonly` media type parameter in an `a=fmtp` parameter string
/// (RFC 5109 13): `true` for `onelevelonly=1`, `false` for `0`, for an absent parameter (its
/// default) and for any other value.
///
/// The input the SDP side has for [`UlpfecSendBuilder::with_one_level_only`] and
/// [`UlpfecReceiveBuilder::with_one_level_only`].
pub fn one_level_only_from_fmtp(fmtp: &str) -> bool {
    fmtp.split(';').any(|parameter| {
        let mut parts = parameter.splitn(2, '=');
        let name = parts.next().unwrap_or_default().trim();
        let value = parts.next().unwrap_or_default().trim();
        name.eq_ignore_ascii_case("onelevelonly") && value == "1"
    })
}

pub use decoder::{UlpfecDecoder, UlpfecDecoderStats};
pub use encoder::{ProtectionLevel, UlpfecEncoder, UlpfecStreamPacketizer, validate_scheme};
pub use header::{
    FEC_HEADER_LENGTH, LONG_MASK_BITS, MAX_LEVELS, SHORT_MASK_BITS, UlpfecLevel, UlpfecPacket,
};
pub use receiver::{
    FecSessionPacket, UlpfecReceiveBuilder, UlpfecReceiveInterceptor, UlpfecRepair,
};
pub use red::{RedFecPayload, depacketize_red};
pub use sender::{RedPlacement, UlpfecSendBuilder, UlpfecSendInterceptor};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onelevelonly_is_read_from_an_fmtp_line() {
        assert!(one_level_only_from_fmtp("onelevelonly=1"));
        assert!(one_level_only_from_fmtp("foo=bar; OneLevelOnly = 1"));
        assert!(!one_level_only_from_fmtp("onelevelonly=0"));
        assert!(!one_level_only_from_fmtp(""), "absent means 0");
        assert!(!one_level_only_from_fmtp("onelevelonly=2"));
        assert!(!one_level_only_from_fmtp("xonelevelonly=1"));
    }
}
