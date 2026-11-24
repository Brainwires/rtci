//! Shared helpers: packet demultiplexing and random strings.
//!
//! WebRTC multiplexes STUN, DTLS and SRTP onto one port, so the first byte of a datagram decides
//! which layer receives it ([RFC 7983]). The `match_*` predicates implement those ranges, and
//! [`is_rtcp`](crate::util::is_rtcp) separates RTCP from RTP once a packet is known to be one of the two.
//!
//! [RFC 7983]: https://datatracker.ietf.org/doc/html/rfc7983
use crate::error::{Error, Result};
use rand::{RngExt, rng};
use std::net::{SocketAddr, ToSocketAddrs};

// match_range is a MatchFunc that accepts packets with the first byte in [lower..upper]
fn match_range(lower: u8, upper: u8) -> impl Fn(&[u8]) -> bool {
    move |buf: &[u8]| -> bool {
        if buf.is_empty() {
            return false;
        }
        let b = buf[0];
        b >= lower && b <= upper
    }
}

/// MatchFuncs as described in RFC7983
/// <https://tools.ietf.org/html/rfc7983>
///              +----------------+
///              |        [0..3] -+--> forward to STUN
///              |                |
///              |      [16..19] -+--> forward to ZRTP
///              |                |
///  packet -->  |      [20..63] -+--> forward to DTLS
///              |                |
///              |      [64..79] -+--> forward to TURN Channel
///              |                |
///              |    [128..191] -+--> forward to RTP/RTCP
///              +----------------+
/// match_dtls is a MatchFunc that accepts packets with the first byte in [20..63]
/// as defied in RFC7983
pub fn match_dtls(b: &[u8]) -> bool {
    match_range(20, 63)(b)
}

/// Returns `true` if `b` looks like SRTP or SRTCP: its first byte is in `[128, 191]`.
///
/// One of the demultiplexing predicates from [RFC 7983], which is how a single port can carry
/// STUN, DTLS and SRTP at once.
///
/// [RFC 7983]: https://datatracker.ietf.org/doc/html/rfc7983
pub fn match_srtp_or_srtcp(b: &[u8]) -> bool {
    match_range(128, 191)(b)
}

/// Returns `true` if `buf` is RTCP rather than RTP.
///
/// Distinguished by the second octet, as [RFC 5761] §4 has it: an RTCP packet carries its
/// packet type there, and the types RTCP uses next to RTP are `[192, 223]`. An RTP packet
/// carries the marker bit and its 7-bit payload type there, so the octet is in that range only
/// for payload types 64 to 95 sent with the marker bit set, which is why RFC 5761 forbids
/// those payload types when RTP and RTCP share a port. The same payload types without the
/// marker bit (second octet 64 to 95) are RTP like any other.
///
/// Returns `false` for buffers too short to tell.
///
/// [RFC 5761]: https://datatracker.ietf.org/doc/html/rfc5761#section-4
pub fn is_rtcp(buf: &[u8]) -> bool {
    // Not long enough to determine RTP/RTCP
    if buf.len() < 4 {
        return false;
    }

    let rtcp_packet_type = buf[1];
    (192..=223).contains(&rtcp_packet_type)
}

/// match_srtp is a MatchFunc that only matches SRTP and not SRTCP
pub fn match_srtp(buf: &[u8]) -> bool {
    match_srtp_or_srtcp(buf) && !is_rtcp(buf)
}

/// match_srtcp is a MatchFunc that only matches SRTCP and not SRTP
pub fn match_srtcp(buf: &[u8]) -> bool {
    match_srtp_or_srtcp(buf) && is_rtcp(buf)
}

/// lookup host to SocketAddr
pub fn lookup_host<T>(use_ipv4: bool, host: T) -> Result<SocketAddr>
where
    T: ToSocketAddrs,
{
    for remote_addr in host.to_socket_addrs()? {
        if (use_ipv4 && remote_addr.is_ipv4()) || (!use_ipv4 && remote_addr.is_ipv6()) {
            return Ok(remote_addr);
        }
    }

    Err(Error::ErrAddressParseFailed)
}

const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const RUNES_ALPHA_NUMBER: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
pub fn math_rand_alpha(n: usize) -> String {
    generate_crypto_random_string(n, RUNES_ALPHA)
}

/// math_rand_alpha generates a mathematical random alphabet and number sequence of the requested length.
pub fn math_rand_alpha_number(n: usize) -> String {
    generate_crypto_random_string(n, RUNES_ALPHA_NUMBER)
}

//TODO: generates a random string for cryptographic usage.
/// Generates a random `n`-character string drawn from `runes`.
///
/// Used for values that must be unguessable, such as ICE credentials and SDP identifiers.
pub fn generate_crypto_random_string(n: usize, runes: &[u8]) -> String {
    let mut rng = rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.random_range(0..runes.len());
            runes[idx] as char
        })
        .collect();

    rand_string
}

#[cfg(test)]
mod rtp_rtcp_demux_test {
    use super::*;

    fn packet(first: u8, second: u8) -> [u8; 12] {
        let mut p = [0u8; 12];
        p[0] = first;
        p[1] = second;
        p
    }

    // RFC 5761 4: "RTCP packet types in the ranges 1-191 and 224-254 SHOULD only be used when
    // other values have been exhausted", and the demultiplexing is on 192 to 223.
    #[test]
    fn the_second_octet_192_to_223_is_rtcp_and_nothing_else_is() {
        for second in 0..=u8::MAX {
            let want = (192..=223).contains(&second);
            assert_eq!(
                want,
                is_rtcp(&packet(0x80, second)),
                "second octet {second}"
            );
            assert_eq!(
                want,
                match_srtcp(&packet(0x80, second)),
                "second octet {second}"
            );
            assert_eq!(
                !want,
                match_srtp(&packet(0x80, second)),
                "second octet {second}"
            );
        }
    }

    // RFC 5761 4: payload types 64 to 95 collide with RTCP only when the marker bit is set
    // (second octet 192 to 223). Without it they are RTP: the test is on the whole octet, not
    // on the payload type with the marker bit masked away.
    #[test]
    fn payload_types_64_to_95_are_rtcp_only_with_the_marker_bit() {
        for payload_type in 64..=95u8 {
            assert!(
                !is_rtcp(&packet(0x80, payload_type)),
                "PT {payload_type}, M=0"
            );
            assert!(
                is_rtcp(&packet(0x80, 0x80 | payload_type)),
                "PT {payload_type}, M=1"
            );
        }
        // The payload types WebRTC uses, with and without the marker bit.
        for payload_type in (0..=63u8).chain(96..=127) {
            assert!(
                !is_rtcp(&packet(0x80, payload_type)),
                "PT {payload_type}, M=0"
            );
            assert!(
                !is_rtcp(&packet(0x80, 0x80 | payload_type)),
                "PT {payload_type}, M=1"
            );
        }
    }

    // The RTCP packet types in use, each with the counts and formats they come with.
    #[test]
    fn every_rtcp_packet_type_in_use_is_rtcp() {
        for (first, packet_type) in [
            (0x80, 200), // SR
            (0x81, 201), // RR
            (0x81, 202), // SDES
            (0x81, 203), // BYE
            (0x80, 204), // APP
            (0x81, 205), // RTPFB, generic NACK
            (0x8f, 205), // RTPFB, transport-wide feedback
            (0x81, 206), // PSFB, PLI
            (0xaf, 206), // PSFB, REMB, padded
            (0x80, 207), // XR
        ] {
            assert!(is_rtcp(&packet(first, packet_type)), "PT {packet_type}");
        }
    }

    // RFC 7983 7: the first octet picks the protocol; 128 to 191 is RTP or RTCP. `is_rtcp`
    // only tells those two apart, so `match_srtcp` asks for both.
    #[test]
    fn only_a_first_octet_of_128_to_191_is_rtp_or_rtcp() {
        for first in 0..=u8::MAX {
            let rtp_or_rtcp = (128..=191).contains(&first);
            assert_eq!(
                rtp_or_rtcp,
                match_srtcp(&packet(first, 200)),
                "first octet {first}"
            );
            assert_eq!(
                rtp_or_rtcp,
                match_srtp(&packet(first, 96)),
                "first octet {first}"
            );
            assert!(!match_srtp(&packet(first, 200)));
            assert!(!match_srtcp(&packet(first, 96)));
        }
    }

    // Shorter than an RTCP header there is nothing to classify.
    #[test]
    fn a_buffer_shorter_than_an_rtcp_header_is_not_rtcp() {
        assert!(!is_rtcp(&[]));
        assert!(!is_rtcp(&[0x80]));
        assert!(!is_rtcp(&[0x80, 200]));
        assert!(!is_rtcp(&[0x80, 200, 0]));
        assert!(is_rtcp(&[0x80, 200, 0, 0]));
    }
}
