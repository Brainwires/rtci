//! W3C webrtc-pc 4.4.2 "administratively prohibited" remote candidates: the ICE agent never
//! checks connectivity to one, yet `addIceCandidate` behaves exactly as if it were added (the
//! candidate is written into the remote description and its statistics object exists), so
//! the application cannot tell that an address is blocked.

use crate::peer_connection::configuration::RTCIceTransportPolicy;
use ice::candidate::Candidate;
use ice::tcp_type::TcpType;
use std::net::IpAddr;

/// The Fetch standard's "bad port" list (fetch.spec.whatwg.org, "block bad port"), which
/// webrtc-pc 4.4.2 says connections MUST NOT be made to.
pub(crate) const BAD_PORTS: [u16; 83] = [
    0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101,
    102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427,
    465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990,
    993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667,
    6668, 6669, 6679, 6697, 10080,
];

/// Whether a remote candidate is administratively prohibited: its port is a bad port, or,
/// under the "relay" policy, its address needs external resolution (an mDNS `.local` name or
/// another DNS name: anything that is not an IP literal).
///
/// A `tcptype active` candidate's port is not a destination: RFC 6544 section 4.5 has it
/// "set to 9 (i.e., Discard)", and section 3 "the port is meaningless [...] and is ignored by
/// the peer"; no connection is attempted to it (the peer dials us). The bad-port rule ("The UA
/// MUST prohibit connections to addresses on the [Fetch] block bad port list") does not
/// apply to it.
pub(crate) fn is_administratively_prohibited(
    candidate: &Candidate,
    policy: RTCIceTransportPolicy,
) -> bool {
    if BAD_PORTS.contains(&candidate.port()) && candidate.tcp_type() != TcpType::Active {
        return true;
    }
    policy == RTCIceTransportPolicy::Relay && candidate.address().parse::<IpAddr>().is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ice::candidate::unmarshal_candidate;

    fn candidate(address: &str, port: u16) -> Candidate {
        unmarshal_candidate(&format!("1 1 udp 2130706431 {address} {port} typ host"))
            .expect("a candidate")
    }

    /// RFC 6544 section 4.5: an active TCP candidate is signalled with port 9, a bad port,
    /// which no connection is made to: it is not prohibited for it. A passive one on port 9
    /// is a destination, and is.
    #[test]
    fn an_active_tcp_candidates_discard_port_is_not_a_bad_port() {
        let all = RTCIceTransportPolicy::All;
        let tcp = |tcp_type: &str| {
            unmarshal_candidate(&format!(
                "1 1 tcp 2130706431 192.0.2.1 9 typ host tcptype {tcp_type}"
            ))
            .expect("a candidate")
        };
        assert!(!is_administratively_prohibited(&tcp("active"), all));
        assert!(is_administratively_prohibited(&tcp("passive"), all));
    }

    #[test]
    fn bad_ports_and_names_under_the_relay_policy_are_prohibited() {
        let all = RTCIceTransportPolicy::All;
        let relay = RTCIceTransportPolicy::Relay;
        for port in [1, 6000, 5060, 10080] {
            assert!(is_administratively_prohibited(
                &candidate("192.0.2.1", port),
                all
            ));
        }
        assert!(!is_administratively_prohibited(
            &candidate("192.0.2.1", 6001),
            all
        ));
        assert!(!is_administratively_prohibited(
            &candidate("2001:db8::1", 50000),
            relay
        ));
        assert!(!is_administratively_prohibited(
            &candidate("192.0.2.1", 50000),
            relay
        ));
        let mdns = "0f0e0d0c-0b0a-0908-0706-050403020100.local";
        assert!(!is_administratively_prohibited(
            &candidate(mdns, 50000),
            all
        ));
        assert!(is_administratively_prohibited(
            &candidate(mdns, 50000),
            relay
        ));
    }
}
