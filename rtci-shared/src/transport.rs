use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

/// Explicit congestion notification codepoint (RFC 3168 section 5): the low two bits of the
/// IPv4 TOS byte or the IPv6 Traffic Class. Not-ECT (`00`) is the absence of one, `None`.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EcnCodepoint {
    /// `10`: ECN-Capable Transport, ECT(0).
    Ect0 = 0b10,
    /// `01`: ECN-Capable Transport, ECT(1), the L4S identifier (RFC 9331).
    Ect1 = 0b01,
    /// `11`: Congestion Experienced.
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

/// Type of transport protocol, either UDP or TCP
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TransportProtocol {
    /// UDP
    #[default]
    UDP,
    /// TCP
    TCP,
}

/// Transport Context with local address, peer address, ECN, protocol, etc.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportContext {
    /// Local address, either IPv4 or IPv6.
    ///
    /// For a datagram handed to a connection's `handle_read`, the transport address of the
    /// local ICE candidate it arrived on, which the ICE agent matches exactly: a host
    /// candidate's address, or, for a datagram a TURN allocation relayed, the relayed address
    /// (the relay candidate's). A socket bound to the unspecified address (`0.0.0.0:port`,
    /// `[::]:port`) reports the concrete address the datagram was received on (its destination
    /// address, e.g. from `IP_PKTINFO` / `IPV6_RECVPKTINFO`), not its own unspecified one. For a
    /// datagram from `poll_write`, the address to send from: a host candidate's socket, or a
    /// relayed address, whose datagrams go through that TURN allocation.
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
    /// Type of transport protocol, either UDP or TCP
    pub transport_protocol: TransportProtocol,
    /// Explicit congestion notification codepoint (`None` is Not-ECT).
    ///
    /// On a received datagram, the codepoint it arrived with, as the socket layer read it
    /// (`IP_RECVTOS` / `IPV6_RECVTCLASS`); on a datagram to send, the codepoint to set on it
    /// (`IP_TOS` / `IPV6_TCLASS`).
    pub ecn: Option<EcnCodepoint>,
}

impl Default for TransportContext {
    fn default() -> Self {
        Self {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        }
    }
}

/// A generic transmit with [TransportContext]
pub struct TransportMessage<T> {
    /// Received/Sent time
    pub now: Instant,
    /// A transport context with [local_addr](TransportContext::local_addr) and [peer_addr](TransportContext::peer_addr)
    pub transport: TransportContext,
    /// Message body with generic type
    pub message: T,
}

/// BytesMut type transmit with [TransportContext]
pub type TaggedBytesMut = TransportMessage<BytesMut>;

/// String type transmit with [TransportContext]
pub type TaggedString = TransportMessage<String>;

/// Four Tuple consists of local address and peer address
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FourTuple {
    /// Local socket address, either IPv4 or IPv6
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
}

impl From<&TransportContext> for FourTuple {
    fn from(value: &TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
        }
    }
}

impl From<TransportContext> for FourTuple {
    fn from(value: TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
        }
    }
}

/// Five Tuple consists of local address, peer address and protocol
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FiveTuple {
    /// Local socket address, either IPv4 or IPv6
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
    /// Type of protocol, either UDP or TCP
    pub transport_protocol: TransportProtocol,
}

impl From<&TransportContext> for FiveTuple {
    fn from(value: &TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
            transport_protocol: value.transport_protocol,
        }
    }
}

impl From<TransportContext> for FiveTuple {
    fn from(value: TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
            transport_protocol: value.transport_protocol,
        }
    }
}
