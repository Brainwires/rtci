//! The mDNS half of a [`PeerDriver`](crate::peer::PeerDriver): the host's mDNS sockets (port
//! 5353, joined to the mDNS groups) and the process-wide message budget every driven
//! connection's mDNS takes from.
//!
//! The engine's mDNS (`rtci-mdns`, inside each ICE agent) builds queries, probes, answers and
//! goodbyes and hands them out as datagrams from local port 5353; it keeps no state shared
//! between connections (the sans-I/O crates keep no process-wide state). The driver is where
//! the process is: draft-ietf-mmusic-mdns-ice-candidates section 7.1 asks that "an
//! implementation-wide rate limit" cover "all mDNS queries and responses" of gathering and of
//! processing remote candidates, so every mDNS datagram any driver of the process sends takes
//! one message from one budget ([`process_mdns_rate_limit`]); one the budget refuses waits
//! in its driver, in order, until the budget has room.

use rtci::mdns::{MDNS_PORT, MdnsRateLimit, MulticastSocket};
use rtci::shared::TaggedBytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Instant;

/// The mDNS IPv6 link-local group (RFC 6762 section 3).
pub const MDNS_MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// The largest mDNS message read: RFC 6762 section 17 allows up to 9000 bytes.
pub(crate) const MDNS_MAX_DATAGRAM: usize = 9000;

/// How many mDNS datagrams one driver holds while the budget refuses them. Past it the oldest
/// is dropped (and counted as unsent): the engine retries what matters (queries, probes and
/// announcements are repeated) and a queue without bound would let a burst of names grow it.
pub(crate) const MAX_HELD_MDNS: usize = 256;

/// The message budget every [`PeerDriver`](crate::peer::PeerDriver) of this process takes
/// its mDNS from, unless its configuration names another
/// ([`PeerDriverConfig::mdns_rate_limit`](crate::peer::PeerDriverConfig::mdns_rate_limit)):
/// 40 messages at once, then 10 a second (`MdnsRateLimit::default`). One budget for the
/// process is draft-ietf-mmusic-mdns-ice-candidates section 7.1's "implementation-wide rate
/// limit". The returned value is a handle: every clone takes from the same budget.
pub fn process_mdns_rate_limit() -> MdnsRateLimit {
    static LIMIT: OnceLock<MdnsRateLimit> = OnceLock::new();
    LIMIT.get_or_init(MdnsRateLimit::default).clone()
}

/// What a driver's connection wants to send by mDNS, held to the budget.
pub(crate) struct MdnsEgress {
    limit: MdnsRateLimit,
    held: VecDeque<TaggedBytesMut>,
}

impl MdnsEgress {
    pub(crate) fn new(limit: MdnsRateLimit) -> Self {
        Self {
            limit,
            held: VecDeque::new(),
        }
    }

    /// Queues `datagram` behind what is already held. `false` when the queue was full and its
    /// oldest datagram was dropped to make room.
    pub(crate) fn push(&mut self, datagram: TaggedBytesMut) -> bool {
        let room = self.held.len() < MAX_HELD_MDNS;
        if !room {
            self.held.pop_front();
        }
        self.held.push_back(datagram);
        room
    }

    /// The next held datagram, if the budget gives it a message at `now`.
    pub(crate) fn pop_ready(&mut self, now: Instant) -> Option<TaggedBytesMut> {
        if self.held.is_empty() || !self.limit.take(now) {
            return None;
        }
        self.held.pop_front()
    }

    /// When the next held datagram may go; `None` when nothing is held.
    pub(crate) fn next_ready(&self, now: Instant) -> Option<Instant> {
        (!self.held.is_empty()).then(|| self.limit.ready_at(now))
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }
}

/// The IPv4 mDNS socket: port 5353, joined to 224.0.0.251 (`rtci_mdns::MulticastSocket`).
pub(crate) fn bind_mdns_v4() -> io::Result<std::net::UdpSocket> {
    MulticastSocket::new().into_std()
}

/// The IPv6 mDNS socket: `[::]:5353`, IPv6 only, joined to ff02::fb on the default interface,
/// sending with hop limit 255 (RFC 6762 section 11). An error where the host has no IPv6 or
/// cannot join the group.
pub(crate) fn bind_mdns_v6() -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_hops_v6(255)?;
    socket.set_unicast_hops_v6(255)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), MDNS_PORT).into())?;
    socket.join_multicast_v6(&MDNS_MULTICAST_IPV6, 0)?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use rtci::mdns::MDNS_MULTICAST_IPV4;
    use rtci::shared::{TransportContext, TransportProtocol};
    use std::time::Duration;

    fn datagram(n: u8) -> TaggedBytesMut {
        TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: SocketAddr::from(([0, 0, 0, 0], MDNS_PORT)),
                peer_addr: SocketAddr::from((MDNS_MULTICAST_IPV4, MDNS_PORT)),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&[n][..]),
        }
    }

    fn drain(egress: &mut MdnsEgress, now: Instant) -> Vec<u8> {
        std::iter::from_fn(|| egress.pop_ready(now))
            .map(|d| d.message[0])
            .collect()
    }

    // draft-ietf-mmusic-mdns-ice-candidates section 7.1: what the budget refuses waits, in
    // order, and leaves when the budget has room again; nothing beyond the rate leaves.
    #[test]
    fn mdns_the_budget_refuses_waits_in_order_and_leaves_at_its_rate() {
        let t0 = Instant::now();
        let mut egress = MdnsEgress::new(MdnsRateLimit::new(2, 4));
        for n in 0..5 {
            assert!(egress.push(datagram(n)));
        }
        assert_eq!(drain(&mut egress, t0), vec![0, 1], "the burst");
        assert_eq!(egress.held(), 3);
        assert_eq!(egress.next_ready(t0), Some(t0 + Duration::from_millis(250)));
        assert!(drain(&mut egress, t0 + Duration::from_millis(249)).is_empty());
        assert_eq!(drain(&mut egress, t0 + Duration::from_millis(250)), vec![2]);
        assert_eq!(
            drain(&mut egress, t0 + Duration::from_millis(750)),
            vec![3, 4]
        );
        assert_eq!(egress.next_ready(t0 + Duration::from_millis(750)), None);
    }

    // Section 7.1's limit is implementation-wide: two drivers made with the default
    // configuration take from one budget, so what one spent the other cannot send.
    #[test]
    fn drivers_with_the_default_configuration_share_one_mdns_budget() {
        let config = crate::peer::PeerDriverConfig::on(vec![]);
        let mut first = MdnsEgress::new(config.mdns_rate_limit());
        let mut second = MdnsEgress::new(config.mdns_rate_limit());
        // A time no other test of this binary uses: the budget refills to its burst (40) by then.
        let t = Instant::now() + Duration::from_secs(3600);
        for n in 0..40 {
            first.push(datagram(n));
        }
        second.push(datagram(100));
        assert_eq!(drain(&mut first, t).len(), 40, "the process's burst");
        assert!(
            drain(&mut second, t).is_empty(),
            "the other driver's message waits for the same budget"
        );
        assert_eq!(second.next_ready(t), Some(t + Duration::from_millis(100)));
        assert_eq!(
            drain(&mut second, t + Duration::from_millis(100)),
            vec![100]
        );
    }

    #[test]
    fn a_full_mdns_queue_drops_its_oldest_datagram() {
        let mut egress = MdnsEgress::new(MdnsRateLimit::new(1, 1));
        for n in 0..MAX_HELD_MDNS {
            assert!(egress.push(datagram(n as u8)));
        }
        assert!(!egress.push(datagram(7)), "past the bound, one is dropped");
        assert_eq!(egress.held(), MAX_HELD_MDNS);
        assert_eq!(
            drain(&mut egress, Instant::now()),
            vec![1],
            "the oldest went"
        );
    }
}
