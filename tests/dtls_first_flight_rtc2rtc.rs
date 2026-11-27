//! The DTLS client's first flight leaves in the instant ICE selects the pair it goes on, between
//! two `rtci` peer connections in virtual time, under two drivers that follow the sans-I/O
//! contract: the README's event loop (`poll_write`, `poll_event`, `poll_read`, then
//! `poll_timeout`, and `handle_timeout` when it is due), and the stream driver's
//! (`examples/stream-driver`, `PeerDriver::step`: after every wake, the datagrams read and then
//! `handle_timeout`, before the writes and events are drained).
//!
//! RFC 8842 section 5 has the `active` endpoint start the handshake once ICE has a path, and
//! RFC 6347 section 4.2.4 / RFC 9147 section 5.8 give the client's flight a retransmission
//! timer, not a delay: the ClientHello is sent when the handshake starts. The peer connection
//! starts it when its DTLS handler sees the selected-pair event, which the application drains
//! in `poll_event`, after its `poll_write`; the flight it produced there was left in the DTLS
//! endpoint, and `poll_timeout` named only the endpoint's retransmission timer, so the flight
//! left with whatever woke the connection next (a consumer measured about 185 ms from ICE
//! connected to the ClientHello). Under the README's loop it left at once only because the
//! ICE agent asks for an immediate look at its state when it concludes (`conclude`), and the
//! `handle_timeout` that brings drains the DTLS endpoint too; a driver that calls
//! `handle_timeout` after the read, before it drains the selected-pair event, uses that wake up
//! before the flight exists.

use anyhow::{Result, bail};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// One way across the in-memory network.
const LATENCY: Duration = Duration::from_millis(10);

fn host(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

/// Whether `datagram` is a DTLS record carrying a ClientHello (content type 22, handshake
/// type 1 after the 13-octet record header; DTLS 1.3 sends its ClientHello in the same
/// DTLSPlaintext form, RFC 9147 section 4).
fn is_client_hello(datagram: &[u8]) -> bool {
    datagram.first() == Some(&22) && datagram.get(13) == Some(&1)
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    /// When the application drained its first `OnSelectedCandidatePairChange`.
    selected_at: Option<Instant>,
    /// When `poll_write` handed out its first ClientHello.
    client_hello_at: Option<Instant>,
}

/// How the driver orders its calls.
#[derive(Clone, Copy, Debug)]
enum Driver {
    /// The README's loop: `handle_timeout` only when `poll_timeout` is due.
    Readme,
    /// The stream driver's step: `handle_timeout` after every wake, right after the reads.
    StreamDriver,
}

struct World {
    driver: Driver,
    peers: [Peer; 2],
    now: Instant,
    /// Datagrams on their way: when they arrive, the index of the peer they go to, their
    /// destination and their source.
    in_flight: Vec<(Instant, usize, SocketAddr, SocketAddr, bytes::BytesMut)>,
}

impl World {
    fn new(answering_role: RTCDtlsRole, driver: Driver) -> Result<Self> {
        let now = Instant::now();
        let peer = |addr: &str| -> Result<Peer> {
            Ok(Peer {
                pc: RTCPeerConnectionBuilder::new()
                    .with_setting_engine(
                        SettingEngineBuilder::new()
                            .with_answering_dtls_role(answering_role)
                            .build(),
                    )
                    .build(now)?,
                addr: addr.parse()?,
                selected_at: None,
                client_hello_at: None,
            })
        };
        let mut world = Self {
            driver,
            peers: [peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?],
            now,
            in_flight: Vec::new(),
        };
        let [offerer, answerer] = &mut world.peers;
        offerer.pc.create_data_channel("d", None)?;
        let offer = offerer.pc.create_offer(None)?;
        offerer.pc.set_local_description(now, offer.clone())?;
        answerer.pc.set_remote_description(now, offer)?;
        let answer = answerer.pc.create_answer(None)?;
        answerer.pc.set_local_description(now, answer.clone())?;
        offerer
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(answer.sdp)?)?;
        for (from, to) in [(0, 1), (1, 0)] {
            let candidate = host(world.peers[from].addr)?;
            world.peers[from]
                .pc
                .add_local_candidate(candidate.clone())?;
            world.peers[to].pc.add_remote_candidate(candidate)?;
        }
        Ok(world)
    }

    /// The README's loop for each peer at the current instant: writes, events, reads.
    fn drain(&mut self) {
        let now = self.now;
        let addrs: Vec<SocketAddr> = self.peers.iter().map(|p| p.addr).collect();
        for peer in self.peers.iter_mut() {
            while let Some(datagram) = peer.pc.poll_write() {
                if is_client_hello(&datagram.message) && peer.client_hello_at.is_none() {
                    peer.client_hello_at = Some(now);
                }
                let to = addrs
                    .iter()
                    .position(|a| *a == datagram.transport.peer_addr)
                    .unwrap_or(usize::MAX);
                self.in_flight.push((
                    now + LATENCY,
                    to,
                    datagram.transport.peer_addr,
                    datagram.transport.local_addr,
                    datagram.message,
                ));
            }
            while let Some(event) = peer.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_) = event
                    && peer.selected_at.is_none()
                {
                    peer.selected_at = Some(now);
                }
            }
            while peer.pc.poll_read().is_some() {}
        }
    }

    /// Runs until both peers' DTLS clients have sent a ClientHello or `limit` has passed. The
    /// clock never moves past a deadline a peer named: a deadline at or before the current
    /// instant is handled at the current instant.
    fn run(&mut self, limit: Duration) -> Result<()> {
        let end = self.now + limit;
        let mut iterations = 0u32;
        while self.now < end {
            iterations += 1;
            if iterations > 200_000 {
                bail!("the peers never stop asking for the current instant");
            }
            self.drain();
            if self.peers.iter().any(|p| p.client_hello_at.is_some()) {
                return Ok(());
            }
            let timeouts: Vec<Option<Instant>> =
                self.peers.iter_mut().map(|p| p.pc.poll_timeout()).collect();
            let arrival = self.in_flight.iter().map(|(at, ..)| *at).min();
            let next = timeouts
                .iter()
                .flatten()
                .copied()
                .chain(arrival)
                .min()
                .unwrap_or(end)
                .min(end);
            self.now = self.now.max(next);
            let now = self.now;
            let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.in_flight)
                .into_iter()
                .partition(|(at, ..)| *at <= now);
            self.in_flight = later;
            for (_, to, destination, source, message) in due {
                let Some(peer) = self.peers.get_mut(to) else {
                    continue;
                };
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: destination,
                        peer_addr: source,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message,
                });
            }
            let every_wake = matches!(self.driver, Driver::StreamDriver);
            for (peer, timeout) in self.peers.iter_mut().zip(timeouts) {
                if every_wake || timeout.is_some_and(|at| at <= now) {
                    peer.pc.handle_timeout(now)?;
                }
            }
        }
        Ok(())
    }
}

/// The ClientHello leaves in the instant the DTLS client's application learns of the selected
/// pair: no wait, under either driver, whichever side is the DTLS client (the controlled
/// answerer by default, RFC 8842 section 5.3's `active` answer; the controlling offerer when
/// the answer is `passive`).
#[test]
fn the_client_hello_leaves_in_the_instant_the_pair_is_selected() -> Result<()> {
    for (driver, answering_role, client) in [
        (Driver::Readme, RTCDtlsRole::Client, 1usize),
        (Driver::Readme, RTCDtlsRole::Server, 0),
        (Driver::StreamDriver, RTCDtlsRole::Client, 1),
        (Driver::StreamDriver, RTCDtlsRole::Server, 0),
    ] {
        let answering_role = (driver, answering_role);
        let mut world = World::new(answering_role.1, driver)?;
        world.run(Duration::from_secs(10))?;
        let peer = &world.peers[client];
        let other = &world.peers[1 - client];
        assert!(
            other.client_hello_at.is_none(),
            "{answering_role:?}: the server sent no ClientHello"
        );
        let (Some(selected), Some(hello)) = (peer.selected_at, peer.client_hello_at) else {
            bail!(
                "{answering_role:?}: selected {:?}, ClientHello {:?}",
                peer.selected_at,
                peer.client_hello_at
            );
        };
        assert_eq!(
            hello.duration_since(selected),
            Duration::ZERO,
            "{answering_role:?}: from the selected pair to the ClientHello"
        );
    }
    Ok(())
}
