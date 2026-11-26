//! An ICE restart with new TURN credentials keeps the relayed path in use until the restart
//! has selected a pair (RFC 8445 section 9: "during the restart, data can continue to be sent
//! using existing data sessions"; section 5.1.1.4: relayed candidates "MUST be kept alive until
//! ICE processing has completed").
//!
//! The recipe W3C gives for new servers is `setConfiguration` and an ICE restart ("If a script
//! wants this to happen immediately, it should do an ICE restart"). With new credentials the
//! next generation needs a new allocation (RFC 8656 section 5: requests on an allocation carry
//! its own username, 441 otherwise), and a second allocation needs another 5-tuple (section
//! 2.2): it comes from a second UDP base of the transport.
//!
//! Peer A has the relay policy, a `turn:` server and two UDP host candidates (two sockets of
//! the application); peer B has a host candidate. The server is the in-memory coturn-like one
//! of `common/turn_server.rs`. Time is virtual, nothing touches a network.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{
    RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy,
};
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::message::METHOD_ALLOCATE;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
#[path = "common/turn_server.rs"]
mod turn_server;
use turn_server::{Auth, TurnServer};

/// Virtual time a message gets to arrive: far below the ICE timeouts, so one that arrives did
/// not wait for a new pair.
const STEP: Duration = Duration::from_secs(3);
const A_HOST: &str = "10.0.0.1:4000";
const A_HOST_2: &str = "10.0.0.1:4001";
const B_HOST: &str = "10.0.0.2:5000";
const SERVER: &str = "192.0.2.20:3478";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Peer {
    pc: RTCPeerConnection,
    addrs: Vec<SocketAddr>,
    connected: bool,
    channel: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
    /// Local candidates announced, not yet given to the other peer.
    candidates: Vec<RTCIceCandidateInit>,
}

impl Peer {
    fn new(addrs: &[&str], configuration: RTCConfiguration) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_candidate_gathering(false)
                    .build(),
            )
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addrs: addrs.iter().map(|s| a(s)).collect(),
            connected: false,
            channel: None,
            received: vec![],
            candidates: vec![],
        })
    }

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

    fn ufrag(&self) -> String {
        let sdp = self.pc.local_description().expect("a description").sdp;
        sdp.lines()
            .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
            .expect("an ice-ufrag")
            .to_owned()
    }
}

fn turn_config(user: &str, pass: &str) -> RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec![format!("turn:{SERVER}")],
            username: user.to_owned(),
            credential: pass.to_owned(),
        }])
        .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
        .build()
}

struct World {
    peers: Vec<Peer>,
    server: TurnServer,
    now: Instant,
    /// Whether announced candidates are passed on (off while a restart's descriptions are on
    /// their way, as over a signalling channel that orders them after the descriptions).
    trickle: bool,
    /// Datagrams with nowhere to go: (from, to).
    lost: Vec<(SocketAddr, SocketAddr)>,
}

impl World {
    fn deliver(
        pc: &mut RTCPeerConnection,
        now: Instant,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) {
        let _ = pc.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: to,
                peer_addr: from,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(data),
        });
    }

    /// Runs everything until `done`, or fails after `STEP` of virtual time.
    fn run(&mut self, what: &str, done: impl Fn(&World) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let mut moved = false;
            let now = self.now;
            for i in 0..2 {
                while let Some(w) = self.peers[i].pc.poll_write() {
                    moved = true;
                    let (from, to) = (w.transport.local_addr, w.transport.peer_addr);
                    if self.server.addresses.contains(&to) {
                        self.server.client_sent(now, from, to, &w.message)?;
                    } else if self.server.is_relayed(to) {
                        self.server.peer_sent(now, from, to, &w.message)?;
                    } else if let Some(j) = self.peers.iter().position(|p| p.addrs.contains(&to)) {
                        if self.peers[i].addrs.contains(&from) {
                            Self::deliver(&mut self.peers[j].pc, now, from, to, &w.message);
                        } else {
                            // From an address the peer has no socket on (a relayed one): it
                            // could only leave through its allocation.
                            self.lost.push((from, to));
                        }
                    } else {
                        self.lost.push((from, to));
                    }
                }
            }
            for (from, to, data) in std::mem::take(&mut self.server.out) {
                moved = true;
                match self.peers.iter().position(|p| p.addrs.contains(&to)) {
                    Some(j) => Self::deliver(&mut self.peers[j].pc, now, from, to, &data),
                    None => self.lost.push((from, to)),
                }
            }
            for i in 0..2 {
                let peer = &mut self.peers[i];
                while let Some(event) = peer.pc.poll_event() {
                    moved = true;
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            if state == RTCPeerConnectionState::Failed {
                                bail!("{what}: peer {i}'s connection failed");
                            }
                            peer.connected = state == RTCPeerConnectionState::Connected;
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                            peer.channel = Some(id)
                        }
                        RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                            if let Some(mut init) = ev.candidate.and_then(|c| c.to_json().ok()) {
                                init.url = None;
                                peer.candidates.push(init);
                            }
                        }
                        _ => {}
                    }
                }
                while let Some(message) = peer.pc.poll_read() {
                    if let RTCMessage::DataChannelMessage(_, m) = message.message {
                        peer.received.push(m.data.to_vec());
                    }
                }
            }
            if self.trickle {
                for i in 0..2 {
                    for init in std::mem::take(&mut self.peers[i].candidates) {
                        if init.candidate.is_empty() {
                            continue;
                        }
                        self.peers[1 - i].pc.add_remote_candidate(init)?;
                        moved = true;
                    }
                }
            }
            if done(self) {
                return Ok(());
            }
            if moved {
                continue;
            }
            if self.now.duration_since(start) >= STEP {
                bail!(
                    "{what}: not done after {STEP:?} of virtual time (lost datagrams: {:?})",
                    self.lost.iter().rev().take(4).collect::<Vec<_>>()
                );
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(self.now + Duration::from_millis(50));
            self.now = next
                .max(self.now + Duration::from_millis(1))
                .min(self.now + Duration::from_millis(20));
            for peer in self.peers.iter_mut() {
                let _ = peer.pc.handle_timeout(self.now);
            }
        }
    }

    /// A message each way over the data channel; each must arrive within `STEP`.
    fn ping_pong(&mut self, what: &str) -> Result<()> {
        for from in 0..2 {
            let to = 1 - from;
            let payload = format!("{what} / {from} to {to}").into_bytes();
            let before = self.peers[to].received.len();
            let channel = self.peers[from].channel.expect("an open channel");
            self.peers[from]
                .pc
                .data_channel(channel)
                .expect("the channel")
                .send(self.now, BytesMut::from(&payload[..]))?;
            self.run(&format!("{what}: a message from peer {from}"), |w| {
                w.peers[to].received.len() > before
            })?;
            assert_eq!(self.peers[to].received.last(), Some(&payload), "{what}");
        }
        Ok(())
    }

    /// The relayed address the server relays A's data through last.
    fn last_relay(&self) -> Option<SocketAddr> {
        self.server.relayed.last().map(|r| r.0)
    }
}

/// Connects A (relay policy, credentials `u1`) and B over the in-memory server.
fn connected_world() -> Result<World> {
    common::install_crypto_provider();
    let now = Instant::now();
    let server = TurnServer::new(
        Auth::Static(vec![
            ("u1".to_owned(), "p1".to_owned()),
            ("u2".to_owned(), "p2".to_owned()),
        ]),
        vec![a(SERVER)],
        a(SERVER).ip(),
        now,
    );
    let mut world = World {
        peers: vec![
            Peer::new(&[A_HOST, A_HOST_2], turn_config("u1", "p1"))?,
            Peer::new(&[B_HOST], RTCConfigurationBuilder::new().build())?,
        ],
        server,
        now,
        trickle: true,
        lost: vec![],
    };
    world.peers[0].pc.create_data_channel("relayed", None)?;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    for i in 0..2 {
        for addr in world.peers[i].addrs.clone() {
            world.peers[i].pc.add_local_candidate(Peer::host(addr)?)?;
        }
    }
    world.run("the first connection", |w| {
        w.peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    world.ping_pong("connected")?;
    Ok(world)
}

/// RFC 8445 section 9 with RFC 8656 sections 2.2 and 5: `set_configuration` with new
/// credentials and an ICE restart, one signalling step at a time. Data keeps flowing through
/// the first allocation at every step until the restart has selected its pair; the new
/// allocation is made from the second UDP base (another 5-tuple: no 437) before the first is
/// deleted with a Refresh of LIFETIME 0, which happens only once data runs through the new
/// one.
#[test]
fn a_restart_with_new_turn_credentials_keeps_the_previous_allocation_until_it_selects() -> Result<()>
{
    let mut world = connected_world()?;
    let first = world.last_relay().expect("data relayed");
    assert_eq!(world.server.allocations.len(), 1);
    let ufrag = world.peers[0].ufrag();

    world.peers[0]
        .pc
        .set_configuration(turn_config("u2", "p2"))?;
    world.peers[0].pc.restart_ice();
    world.trickle = false;
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_ne!(world.peers[0].ufrag(), ufrag, "the offer restarts ICE");
    world.ping_pong("the offerer applied its restart offer")?;
    assert!(
        world.server.deleted.is_empty(),
        "the allocation in use is not deleted by the restart offer: {:?}",
        world.server.deleted
    );

    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    world.ping_pong("the answerer applied the restart offer")?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let now = world.now;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.ping_pong("the answerer applied its answer")?;
    let now = world.now;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.ping_pong("the offerer applied the answer")?;

    world.trickle = true;
    world.ping_pong("the new candidates were signalled")?;
    // The new generation's checks and nomination, then the retirement of the previous path.
    for round in 0..20 {
        let _ = world.run("the new generation", |_| false);
        world.ping_pong(&format!("round {round} after the restart"))?;
        if !world.server.deleted.is_empty() {
            break;
        }
    }
    let second = world.last_relay().expect("data relayed");
    assert_ne!(second, first, "data runs through the new allocation");
    let (client, _, relayed, at) = world
        .server
        .deleted
        .first()
        .copied()
        .expect("the previous allocation is deleted once the restart selected its pair");
    assert_eq!(relayed, first);
    assert_eq!(client, a(A_HOST));
    let first_on_new = world
        .server
        .relayed
        .iter()
        .find(|r| r.0 == second)
        .map(|r| r.3)
        .expect("data through the new allocation");
    assert!(first_on_new <= at, "make before break");
    let new_allocation = world
        .server
        .allocations
        .iter()
        .find(|(_, al)| al.relayed == second)
        .map(|(t, al)| (t.0, al.username.clone()))
        .expect("the new allocation lives");
    assert_eq!(new_allocation, (a(A_HOST_2), "u2".to_owned()));
    assert!(
        !world
            .server
            .rejections
            .iter()
            .any(|r| r.0 == METHOD_ALLOCATE && r.1 == 437),
        "no Allocate on a 5-tuple in use: {:?}",
        world.server.rejections
    );
    Ok(())
}

/// The fixture itself: A and B connect through the in-memory server, and data keeps flowing
/// through the one allocation for longer than a permission lasts (refreshed by the engine).
#[test]
fn a_relayed_session_runs_through_the_in_memory_server() -> Result<()> {
    let mut world = connected_world()?;
    let first = world.last_relay().expect("data relayed");
    assert_eq!(world.server.allocations.len(), 1);
    let (tuple, _) = world.server.allocations.iter().next().expect("one");
    assert_eq!(tuple.0, a(A_HOST), "allocated from the first UDP base");
    for round in 0..120 {
        let _ = world.run("idle", |_| false);
        world.ping_pong(&format!("round {round}"))?;
    }
    assert_eq!(world.last_relay(), Some(first));
    assert!(world.server.rejections.iter().all(|r| r.1 == 401));
    Ok(())
}

/// A restart with the same servers keeps the allocation (the same URL and credentials): data
/// flows at every step and nothing is deleted. Passes on 0.2.0; the control for the test above.
#[test]
fn a_restart_with_the_same_turn_credentials_keeps_its_allocation() -> Result<()> {
    let mut world = connected_world()?;
    let first = world.last_relay().expect("data relayed");
    world.peers[0].pc.restart_ice();
    world.trickle = false;
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.ping_pong("the offerer applied its restart offer")?;
    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let now = world.now;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    let now = world.now;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.trickle = true;
    for round in 0..5 {
        let _ = world.run("the new generation", |_| false);
        world.ping_pong(&format!("round {round} after the restart"))?;
    }
    assert!(
        world.server.deleted.is_empty(),
        "{:?}",
        world.server.deleted
    );
    assert_eq!(world.last_relay(), Some(first));
    Ok(())
}
