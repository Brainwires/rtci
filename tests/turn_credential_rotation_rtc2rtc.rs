//! TURN credential rotation on a long relayed session (`RTCPeerConnection::rotate_ice_servers`),
//! against an in-memory server that checks a REST username's expiry on every authenticated
//! request, as coturn's `use-auth-secret` does (`common/turn_server.rs`).
//!
//! The rules the rotation follows: new servers apply from the next gathering phase, and "if a
//! script wants this to happen immediately, it should do an ICE restart" (W3C "set the
//! configuration", RFC 9429 section 4.1.18); new credentials are a new allocation (RFC 8656
//! section 5: a request carries the allocation's own username, 441 otherwise); a second
//! allocation needs another 5-tuple (section 2.2); during the restart data continues on the
//! previous path (RFC 8445 section 9), and the allocation that is no longer wanted is deleted
//! (RFC 8656 section 8).
//!
//! Peer A (a host daemon: relay policy, one UDP socket at first) talks to peer B over the
//! relay. Time is virtual, nothing touches a network.

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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
#[path = "common/turn_server.rs"]
mod turn_server;
use turn_server::{Auth, TurnServer, rest_password};

const A_HOST: &str = "10.0.0.1:4000";
const A_HOST_2: &str = "10.0.0.1:4001";
const B_HOST: &str = "10.0.0.2:5000";
const SERVER: &str = "192.0.2.20:3478";
const SECRET: &str = "static-auth-secret";
/// How long a REST credential is valid.
const VALID: Duration = Duration::from_secs(600);
/// A message each way this often while the rotation is under way.
const TICK: Duration = Duration::from_millis(20);
/// The longest a message may take then: a lost one (the SCTP retransmission timer is a second
/// at least) or one held for a new path would take far longer.
const MAX_DELAY: Duration = Duration::from_millis(200);

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Peer {
    pc: RTCPeerConnection,
    addrs: Vec<SocketAddr>,
    states: Vec<RTCPeerConnectionState>,
    channel: Option<RTCDataChannelId>,
    channel_closed: bool,
    /// Messages received and when.
    received: Vec<(String, Instant)>,
    /// Local candidates announced, not yet given to the other peer.
    candidates: Vec<RTCIceCandidateInit>,
    events: Vec<RTCPeerConnectionEvent>,
}

impl Peer {
    fn new(now: Instant, addrs: &[&str], configuration: RTCConfiguration) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_candidate_gathering(false)
                    .build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addrs: addrs.iter().map(|s| a(s)).collect(),
            states: vec![],
            channel: None,
            channel_closed: false,
            received: vec![],
            candidates: vec![],
            events: vec![],
        })
    }

    fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
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

    fn fingerprint(&self) -> String {
        let sdp = self.pc.local_description().expect("a description").sdp;
        sdp.lines()
            .find_map(|l| l.strip_prefix("a=fingerprint:"))
            .expect("a fingerprint")
            .to_owned()
    }
}

fn turn_server(user: &str) -> Result<RTCIceServer> {
    Ok(RTCIceServer {
        urls: vec![format!("turn:{SERVER}")],
        username: user.to_owned(),
        credential: rest_password(SECRET, user)?,
    })
}

struct World {
    peers: Vec<Peer>,
    server: TurnServer,
    now: Instant,
    trickle: bool,
    /// Send times of the messages, by text.
    sent: HashMap<String, Instant>,
    next: u64,
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

    /// Moves everything that can move at the current instant.
    fn pump(&mut self) -> Result<()> {
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
                    } else if let Some(j) = self.peers.iter().position(|p| p.addrs.contains(&to))
                        && self.peers[i].addrs.contains(&from)
                    {
                        Self::deliver(&mut self.peers[j].pc, now, from, to, &w.message);
                    }
                }
            }
            for (from, to, data) in std::mem::take(&mut self.server.out) {
                moved = true;
                if let Some(j) = self.peers.iter().position(|p| p.addrs.contains(&to)) {
                    Self::deliver(&mut self.peers[j].pc, now, from, to, &data);
                }
            }
            for i in 0..2 {
                let peer = &mut self.peers[i];
                while let Some(event) = peer.pc.poll_event() {
                    moved = true;
                    match &event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            peer.states.push(*state)
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                            peer.channel = Some(*id)
                        }
                        RTCPeerConnectionEvent::OnDataChannel(
                            RTCDataChannelEvent::OnClose(_) | RTCDataChannelEvent::OnClosing(_),
                        ) => peer.channel_closed = true,
                        RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                            if let Some(mut init) =
                                ev.candidate.as_ref().and_then(|c| c.to_json().ok())
                            {
                                init.url = None;
                                peer.candidates.push(init);
                            }
                        }
                        _ => {}
                    }
                    peer.events.push(event);
                }
                while let Some(message) = peer.pc.poll_read() {
                    if let RTCMessage::DataChannelMessage(_, m) = message.message {
                        peer.received
                            .push((String::from_utf8_lossy(&m.data).into_owned(), now));
                    }
                }
            }
            if self.trickle {
                for i in 0..2 {
                    for init in std::mem::take(&mut self.peers[i].candidates) {
                        if !init.candidate.is_empty() {
                            self.peers[1 - i].pc.add_remote_candidate(init)?;
                            moved = true;
                        }
                    }
                }
            }
            if !moved {
                return Ok(());
            }
        }
    }

    /// Runs until the virtual instant `until`, the timers at most `TICK` apart.
    fn run_until(&mut self, until: Instant) -> Result<()> {
        loop {
            self.pump()?;
            if self.now >= until {
                return Ok(());
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(until);
            self.now = next
                .max(self.now + Duration::from_millis(1))
                .min(self.now + TICK)
                .min(until.max(self.now + Duration::from_millis(1)));
            for peer in self.peers.iter_mut() {
                let _ = peer.pc.handle_timeout(self.now);
            }
        }
    }

    fn send(&mut self, from: usize, text: String) -> Result<()> {
        let channel = self.peers[from].channel.expect("an open channel");
        self.sent.insert(text.clone(), self.now);
        self.peers[from]
            .pc
            .data_channel(channel)
            .expect("the channel")
            .send(self.now, BytesMut::from(text.as_bytes()))?;
        Ok(())
    }

    /// A message each way every `TICK` for `d`.
    fn stream(&mut self, d: Duration) -> Result<()> {
        let end = self.now + d;
        while self.now < end {
            for from in 0..2 {
                self.next += 1;
                let text = format!("{from}:{}", self.next);
                self.send(from, text)?;
            }
            let until = self.now + TICK;
            self.run_until(until)?;
        }
        Ok(())
    }

    /// A message each way, then `d` of virtual time; fails when one has not arrived within
    /// three seconds.
    fn ping_and_wait(&mut self, d: Duration) -> Result<()> {
        let before: Vec<usize> = self.peers.iter().map(|p| p.received.len()).collect();
        for from in 0..2 {
            self.next += 1;
            let text = format!("{from}:{}", self.next);
            self.send(from, text)?;
        }
        let until = self.now + Duration::from_secs(3);
        self.run_until(until)?;
        for (i, p) in self.peers.iter().enumerate() {
            if p.received.len() <= before[i] {
                bail!(
                    "no message reached peer {i} at {:?}",
                    self.now - self.server_start()
                );
            }
        }
        let until = self.now + d.saturating_sub(Duration::from_secs(3));
        self.run_until(until)
    }

    fn server_start(&self) -> Instant {
        self.server.start()
    }

    /// The messages sent from `from` and their delay at the other peer (`None`: never
    /// received).
    fn delays(&self) -> Vec<(String, Option<Duration>)> {
        let mut out = vec![];
        for (text, at) in &self.sent {
            let to = if text.starts_with("0:") { 1 } else { 0 };
            let got = self.peers[to]
                .received
                .iter()
                .find(|(t, _)| t == text)
                .map(|(_, r)| r.saturating_duration_since(*at));
            out.push((text.clone(), got));
        }
        out.sort();
        out
    }

    fn released(&self) -> Vec<(SocketAddr, Option<SocketAddr>)> {
        self.peers[0]
            .events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnTurnAllocationReleased {
                    local_address,
                    relayed_address,
                    ..
                } => Some((*local_address, *relayed_address)),
                _ => None,
            })
            .collect()
    }
}

/// A connected session: A (relay policy, its first REST credential, the hosts `hosts`) and B.
fn connected(hosts: &[&str]) -> Result<(World, String)> {
    common::install_crypto_provider();
    let now = Instant::now();
    let server = TurnServer::new(
        Auth::Rest {
            secret: SECRET.to_owned(),
        },
        vec![a(SERVER)],
        a(SERVER).ip(),
        now,
    );
    let user = server.rest_username(now, VALID, "host");
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![turn_server(&user)?])
        .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
        .build();
    let mut world = World {
        peers: vec![
            Peer::new(now, hosts, config)?,
            Peer::new(now, &[B_HOST], RTCConfigurationBuilder::new().build())?,
        ],
        server,
        now,
        trickle: true,
        sent: HashMap::new(),
        next: 0,
    };
    world.peers[0].pc.create_data_channel("rotation", None)?;
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
    let until = now + Duration::from_secs(5);
    world.run_until(until)?;
    assert!(
        world
            .peers
            .iter()
            .all(|p| p.connected() && p.channel.is_some()),
        "connected through the relay: {:?} / {:?}",
        world.peers[0].states,
        world.peers[1].states
    );
    Ok((world, user))
}

/// The rotation, one offer / answer round, data streaming at every step. `second_base`: the
/// application binds a second socket and adds its host candidate while the restart is staged.
fn rotate(world: &mut World, second_base: bool) -> Result<String> {
    let user = world.server.rest_username(world.now, VALID, "host");
    let now = world.now;
    world.peers[0]
        .pc
        .rotate_ice_servers(now, vec![turn_server(&user)?])?;
    world.trickle = false;
    let offer = world.peers[0].pc.create_offer(None)?;
    if second_base {
        world.peers[0].addrs.push(a(A_HOST_2));
        world.peers[0]
            .pc
            .add_local_candidate(Peer::host(a(A_HOST_2))?)?;
    }
    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.stream(Duration::from_millis(500))?;
    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    world.stream(Duration::from_millis(500))?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let now = world.now;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.stream(Duration::from_millis(500))?;
    let now = world.now;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.stream(Duration::from_millis(500))?;
    // The new generation's candidates; B kept its host candidate across the restart and
    // announces nothing, so the application re-sends it.
    world.trickle = true;
    world.peers[0]
        .pc
        .add_remote_candidate(Peer::host(a(B_HOST))?)?;
    Ok(user)
}

/// The session outlives its first REST credential: rotated at half its life with a second
/// UDP socket, the new allocation (from the new socket, the new username) takes over, the old
/// one is deleted once the new pair carries the data, and `OnTurnAllocationReleased` says the
/// first socket is free. No message is lost or delayed past `MAX_DELAY` through the rotation,
/// the DTLS association and the data channel are the same, the connection stays connected,
/// and the server never answers 437 or 441. Afterwards the session runs past the first
/// credential's expiry and the permission lifetime (300 s).
#[test]
fn a_relayed_session_outlives_its_rest_credential_rotated_with_a_second_socket() -> Result<()> {
    let (mut world, first_user) = connected(&[A_HOST])?;
    let fingerprints = [world.peers[0].fingerprint(), world.peers[1].fingerprint()];
    let start = world.server_start();
    let first_relay = world
        .server
        .allocations
        .values()
        .next()
        .map(|al| al.relayed)
        .expect("allocated");
    while world.now < start + VALID / 2 {
        world.ping_and_wait(Duration::from_secs(10))?;
    }
    let states_before: Vec<usize> = world.peers.iter().map(|p| p.states.len()).collect();
    world.sent.clear();

    let second_user = rotate(&mut world, true)?;
    let mut waited = Duration::ZERO;
    while world.released().is_empty() {
        if waited > Duration::from_secs(30) {
            bail!(
                "the first allocation was not released: allocations {:?}, deleted {:?}, rejections {:?}",
                world
                    .server
                    .allocations
                    .iter()
                    .map(|(t, al)| (t.0, al.username.clone(), al.relayed))
                    .collect::<Vec<_>>(),
                world.server.deleted,
                world.server.rejections
            );
        }
        world.stream(Duration::from_secs(1))?;
        waited += Duration::from_secs(1);
    }
    world.stream(Duration::from_secs(2))?;
    let delays = world.delays();
    let late: Vec<_> = delays
        .iter()
        .filter(|(_, d)| d.is_none_or(|d| d > MAX_DELAY))
        .collect();
    assert!(
        late.is_empty(),
        "{} of {} messages lost or late: {:?}",
        late.len(),
        delays.len(),
        late.iter().take(8).collect::<Vec<_>>()
    );

    assert_eq!(world.released(), vec![(a(A_HOST), Some(first_relay))]);
    assert!(
        world
            .server
            .deleted
            .iter()
            .any(|(client, _, relayed, _)| *client == a(A_HOST) && *relayed == first_relay),
        "{:?}",
        world.server.deleted
    );
    let live: Vec<_> = world
        .server
        .allocations
        .iter()
        .map(|(t, al)| (t.0, al.username.clone()))
        .collect();
    assert_eq!(live, vec![(a(A_HOST_2), second_user.clone())]);
    assert!(
        !world
            .server
            .rejections
            .iter()
            .any(|r| r.1 == 437 || r.1 == 441),
        "{:?}",
        world.server.rejections
    );
    assert!(!world.peers[0].events.iter().any(|e| matches!(
        e,
        RTCPeerConnectionEvent::OnTurnAllocationReplacedInPlace { .. }
    )));
    for (i, p) in world.peers.iter().enumerate() {
        assert!(!p.channel_closed, "peer {i}'s data channel stayed open");
        assert!(
            p.states[states_before[i]..]
                .iter()
                .all(|s| *s == RTCPeerConnectionState::Connected),
            "peer {i} stayed connected: {:?}",
            &p.states[states_before[i]..]
        );
        assert_eq!(
            p.fingerprint(),
            fingerprints[i],
            "the same DTLS certificate"
        );
    }

    // Past the first credential's expiry and a permission lifetime: the session runs on the
    // new allocation, whose credential is still valid.
    while world.now < start + VALID + Duration::from_secs(360) {
        world.ping_and_wait(Duration::from_secs(10))?;
    }
    assert!(
        !world
            .server
            .rejections
            .iter()
            .any(|r| r.2 == first_user || r.2 == second_user),
        "no authenticated request was refused: {:?}",
        world.server.rejections
    );
    Ok(())
}

/// With one socket the new allocation needs the old one's 5-tuple: the old one is released
/// first (break before make) and `OnTurnAllocationReplacedInPlace` says so; the session
/// continues on the new allocation after the restart, with the same data channel and DTLS
/// association, and without a 437.
#[test]
fn with_one_socket_the_rotation_breaks_before_it_makes_and_says_so() -> Result<()> {
    let (mut world, _) = connected(&[A_HOST])?;
    let start = world.server_start();
    while world.now < start + Duration::from_secs(60) {
        world.ping_and_wait(Duration::from_secs(10))?;
    }
    let second_user = rotate(&mut world, false)?;
    let until = world.now + Duration::from_secs(10);
    world.run_until(until)?;
    assert!(
        world.peers[0].events.iter().any(|e| matches!(
            e,
            RTCPeerConnectionEvent::OnTurnAllocationReplacedInPlace { local_address, .. }
                if *local_address == a(A_HOST)
        )),
        "the break before make is announced"
    );
    for _ in 0..5 {
        world.ping_and_wait(Duration::from_secs(5))?;
    }
    let live: Vec<_> = world
        .server
        .allocations
        .iter()
        .map(|(t, al)| (t.0, al.username.clone()))
        .collect();
    assert_eq!(live, vec![(a(A_HOST), second_user)]);
    assert!(
        !world
            .server
            .rejections
            .iter()
            .any(|r| r.1 == 437 || r.1 == 441)
    );
    assert!(world.peers.iter().all(|p| !p.channel_closed));
    Ok(())
}

/// Without a rotation the credential expires and the server refuses the next authenticated
/// request on the allocation with 401: the engine raises `OnTurnRequestRejected` with the
/// request and the code (the warning an application without a REST-aware schedule gets).
#[test]
fn an_expired_rest_credential_is_reported_when_the_server_refuses_it() -> Result<()> {
    let (mut world, _) = connected(&[A_HOST])?;
    let start = world.server_start();
    let until = start + VALID + Duration::from_secs(400);
    world.run_until(until)?;
    let rejected: Vec<_> = world.peers[0]
        .events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnTurnRequestRejected {
                method,
                error_code,
                relay,
                ..
            } => Some((*method, *error_code, relay.is_some())),
            _ => None,
        })
        .collect();
    assert!(
        rejected.iter().any(|(m, c, r)| *c == 401
            && *r
            && ["Refresh", "CreatePermission", "ChannelBind"].contains(m)),
        "{rejected:?}; server rejections {:?}",
        world.server.rejections
    );
    Ok(())
}
