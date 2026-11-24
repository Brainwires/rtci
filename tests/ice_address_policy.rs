//! The embedder's address policy at the peer connection
//! (`SettingEngineBuilder::with_ice_address_policy`, an `IceAddressPolicy`): one predicate over
//! an address, its direction and its purpose, asked wherever an address enters the ICE agent
//! or the peer connection's stream, TURN and server-reflexive code. What it refuses is never
//! answered, learned, paired, contacted or taken in; with the "relay" ICE transport policy no
//! host address is used or revealed.
//!
//! No network: peers exchange datagrams in memory, servers and drivers are the test, and the
//! clock is virtual.

mod common;

use anyhow::Result;
use bytes::BytesMut;
use rtci::ice::attributes::priority::PriorityAttr;
use rtci::ice::{AddressDirection, AddressPurpose, IceAddressPolicy};
use rtci::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtci::peer_connection::configuration::{
    RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy,
};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCIceConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::stream::{StreamCommand, StreamEvent};
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::attributes::ATTR_USERNAME;
use rtci::stun::fingerprint::FINGERPRINT;
use rtci::stun::integrity::MessageIntegrity;
use rtci::stun::message::{BINDING_REQUEST, Message, Setter, TransactionId};
use rtci::stun::textattrs::Username;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn candidate(line: &str) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: format!("candidate:{line}"),
        // The one media section (the data channel's).
        sdp_mline_index: Some(0),
        ..Default::default()
    }
}

fn host(addr: SocketAddr) -> RTCIceCandidateInit {
    candidate(&format!(
        "1 1 udp 2130706431 {} {} typ host",
        addr.ip(),
        addr.port()
    ))
}

/// A policy refusing the IP addresses `refused` for `purpose`, everything else allowed.
fn refusing(refused: &[&str], purpose: AddressPurpose) -> IceAddressPolicy {
    let refused: Vec<IpAddr> = refused.iter().map(|s| s.parse().unwrap()).collect();
    IceAddressPolicy::new(move |addr, _, p| !(p == purpose && refused.contains(&addr.ip())))
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
    }
}

/// An embedder's "no private addresses" policy: servers anywhere, peers public only, in both
/// directions.
fn no_private_peers() -> IceAddressPolicy {
    IceAddressPolicy::new(|addr, direction, purpose| {
        assert_eq!(direction, purpose.direction());
        purpose == AddressPurpose::StunTurnServer || !is_private(addr.ip())
    })
}

fn pc(configuration: RTCConfiguration, settings: SettingEngine, now: Instant) -> RTCPeerConnection {
    common::install_crypto_provider();
    RTCPeerConnectionBuilder::new()
        .with_configuration(configuration)
        .with_setting_engine(settings)
        .build(now)
        .unwrap()
}

fn ice_line<'a>(sdp: &'a str, attribute: &str) -> &'a str {
    sdp.lines()
        .find_map(|l| l.strip_prefix(attribute))
        .unwrap_or_else(|| panic!("no {attribute} in {sdp}"))
        .trim()
}

/// An authenticated Binding request of `remote` to `pc` (RFC 8445 Section 7.2.2), without a
/// role attribute so that no role conflict is in play.
fn binding_request(pc: &RTCPeerConnection, remote: &RTCPeerConnection) -> Vec<u8> {
    let local = pc.local_description().expect("local description").sdp;
    let theirs = remote
        .local_description()
        .expect("remote's description")
        .sdp;
    let username = format!(
        "{}:{}",
        ice_line(&local, "a=ice-ufrag:"),
        ice_line(&theirs, "a=ice-ufrag:")
    );
    let provider = rtci::crypto::default_provider().unwrap();
    let mut m = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(PriorityAttr(1_845_501_695)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            ice_line(&local, "a=ice-pwd:").to_owned(),
            provider.crypto(),
        )),
        Box::new(FINGERPRINT),
    ];
    m.build(&setters).unwrap();
    m.raw
}

fn udp(local: SocketAddr, peer: SocketAddr, now: Instant, message: &[u8]) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: local,
            peer_addr: peer,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(message),
    }
}

fn connected(pc: &RTCPeerConnection) -> bool {
    matches!(
        pc.ice_connection_state(),
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
    )
}

/// One peer of an in-memory run: everything it wrote and every event it raised.
struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    written: Vec<TaggedBytesMut>,
    events: Vec<RTCPeerConnectionEvent>,
}

impl Peer {
    fn new(pc: RTCPeerConnection, addr: &str) -> Self {
        Self {
            pc,
            addr: a(addr),
            written: vec![],
            events: vec![],
        }
    }

    /// Takes its events and reads, returns what it writes now.
    fn turn(&mut self) -> Vec<TaggedBytesMut> {
        while let Some(e) = self.pc.poll_event() {
            self.events.push(e);
        }
        while self.pc.poll_read().is_some() {}
        let out: Vec<TaggedBytesMut> = std::iter::from_fn(|| self.pc.poll_write()).collect();
        for w in &out {
            self.written.push(TaggedBytesMut {
                now: w.now,
                transport: w.transport,
                message: w.message.clone(),
            });
        }
        out
    }

    /// The candidates it signalled (`icecandidate`), as `a=candidate` values.
    fn signalled(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev.candidate.as_ref(),
                _ => None,
            })
            .filter(|c| !c.end_of_candidates)
            .filter_map(|c| c.to_json().ok())
            .map(|c| c.candidate)
            .collect()
    }
}

/// Offer from `offerer`, answer from `answerer`.
fn negotiate(offerer: &mut Peer, answerer: &mut Peer, now: Instant) -> Result<()> {
    offerer.pc.create_data_channel("policy", None)?;
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer.pc.set_remote_description(now, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;
    Ok(())
}

/// Moves time on to the next timer of either peer; false when none is due before `deadline`.
fn tick(x: &mut Peer, y: &mut Peer, now: &mut Instant, deadline: Instant) -> bool {
    let next = [x.pc.poll_timeout(), y.pc.poll_timeout()]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(deadline)
        .max(*now + Duration::from_millis(1));
    if next >= deadline {
        return false;
    }
    *now = next;
    x.pc.handle_timeout(*now).unwrap();
    y.pc.handle_timeout(*now).unwrap();
    true
}

/// The offerer sits behind a NAT that maps its host address to `NAT`; the answerer is given
/// none of its candidates and meets it only as the source of its checks (a peer-reflexive
/// candidate, RFC 8445 Section 7.3.1.3). `refuse_nat` makes the answerer's policy refuse that
/// source as an inbound datagram source. Returns (offerer, answerer, checks the answerer got).
fn behind_a_nat(refuse_nat: bool) -> Result<(Peer, Peer, usize)> {
    const NAT: &str = "198.51.100.7:40000";
    let start = Instant::now();
    let refused = if refuse_nat {
        "198.51.100.7"
    } else {
        "203.0.113.99"
    };
    let mut o = Peer::new(
        pc(
            RTCConfigurationBuilder::new().build(),
            SettingEngine::default(),
            start,
        ),
        "10.0.0.1:4000",
    );
    let mut b = Peer::new(
        pc(
            RTCConfigurationBuilder::new().build(),
            SettingEngineBuilder::new()
                .with_ice_address_policy(refusing(
                    &[refused],
                    AddressPurpose::InboundDatagramSource,
                ))
                .build(),
            start,
        ),
        "192.0.2.30:5000",
    );
    negotiate(&mut o, &mut b, start)?;
    o.pc.add_local_candidate(host(o.addr))?;
    b.pc.add_local_candidate(host(b.addr))?;
    o.pc.add_remote_candidate(host(b.addr))?;

    let mut now = start;
    let deadline = start + Duration::from_secs(15);
    let mut checks = 0;
    loop {
        for w in o.turn() {
            if w.transport.peer_addr == b.addr {
                checks += 1;
                b.pc.handle_read(udp(b.addr, a(NAT), now, &w.message))?;
            }
        }
        for w in b.turn() {
            if w.transport.peer_addr == a(NAT) {
                o.pc.handle_read(udp(o.addr, b.addr, now, &w.message))?;
            }
        }
        if !tick(&mut o, &mut b, &mut now, deadline) {
            break;
        }
    }
    Ok((o, b, checks))
}

/// A Binding request from a source the policy refuses gets no answer out of `poll_write`, and
/// the source is not learned, so ICE never connects; the same peer from an allowed source
/// (the policy refusing another address) is answered and connects.
#[test]
fn a_denied_sources_checks_get_no_answer_from_poll_write_and_an_allowed_one_connects() -> Result<()>
{
    let nat = a("198.51.100.7:40000");
    let (_, b, checks) = behind_a_nat(true)?;
    assert!(checks > 0, "the offerer's checks reached the answerer");
    let to_nat = b
        .written
        .iter()
        .filter(|w| w.transport.peer_addr == nat)
        .count();
    assert_eq!(to_nat, 0, "nothing leaves poll_write for a refused source");
    assert!(!connected(&b.pc), "no pair with a refused source");

    let (o, b, _) = behind_a_nat(false)?;
    assert!(
        b.written.iter().any(|w| w.transport.peer_addr == nat),
        "an allowed source is answered"
    );
    assert!(connected(&b.pc) && connected(&o.pc), "and connects");
    Ok(())
}

/// A signalled remote candidate on an address the policy refuses is "administratively
/// prohibited" (W3C webrtc-pc 4.4.2): `addIceCandidate` succeeds and the candidate is in the
/// remote description, but no check is ever sent there. Another candidate is checked.
#[test]
fn a_denied_remote_candidate_is_added_but_never_checked() -> Result<()> {
    let start = Instant::now();
    let mut o = Peer::new(
        pc(
            RTCConfigurationBuilder::new().build(),
            SettingEngine::default(),
            start,
        ),
        "192.0.2.31:4000",
    );
    let mut b = Peer::new(
        pc(
            RTCConfigurationBuilder::new().build(),
            SettingEngineBuilder::new()
                .with_ice_address_policy(refusing(
                    &["198.51.100.8"],
                    AddressPurpose::RemoteCandidate,
                ))
                .build(),
            start,
        ),
        "192.0.2.30:5000",
    );
    negotiate(&mut o, &mut b, start)?;
    b.pc.add_local_candidate(host(b.addr))?;
    b.turn();
    b.pc.add_remote_candidate(host(a("198.51.100.8:5000")))?;
    b.pc.add_remote_candidate(host(a("198.51.100.9:5000")))?;
    assert!(
        b.pc.remote_description()
            .expect("offer")
            .sdp
            .contains("198.51.100.8 5000 typ host"),
        "the refused candidate is in the remote description, as if added"
    );
    let mut now = start;
    let deadline = start + Duration::from_secs(5);
    loop {
        b.turn();
        o.turn();
        if !tick(&mut o, &mut b, &mut now, deadline) {
            break;
        }
    }
    let sent: Vec<SocketAddr> = b.written.iter().map(|w| w.transport.peer_addr).collect();
    assert!(sent.contains(&a("198.51.100.9:5000")), "{sent:?}");
    assert!(!sent.contains(&a("198.51.100.8:5000")), "{sent:?}");
    Ok(())
}

/// One peer connection with an ICE server, whose driver the test plays: streams served and
/// names resolved by hand.
struct Gatherer {
    pc: RTCPeerConnection,
    now: Instant,
    written: Vec<TaggedBytesMut>,
    commands: Vec<StreamCommand>,
}

impl Gatherer {
    fn new(server: RTCIceServer, policy: IceAddressPolicy) -> Result<Self> {
        let now = Instant::now();
        let mut pc = pc(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![server])
                .build(),
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .with_ice_address_policy(policy)
                .build(),
            now,
        );
        pc.create_data_channel("gather", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer.clone())?;
        let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
        answerer.set_remote_description(now, offer)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        pc.set_remote_description(now, answer)?;
        Ok(Self {
            pc,
            now,
            written: vec![],
            commands: vec![],
        })
    }

    fn pump(&mut self) {
        loop {
            let mut moved = false;
            while let Some(w) = self.pc.poll_write() {
                self.written.push(w);
                moved = true;
            }
            while let Some(c) = self.pc.poll_stream_command() {
                self.commands.push(c);
                moved = true;
            }
            while self.pc.poll_stream_transmit().is_some() {
                moved = true;
            }
            while self.pc.poll_event().is_some() {
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    fn run_for(&mut self, span: Duration) {
        let until = self.now + span;
        loop {
            self.pump();
            match self.pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now + Duration::from_micros(1));
                    self.pc.handle_timeout(self.now).unwrap();
                }
                _ => break,
            }
        }
        self.now = until;
        self.pc.handle_timeout(self.now).unwrap();
        self.pump();
    }

    /// Answers the name query with `addresses`.
    fn resolve(&mut self, addresses: Vec<SocketAddr>) -> Result<()> {
        let query = self
            .commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Resolve { query, .. } => Some(*query),
                _ => None,
            })
            .expect("the server's name goes to the driver");
        self.pc.handle_stream_event(
            self.now,
            StreamEvent::Resolved {
                query,
                addresses: addresses.clone(),
            },
        )?;
        self.pump();
        Ok(())
    }

    fn sent_to(&self, to: SocketAddr) -> usize {
        self.written
            .iter()
            .filter(|w| w.transport.peer_addr == to)
            .count()
    }

    fn touched(&self, to: SocketAddr) -> bool {
        self.sent_to(to) > 0
            || self
                .commands
                .iter()
                .any(|c| matches!(c, StreamCommand::Connect { remote, .. } if *remote == to))
    }
}

/// A STUN server's addresses after its name resolves: one the policy refuses is never sent a
/// Binding request, the other is; a literal server address the policy refuses is never
/// contacted either.
#[test]
fn a_denied_stun_server_address_is_not_contacted_after_resolution() -> Result<()> {
    let denied = a("192.0.2.66:3478");
    let allowed = a("192.0.2.10:3478");
    let policy = || refusing(&["192.0.2.66"], AddressPurpose::StunTurnServer);
    let mut g = Gatherer::new(
        RTCIceServer {
            urls: vec!["stun:stun.example.org:3478".to_owned()],
            ..Default::default()
        },
        policy(),
    )?;
    g.pc.add_local_candidate(host(a("10.0.0.1:4000")))?;
    g.pump();
    g.resolve(vec![denied, allowed])?;
    g.run_for(Duration::from_secs(5));
    assert!(!g.touched(denied), "the refused address is sent nothing");
    assert!(g.sent_to(allowed) > 0, "the allowed address is asked");

    let mut g = Gatherer::new(
        RTCIceServer {
            urls: vec!["stun:192.0.2.66:3478".to_owned()],
            ..Default::default()
        },
        policy(),
    )?;
    g.pc.add_local_candidate(host(a("10.0.0.1:4000")))?;
    g.run_for(Duration::from_secs(5));
    assert!(
        !g.touched(denied),
        "a refused literal address is sent nothing"
    );
    Ok(())
}

/// A TURN server's addresses after its name resolves: the Allocate never goes to one the
/// policy refuses, it goes to the other.
#[test]
fn a_denied_turn_server_address_is_not_contacted_after_resolution() -> Result<()> {
    let denied = a("192.0.2.66:3478");
    let allowed = a("192.0.2.20:3478");
    let mut g = Gatherer::new(
        RTCIceServer {
            urls: vec!["turn:turn.example.org:3478".to_owned()],
            username: "user".to_owned(),
            credential: "pass".to_owned(),
        },
        refusing(&["192.0.2.66"], AddressPurpose::StunTurnServer),
    )?;
    g.pc.add_local_candidate(host(a("10.0.0.1:4000")))?;
    g.pump();
    g.resolve(vec![denied, allowed])?;
    g.run_for(Duration::from_secs(5));
    assert!(!g.touched(denied), "the refused address is sent nothing");
    assert!(
        g.sent_to(allowed) > 0,
        "the Allocate goes to the allowed one"
    );
    Ok(())
}

/// "relay" ICE transport policy (W3C webrtc-pc 4.2.5) plus a policy refusing private peer
/// addresses: the peer connection uses its relayed candidate only. It connects through it;
/// it signals no host candidate and no related address (RFC 8827 section 6.4); nothing
/// leaves from its host address, even to answer a check that reached the host socket; nothing
/// goes to the peer's private candidate or answers a check from a private source.
#[test]
fn relay_only_with_a_policy_neither_uses_nor_reveals_a_host_address() -> Result<()> {
    const HOST: &str = "10.0.0.1:4000";
    const RELAYED: &str = "192.0.2.20:50099";
    const PEER_PRIVATE: &str = "10.0.0.2:5000";
    let start = Instant::now();
    let mut r = Peer::new(
        pc(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build(),
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .with_ice_address_policy(no_private_peers())
                .build(),
            start,
        ),
        RELAYED,
    );
    let mut p = Peer::new(
        pc(
            RTCConfigurationBuilder::new().build(),
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .build(),
            start,
        ),
        "198.51.100.9:5000",
    );
    negotiate(&mut r, &mut p, start)?;
    // The application gathers: a host candidate (refused by the relay policy) and the relayed
    // candidate of its own TURN client.
    r.pc.add_local_candidate(host(a(HOST)))?;
    r.pc.add_local_candidate(candidate(&format!(
        "9 1 udp 16777215 192.0.2.20 50099 typ relay raddr {} rport {}",
        a(HOST).ip(),
        a(HOST).port()
    )))?;
    p.pc.add_local_candidate(host(p.addr))?;
    r.turn();
    for c in r.signalled() {
        p.pc.add_remote_candidate(candidate(c.trim_start_matches("candidate:")))?;
    }
    r.pc.add_remote_candidate(host(p.addr))?;
    r.pc.add_remote_candidate(host(a(PEER_PRIVATE)))?;

    let mut now = start;
    let deadline = start + Duration::from_secs(15);
    loop {
        for w in r.turn() {
            // The TURN server relays what leaves the relayed candidate.
            if w.transport.local_addr == r.addr
                && (w.transport.peer_addr == p.addr || w.transport.peer_addr == a(PEER_PRIVATE))
            {
                p.pc.handle_read(udp(p.addr, r.addr, now, &w.message))?;
            }
        }
        for w in p.turn() {
            if w.transport.peer_addr == r.addr {
                r.pc.handle_read(udp(r.addr, p.addr, now, &w.message))?;
                // The same check reaching the host socket directly, and the relayed address
                // from a private source.
                r.pc.handle_read(udp(a(HOST), p.addr, now, &w.message))?;
                r.pc.handle_read(udp(r.addr, a(PEER_PRIVATE), now, &w.message))?;
            }
        }
        if !tick(&mut r, &mut p, &mut now, deadline) {
            break;
        }
    }
    let probe = binding_request(&r.pc, &p.pc);
    r.pc.handle_read(udp(a(HOST), a("198.51.100.10:6000"), now, &probe))?;
    r.pc.handle_read(udp(r.addr, a(PEER_PRIVATE), now, &probe))?;
    r.turn();

    assert!(connected(&r.pc), "the relayed path connects");
    for w in &r.written {
        assert_ne!(
            w.transport.local_addr,
            a(HOST),
            "a datagram left from the host address"
        );
        assert!(
            !is_private(w.transport.peer_addr.ip()),
            "a datagram went to a private address: {}",
            w.transport.peer_addr
        );
    }
    let signalled = r.signalled();
    assert!(!signalled.is_empty());
    for c in &signalled {
        assert!(c.contains("typ relay"), "only the relayed candidate: {c}");
        assert!(
            !c.contains("10.0.0.1"),
            "the host address is not revealed: {c}"
        );
    }
    Ok(())
}

/// ICE-TCP (RFC 6544): a connection the driver accepted from a source the policy refuses is
/// not taken; one from an allowed source is, and a check on it is answered. Once the policy
/// refuses that source, its stream data is dropped unanswered and the connection reset.
#[test]
fn ice_tcp_stream_data_from_a_denied_source_is_dropped() -> Result<()> {
    let now = Instant::now();
    let cut = Arc::new(AtomicBool::new(false));
    let flag = cut.clone();
    let policy = IceAddressPolicy::new(move |addr, direction, purpose| {
        let refused = addr.ip() == "203.0.113.66".parse::<IpAddr>().unwrap()
            || (flag.load(Ordering::SeqCst)
                && addr.ip() == "198.51.100.9".parse::<IpAddr>().unwrap());
        !(direction == AddressDirection::Inbound
            && purpose == AddressPurpose::InboundDatagramSource
            && refused)
    });
    let mut pc = pc(
        RTCConfigurationBuilder::new().build(),
        SettingEngineBuilder::new()
            .with_ice_address_policy(policy)
            .build(),
        now,
    );
    pc.create_data_channel("tcp", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    pc.set_remote_description(now, answer)?;
    pc.add_local_candidate(host(a("10.0.0.1:4000")))?;
    let mut listens = vec![];
    while let Some(c) = pc.poll_stream_command() {
        if let StreamCommand::Listen {
            listener, local, ..
        } = c
        {
            listens.push((listener, local));
        }
    }
    assert!(!listens.is_empty(), "the engine listens for ICE-TCP");
    let mut bound = vec![];
    for (i, (listener, local)) in listens.into_iter().enumerate() {
        let at = SocketAddr::new(local.ip(), 6000 + i as u16);
        pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: at,
            },
        )?;
        bound.push((listener, at));
    }
    while pc.poll_event().is_some() {}
    let (listener, local) = bound[0];

    assert_eq!(
        pc.handle_stream_accepted(now, listener, local, a("203.0.113.66:40001")),
        None,
        "a connection from a refused source is not taken"
    );
    let id = pc
        .handle_stream_accepted(now, listener, local, a("198.51.100.9:40002"))
        .expect("a connection from an allowed source is taken");

    let framed = |m: &[u8]| {
        let mut f = (m.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(m);
        f
    };
    let request = binding_request(&pc, &answerer);
    pc.handle_stream_read(now, id, &framed(&request))?;
    let answered = std::iter::from_fn(|| pc.poll_stream_transmit()).any(|t| t.id == id);
    assert!(answered, "a check on an allowed connection is answered");

    cut.store(true, Ordering::SeqCst);
    let request = binding_request(&pc, &answerer);
    pc.handle_stream_read(now, id, &framed(&request))?;
    let answered = std::iter::from_fn(|| pc.poll_stream_transmit()).any(|t| t.id == id);
    assert!(!answered, "data from a refused source is not answered");
    let reset = std::iter::from_fn(|| pc.poll_stream_command())
        .any(|c| matches!(c, StreamCommand::Reset { id: r } if r == id));
    assert!(reset, "the connection is reset");
    Ok(())
}
