//! TURN over plain UDP run by the engine (RFC 8656; `turn:` servers of the configuration), on
//! the application's UDP socket: the Allocate and everything after it leave through
//! `poll_write` from the host candidate's base, the server's answers are taken out of
//! `handle_read` before ICE sees them. The server is scripted by the test; there is no
//! network and the clock is virtual.

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::{RTCIceCandidateInit, RTCIceServerTransportProtocol};
use rtc::peer_connection::turn_streams::RelayGathering;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::stream::{StreamCommand, StreamEvent};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM};
use rtc::stun::error_code::{CODE_UNAUTHORIZED, ErrorCodeAttribute};
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter,
    METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_DATA, METHOD_REFRESH,
    METHOD_SEND, Message, MessageClass, MessageType, Setter, TransactionId,
};
use rtc::stun::textattrs::{Nonce, Realm};
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::proto::chandata::ChannelData;
use rtc::turn::proto::data::Data;
use rtc::turn::proto::lifetime::Lifetime;
use rtc::turn::proto::peeraddr::PeerAddress;
use rtc::turn::proto::relayaddr::RelayedAddress;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
mod dtls_sdp_common;

const HOST: &str = "10.0.0.1:4000";
const HOST6: &str = "[2001:db8::1]:4000";
const SERVER: &str = "192.0.2.20:3478";
const SERVER6: &str = "[2001:db8::20]:3478";
const RELAYED: &str = "192.0.2.20:50000";
const RELAYED6: &str = "192.0.2.20:50006";
const USER: &str = "user";
const PASS: &str = "pass";
const REALM: &str = "rtc.test";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The scripted TURN server: one or two addresses, a long-term credential unless
/// `open` (RFC 8155 section 9: no authentication).
struct Server {
    key: Vec<u8>,
    open: bool,
    /// Every datagram the engine sent to one of the server's addresses: (to, message).
    requests: Vec<(SocketAddr, Message)>,
    /// ChannelData the engine sent: (to, data).
    channel_data: Vec<(SocketAddr, Vec<u8>)>,
    /// The engine's base each of `requests` came from.
    sources: Vec<SocketAddr>,
    /// Each base gets an allocation on a relayed address of its own: the relayed port is
    /// `RELAYED`'s plus the base's port less 4000 (`HOST`'s).
    relay_per_base: bool,
    /// Addresses whose requests are held unanswered until `release`.
    silent: HashSet<SocketAddr>,
    held: Vec<(SocketAddr, SocketAddr, Message)>,
    /// What the server sends back: (from server address, to base, bytes).
    out: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
}

impl Server {
    fn new() -> Result<Self> {
        let provider = rtc::crypto::default_provider()?;
        let key = MessageIntegrity::long_term_integrity_key(
            USER.to_owned(),
            REALM.to_owned(),
            PASS.to_owned(),
            provider.crypto(),
        )?;
        Ok(Self {
            key,
            open: false,
            requests: vec![],
            sources: vec![],
            relay_per_base: false,
            channel_data: vec![],
            silent: HashSet::new(),
            held: vec![],
            out: vec![],
        })
    }

    fn reply(
        &self,
        request: &Message,
        class: MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        sign: bool,
    ) -> Result<Vec<u8>> {
        let provider = rtc::crypto::default_provider()?;
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, class)),
        ];
        setters.extend(attrs);
        if sign {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                self.key.clone(),
                provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut m = Message::new();
        m.build(&setters)?;
        Ok(m.raw)
    }

    fn answer(&self, to: SocketAddr, from: SocketAddr, request: &Message) -> Result<Vec<u8>> {
        let signed = request.contains(ATTR_MESSAGE_INTEGRITY);
        if !signed && !self.open {
            return self.reply(
                request,
                CLASS_ERROR_RESPONSE,
                vec![
                    Box::new(ErrorCodeAttribute {
                        code: CODE_UNAUTHORIZED,
                        reason: b"Unauthorized".to_vec(),
                    }),
                    Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
                    Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
                ],
                false,
            );
        }
        let attrs: Vec<Box<dyn Setter>> = match request.typ.method {
            METHOD_ALLOCATE => {
                let mut relay = a(if to == a(SERVER6) { RELAYED6 } else { RELAYED });
                if self.relay_per_base {
                    relay.set_port(relay.port() + from.port().saturating_sub(4000));
                }
                vec![
                    Box::new(RelayedAddress {
                        ip: relay.ip(),
                        port: relay.port(),
                    }),
                    Box::new(XorMappedAddress {
                        ip: from.ip(),
                        port: from.port(),
                    }),
                    Box::new(Lifetime(Duration::from_secs(600))),
                ]
            }
            METHOD_REFRESH => {
                let mut lifetime = Lifetime::default();
                let _ = lifetime.get_from(request);
                vec![Box::new(lifetime)]
            }
            _ => vec![],
        };
        self.reply(request, CLASS_SUCCESS_RESPONSE, attrs, signed)
    }

    /// Reads a datagram the engine sent from `from` to `to`.
    fn read(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) -> Result<()> {
        if ChannelData::is_channel_data(data) {
            self.channel_data.push((to, data.to_vec()));
            return Ok(());
        }
        let mut m = Message::new();
        m.unmarshal_binary(data)?;
        self.requests.push((to, m.clone()));
        self.sources.push(from);
        if m.typ.class != CLASS_REQUEST {
            return Ok(());
        }
        if self.silent.contains(&to) {
            self.held.push((to, from, m));
            return Ok(());
        }
        let reply = self.answer(to, from, &m)?;
        self.out.push((to, from, reply));
        Ok(())
    }

    /// Answers what `addr` held back.
    fn release(&mut self, addr: SocketAddr) -> Result<()> {
        self.silent.remove(&addr);
        for (to, from, m) in std::mem::take(&mut self.held) {
            if to == addr {
                let reply = self.answer(to, from, &m)?;
                self.out.push((to, from, reply));
            } else {
                self.held.push((to, from, m));
            }
        }
        Ok(())
    }

    fn requests_of(&self, method: rtc::stun::message::Method) -> Vec<(SocketAddr, Message)> {
        self.requests
            .iter()
            .filter(|(_, m)| m.typ.method == method && m.typ.class == CLASS_REQUEST)
            .cloned()
            .collect()
    }
}

struct Harness {
    pc: RTCPeerConnection,
    server: Server,
    now: Instant,
    events: Vec<RTCPeerConnectionEvent>,
    /// Datagrams to anyone but the server.
    other: Vec<TaggedBytesMut>,
    /// The server's addresses, for the routing of the engine's datagrams.
    addresses: Vec<SocketAddr>,
}

impl Harness {
    fn new(url: &str) -> Result<Self> {
        Self::with(
            url,
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .build(),
            vec![a(SERVER)],
        )
    }

    /// The engine with the TURN server of `url`, its offer answered by a second peer
    /// connection (so a peer's checks can be answered).
    fn with(url: &str, settings: SettingEngine, addresses: Vec<SocketAddr>) -> Result<Self> {
        common::install_crypto_provider();
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![url.to_owned()],
                        username: USER.to_owned(),
                        credential: PASS.to_owned(),
                    }])
                    .build(),
            )
            .with_setting_engine(settings)
            .build(now)?;
        pc.create_data_channel("turn-udp", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer.clone())?;
        let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
        answerer.set_remote_description(now, offer.clone())?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        pc.set_remote_description(now, answer.clone())?;
        Ok(Self {
            pc,
            server: Server::new()?,
            now,
            events: vec![],
            other: vec![],
            addresses,
        })
    }

    fn add_host(&mut self, host: &str) -> Result<()> {
        let host = a(host);
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: format!(
                "candidate:1 1 udp 2130706431 {} {} typ host",
                host.ip(),
                host.port()
            ),
            ..Default::default()
        })?;
        Ok(())
    }

    /// The application's own relayed candidate for the server (its own TURN client).
    fn add_application_relay(&mut self, url: Option<&str>) -> Result<()> {
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:9 1 udp 16777215 192.0.2.20 50099 typ relay raddr 10.0.0.1 \
                        rport 4000"
                .to_owned(),
            url: url.map(str::to_owned),
            ..Default::default()
        })?;
        Ok(())
    }

    fn deliver(&mut self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.pc.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: to,
                peer_addr: from,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&data[..]),
        })?;
        Ok(())
    }

    /// Moves datagrams both ways and the timers on, until nothing moves or `until`.
    fn run(&mut self, until: Instant) -> Result<()> {
        loop {
            let mut moved = false;
            while let Some(w) = self.pc.poll_write() {
                moved = true;
                if self.addresses.contains(&w.transport.peer_addr) {
                    assert_eq!(w.transport.transport_protocol, TransportProtocol::UDP);
                    self.server
                        .read(w.transport.local_addr, w.transport.peer_addr, &w.message)?;
                } else {
                    self.other.push(w);
                }
            }
            for (from, to, data) in std::mem::take(&mut self.server.out) {
                moved = true;
                self.deliver(from, to, data)?;
            }
            while let Some(e) = self.pc.poll_event() {
                self.events.push(e);
                moved = true;
            }
            if moved {
                continue;
            }
            match self.pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now + Duration::from_micros(1));
                    self.pc.handle_timeout(self.now)?;
                }
                _ => return Ok(()),
            }
        }
    }

    /// The relayed candidates announced, with their URL and relay protocol.
    fn relayed(&self) -> Vec<(String, Option<String>, RTCIceServerTransportProtocol)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                    let c = ev.candidate.as_ref()?;
                    let init = c.to_json().ok()?;
                    init.candidate
                        .contains("typ relay")
                        .then(|| (init.candidate, ev.url.clone(), c.relay_protocol))
                }
                _ => None,
            })
            .collect()
    }

    /// A Data indication from the server: `data` from `peer`, relayed.
    fn data_indication(peer: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        let mut m = Message::new();
        m.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(Data(data.to_vec())),
            Box::new(FINGERPRINT),
        ])?;
        Ok(m.raw)
    }

    fn gathering_complete(&self) -> bool {
        self.pc.ice_gathering_state() == RTCIceGatheringState::Complete
    }
}

/// RFC 8656 sections 3.1 and 7, RFC 8445 section 5.1.1.2: with a `turn:` server over UDP the
/// engine allocates from the host candidate's base on the application's socket (the 401
/// exchange, then the signed Allocate), announces the relayed candidate with `relayProtocol`
/// "udp" and the server's URL, and the end of gathering waits for it.
#[test]
fn a_turn_server_over_udp_is_allocated_on_by_the_engine_from_the_host_candidate() -> Result<()> {
    let mut h = Harness::new(&format!("turn:{SERVER}"))?;
    h.add_host(HOST)?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    assert!(
        !h.gathering_complete(),
        "the end of gathering waits for the allocation"
    );
    h.run(h.now + Duration::from_secs(5))?;
    let allocates = h.server.requests_of(METHOD_ALLOCATE);
    assert_eq!(
        allocates.len(),
        2,
        "the 401 exchange, then the signed request"
    );
    assert!(!allocates[0].1.contains(ATTR_MESSAGE_INTEGRITY));
    assert!(allocates[1].1.contains(ATTR_MESSAGE_INTEGRITY));
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    let (candidate, url, protocol) = &relayed[0];
    assert!(
        candidate.contains("192.0.2.20 50000 typ relay raddr 10.0.0.1 rport 4000"),
        "{candidate}"
    );
    assert_eq!(url.as_deref(), Some("turn:192.0.2.20:3478?transport=udp"));
    assert_eq!(*protocol, RTCIceServerTransportProtocol::Udp);
    assert!(h.gathering_complete());
    Ok(())
}

/// RFC 8656 sections 9 to 12, RFC 8445 section 5.1.1.2: two peer connections connect through
/// the engine's allocation alone. A has the relay policy and a `turn:` server; the scripted
/// server relays for it (Send indications and ChannelData out, Data indications in) to B,
/// which has its host candidate only. A's checks leave through the allocation once a
/// CreatePermission for B's address was granted, nothing of A's leaves around the server, and
/// the data channel opens.
#[test]
fn two_peers_connect_through_the_engine_udp_allocation() -> Result<()> {
    use dtls_sdp_common::{Peer, World};
    use rtc::peer_connection::configuration::RTCIceTransportPolicy;
    use rtc::peer_connection::event::RTCDataChannelEvent;
    common::install_crypto_provider();
    let b_addr = a("10.0.0.2:5000");
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec![format!("turn:{SERVER}")],
            username: USER.to_owned(),
            credential: PASS.to_owned(),
        }])
        .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
        .build();
    let mut world = World::new(
        Peer::with_configuration(HOST, config, SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("relayed", None)?;
    world.exchange(0)?;
    let host_a = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(host_a)?;
    let host_b = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(host_b.clone())?;
    world.peers[0].pc.add_remote_candidate(host_b)?;

    let mut server = Server::new()?;
    // Channels the engine bound: number to peer.
    let mut channels: Vec<(u16, SocketAddr)> = vec![];
    let mut around = 0usize;
    let mut now = world.now;
    let end = now + Duration::from_secs(30);
    let mut opened = [false, false];
    let read = |pc: &mut RTCPeerConnection, now, local, peer, data: &[u8]| {
        let _ = pc.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: local,
                peer_addr: peer,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(data),
        });
    };
    while now < end && !(opened[0] && opened[1]) {
        // A: everything to the server; anything else goes around it.
        while let Some(w) = world.peers[0].pc.poll_write() {
            if w.transport.peer_addr != a(SERVER) {
                around += 1;
                continue;
            }
            let data = w.message.to_vec();
            if ChannelData::is_channel_data(&data) {
                let mut cd = ChannelData {
                    raw: data.clone(),
                    ..Default::default()
                };
                cd.decode()?;
                if let Some((_, peer)) = channels.iter().find(|(n, _)| *n == cd.number.0) {
                    read(&mut world.peers[1].pc, now, *peer, a(RELAYED), &cd.data);
                }
                continue;
            }
            let mut m = Message::new();
            m.unmarshal_binary(&data)?;
            if m.typ.method == METHOD_SEND && m.typ.class == CLASS_INDICATION {
                let mut peer = PeerAddress::default();
                peer.get_from(&m)?;
                let mut payload = Data::default();
                payload.get_from(&m)?;
                let to = SocketAddr::new(peer.ip, peer.port);
                if server
                    .requests_of(METHOD_CREATE_PERMISSION)
                    .iter()
                    .any(|(_, r)| {
                        let mut p = PeerAddress::default();
                        p.get_from(r).is_ok() && p.ip == to.ip()
                    })
                {
                    read(&mut world.peers[1].pc, now, to, a(RELAYED), &payload.0);
                }
            }
            if m.typ.method == METHOD_CHANNEL_BIND && m.typ.class == CLASS_REQUEST {
                let mut number = rtc::turn::proto::channum::ChannelNumber::default();
                let mut peer = PeerAddress::default();
                if number.get_from(&m).is_ok() && peer.get_from(&m).is_ok() {
                    channels.push((number.0, SocketAddr::new(peer.ip, peer.port)));
                }
            }
            server.read(w.transport.local_addr, a(SERVER), &data)?;
        }
        for (from, to, data) in std::mem::take(&mut server.out) {
            read(&mut world.peers[0].pc, now, to, from, &data);
        }
        // B: to the relayed address, through the server as a Data indication.
        while let Some(w) = world.peers[1].pc.poll_write() {
            if w.transport.peer_addr == a(RELAYED) {
                let indication = Harness::data_indication(b_addr, &w.message)?;
                read(&mut world.peers[0].pc, now, a(HOST), a(SERVER), &indication);
            }
        }
        let mut relayed = vec![];
        for (i, peer) in world.peers.iter_mut().enumerate() {
            while let Some(e) = peer.pc.poll_event() {
                match e {
                    RTCPeerConnectionEvent::OnIceCandidateEvent(ev) if i == 0 => {
                        if let Some(init) = ev.candidate.and_then(|c| c.to_json().ok())
                            && init.candidate.contains("typ relay")
                        {
                            relayed.push(init);
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                        opened[i] = true;
                    }
                    _ => {}
                }
            }
        }
        for mut init in relayed {
            init.url = None;
            world.peers[1].pc.add_remote_candidate(init)?;
        }
        now += Duration::from_millis(20);
        for peer in world.peers.iter_mut() {
            let _ = peer.pc.handle_timeout(now);
        }
    }
    let permissions = server.requests_of(METHOD_CREATE_PERMISSION);
    assert!(!permissions.is_empty(), "a permission for B");
    let mut peer = PeerAddress::default();
    peer.get_from(&permissions[0].1)?;
    assert_eq!(peer.ip, b_addr.ip());
    assert_eq!(around, 0, "nothing of A's went around the server");
    assert!(
        opened[0] && opened[1],
        "the data channel opened through the relay"
    );
    Ok(())
}

/// RFC 8656 section 7.3 (and 8): the engine refreshes its allocation before the lifetime the
/// server granted runs out, with the long-term credential.
#[test]
fn the_engine_refreshes_its_udp_allocation_before_it_expires() -> Result<()> {
    let mut h = Harness::new(&format!("turn:{SERVER}"))?;
    h.add_host(HOST)?;
    h.run(h.now + Duration::from_secs(1))?;
    let start = h.now;
    assert!(h.server.requests_of(METHOD_REFRESH).is_empty());
    h.run(start + Duration::from_secs(600))?;
    let refreshes = h.server.requests_of(METHOD_REFRESH);
    assert!(!refreshes.is_empty(), "a Refresh within the 600 s lifetime");
    assert!(refreshes[0].1.contains(ATTR_MESSAGE_INTEGRITY));
    Ok(())
}

/// The SOFTWARE of the engine's TURN client over UDP (RFC 8656 section 5: SOFTWARE "SHOULD"
/// be in every Allocate and Refresh request; RFC 8489 section 16.1.2: "Implementers SHOULD make usage
/// of the SOFTWARE attribute a configurable option"): `rtc-turn` and its version by default, the text
/// `with_ice_software` names, and with `with_ice_software(None)` no SOFTWARE in any message
/// sent to the server (the 401 exchange, the signed Allocate, the Refresh).
#[test]
fn the_engine_udp_turn_client_sends_the_software_with_ice_software_names() -> Result<()> {
    use rtc::stun::attributes::ATTR_SOFTWARE;
    use rtc::stun::textattrs::Software;
    for (setting, expected) in [
        (None, Some(rtc::turn::client::DEFAULT_SOFTWARE.to_owned())),
        (Some(None), None),
        (Some(Some("app 1.0".to_owned())), Some("app 1.0".to_owned())),
    ] {
        let mut settings = SettingEngineBuilder::new().with_tcp_candidate_gathering(false);
        if let Some(software) = setting.clone() {
            settings = settings.with_ice_software(software);
        }
        let mut h = Harness::with(&format!("turn:{SERVER}"), settings.build(), vec![a(SERVER)])?;
        h.add_host(HOST)?;
        h.run(h.now + Duration::from_secs(600))?;
        assert_eq!(
            h.server.requests_of(METHOD_ALLOCATE).len(),
            2,
            "{setting:?}"
        );
        assert!(
            !h.server.requests_of(METHOD_REFRESH).is_empty(),
            "{setting:?}"
        );
        for (_, m) in &h.server.requests {
            let software = Software::get_from_as(m, ATTR_SOFTWARE)
                .ok()
                .map(|software| software.text);
            assert_eq!(software, expected, "{setting:?}: {}", m.typ);
        }
    }
    Ok(())
}

/// The "who gathers" rule: a server for which the application adds its own relayed candidate
/// (here before the engine had a base to start from) is left to it. The engine sends nothing
/// to the server, announces no relayed candidate of its own, and gathering is not held for
/// it.
#[test]
fn a_server_the_application_gathers_from_itself_gets_nothing_from_the_engine() -> Result<()> {
    let mut h = Harness::new(&format!("turn:{SERVER}"))?;
    h.add_application_relay(Some(&format!("turn:{SERVER}?transport=udp")))?;
    h.add_host(HOST)?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    h.run(h.now + Duration::from_secs(5))?;
    assert!(h.server.requests.is_empty(), "{:?}", h.server.requests);
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "the application's only: {relayed:?}");
    assert!(relayed[0].0.contains("50099"), "{relayed:?}");
    assert!(h.gathering_complete());
    Ok(())
}

/// The same while the engine's Allocate is on its way: the application's relayed candidate
/// (without a URL: any server) stops it; the server's late 401 is not taken (it may be the
/// application's client's), no signed Allocate follows, no second relayed candidate.
#[test]
fn an_application_relayed_candidate_stops_the_engine_allocation_on_its_way() -> Result<()> {
    let mut h = Harness::new(&format!("turn:{SERVER}"))?;
    h.server.silent.insert(a(SERVER));
    h.add_host(HOST)?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    h.run(h.now + Duration::from_millis(100))?;
    assert_eq!(h.server.requests_of(METHOD_ALLOCATE).len(), 1);
    assert!(!h.gathering_complete());
    h.add_application_relay(None)?;
    h.server.release(a(SERVER))?;
    h.run(h.now + Duration::from_secs(5))?;
    assert_eq!(
        h.server.requests_of(METHOD_ALLOCATE).len(),
        1,
        "no signed Allocate after the application took over"
    );
    assert_eq!(h.relayed().len(), 1, "{:?}", h.relayed());
    assert!(h.gathering_complete());
    Ok(())
}

/// `RelayGathering::Application`: the engine sends nothing to a `turn:` server over UDP.
#[test]
fn with_application_relay_gathering_the_engine_sends_nothing_to_a_udp_turn_server() -> Result<()> {
    let settings = SettingEngineBuilder::new()
        .with_relay_gathering(RelayGathering::Application)
        .build();
    let mut h = Harness::with(&format!("turn:{SERVER}"), settings, vec![a(SERVER)])?;
    h.add_host(HOST)?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    h.run(h.now + Duration::from_secs(5))?;
    assert!(h.server.requests.is_empty());
    assert!(h.relayed().is_empty());
    assert!(h.gathering_complete());
    Ok(())
}

/// The engine as the driver of a name: resolves `turn.example` to both families.
fn resolve_both(h: &mut Harness) -> Result<()> {
    let mut query = None;
    while let Some(c) = h.pc.poll_stream_command() {
        if let StreamCommand::Resolve { query: q, host, .. } = c {
            assert_eq!(host, "turn.example");
            query = Some(q);
        }
    }
    h.pc.handle_stream_event(
        h.now,
        StreamEvent::Resolved {
            query: query.expect("the name is resolved through the driver"),
            addresses: vec![a(SERVER), a(SERVER6)],
        },
    )?;
    Ok(())
}

/// RFC 8656 section 3.9 for clear text UDP: an unauthenticated Allocate to each address
/// family (IPv6 first, the IPv4 one a Connection Attempt Delay later, RFC 8305); "the TURN
/// client will use the first UDP connection on which a 401 error response is received", and
/// the 401 that comes later on the other family is dropped: no signed Allocate goes there.
#[test]
fn udp_allocates_race_across_the_families_and_the_first_401_wins() -> Result<()> {
    let mut h = Harness::with(
        "turn:turn.example:3478",
        SettingEngineBuilder::new().build(),
        vec![a(SERVER), a(SERVER6)],
    )?;
    h.server.silent.insert(a(SERVER6));
    h.add_host(HOST6)?;
    h.add_host(HOST)?;
    resolve_both(&mut h)?;
    let start = h.now;
    h.run(start + Duration::from_millis(10))?;
    let first = h.server.requests_of(METHOD_ALLOCATE);
    assert_eq!(first.len(), 1, "one attempt at first");
    assert_eq!(first[0].0, a(SERVER6), "IPv6 first (RFC 8305 section 4)");
    h.run(start + Duration::from_millis(400))?;
    let v4: Vec<_> = h
        .server
        .requests_of(METHOD_ALLOCATE)
        .into_iter()
        .filter(|(to, _)| *to == a(SERVER))
        .collect();
    assert_eq!(
        v4.len(),
        2,
        "the IPv4 Allocate after the delay, answered 401, then signed"
    );
    // The IPv6 address answers late: its 401 is dropped.
    h.server.release(a(SERVER6))?;
    h.run(h.now + Duration::from_secs(2))?;
    let signed_v6 = h
        .server
        .requests_of(METHOD_ALLOCATE)
        .into_iter()
        .filter(|(to, m)| *to == a(SERVER6) && m.contains(ATTR_MESSAGE_INTEGRITY))
        .count();
    assert_eq!(signed_v6, 0, "the later 401 is silently abandoned");
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert!(relayed[0].0.contains("50000"), "the IPv4 allocation's");
    Ok(())
}

/// RFC 8656 section 3.9: with a server that does not authenticate (RFC 8155 section 9) both
/// families' Allocates may succeed; "the TURN client sends a Refresh with a LIFETIME value of
/// zero on the allocation using the IP address family with lower precedence".
#[test]
fn an_allocation_the_losing_family_made_is_deleted_with_lifetime_zero() -> Result<()> {
    let mut h = Harness::with(
        "turn:turn.example:3478",
        SettingEngineBuilder::new().build(),
        vec![a(SERVER), a(SERVER6)],
    )?;
    h.server.open = true;
    h.server.silent.insert(a(SERVER6));
    h.add_host(HOST6)?;
    h.add_host(HOST)?;
    resolve_both(&mut h)?;
    h.run(h.now + Duration::from_millis(400))?;
    h.server.release(a(SERVER6))?;
    h.run(h.now + Duration::from_secs(2))?;
    let deleted = h
        .server
        .requests_of(METHOD_REFRESH)
        .into_iter()
        .filter(|(to, _)| *to == a(SERVER6))
        .any(|(_, m)| {
            let mut lifetime = Lifetime::default();
            lifetime.get_from(&m).is_ok() && lifetime.0 == Duration::ZERO
        });
    assert!(deleted, "the IPv6 allocation is deleted");
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert!(
        relayed[0].0.contains("50000"),
        "the IPv4 allocation is kept"
    );
    Ok(())
}

/// RFC 8842 section 5.1 with the engine's TURN client (`RelayGathering::Engine`, the
/// default): "the offerer MUST allocate a new 3-tuple for the offer" of a new DTLS
/// association, the relayed one included. `renew_dtls_association` and the offer that asks
/// for the new association: the engine deletes its allocation (RFC 8656 section 8: a Refresh
/// with a LIFETIME of 0, from the base it was made from) when the offer is applied, and once
/// the application gathers on a new port (the previous one is refused for the new
/// association) it allocates again from that base and announces the relayed candidate of the
/// new allocation, on its new relayed address.
#[test]
fn a_new_dtls_association_deletes_the_engine_allocation_and_allocates_again() -> Result<()> {
    let mut h = Harness::new(&format!("turn:{SERVER}"))?;
    h.server.relay_per_base = true;
    h.add_host(HOST)?;
    h.run(h.now + Duration::from_secs(5))?;
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert!(
        relayed[0]
            .0
            .contains("192.0.2.20 50000 typ relay raddr 10.0.0.1 rport 4000"),
        "{relayed:?}"
    );
    let from_base = |h: &Harness, method, base: &str| {
        h.server
            .requests
            .iter()
            .zip(&h.server.sources)
            .filter(|((_, m), from)| {
                m.typ.method == method && m.typ.class == CLASS_REQUEST && **from == a(base)
            })
            .map(|((_, m), _)| m.clone())
            .collect::<Vec<Message>>()
    };
    let deleted = |h: &Harness| {
        from_base(h, METHOD_REFRESH, HOST).iter().any(|m| {
            let mut lifetime = Lifetime::default();
            lifetime.get_from(m).is_ok() && lifetime.0 == Duration::ZERO
        })
    };
    assert!(!deleted(&h), "the allocation is in use");

    h.pc.renew_dtls_association();
    let offer = h.pc.create_offer(None)?;
    h.pc.set_local_description(h.now, offer)?;
    h.run(h.now + Duration::from_secs(1))?;
    assert!(deleted(&h), "the previous allocation is deleted");

    assert!(
        h.add_host(HOST).is_err(),
        "the previous base is refused for the new association"
    );
    let new_host = "10.0.0.1:4001";
    h.add_host(new_host)?;
    h.run(h.now + Duration::from_secs(5))?;
    let allocates = from_base(&h, METHOD_ALLOCATE, new_host);
    assert!(
        allocates.iter().any(|m| m.contains(ATTR_MESSAGE_INTEGRITY)),
        "a new allocation from the new base"
    );
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 2, "{relayed:?}");
    assert!(
        relayed[1]
            .0
            .contains("192.0.2.20 50001 typ relay raddr 10.0.0.1 rport 4001"),
        "the new allocation's relayed address: {relayed:?}"
    );
    Ok(())
}
