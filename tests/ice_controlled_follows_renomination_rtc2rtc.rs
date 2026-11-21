//! The controlled agent follows the controlling agent to another pair mid-session, and data
//! keeps flowing (RFC 8445 Section 7.3.1.5), between two `rtc` peers on a simulated network.
//!
//! libwebrtc, controlling, moves a session to another candidate pair about a second after it
//! connects when it gathers on more interfaces (with camera / microphone permission): it sends a
//! Binding request with USE-CANDIDATE on the new pair and stops using the old one. The
//! controlled agent took only the first nomination, so it kept sending on the abandoned pair
//! and dropped the peer's DTLS / SCTP from the new one: data stopped both ways.
//!
//! `rtc`'s own controlling agent nominates once, so the test plays libwebrtc's part on the
//! wire: the offerer has two addresses; once connected, the network moves the offerer's
//! traffic from the address it used to its other one and drops anything still sent to the old
//! one, and the offerer's USE-CANDIDATE on the new pair is injected, signed with the answerer's
//! ICE password as libwebrtc's would be. No sockets and no wall clock: time is virtual.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::ice::attributes::control::AttrControlling;
use rtc::ice::attributes::priority::PriorityAttr;
use rtc::ice::attributes::use_candidate::UseCandidateAttr;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::attributes::ATTR_USERNAME;
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{BINDING_REQUEST, Message, TransactionId};
use rtc::stun::textattrs::Username;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time each wait gets: below the ICE disconnected timeout, so data that arrives did
/// not need the session to fail and recover.
const STEP: Duration = Duration::from_secs(3);

const OFFERER_FIRST: &str = "10.0.0.1:5000";
const OFFERER_SECOND: &str = "10.0.1.1:5000";
const ANSWERER: &str = "10.0.0.2:5000";

struct Peer {
    pc: RTCPeerConnection,
    addrs: Vec<SocketAddr>,
    connected: bool,
    channel: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
}

impl Peer {
    fn new(addrs: &[&str]) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addrs: addrs.iter().map(|a| a.parse()).collect::<Result<_, _>>()?,
            connected: false,
            channel: None,
            received: Vec::new(),
        })
    }

    fn candidates(&self) -> Result<Vec<RTCIceCandidateInit>> {
        self.addrs
            .iter()
            .map(|addr| {
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
            })
            .collect()
    }

    fn sdp_attribute(&self, name: &str) -> String {
        let sdp = self
            .pc
            .local_description()
            .expect("a local description")
            .sdp;
        let prefix = format!("a={name}:");
        sdp.lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("an {name}"))
            .trim()
            .to_owned()
    }
}

fn is_stun(data: &[u8]) -> bool {
    data.first().is_some_and(|b| *b < 4)
}

struct World {
    peers: Vec<Peer>,
    now: Instant,
    /// The offerer's address and the one it moves to, once it has moved.
    moved: Option<(SocketAddr, SocketAddr)>,
    /// The source address of the offerer's last DTLS / SCTP datagram.
    offerer_media_from: Option<SocketAddr>,
    /// Datagrams sent to the address the offerer left.
    to_abandoned: usize,
}

impl World {
    fn deliver(&mut self, from: SocketAddr, to: SocketAddr, data: BytesMut) {
        if let Some((old, _)) = self.moved
            && to == old
        {
            self.to_abandoned += 1;
            return;
        }
        let Some(peer) = self.peers.iter_mut().find(|p| p.addrs.contains(&to)) else {
            return;
        };
        let _ = peer.pc.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: to,
                peer_addr: from,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: data,
        });
    }

    /// Runs both peers until `done`, or fails after `STEP` of virtual time.
    fn run(&mut self, what: &str, done: impl Fn(&[Peer]) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    let mut from = msg.transport.local_addr;
                    if i == 0 {
                        // The offerer has moved: whatever it still sends from the old address
                        // leaves from the new one.
                        if let Some((old, new)) = self.moved
                            && from == old
                        {
                            from = new;
                        }
                        if !is_stun(&msg.message) {
                            self.offerer_media_from = Some(from);
                        }
                    }
                    in_flight.push((from, msg.transport.peer_addr, msg.message));
                }
            }
            let delivered = !in_flight.is_empty();
            for (from, to, data) in in_flight {
                self.deliver(from, to, data);
            }
            for peer in self.peers.iter_mut() {
                while let Some(event) = peer.pc.poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            if state == RTCPeerConnectionState::Failed {
                                bail!("{what}: a peer's connection failed");
                            }
                            peer.connected = state == RTCPeerConnectionState::Connected;
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                            peer.channel = Some(id)
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
            if done(&self.peers) {
                return Ok(());
            }
            if delivered {
                continue;
            }
            if self.now.duration_since(start) >= STEP {
                bail!("{what}: not done after {STEP:?} of virtual time");
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(self.now + Duration::from_millis(50));
            self.now = next.max(self.now + Duration::from_millis(1));
            for peer in self.peers.iter_mut() {
                let _ = peer.pc.handle_timeout(self.now);
            }
        }
    }

    /// A message each way over the data channel; both must arrive within `STEP`.
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
            self.run(&format!("{what}: a message from peer {from}"), |peers| {
                peers[to].received.len() > before
            })?;
            assert_eq!(self.peers[to].received.last(), Some(&payload), "{what}");
        }
        Ok(())
    }

    /// The offerer's USE-CANDIDATE Binding request on the pair from `from` to the answerer,
    /// as libwebrtc sends it when it renominates.
    fn nominate(&mut self, from: SocketAddr) -> Result<()> {
        let answerer_ufrag = self.peers[1].sdp_attribute("ice-ufrag");
        let answerer_pwd = self.peers[1].sdp_attribute("ice-pwd");
        let offerer_ufrag = self.peers[0].sdp_attribute("ice-ufrag");
        let provider = rtc::crypto::default_provider()
            .expect("a built-in crypto provider must be enabled for tests");
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(
                ATTR_USERNAME,
                format!("{answerer_ufrag}:{offerer_ufrag}"),
            )),
            Box::new(UseCandidateAttr::new()),
            Box::new(AttrControlling(u64::MAX)),
            Box::new(PriorityAttr(2_130_706_431)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                answerer_pwd,
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        let to = self.peers[1].addrs[0];
        self.deliver(from, to, BytesMut::from(&m.raw[..]));
        Ok(())
    }
}

#[test]
fn data_flows_after_the_controlling_agent_moves_to_another_pair() -> Result<()> {
    let mut world = World {
        peers: vec![
            Peer::new(&[OFFERER_FIRST, OFFERER_SECOND])?,
            Peer::new(&[ANSWERER])?,
        ],
        now: Instant::now(),
        moved: None,
        offerer_media_from: None,
        to_abandoned: 0,
    };

    // Connect, with a data channel from the offerer (the controlling agent).
    let now = world.now;
    world.peers[0].pc.create_data_channel("renominate", None)?;
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
        for candidate in world.peers[i].candidates()? {
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
    }
    world.run("the first connection", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    world.ping_pong("connected")?;

    // Run on for `STEP`, so the answerer's checks on the other pair have finished, as they
    // have by the time libwebrtc renominates (about a second in).
    let start = world.now;
    assert!(world.run("settling", |_| false).is_err());
    assert!(world.now >= start + STEP);
    world.ping_pong("settled")?;

    // The offerer moves to its other address and nominates the pair from there.
    let old = world.offerer_media_from.expect("the offerer sent data");
    let new = world.peers[0]
        .addrs
        .iter()
        .copied()
        .find(|a| *a != old)
        .expect("the offerer's other address");
    world.moved = Some((old, new));
    world.nominate(new)?;

    world.ping_pong("the controlling agent moved to another pair")?;
    world.ping_pong("and again")?;
    for peer in &world.peers {
        assert!(peer.connected);
    }
    assert_eq!(
        world.to_abandoned, 0,
        "the answerer kept sending to the address the offerer left"
    );
    Ok(())
}
