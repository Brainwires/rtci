//! A rolled-back remote offer leaves the ICE and DTLS transports as they were (RFC 9429
//! section 5.7: "any media that is received is processed according to the previous local and
//! remote descriptions"), between two `rtc` peers on a simulated UDP network in virtual time.
//!
//! Applying a remote offer used to start the transports (the first offer), restart ICE (an
//! offer with new credentials) or replace the DTLS association (an offer with another
//! `tls-id`) at once, and a rollback undid none of it. The answerer now takes the offer's
//! transport parameters when it applies its answer.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time each step gets.
const STEP: Duration = Duration::from_secs(3);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    channel: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
    /// Datagrams this peer wrote.
    sent: usize,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            channel: None,
            received: Vec::new(),
            sent: 0,
        })
    }

    fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }
}

/// The value of the first `a=<attribute>:` line of `sdp`.
fn attribute(sdp: &str, attribute: &str) -> String {
    let prefix = format!("a={attribute}:");
    sdp.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("an a={attribute} line in:\n{sdp}"))
        .to_owned()
}

fn rollback() -> RTCSessionDescription {
    RTCSessionDescription::rollback(None).expect("a rollback description")
}

struct World {
    peers: Vec<Peer>,
    now: Instant,
}

impl World {
    fn new() -> Result<Self> {
        Ok(Self {
            peers: vec![Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
        })
    }

    /// Runs both peers until `done`, or fails after `STEP` of virtual time.
    fn run(&mut self, what: &str, done: impl Fn(&[Peer]) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let mut in_flight = Vec::new();
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
                    peer.sent += 1;
                    in_flight.push((
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            let delivered = !in_flight.is_empty();
            for (from, to, data) in in_flight {
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                    continue;
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
            for peer in self.peers.iter_mut() {
                while let Some(event) = peer.pc.poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            if state == RTCPeerConnectionState::Failed {
                                bail!("{what}: a peer's connection failed");
                            }
                            peer.connected = state == RTCPeerConnectionState::Connected;
                            peer.states.push(state);
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

    /// Lets `duration` of virtual time pass.
    fn idle(&mut self, duration: Duration) {
        let until = self.now + duration;
        while self.now < until {
            let _ = self.run("idle", |_| false);
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

    /// Each peer's host candidate: to its own agent, and to the other peer.
    fn trickle(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    /// Peer 0 offers, peer 1 answers, the candidates are exchanged and the data channel opens.
    fn connect(&mut self) -> Result<()> {
        let now = self.now;
        self.peers[0].pc.create_data_channel("rollback", None)?;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        self.trickle()?;
        self.run("the connection", |peers| {
            peers.iter().all(|p| p.connected && p.channel.is_some())
        })?;
        self.ping_pong("connected")
    }
}

/// The first remote offer, rolled back, starts no ICE checks and no DTLS: the answerer's
/// transports are still `new`, and it sends nothing, though it holds the offerer's candidate
/// and a local one of its own. The offer applied again afterwards connects as usual.
#[test]
fn a_rolled_back_first_offer_starts_no_transport() -> Result<()> {
    let mut world = World::new()?;
    let now = world.now;
    world.peers[0].pc.create_data_channel("rollback", None)?;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;

    world.peers[1]
        .pc
        .set_remote_description(now, offer.clone())?;
    let local = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(local)?;
    let remote = world.peers[0].candidate()?;
    world.peers[1].pc.add_remote_candidate(remote)?;
    world.idle(Duration::from_secs(1));
    assert_eq!(
        world.peers[1].sent, 0,
        "the answerer checks nothing before it answers"
    );
    assert_eq!(
        world.peers[1].pc.ice_connection_state(),
        RTCIceConnectionState::New
    );

    world.peers[1]
        .pc
        .set_remote_description(world.now, rollback())?;
    world.idle(Duration::from_secs(2));
    assert_eq!(world.peers[1].sent, 0, "nor after the rollback");
    assert_eq!(
        world.peers[1].pc.ice_connection_state(),
        RTCIceConnectionState::New
    );

    // Answered this time.
    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.trickle()?;
    world.run("the connection", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    world.ping_pong("connected after the rollback")
}

/// An ICE restart offer, rolled back: the answerer keeps its credentials, its peer's and its
/// selected pair. Its next offer restarts nothing, and data flows on as before.
#[test]
fn a_rolled_back_ice_restart_offer_leaves_the_ice_session_as_it_was() -> Result<()> {
    let mut world = World::new()?;
    world.connect()?;
    let answer = world.peers[1]
        .pc
        .local_description()
        .expect("an answer")
        .sdp;
    let ufrag = attribute(&answer, "ice-ufrag");
    let pwd = attribute(&answer, "ice-pwd");
    let states = world.peers[1].states.len();

    // The offerer asks for a restart; its offer reaches the answerer and is abandoned there.
    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    // The answer it would make carries new credentials, staged for it.
    let restart_answer = world.peers[1].pc.create_answer(None)?;
    assert_ne!(attribute(&restart_answer.sdp, "ice-ufrag"), ufrag);
    assert!(
        restart_answer.sdp.contains("a=candidate:"),
        "the restart keeps the local candidates, so its answer lists them: {}",
        restart_answer.sdp
    );
    world.peers[1]
        .pc
        .set_local_description(world.now, rollback())?;

    world.idle(Duration::from_secs(10));
    world.ping_pong("after the rollback")?;
    assert_eq!(
        world.peers[1].states.len(),
        states,
        "the connection state never left connected: {:?}",
        world.peers[1].states
    );
    assert!(matches!(
        world.peers[1].pc.ice_connection_state(),
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
    ));

    // The rolled-back peer's own offer keeps its credentials: no restart is left staged.
    let offer = world.peers[1].pc.create_offer(None)?;
    assert_eq!(attribute(&offer.sdp, "ice-ufrag"), ufrag);
    assert_eq!(attribute(&offer.sdp, "ice-pwd"), pwd);
    Ok(())
}

/// An offer whose `tls-id` asks for a new DTLS association (RFC 8842 section 5.5), rolled
/// back: the association goes on and data flows over it. Answered, the new association's
/// `tls-id` is the one the answer carried.
#[test]
fn a_rolled_back_offer_for_a_new_dtls_association_keeps_the_association() -> Result<()> {
    let mut world = World::new()?;
    world.connect()?;
    let first_answer = world.peers[1]
        .pc
        .local_description()
        .expect("an answer")
        .sdp;
    let states = world.peers[1].states.len();

    let offer = world.peers[0].pc.create_offer(None)?;
    let tls_id = attribute(&offer.sdp, "tls-id");
    let replaced = offer.sdp.replace(
        &format!("a=tls-id:{tls_id}"),
        "a=tls-id:0123456789abcdef0123456789abcdef",
    );
    assert_ne!(replaced, offer.sdp);
    let now = world.now;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(replaced.clone())?)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let answered_tls_id = attribute(&answer.sdp, "tls-id");
    assert_ne!(
        answered_tls_id,
        attribute(&first_answer, "tls-id"),
        "the answer to it states a new association"
    );
    world.peers[1]
        .pc
        .set_remote_description(world.now, rollback())?;

    world.idle(Duration::from_secs(5));
    world.ping_pong("after the rollback")?;
    assert_eq!(
        world.peers[1].states.len(),
        states,
        "the association was not replaced: {:?}",
        world.peers[1].states
    );

    // Answered, the new association takes the `tls-id` its answer stated.
    let now = world.now;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(replaced)?)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let answered_tls_id = attribute(&answer.sdp, "tls-id");
    world.peers[1].pc.set_local_description(now, answer)?;
    let next = world.peers[1].pc.create_offer(None);
    assert!(next.is_ok(), "{next:?}");
    assert_eq!(attribute(&next?.sdp, "tls-id"), answered_tls_id);
    Ok(())
}

/// This side's own ICE restart offer, rolled back (RFC 9429 section 5.7: "any resources
/// allocated by the abandoned local description are discarded"): the agent goes on with the
/// session it had, its credentials, its peer's and its selected pair, past the 30 s within
/// which consent would expire. A restart offered afterwards and answered works as usual.
#[test]
fn a_rolled_back_local_ice_restart_offer_keeps_the_ice_session() -> Result<()> {
    let mut world = World::new()?;
    world.connect()?;
    let ufrag = attribute(
        &world.peers[0].pc.local_description().expect("an offer").sdp,
        "ice-ufrag",
    );

    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    assert_ne!(attribute(&offer.sdp, "ice-ufrag"), ufrag, "a restart offer");
    let now = world.now;
    world.peers[0].pc.set_local_description(now, offer)?;
    world.peers[0]
        .pc
        .set_local_description(world.now, rollback())?;
    assert_eq!(
        attribute(
            &world.peers[0]
                .pc
                .local_description()
                .expect("the offer before")
                .sdp,
            "ice-ufrag"
        ),
        ufrag
    );

    world.idle(Duration::from_secs(40));
    world.ping_pong("after the rollback")?;
    assert!(
        matches!(
            world.peers[0].pc.ice_connection_state(),
            RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
        ),
        "the ICE session is the one before the restart: {:?}",
        world.peers[0].pc.ice_connection_state()
    );

    // The restart the application asked for is still to be made (W3C restartIce): offered
    // and answered this time, it completes.
    let offer = world.peers[0].pc.create_offer(None)?;
    assert_ne!(attribute(&offer.sdp, "ice-ufrag"), ufrag);
    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.trickle()?;
    world.idle(Duration::from_secs(5));
    world.ping_pong("after the restart")
}

/// The same restart offer, rolled back implicitly by an offer from the peer (glare, W3C
/// `setRemoteDescription`): the peer's offer, made with the credentials in use, is answered
/// and the session goes on.
#[test]
fn a_local_ice_restart_offer_rolled_back_by_a_remote_offer_keeps_the_ice_session() -> Result<()> {
    let mut world = World::new()?;
    world.connect()?;
    let local = |world: &World| {
        let sdp = world.peers[0]
            .pc
            .local_description()
            .expect("a local description")
            .sdp;
        (attribute(&sdp, "ice-ufrag"), attribute(&sdp, "ice-pwd"))
    };
    let credentials = local(&world);

    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[0].pc.set_local_description(now, offer)?;
    assert_ne!(local(&world), credentials, "the restart offer is applied");

    let glare = world.peers[1].pc.create_offer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, glare.clone())?;
    world.peers[0].pc.set_remote_description(now, glare)?;
    let answer = world.peers[0].pc.create_answer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[1].pc.set_remote_description(now, answer)?;
    assert_eq!(
        local(&world),
        credentials,
        "the answer is made in the ICE session the restart offer would have replaced"
    );

    world.idle(Duration::from_secs(40));
    world.ping_pong("after the glare")?;
    assert!(
        matches!(
            world.peers[0].pc.ice_connection_state(),
            RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
        ),
        "{:?}",
        world.peers[0].pc.ice_connection_state()
    );
    Ok(())
}
