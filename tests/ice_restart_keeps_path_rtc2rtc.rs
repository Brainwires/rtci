//! An ICE restart does not interrupt data (RFC 8445 Section 9), between two `rtc` peers on a
//! simulated UDP network.
//!
//! "The ICE agent continues to use the previously selected candidate pair until a new pair is
//! selected by the restart." The agent used to drop its selected pair the moment the restart
//! was applied (`setLocalDescription` of the restart offer on the offerer, `setRemoteDescription`
//! of it on the answerer), and with it the path DTLS and SCTP write to and read from: every
//! data channel message between that point and the first nomination of the new generation was
//! lost, for as long as the offer/answer exchange took.
//!
//! The test walks the exchange one step at a time, as an application signalling over a slow
//! channel does, and sends a message each way after every step. No sockets and no wall clock:
//! time is virtual, so the run is deterministic.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time each step gets. Far below the ICE disconnected and failed timeouts, so a
/// message that arrives did not wait for a new pair.
const STEP: Duration = Duration::from_secs(3);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    channel: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
}

impl Peer {
    fn new(addr: &str, discard_local_candidates: bool) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_discard_local_candidates_during_ice_restart(discard_local_candidates)
                    .build(),
            )
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            channel: None,
            received: Vec::new(),
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

    fn ufrag(&self) -> String {
        let sdp = self
            .pc
            .local_description()
            .expect("a local description")
            .sdp;
        sdp.lines()
            .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
            .expect("an ice-ufrag")
            .to_owned()
    }
}

struct World {
    peers: Vec<Peer>,
    now: Instant,
    /// Datagrams addressed to neither peer.
    dropped: usize,
}

impl World {
    /// Runs both peers until `done`, or fails after `STEP` of virtual time.
    fn run(&mut self, what: &str, done: impl Fn(&[Peer]) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let mut in_flight = Vec::new();
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
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
                    self.dropped += 1;
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

    /// Trickles each peer's host candidate to the other, as after gathering.
    fn trickle(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }
}

#[test]
fn data_flows_at_every_step_of_an_ice_restart() -> Result<()> {
    restart_step_by_step(false)
}

/// The same when a restart discards the local candidates (a new gathering phase on the
/// sockets already bound, as an application that re-announces its candidates does).
#[test]
fn data_flows_at_every_step_of_an_ice_restart_that_regathers() -> Result<()> {
    restart_step_by_step(true)
}

fn restart_step_by_step(discard_local_candidates: bool) -> Result<()> {
    let mut world = World {
        peers: vec![
            Peer::new("10.0.0.1:5000", discard_local_candidates)?,
            Peer::new("10.0.0.2:5000", discard_local_candidates)?,
        ],
        now: Instant::now(),
        dropped: 0,
    };

    // Connect, with a data channel from the offerer.
    let now = world.now;
    world.peers[0].pc.create_data_channel("restart", None)?;
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
    world.trickle()?;
    world.run("the first connection", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    world.ping_pong("connected")?;
    let ufrags = [world.peers[0].ufrag(), world.peers[1].ufrag()];

    // The restart, one signalling step at a time. Data flows after each.
    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_ne!(world.peers[0].ufrag(), ufrags[0], "the offer restarts ICE");
    world.ping_pong("the offerer applied its restart offer")?;

    let now = world.now;
    world.peers[1].pc.set_remote_description(now, offer)?;
    world.ping_pong("the answerer applied the restart offer")?;

    let answer = world.peers[1].pc.create_answer(None)?;
    let now = world.now;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert_ne!(world.peers[1].ufrag(), ufrags[1], "the answer restarts ICE");
    world.ping_pong("the answerer applied its answer")?;

    let now = world.now;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.ping_pong("the offerer applied the answer")?;

    // The new generation's candidates arrive: a pair is selected again on both sides, and data
    // still flows, now on it.
    world.trickle()?;
    world.ping_pong("the new candidates were signalled")?;
    // (Applying the restart took both peers back to `Connecting`.)
    let mut waited = 0;
    while !world.peers.iter().all(|p| p.connected) {
        if waited == 7 {
            bail!(
                "the restart selected no pair: {:?} / {:?}",
                world.peers[0].states,
                world.peers[1].states
            );
        }
        // Up to `STEP` of virtual time.
        let _ = world.run("waiting for the new pair", |peers| {
            peers.iter().all(|p| p.connected)
        });
        waited += 1;
    }
    world.ping_pong("the restart selected its pair")?;
    for peer in &world.peers {
        assert!(peer.connected, "connection states: {:?}", peer.states);
    }
    assert_eq!(world.dropped, 0, "every datagram went to a peer");
    Ok(())
}
