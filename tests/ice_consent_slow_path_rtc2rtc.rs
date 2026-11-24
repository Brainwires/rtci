//! Two `rtci` peers stay connected when the round trip of their path becomes long.
//!
//! A path that delivers every datagram, late, is a working path: a queue that filled up behind
//! a bottleneck, a route that changed, a satellite hop. ICE consent (RFC 7675 section 5.1) is
//! lost when "a valid STUN binding response has not been received [...] in 30 seconds"; here
//! every consent request is answered, each answer a round trip after its request, and "a
//! response might be for a previous request (rather than for the most recently sent
//! request)". An engine that stopped waiting for an answer after 500 ms declared such a path
//! failed 30 seconds after its round trip rose above that, with every check answered.
//!
//! The whole stack (ICE, DTLS, SCTP, a data channel) runs between two peers on a simulated
//! link in virtual time, with no loss: each datagram arrives one one-way delay after it left,
//! in order. The peers' randomness (the 4 to 6 second consent intervals among it) is seeded,
//! so a run is the same every time.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MS: Duration = Duration::from_millis(1);
const S: Duration = Duration::from_secs(1);

/// The smallest step of virtual time.
const VIRTUAL_TICK: Duration = Duration::from_micros(100);

/// A small deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`]: what the
/// engine draws through `RTCCryptoProvider::random()` (the consent intervals among it) is the
/// same in every run. Not secure; this test needs no secrecy.
struct SeededProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    rng: Mutex<Rng>,
}

impl RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut rng = self.rng.lock().map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    /// Every state the peer reported, with the virtual time since the start.
    states: Vec<(Duration, RTCPeerConnectionState)>,
    ice_states: Vec<(Duration, RTCIceConnectionState)>,
    open: Option<RTCDataChannelId>,
    received: Vec<u32>,
    /// Binding requests this peer sent and Binding success responses that reached it.
    binding_requests: u32,
    binding_responses: u32,
}

impl Peer {
    fn new(addr: &str, now: Instant, seed: u64) -> Result<Self> {
        let provider = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(Rng(seed)),
        });
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_crypto_provider(provider)
                    .build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            states: Vec::new(),
            ice_states: Vec::new(),
            open: None,
            received: Vec::new(),
            binding_requests: 0,
            binding_responses: 0,
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

    /// The states that say the path is in trouble, with their times.
    fn troubles(&self) -> Vec<String> {
        let mut out = vec![];
        for (at, state) in &self.states {
            if matches!(
                state,
                RTCPeerConnectionState::Disconnected | RTCPeerConnectionState::Failed
            ) {
                out.push(format!("{state} at {at:?}"));
            }
        }
        for (at, state) in &self.ice_states {
            if matches!(
                state,
                RTCIceConnectionState::Disconnected | RTCIceConnectionState::Failed
            ) {
                out.push(format!("ice {state} at {at:?}"));
            }
        }
        out
    }
}

/// Two peers and the link between them: every datagram arrives `one_way[from]` after it
/// left, none is lost, and none overtakes another of its direction.
struct World {
    peers: [Peer; 2],
    start: Instant,
    now: Instant,
    /// The one-way delay of what each peer sends.
    one_way: [Duration; 2],
    /// Datagrams in flight, by arrival time (and a sequence number for ties): destination
    /// index, source address, payload.
    in_flight: BTreeMap<(Instant, u64), (usize, SocketAddr, BytesMut)>,
    /// The latest arrival scheduled in each direction: a delay that shrinks does not let a
    /// datagram overtake the ones before it.
    last_arrival: [Option<Instant>; 2],
    sequence: u64,
}

impl World {
    fn new(seed: u64, one_way: Duration) -> Result<Self> {
        let now = Instant::now();
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1:5000", now, Rng(seed ^ 1).next_u64())?,
                Peer::new("10.0.0.2:5000", now, Rng(seed ^ 2).next_u64())?,
            ],
            start: now,
            now,
            one_way: [one_way; 2],
            in_flight: BTreeMap::new(),
            last_arrival: [None; 2],
            sequence: 0,
        })
    }

    /// Takes what both peers want to send onto the link, delivers what is due and collects
    /// events and messages, until nothing is due now.
    fn pump(&mut self) {
        loop {
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    let to = msg.transport.peer_addr;
                    let Some(dest) = self.peers.iter().position(|p| p.addr == to) else {
                        continue;
                    };
                    // STUN message type 0x0001: Binding request.
                    if msg.message.len() >= 20 && msg.message[0] == 0x00 && msg.message[1] == 0x01 {
                        self.peers[i].binding_requests += 1;
                    }
                    let arrival =
                        (self.now + self.one_way[i]).max(self.last_arrival[i].unwrap_or(self.now));
                    self.last_arrival[i] = Some(arrival);
                    self.sequence += 1;
                    self.in_flight.insert(
                        (arrival, self.sequence),
                        (dest, msg.transport.local_addr, msg.message),
                    );
                }
            }
            let mut delivered = false;
            while let Some(entry) = self.in_flight.first_entry() {
                if entry.key().0 > self.now {
                    break;
                }
                let (dest, from, data) = entry.remove();
                let peer = &mut self.peers[dest];
                // STUN message type 0x0101: Binding success response.
                if data.len() >= 20 && data[0] == 0x01 && data[1] == 0x01 {
                    peer.binding_responses += 1;
                }
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: peer.addr,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: data,
                });
                delivered = true;
            }
            let since_start = self.now - self.start;
            for peer in self.peers.iter_mut() {
                while let Some(event) = peer.pc.poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            peer.states.push((since_start, state))
                        }
                        RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                            peer.ice_states.push((since_start, state))
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                            peer.open = Some(id)
                        }
                        _ => {}
                    }
                }
                while let Some(message) = peer.pc.poll_read() {
                    if let RTCMessage::DataChannelMessage(_, msg) = message.message
                        && msg.data.len() >= 4
                    {
                        peer.received
                            .push(u32::from_be_bytes(msg.data[..4].try_into().unwrap()));
                    }
                }
            }
            if !delivered {
                break;
            }
        }
    }

    /// Moves virtual time to the earliest of both peers' deadlines, the next arrival and
    /// `wake`, and fires the timers that are due.
    fn advance(&mut self, wake: Instant) -> Result<()> {
        let mut next = wake;
        if let Some((key, _)) = self.in_flight.first_key_value() {
            next = next.min(key.0);
        }
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let Some(deadline) = peer.pc.poll_timeout() else {
                bail!("peer {i} reports no deadline");
            };
            next = next.min(deadline);
        }
        self.now = next.max(self.now + VIRTUAL_TICK);
        for peer in self.peers.iter_mut() {
            peer.pc.handle_timeout(self.now)?;
        }
        Ok(())
    }

    /// Runs until `until` (since the start).
    fn run_until(&mut self, until: Duration) -> Result<()> {
        let until = self.start + until;
        while self.now < until {
            self.pump();
            self.advance(until)?;
        }
        self.pump();
        Ok(())
    }

    /// Offer, answer and one host candidate each way, with a data channel.
    fn signal(&mut self) -> Result<()> {
        self.peers[0].pc.create_data_channel(
            "slow-path",
            Some(RTCDataChannelInit {
                ordered: true,
                ..Default::default()
            }),
        )?;
        let now = self.now;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    /// Sends the message numbered `n` from the offerer on its data channel.
    fn send(&mut self, n: u32) -> Result<()> {
        let Some(id) = self.peers[0].open else {
            bail!("the data channel is not open");
        };
        let now = self.now;
        let Some(mut channel) = self.peers[0].pc.data_channel(id) else {
            bail!("no data channel {id}");
        };
        channel.send(now, BytesMut::from(&n.to_be_bytes()[..]))?;
        Ok(())
    }

    fn describe(&self) -> String {
        self.peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                format!(
                    "peer {i}: {:?} / ice {:?}, {} Binding requests sent, {} success responses received",
                    p.states, p.ice_states, p.binding_requests, p.binding_responses
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Connects two peers over a link with a one-way delay of `before`, lets them run for
/// `settle`, changes the one-way delay of each direction to `after`, and runs for another
/// `rest`. Nothing is lost at any time. Neither peer may report `disconnected` or `failed`,
/// each must go on receiving the answers to its consent requests, and a message sent on the
/// data channel at the end must arrive.
fn session_whose_delay_changes(
    seed: u64,
    before: Duration,
    settle: Duration,
    after: [Duration; 2],
    rest: Duration,
) -> Result<()> {
    let mut world = World::new(seed, before)?;
    world.signal()?;
    world.run_until(settle)?;
    for (i, peer) in world.peers.iter().enumerate() {
        if peer.states.last().map(|(_, s)| *s) != Some(RTCPeerConnectionState::Connected) {
            bail!(
                "seed {seed}: peer {i} is not connected after {settle:?} at a one-way delay of \
                 {before:?}: {}",
                world.describe()
            );
        }
    }
    if world.peers[0].open.is_none() {
        bail!(
            "seed {seed}: the data channel did not open: {}",
            world.describe()
        );
    }
    world.send(1)?;

    world.one_way = after;
    let answered_before: Vec<u32> = world.peers.iter().map(|p| p.binding_responses).collect();
    world.run_until(settle + rest)?;

    for (i, peer) in world.peers.iter().enumerate() {
        let troubles = peer.troubles();
        if !troubles.is_empty() {
            bail!(
                "seed {seed}, one-way delays {after:?}: peer {i} reported {troubles:?} on a path \
                 that delivered every datagram: {}",
                world.describe()
            );
        }
        // A consent request every 4 to 6 seconds, each answered.
        let answered = peer.binding_responses - answered_before[i];
        let least = u32::try_from(rest.as_secs() / 6).unwrap().saturating_sub(2);
        if answered < least {
            bail!(
                "seed {seed}: peer {i} received {answered} Binding success responses in \
                 {rest:?}, expected at least {least}: {}",
                world.describe()
            );
        }
    }

    // The path still carries data.
    world.send(2)?;
    let end = world.now - world.start + 20 * S;
    world.run_until(end)?;
    if world.peers[1].received != [1, 2] {
        bail!(
            "seed {seed}: the answerer received {:?}, expected [1, 2]: {}",
            world.peers[1].received,
            world.describe()
        );
    }
    Ok(())
}

/// The round trip rises from 20 ms to 600, 800 and 1000 ms (the same delay each way), with
/// no loss, and stays there for two minutes: both peers stay `connected` throughout.
#[test]
fn a_connected_session_stays_connected_when_the_round_trip_rises_above_half_a_second() -> Result<()>
{
    for (seed, one_way) in [(1, 300 * MS), (2, 400 * MS), (3, 500 * MS), (4, 400 * MS)] {
        session_whose_delay_changes(seed, 10 * MS, 10 * S, [one_way; 2], 120 * S)?;
    }
    Ok(())
}

/// The delay rises in one direction only (a queue behind a bottleneck on one peer's uplink):
/// that peer's requests arrive late, and so do the answers to the other peer's requests.
#[test]
fn a_connected_session_stays_connected_when_one_direction_becomes_slow() -> Result<()> {
    for (seed, after) in [(5, [800 * MS, 10 * MS]), (6, [10 * MS, 900 * MS])] {
        session_whose_delay_changes(seed, 10 * MS, 10 * S, after, 120 * S)?;
    }
    Ok(())
}

/// A path that is slow from the start (a round trip of 800 ms): the session is set up over
/// it and stays `connected` for two minutes.
#[test]
fn a_session_set_up_over_a_slow_path_stays_connected() -> Result<()> {
    session_whose_delay_changes(7, 400 * MS, 30 * S, [400 * MS; 2], 120 * S)
}

/// A round trip of four seconds (two each way): slow beyond use for media, and still a path
/// that answers every consent request within the time a request waits. Neither peer fails;
/// the answers keep arriving.
#[test]
fn a_session_survives_a_round_trip_of_four_seconds() -> Result<()> {
    session_whose_delay_changes(8, 10 * MS, 10 * S, [2 * S; 2], 120 * S)
}
