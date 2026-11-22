//! A session that is set up and used over a lossy, reordering link reaches `connected` and stays
//! there.
//!
//! The real-network impairment test (`tests/testenv_impairment.rs`, netem) once saw a peer
//! connection go `failed` on a link with 5 % loss and reordering before its data channel opened.
//! Loss is no reason to fail: every connectivity check is a STUN transaction retransmitted
//! `Rc` times (RFC 8445 section 14.3, RFC 8489 section 6.2.1), consent expires only after 30 s
//! without a response (RFC 7675 section 5.1), DTLS retransmits its flights (RFC 6347
//! section 4.2.4) and SCTP its chunks (RFC 9260 section 6.3). These tests run the whole stack
//! (ICE, DTLS, SCTP, the data channel) between two `rtc` peers on a simulated network in
//! virtual time, dropping a fixed share of datagrams in each direction and delaying each one by
//! a random amount (so datagrams also overtake each other), with fixed seeds: the same run
//! every time, on every platform.
//!
//! At 5 % and 10 % loss nothing may fail. At 30 % loss each way a consent check and its
//! response both arrive only about half the time, and RFC 7675 sends each consent request once,
//! at most one every 4 seconds: consent can lapse, and then the peer MUST stop sending. What
//! may not happen is a failure before it lapsed, so there a failure counts only when no Binding
//! success response has reached that peer for 30 seconds.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// A small deterministic generator (SplitMix64): the tests need reproducible loss, not quality.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The link both directions share.
#[derive(Clone, Copy, Debug)]
struct Link {
    /// Share of datagrams dropped, each direction, independently.
    loss: f64,
    /// One-way delay.
    delay: Duration,
    /// Each datagram's delay is `delay` plus or minus up to this much, uniformly, so datagrams
    /// sent close together arrive out of order.
    jitter: Duration,
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    states: Vec<RTCPeerConnectionState>,
    ice_states: Vec<RTCIceConnectionState>,
    open: Option<RTCDataChannelId>,
    received: Vec<u32>,
    /// When a Binding success response last reached this peer (RFC 7675: only such a response
    /// refreshes consent).
    last_binding_success: Option<Instant>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            states: Vec::new(),
            ice_states: Vec::new(),
            open: None,
            received: Vec::new(),
            last_binding_success: None,
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

    fn failed(&self) -> bool {
        self.states.contains(&RTCPeerConnectionState::Failed)
            || self.ice_states.contains(&RTCIceConnectionState::Failed)
    }
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    link: Link,
    rng: Rng,
    /// Datagrams in flight, by arrival time (and a sequence number for ties): destination
    /// index, source address, payload.
    in_flight: BTreeMap<(Instant, u64), (usize, SocketAddr, BytesMut)>,
    seq: u64,
    sent: u64,
    dropped: u64,
}

impl World {
    fn new(link: Link, seed: u64) -> Result<Self> {
        Ok(Self {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            link,
            rng: Rng(seed),
            in_flight: BTreeMap::new(),
            seq: 0,
            sent: 0,
            dropped: 0,
        })
    }

    /// Takes what both peers want to send onto the link (dropping and delaying it), delivers
    /// what is due, and collects events and messages; repeated until nothing is due now.
    fn pump(&mut self) {
        loop {
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    let to = msg.transport.peer_addr;
                    let Some(dest) = self.peers.iter().position(|p| p.addr == to) else {
                        continue;
                    };
                    self.sent += 1;
                    if self.rng.unit() < self.link.loss {
                        self.dropped += 1;
                        continue;
                    }
                    let jitter = self.link.jitter.as_secs_f64() * (2.0 * self.rng.unit() - 1.0);
                    let delay = (self.link.delay.as_secs_f64() + jitter).max(0.0);
                    let at = self.now + Duration::from_secs_f64(delay);
                    self.seq += 1;
                    self.in_flight.insert(
                        (at, self.seq),
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
                    peer.last_binding_success = Some(self.now);
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
            for peer in self.peers.iter_mut() {
                while let Some(event) = peer.pc.poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            peer.states.push(state)
                        }
                        RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                            peer.ice_states.push(state)
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
    /// `wake` (when the test wants to act), and fires the timers that are due.
    fn advance(&mut self, wake: Option<Instant>) -> Result<()> {
        let mut next = self.in_flight.first_key_value().map(|(k, _)| k.0);
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let Some(deadline) = peer.pc.poll_timeout() else {
                bail!("peer {i} reports no deadline, so it would never make progress");
            };
            next = Some(next.map_or(deadline, |n: Instant| n.min(deadline)));
        }
        if let Some(wake) = wake {
            next = Some(next.map_or(wake, |n| n.min(wake)));
        }
        let next = next.expect("two peers");
        self.now = next.max(self.now + Duration::from_micros(100));
        for peer in self.peers.iter_mut() {
            peer.pc.handle_timeout(self.now)?;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!(
            "a: {:?} / ice {:?}; b: {:?} / ice {:?}; {} of {} datagrams dropped",
            self.peers[0].states,
            self.peers[0].ice_states,
            self.peers[1].states,
            self.peers[1].ice_states,
            self.dropped,
            self.sent
        )
    }
}

/// How a session over a lossy link ended.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Every message arrived, exactly once.
    Delivered,
    /// A peer failed after its consent had lapsed: no Binding success response had reached it
    /// for 30 seconds (RFC 7675 Section 5.1).
    ConsentLapsed,
}

/// RFC 7675 Section 5.1: "Consent expires after 30 seconds."
const CONSENT_EXPIRY: Duration = Duration::from_secs(30);

/// Sets up a session over `link` (seeded with `seed`), opens a reliable unordered data channel
/// and sends `count` numbered messages over it. An error if either peer reports `failed` before
/// the channel opened, or (unless `lapse_allowed` and its consent had lapsed) at any time; if
/// the channel does not open within `open_within`; or if not every message arrives (exactly
/// once) within `deliver_within`; all in virtual time.
fn session_over(
    link: Link,
    seed: u64,
    count: u32,
    open_within: Duration,
    deliver_within: Duration,
    lapse_allowed: bool,
) -> Result<Outcome> {
    let mut world = World::new(link, seed)?;
    world.peers[0].pc.create_data_channel(
        "lossy-link",
        Some(RTCDataChannelInit {
            ordered: false,
            ..Default::default()
        }),
    )?;
    let now = world.now;
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
        let candidate = world.peers[i].candidate()?;
        world.peers[i].pc.add_local_candidate(candidate.clone())?;
        world.peers[1 - i].pc.add_remote_candidate(candidate)?;
    }

    let start = world.now;
    let interval = Duration::from_millis(2);
    let mut next = 0u32;
    let mut next_send = start;
    loop {
        world.pump();
        if let Some(failed) = world.peers.iter().find(|p| p.failed()) {
            let silent_for = world.now - failed.last_binding_success.unwrap_or(start).max(start);
            if lapse_allowed && world.peers[0].open.is_some() && silent_for >= CONSENT_EXPIRY {
                return Ok(Outcome::ConsentLapsed);
            }
            bail!(
                "seed {seed}, {link:?}: a peer failed after {:?}, {silent_for:?} after the last \
                 Binding success response reached it (channel open: {}, {next} of {count} \
                 sent): {}",
                world.now - start,
                world.peers[0].open.is_some(),
                world.describe()
            );
        }
        let Some(id) = world.peers[0].open else {
            if world.now - start > open_within {
                bail!(
                    "seed {seed}, {link:?}: the channel did not open within {open_within:?}: {}",
                    world.describe()
                );
            }
            world.advance(None)?;
            continue;
        };
        if next < count && world.now >= next_send {
            let mut payload = next.to_be_bytes().to_vec();
            payload.resize(1024, 0xab);
            if let Some(mut dc) = world.peers[0].pc.data_channel(id)
                && dc.send(world.now, BytesMut::from(&payload[..])).is_ok()
            {
                next += 1;
            }
            next_send = world.now + interval;
            continue;
        }
        let received = &world.peers[1].received;
        if received.len() >= count as usize {
            let unique: HashSet<u32> = received.iter().copied().collect();
            assert_eq!(
                unique.len(),
                count as usize,
                "seed {seed}: every message arrives"
            );
            assert_eq!(received.len(), count as usize, "seed {seed}: and only once");
            return Ok(Outcome::Delivered);
        }
        if world.now - start > open_within + deliver_within {
            bail!(
                "seed {seed}, {link:?}: {} of {count} messages arrived ({next} sent) within \
                 {deliver_within:?} of opening: {}",
                received.len(),
                world.describe()
            );
        }
        world.advance((next < count).then_some(next_send))?;
    }
}

const SEEDS: [u64; 4] = [1, 2, 3, 0x5eed];

/// The netem link `tests/testenv_impairment.rs` ran the reliable unordered channel over: 5 %
/// loss, 30 ms plus or minus 15 ms, so datagrams sent within 30 ms of each other overtake each
/// other.
#[test]
fn a_session_over_a_link_with_loss_and_reordering_connects_and_delivers_everything() -> Result<()> {
    let link = Link {
        loss: 0.05,
        delay: Duration::from_millis(30),
        jitter: Duration::from_millis(15),
    };
    for seed in SEEDS {
        session_over(
            link,
            seed,
            500,
            Duration::from_secs(30),
            Duration::from_secs(60),
            false,
        )?;
    }
    Ok(())
}

/// 10 % loss each way.
#[test]
fn a_session_over_a_link_with_ten_percent_loss_connects_and_delivers_everything() -> Result<()> {
    let link = Link {
        loss: 0.10,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(2),
    };
    for seed in SEEDS {
        session_over(
            link,
            seed,
            300,
            Duration::from_secs(30),
            Duration::from_secs(90),
            false,
        )?;
    }
    Ok(())
}

/// 30 % loss each way: about half of all check transactions lose the request or the
/// response. The session still connects and opens its channel every time, and fails only when
/// consent has lapsed; the seeds below include runs where it does not, which deliver
/// everything.
#[test]
fn a_session_over_a_link_with_thirty_percent_loss_fails_only_when_consent_lapses() -> Result<()> {
    let link = Link {
        loss: 0.30,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(5),
    };
    let mut outcomes = Vec::new();
    for seed in SEEDS {
        outcomes.push(session_over(
            link,
            seed,
            100,
            Duration::from_secs(60),
            Duration::from_secs(180),
            true,
        )?);
    }
    assert!(
        outcomes.contains(&Outcome::Delivered),
        "no seed delivered everything: {outcomes:?}"
    );
    Ok(())
}
