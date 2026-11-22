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
//!
//! Nor may the data channel be closed before it opened without an error: its DATA_CHANNEL_OPEN
//! and DATA_CHANNEL_ACK travel on a reliable stream (RFC 8832 section 6), so the channel opens
//! while the association lives, and fails with it, with an error. At 30 % loss the association
//! can give up: the handshake after Max.Init.Retransmits (8) expiries of T1-init or T1-cookie,
//! or the side that came up first after Association.Max.Retrans (10) expiries of T3-rtx while
//! its peer, its COOKIE ACK lost, still discards DATA in COOKIE-ECHOED (RFC 9260 sections 5.1,
//! 6 and 8.1); all of it within about 320 seconds, at RTOs doubling to 60 seconds. There a
//! channel failed with an error is a valid end, a close without one is not, and neither is a
//! channel that has not opened, failed or lapsed after 400 seconds. Every message still
//! arrives exactly once, but not within any fixed time: a DATA
//! chunk and its SACK both arrive about half the time, each retransmission timeout doubles the
//! RTO up to RTO.Max, 60 seconds (RFC 9260 section 6.3.3 E2, and rule C7 allows no lower
//! ceiling), and Karn's algorithm (C5) takes no RTT sample from a retransmitted chunk, so once
//! every message is out the RTO stays backed off until the last is acknowledged.
//!
//! The engine draws random numbers of its own (ICE credentials and tie-breakers, the 4 to 6
//! second consent intervals, DTLS randoms, SCTP tags and heartbeat jitter), so a seed fixes
//! the link, not the whole run: the same seed can take a different course. Both peers are
//! built at the virtual start time.
//!
//! At every loss rate the consent rule is judged on every datagram, whatever the number of
//! datagrams a run takes: a peer sends no application data (anything but STUN, RFC 7983)
//! before a Binding success response has reached it or more than 30 seconds after the last
//! one (RFC 7675 Section 5.1: no data "until consent is obtained", and "the endpoint MUST cease
//! transmission" when it expires).

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
    /// Errors and closes of a data channel announced before any channel opened here.
    closed_before_open: Vec<RTCDataChannelEvent>,
    received: Vec<u32>,
    /// When a Binding success response last reached this peer (RFC 7675: only such a response
    /// refreshes consent).
    last_binding_success: Option<Instant>,
    /// The first application datagram (not STUN) this peer sent without consent: when, and
    /// how long it had been since the last Binding success response reached it.
    sent_without_consent: Option<(Instant, Option<Duration>)>,
}

impl Peer {
    fn new(addr: &str, now: Instant) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            states: Vec::new(),
            ice_states: Vec::new(),
            open: None,
            closed_before_open: Vec::new(),
            received: Vec::new(),
            last_binding_success: None,
            sent_without_consent: None,
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
        let now = Instant::now();
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1:5000", now)?,
                Peer::new("10.0.0.2:5000", now)?,
            ],
            now,
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
                    // RFC 7983: a first byte of 0 to 3 is STUN; anything else (DTLS here) is
                    // application data, which needs consent (RFC 7675 Section 5.1).
                    let peer = &mut self.peers[i];
                    let is_stun = msg.message.first().is_some_and(|b| *b <= 3);
                    let silent_for = peer.last_binding_success.map(|at| self.now - at);
                    if !is_stun
                        && peer.sent_without_consent.is_none()
                        && silent_for.is_none_or(|s| s > CONSENT_EXPIRY + VIRTUAL_TICK)
                    {
                        peer.sent_without_consent = Some((self.now, silent_for));
                    }
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
                        RTCPeerConnectionEvent::OnDataChannel(
                            event @ (RTCDataChannelEvent::OnError(_)
                            | RTCDataChannelEvent::OnClose(_)),
                        ) if peer.open.is_none() => peer.closed_before_open.push(event),
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
        self.now = next.max(self.now + VIRTUAL_TICK);
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
    /// The time was up with the channel open and messages still on their way, each that
    /// arrived having arrived once (only where `lapse_allowed`: RFC 9260 bounds no delivery
    /// time at that loss rate, see the module docs).
    Delivering,
    /// A peer failed after its consent had lapsed: no Binding success response had reached it
    /// for 30 seconds (RFC 7675 Section 5.1).
    ConsentLapsed,
    /// The SCTP association gave up by its retransmission limits before the channel opened,
    /// and the channel failed with an error (only where `lapse_allowed`, see the module docs).
    AssociationFailed,
    /// The peer connection went `failed` while ICE stayed up: the DTLS handshake was given up
    /// at its deadline (30 s, `rtc-dtls` `DEFAULT_HANDSHAKE_TIMEOUT`) before the channel
    /// opened. Not ICE's doing; only where `dtls_give_up_allowed`.
    DtlsGaveUp,
}

/// RFC 7675 Section 5.1: "Consent expires after 30 seconds."
const CONSENT_EXPIRY: Duration = Duration::from_secs(30);

/// The smallest step [`World::advance`] takes; a deadline that close to the current instant
/// fires up to this much late.
const VIRTUAL_TICK: Duration = Duration::from_micros(100);

/// Sets up a session over `link` (seeded with `seed`), opens a reliable unordered data channel
/// and sends `count` numbered messages over it. An error if either peer reports `failed`
/// (unless `lapse_allowed` and its consent had lapsed); if a data channel is closed before it
/// opened (unless `lapse_allowed` and it failed with an error first); if the channel does not
/// open within `open_within`;
/// or if not every message arrives (exactly once) within `deliver_within` (where
/// `lapse_allowed`, the messages that arrived must have arrived once); all in virtual time.
fn session_over(
    link: Link,
    seed: u64,
    count: u32,
    open_within: Duration,
    deliver_within: Duration,
    lapse_allowed: bool,
    dtls_give_up_allowed: bool,
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
        if let Some((i, (at, silent_for))) = world
            .peers
            .iter()
            .enumerate()
            .find_map(|(i, p)| p.sent_without_consent.map(|v| (i, v)))
        {
            bail!(
                "seed {seed}, {link:?}: peer {i} sent application data {:?} into the session \
                 without consent ({}): {}",
                at - start,
                match silent_for {
                    Some(silent_for) =>
                        format!("{silent_for:?} after the last Binding success response reached it"),
                    None => "no Binding success response had reached it".to_owned(),
                },
                world.describe()
            );
        }
        if let Some(failed) = world.peers.iter().find(|p| p.failed()) {
            let silent_for = world.now - failed.last_binding_success.unwrap_or(start).max(start);
            if lapse_allowed && silent_for >= CONSENT_EXPIRY {
                return Ok(Outcome::ConsentLapsed);
            }
            if dtls_give_up_allowed
                && !failed.ice_states.contains(&RTCIceConnectionState::Failed)
                && world.peers.iter().all(|p| p.open.is_none())
            {
                return Ok(Outcome::DtlsGaveUp);
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
        if let Some(peer) = world
            .peers
            .iter()
            .find(|p| !p.closed_before_open.is_empty())
        {
            let failed = peer
                .closed_before_open
                .iter()
                .any(|event| matches!(event, RTCDataChannelEvent::OnError(_)));
            if lapse_allowed && failed {
                return Ok(Outcome::AssociationFailed);
            }
            bail!(
                "seed {seed}, {link:?}: {:?} before the channel opened, after {:?}, with the path \
                 up: {}",
                peer.closed_before_open,
                world.now - start,
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
            if lapse_allowed {
                let unique: HashSet<u32> = received.iter().copied().collect();
                assert_eq!(unique.len(), received.len(), "seed {seed}: only once");
                return Ok(Outcome::Delivering);
            }
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
            false,
        )?;
    }
    Ok(())
}

/// 30 % loss each way: about half of all check transactions lose the request or the
/// response. The session fails only when consent has lapsed, its channel opens or fails with
/// an error (never closes silently), and what arrives arrives once.
#[test]
fn a_session_over_a_link_with_thirty_percent_loss_fails_only_when_consent_lapses() -> Result<()> {
    for seed in SEEDS {
        session_over(
            THIRTY_PERCENT,
            seed,
            50,
            Duration::from_secs(400),
            // At 30 % loss SCTP's retransmission timer backs off (RFC 9260 section 6.3.3), so
            // delivery is slow; the bound is about the session not ending, not about speed.
            Duration::from_secs(900),
            true,
            false,
        )?;
    }
    Ok(())
}

const THIRTY_PERCENT: Link = Link {
    loss: 0.30,
    delay: Duration::from_millis(20),
    jitter: Duration::from_millis(5),
};

/// The run that found it: at 30 % loss with seed 0x5eed, ICE and DTLS stayed connected and
/// the channel did not open within 300 s. The SCTP handshake had completed on the offerer
/// and not yet on the answerer (its COOKIE ACK lost, the OPEN discarded in COOKIE-ECHOED until
/// a retransmitted COOKIE ECHO was answered), and a DCEP handshake timeout of 30 s closed the
/// channel, with no error, before the ACK could come. RFC 8832 has no such timeout: the
/// channel opens while the association lives, or fails with an error when it gives up, or
/// consent lapses first.
#[test]
fn the_channel_opens_over_thirty_percent_loss_while_the_path_stays_up() -> Result<()> {
    session_over(
        THIRTY_PERCENT,
        0x5eed,
        50,
        Duration::from_secs(400),
        Duration::from_secs(900),
        true,
        false,
    )?;
    Ok(())
}

/// Seeds of a 41-seed sweep at 30 % loss where the session went `failed` at about 30 seconds
/// while a Binding success response had reached the peer less than 30 seconds before. ICE is
/// not what fails there: it stays connected (a connected pair fails only when its consent
/// expires, RFC 7675 Section 5.1, and the consent rule is judged on every datagram); the peer
/// connection fails because the DTLS handshake is given up at its 30 second deadline. This
/// test holds ICE to the rule on those seeds and lets the DTLS deadline end the run.
#[test]
fn ice_does_not_fail_while_consent_is_fresh_over_thirty_percent_loss() -> Result<()> {
    let mut outcomes = Vec::new();
    for seed in [0xa, 0x1c, 0x21, 0x24] {
        outcomes.push((
            seed,
            session_over(
                THIRTY_PERCENT,
                seed,
                50,
                Duration::from_secs(400),
                Duration::from_secs(900),
                true,
                true,
            )?,
        ));
    }
    println!("30 % loss, outcome by seed: {outcomes:?}");
    Ok(())
}
