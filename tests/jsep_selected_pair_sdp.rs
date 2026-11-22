//! What later descriptions say of the candidate pair ICE selected, between two `rtc` peers on
//! a simulated UDP network in virtual time (RFC 8839 sections 4.2.1.2, 4.3.4, 4.4.1.2.2,
//! 4.4.1.3, 4.4.2, 5.1 and 5.2; RFC 8445 section 8.2).

use anyhow::{Result, bail};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateServerReflexiveConfig, RTCIceCandidate,
    RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_secs(5);

struct Peer {
    pc: RTCPeerConnection,
    /// The addresses this peer receives on.
    addrs: Vec<SocketAddr>,
    connected: bool,
    channel_open: bool,
    negotiation_needed: usize,
}

impl Peer {
    fn new(addrs: &[&str], lite: bool) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(SettingEngineBuilder::new().with_lite(lite).build())
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addrs: addrs.iter().map(|a| a.parse()).collect::<Result<_, _>>()?,
            connected: false,
            channel_open: false,
            negotiation_needed: 0,
        })
    }
}

fn host(addr: &SocketAddr) -> Result<RTCIceCandidateInit> {
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

/// A server-reflexive candidate at an address nothing is delivered to: the default candidate
/// of a description (RFC 8839 section 4.2.1.2 prefers it to a host one), never the pair ICE
/// selects.
fn unreachable_srflx(base: &SocketAddr) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "198.51.100.7".to_owned(),
            port: 6000,
            component: 1,
            ..Default::default()
        },
        rel_addr: base.ip().to_string(),
        rel_port: base.port(),
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

struct World {
    peers: Vec<Peer>,
    now: Instant,
}

impl World {
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
                let Some(peer) = self.peers.iter_mut().find(|p| p.addrs.contains(&to)) else {
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
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                            peer.channel_open = true
                        }
                        RTCPeerConnectionEvent::OnNegotiationNeededEvent => {
                            peer.negotiation_needed += 1
                        }
                        _ => {}
                    }
                }
                while peer.pc.poll_read().is_some() {}
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

    /// Peer 0 offers a data channel, peer 1 answers; then each one's `candidates` go to its
    /// own agent and to the other peer.
    fn negotiate(&mut self, candidates: [Vec<RTCIceCandidateInit>; 2]) -> Result<()> {
        let now = self.now;
        self.peers[0].pc.create_data_channel("pair", None)?;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        // What the exchange itself raised (the data channel asked for negotiation) is not
        // counted.
        for peer in self.peers.iter_mut() {
            while peer.pc.poll_event().is_some() {}
            peer.negotiation_needed = 0;
        }
        for (i, list) in candidates.into_iter().enumerate() {
            for candidate in list {
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }
}

/// The values of the `a=<attribute>:` lines of `sdp`.
fn attributes<'a>(sdp: &'a str, attribute: &str) -> Vec<&'a str> {
    let prefix = format!("a={attribute}:");
    sdp.lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .collect()
}

/// The port of the first `m=` line and the address of the first media-level `c=` line.
fn destination(sdp: &str) -> (String, String) {
    let port = sdp
        .lines()
        .find_map(|l| l.strip_prefix("m="))
        .and_then(|m| m.split(' ').nth(1))
        .expect("an m= line")
        .to_owned();
    let address = sdp
        .split("\r\nm=")
        .nth(1)
        .and_then(|section| {
            section
                .lines()
                .find_map(|l| l.strip_prefix("c=IN IP4 "))
                .map(str::to_owned)
        })
        .expect("a c= line in the first section");
    (port, address)
}

/// Before ICE selects a pair the default candidate (the server-reflexive one) is the
/// destination; once it has, the selected pair's local candidate is, in the offer and in the
/// answer, and the controlling agent's offer names the pair's remote candidate in
/// `a=remote-candidates`, which the answerer takes as its destination.
#[test]
fn once_ice_selected_a_pair_descriptions_name_it() -> Result<()> {
    let mut world = World {
        peers: vec![
            Peer::new(&["10.0.0.1:5000"], false)?,
            Peer::new(&["10.0.0.2:5000"], false)?,
        ],
        now: Instant::now(),
    };
    let a = world.peers[0].addrs[0];
    let b = world.peers[1].addrs[0];
    world.negotiate([vec![host(&a)?, unreachable_srflx(&a)?], vec![host(&b)?]])?;

    // Not selected yet: the default candidate.
    let offer = world.peers[0].pc.create_offer(None)?;
    assert_eq!(
        destination(&offer.sdp),
        ("6000".to_owned(), "198.51.100.7".to_owned()),
        "{}",
        offer.sdp
    );
    assert!(attributes(&offer.sdp, "remote-candidates").is_empty());

    world.run("the connection", |peers| {
        peers.iter().all(|p| p.connected && p.channel_open)
    })?;

    let offer = world.peers[0].pc.create_offer(None)?;
    assert_eq!(
        destination(&offer.sdp),
        ("5000".to_owned(), "10.0.0.1".to_owned()),
        "the selected pair's local candidate: {}",
        offer.sdp
    );
    assert_eq!(
        attributes(&offer.sdp, "remote-candidates"),
        vec!["1 10.0.0.2 5000"],
        "{}",
        offer.sdp
    );
    // Every candidate line names its ICE generation.
    let ufrag = attributes(&offer.sdp, "ice-ufrag")[0].to_owned();
    let candidates = attributes(&offer.sdp, "candidate");
    assert_eq!(candidates.len(), 2, "{}", offer.sdp);
    for line in candidates {
        assert!(line.ends_with(&format!(" ufrag {ufrag}")), "{line}");
    }

    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    assert_eq!(
        destination(&answer.sdp),
        ("5000".to_owned(), "10.0.0.2".to_owned()),
        "{}",
        answer.sdp
    );
    assert!(
        attributes(&answer.sdp, "remote-candidates").is_empty(),
        "never in an answer (RFC 8839 section 4.4.2): {}",
        answer.sdp
    );
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.run("still connected", |peers| peers.iter().all(|p| p.connected))
}

/// Two lite agents with two candidates each pair four ways. The controlling one (the offerer)
/// chooses a pair and asks for negotiation; its offer lists the chosen local candidate alone
/// and the remote one in `a=remote-candidates`; the controlled agent answers with the named
/// candidate alone and takes the pair (RFC 8445 section 8.2, RFC 8839 sections 4.4.1.3 and
/// 4.4.2.2).
#[test]
fn two_lite_agents_reconcile_their_pair_with_an_updated_offer() -> Result<()> {
    let mut world = World {
        peers: vec![
            Peer::new(&["10.0.0.1:5000", "10.1.0.1:5000"], true)?,
            Peer::new(&["10.0.0.2:5000", "10.1.0.2:5000"], true)?,
        ],
        now: Instant::now(),
    };
    let candidates =
        |p: &Peer| -> Result<Vec<RTCIceCandidateInit>> { p.addrs.iter().map(host).collect() };
    let lists = [candidates(&world.peers[0])?, candidates(&world.peers[1])?];
    world.negotiate(lists)?;
    world.run("the update", |peers| peers[0].negotiation_needed > 0)?;

    let offer = world.peers[0].pc.create_offer(None)?;
    let offered = attributes(&offer.sdp, "candidate");
    assert_eq!(
        offered.len(),
        1,
        "the chosen local candidate only: {}",
        offer.sdp
    );
    let named = attributes(&offer.sdp, "remote-candidates");
    assert_eq!(named.len(), 1, "{}", offer.sdp);
    let named_remote: Vec<&str> = named[0].split(' ').collect();

    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, offer.clone())?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let answered = attributes(&answer.sdp, "candidate");
    assert_eq!(answered.len(), 1, "{}", answer.sdp);
    let answered_fields: Vec<&str> = answered[0].split(' ').collect();
    assert_eq!(
        (answered_fields[4], answered_fields[5]),
        (named_remote[1], named_remote[2]),
        "the answer lists the candidate a=remote-candidates names"
    );
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;

    world.run("the reconciled pair", |peers| {
        peers[1]
            .pc
            .sctp()
            .and_then(|sctp| {
                sctp.transport()
                    .ice_transport()
                    .get_selected_candidate_pair()
            })
            .is_some()
    })?;
    let offered_fields: Vec<&str> = offered[0].split(' ').collect();
    let pair = world.peers[1]
        .pc
        .sctp()
        .and_then(|sctp| {
            sctp.transport()
                .ice_transport()
                .get_selected_candidate_pair()
        })
        .expect("a selected pair");
    assert_eq!(
        (
            pair.remote().address.as_str(),
            pair.remote().port.to_string()
        ),
        (offered_fields[4], offered_fields[5].to_owned()),
        "the controlled agent's pair is the controlling agent's"
    );
    // The update is done: no further negotiation is asked for.
    let asked = world.peers[0].negotiation_needed;
    world.run("settle", |_| false).ok();
    assert_eq!(world.peers[0].negotiation_needed, asked);
    Ok(())
}
