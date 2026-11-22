//! webrtc-extensions section 7 between two `rtc` peer connections: the candidate pairs the
//! ICE agent forms are announced (`OnIceCandidatePairAdd`) and listed
//! (`RTCIceTransport::get_candidate_pairs`); `select_candidate_pair` moves the data to another
//! pair, `remove_candidate_pair` drops one (`OnIceCandidatePairRemove`); both refuse what the
//! spec refuses. The offerer has two host candidates, the answerer one.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCIceCandidatePair,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

struct Peer {
    pc: RTCPeerConnection,
    addrs: Vec<SocketAddr>,
    events: Vec<RTCPeerConnectionEvent>,
    /// The local address of every datagram this peer wrote.
    sent_from: Vec<SocketAddr>,
}

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
    fn new(offerer: &[&str], answerer: &[&str]) -> Result<Self> {
        let now = Instant::now();
        let peer = |addrs: &[&str]| -> Result<Peer> {
            Ok(Peer {
                pc: RTCPeerConnectionBuilder::new().build(now)?,
                addrs: addrs.iter().map(|a| a.parse()).collect::<Result<_, _>>()?,
                events: vec![],
                sent_from: vec![],
            })
        };
        Ok(Self {
            peers: [peer(offerer)?, peer(answerer)?],
            now,
        })
    }

    fn negotiate(&mut self) -> Result<()> {
        let now = self.now;
        let [offerer, answerer] = &mut self.peers;
        offerer.pc.create_data_channel("d", None)?;
        let offer = offerer.pc.create_offer(None)?;
        offerer.pc.set_local_description(now, offer.clone())?;
        answerer.pc.set_remote_description(now, offer)?;
        let answer = answerer.pc.create_answer(None)?;
        answerer.pc.set_local_description(now, answer.clone())?;
        offerer
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(answer.sdp)?)?;
        for (from, to) in [(0, 1), (1, 0)] {
            for addr in self.peers[from].addrs.clone() {
                let candidate = host(addr)?;
                self.peers[from].pc.add_local_candidate(candidate.clone())?;
                self.peers[to].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    fn step(&mut self) -> Result<bool> {
        let mut moved = false;
        let mut in_flight = vec![];
        for (i, peer) in self.peers.iter_mut().enumerate() {
            while let Some(event) = peer.pc.poll_event() {
                peer.events.push(event);
            }
            while peer.pc.poll_read().is_some() {}
            while let Some(datagram) = peer.pc.poll_write() {
                peer.sent_from.push(datagram.transport.local_addr);
                in_flight.push((i, datagram));
            }
        }
        for (from, datagram) in in_flight {
            let to = datagram.transport.peer_addr;
            let Some(peer) = self.peers.iter_mut().find(|p| p.addrs.contains(&to)) else {
                continue;
            };
            moved = true;
            let _ = peer.pc.handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: datagram.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
            let _ = from;
        }
        Ok(moved)
    }

    fn run_until(&mut self, done: impl Fn(&World) -> bool) -> Result<bool> {
        let deadline = self.now + Duration::from_secs(30);
        while !done(self) {
            if self.now >= deadline {
                return Ok(false);
            }
            if !self.step()? {
                let next = self
                    .peers
                    .iter_mut()
                    .filter_map(|p| p.pc.poll_timeout())
                    .min()
                    .unwrap_or(self.now + Duration::from_millis(10));
                self.now = next.max(self.now + Duration::from_millis(1));
                for peer in self.peers.iter_mut() {
                    peer.pc.handle_timeout(self.now)?;
                }
            }
        }
        Ok(true)
    }

    fn connected(offerer: &[&str], answerer: &[&str]) -> Result<Self> {
        let mut world = World::new(offerer, answerer)?;
        world.negotiate()?;
        assert!(world.run_until(|w| {
            w.peers
                .iter()
                .all(|p| p.pc.connection_state() == RTCPeerConnectionState::Connected)
        })?);
        // Let the checks of the other pairs finish.
        let until = world.now + Duration::from_secs(2);
        world.run_until(|w| w.now >= until)?;
        Ok(world)
    }
}

fn pairs(pc: &RTCPeerConnection) -> Vec<RTCIceCandidatePair> {
    pc.sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_candidate_pairs()
}

fn selected(pc: &RTCPeerConnection) -> Option<RTCIceCandidatePair> {
    pc.sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
}

const OFFERER: [&str; 2] = ["10.0.0.1:5000", "10.0.0.2:5000"];
const ANSWERER: [&str; 1] = ["10.0.0.3:5000"];

/// webrtc-extensions 7: every pair the agent forms is announced and listed; here the
/// offerer's two host candidates with the answerer's one.
#[test]
fn the_candidate_pairs_are_announced_and_listed() -> Result<()> {
    let world = World::connected(&OFFERER, &ANSWERER)?;
    let offerer = &world.peers[0];
    let listed = pairs(&offerer.pc);
    assert_eq!(listed.len(), 2, "{listed:?}");
    let added: Vec<&RTCIceCandidatePair> = offerer
        .events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidatePairAdd(pair) => Some(pair),
            _ => None,
        })
        .collect();
    for pair in &listed {
        assert!(added.contains(&pair), "{pair} was not announced: {added:?}");
    }
    let locals: Vec<String> = listed
        .iter()
        .map(|p| format!("{}:{}", p.local().address, p.local().port))
        .collect();
    assert_eq!(locals, OFFERER);
    Ok(())
}

/// webrtc-extensions 7 selectCandidatePair: the data moves to the pair the application
/// selected, with a `selectedcandidatepairchange`.
#[test]
fn select_candidate_pair_moves_the_data_to_the_pair() -> Result<()> {
    let mut world = World::connected(&OFFERER, &ANSWERER)?;
    let current = selected(&world.peers[0].pc).expect("a selected pair");
    let other = pairs(&world.peers[0].pc)
        .into_iter()
        .find(|p| *p != current)
        .expect("another pair");
    let now = world.now;
    let before = world.peers[0].events.len();
    world.peers[0].pc.select_candidate_pair(now, &other)?;
    world.peers[0].sent_from.clear();
    let until = world.now + Duration::from_millis(500);
    world.run_until(|w| w.now >= until)?;
    let offerer = &world.peers[0];
    assert_eq!(selected(&offerer.pc), Some(other.clone()));
    assert!(
        offerer.events[before..].iter().any(
            |e| matches!(e, RTCPeerConnectionEvent::OnSelectedCandidatePairChange(p) if *p == other)
        ),
        "the change is announced"
    );
    let from: SocketAddr = format!("{}:{}", other.local().address, other.local().port).parse()?;
    assert!(
        !offerer.sent_from.is_empty() && offerer.sent_from.iter().all(|a| *a == from),
        "everything leaves from {from}: {:?}",
        offerer.sent_from
    );
    Ok(())
}

/// webrtc-extensions 7 removeCandidatePair: the pair goes from the list with an
/// `icecandidatepairremove`; removing it again, or a pair never listed, is a NotFoundError;
/// both calls are InvalidStateErrors before ICE started and after close.
#[test]
fn remove_candidate_pair_drops_the_pair_and_both_calls_refuse_what_the_spec_refuses() -> Result<()>
{
    let mut early = World::new(&OFFERER, &ANSWERER)?;
    early.peers[0].pc.create_data_channel("d", None)?;
    let stranger = RTCIceCandidatePair::new(RTCIceCandidate::default(), RTCIceCandidate::default());
    let now = early.now;
    for refused in [
        early.peers[0].pc.select_candidate_pair(now, &stranger),
        early.peers[0].pc.remove_candidate_pair(now, &stranger),
    ] {
        assert!(
            matches!(refused, Err(Error::InvalidStateError)),
            "{refused:?}"
        );
    }

    let mut world = World::connected(&OFFERER, &ANSWERER)?;
    let current = selected(&world.peers[0].pc).expect("a selected pair");
    let other = pairs(&world.peers[0].pc)
        .into_iter()
        .find(|p| *p != current)
        .expect("another pair");
    let now = world.now;
    let before = world.peers[0].events.len();
    world.peers[0].pc.remove_candidate_pair(now, &other)?;
    world.step()?;
    assert_eq!(pairs(&world.peers[0].pc), [current.clone()]);
    assert!(
        world.peers[0].events[before..].iter().any(
            |e| matches!(e, RTCPeerConnectionEvent::OnIceCandidatePairRemove(p) if *p == other)
        ),
        "the removal is announced"
    );
    for refused in [
        world.peers[0].pc.remove_candidate_pair(now, &other),
        world.peers[0].pc.select_candidate_pair(now, &stranger),
    ] {
        assert!(matches!(refused, Err(Error::NotFoundError)), "{refused:?}");
    }
    assert_eq!(selected(&world.peers[0].pc), Some(current.clone()));

    world.peers[0].pc.close()?;
    let refused = world.peers[0].pc.select_candidate_pair(now, &current);
    assert!(
        matches!(refused, Err(Error::InvalidStateError)),
        "{refused:?}"
    );
    Ok(())
}
