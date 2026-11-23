//! RFC 9147 sections 9 and 11 between two `rtc` peer connections that use DTLS connection
//! ids (`with_dtls_connection_id`): "Implementations SHOULD use a new CID whenever sending on
//! a new path and SHOULD request new CIDs for this purpose if path changes are anticipated"
//! (section 9), and "SHOULD attempt to use fresh CIDs whenever they change local addresses or
//! ports" (section 11). The ICE agent's selected pair is the path: when the application moves
//! the data to another pair (`select_candidate_pair`), the DTLS 1.3 association switches to a
//! fresh connection id. The offerer has two host candidates, the answerer one.
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
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The connection id length both peers ask for.
const CID_LENGTH: usize = 8;

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
    /// The local address of every DTLS datagram (the data, not the STUN checks) this peer
    /// wrote.
    sent_from: Vec<SocketAddr>,
    /// The connection id of every DTLS 1.3 record with one (unified header, C bit) this
    /// peer wrote, with the local address it left from.
    cids: Vec<(SocketAddr, Vec<u8>)>,
}

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
    fn new(offerer: &[&str], answerer: &[&str]) -> Result<Self> {
        Self::new_with_proposals(offerer, answerer, false)
    }

    /// With `proposals`, the offerer (controlling) proposes its nominations
    /// (`with_candidate_pair_proposals`).
    fn new_with_proposals(offerer: &[&str], answerer: &[&str], proposals: bool) -> Result<Self> {
        let now = Instant::now();
        let peer = |addrs: &[&str], proposals: bool| -> Result<Peer> {
            Ok(Peer {
                pc: RTCPeerConnectionBuilder::new()
                    .with_setting_engine(
                        rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                            .with_candidate_pair_proposals(proposals)
                            .with_dtls_connection_id(Some(CID_LENGTH))
                            .build(),
                    )
                    .build(now)?,
                addrs: addrs.iter().map(|a| a.parse()).collect::<Result<_, _>>()?,
                events: vec![],
                sent_from: vec![],
                cids: vec![],
            })
        };
        Ok(Self {
            peers: [peer(offerer, proposals)?, peer(answerer, false)?],
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
                if datagram
                    .message
                    .first()
                    .is_some_and(|b| (20..=63).contains(b))
                {
                    peer.sent_from.push(datagram.transport.local_addr);
                }
                // RFC 9147 section 4: a unified header is 0b001CSLEE; with C set the
                // connection id follows the first byte.
                if let Some(cid) = datagram
                    .message
                    .first()
                    .filter(|b| *b & 0xF0 == 0x30)
                    .and_then(|_| datagram.message.get(1..1 + CID_LENGTH))
                {
                    peer.cids
                        .push((datagram.transport.local_addr, cid.to_vec()));
                }
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

/// The offerer moves its data to its other host candidate: every DTLS 1.3 record it sends
/// from there carries one connection id, a different one from the records before the move.
#[test]
fn a_new_ice_path_gets_a_fresh_connection_id() -> Result<()> {
    let mut world = World::connected(&OFFERER, &ANSWERER)?;
    let before: Vec<Vec<u8>> = world.peers[0].cids.iter().map(|(_, c)| c.clone()).collect();
    assert!(
        !before.is_empty(),
        "DTLS 1.3 records with a connection id before the move"
    );
    let old = before.last().expect("a connection id").clone();
    let current = selected(&world.peers[0].pc).expect("a selected pair");
    let other = pairs(&world.peers[0].pc)
        .into_iter()
        .find(|p| *p != current)
        .expect("another pair");
    let now = world.now;
    world.peers[0].pc.select_candidate_pair(now, &other)?;
    world.peers[0].cids.clear();
    // Data to carry: a new channel's DATA_CHANNEL_OPEN.
    world.peers[0].pc.create_data_channel("after", None)?;
    let until = world.now + Duration::from_millis(500);
    world.run_until(|w| w.now >= until)?;
    assert!(
        world.peers[0].events.iter().any(|e| matches!(
            e,
            RTCPeerConnectionEvent::OnSelectedCandidatePairChange(p) if *p == other
        )),
        "the pair changed"
    );
    let from: SocketAddr = format!("{}:{}", other.local().address, other.local().port).parse()?;
    let after: Vec<&Vec<u8>> = world.peers[0]
        .cids
        .iter()
        .filter(|(addr, _)| *addr == from)
        .map(|(_, c)| c)
        .collect();
    assert!(!after.is_empty(), "records on the new path");
    assert!(
        after.iter().all(|c| **c != old),
        "the old connection id {old:02x?} on the new path: {after:02x?}"
    );
    assert!(
        after.windows(2).all(|w| w[0] == w[1]),
        "one connection id on the new path: {after:02x?}"
    );
    assert_eq!(
        world.peers[0].pc.connection_state(),
        RTCPeerConnectionState::Connected
    );
    Ok(())
}
