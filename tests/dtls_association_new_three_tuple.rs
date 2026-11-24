//! A new DTLS association over UDP runs on a new 3-tuple (RFC 8842 section 5.1):
//!
//! > if an unordered transport is used for the DTLS association, a new 3-tuple
//! > (transport/source address/source port) MUST be allocated by at least one of the
//! > endpoints so that DTLS packets can be demultiplexed.
//! >
//! > When an offerer needs to establish a new DTLS association, and if an unordered transport
//! > (e.g., UDP) is used, the offerer MUST allocate a new 3-tuple for the offer [...]. This
//! > typically means using a local address and/or port, or a set of ICE candidates (see
//! > Section 6), which were not recently used for any other DTLS association.
//! >
//! > When an answerer needs to establish a new DTLS association, if an unordered transport is
//! > used, and the offerer did not allocate a new 3-tuple, the answerer MUST allocate a new
//! > 3-tuple for the answer [...].
//!
//! The engine has no sockets: the application gives it its candidates. What the engine does
//! is to drop, with the ICE restart that comes with the new association, the local candidates
//! of the association it replaces (even when `with_discard_local_candidates_during_ice_restart`
//! is not set), and to refuse a UDP candidate on one of their transport addresses, so that the
//! new association can only run on new ones. Both sides do it: the offerer that asks for the
//! association, and the answerer (with trickle ICE it cannot know whether the offerer did).
//! `with_dtls_new_association_on_previous_addresses(true)` keeps the old behaviour.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent,
};
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use rtc::stun::xoraddr::XorMappedAddress;
use std::net::SocketAddr;
use std::time::Duration;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";
const A_NEW: &str = "10.0.0.1:5001";
const B_NEW: &str = "10.0.0.2:5001";

/// The transport addresses of the local candidates the peer's ICE transport holds.
fn local_candidates(pc: &RTCPeerConnection) -> Vec<SocketAddr> {
    pc.sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_local_candidates()
        .iter()
        .map(|c| SocketAddr::new(c.address.parse().expect("an IP"), c.port))
        .collect()
}

/// The events the connection has queued, taken.
fn take_events(pc: &mut RTCPeerConnection) -> Vec<RTCPeerConnectionEvent> {
    std::iter::from_fn(|| pc.poll_event()).collect()
}

/// The `OnLocalCandidatesNeeded` events among `events`.
fn candidates_needed(events: &[RTCPeerConnectionEvent]) -> Vec<RTCLocalCandidatesNeededEvent> {
    events
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => Some(needed.clone()),
            _ => None,
        })
        .collect()
}

/// A and B connected, then A asks for a new DTLS association (`renew_dtls_association`)
/// and the offer is answered: the offer and the answer are an ICE restart with a new
/// `tls-id` (RFC 9429 section 5.8.3, RFC 8842 section 6).
fn renewed(setting_engine: impl Fn() -> SettingEngine) -> Result<World> {
    let mut world = World::new(
        Peer::new(A, setting_engine())?,
        Peer::new(B, setting_engine())?,
    );
    world.connect()?;
    world.ping_pong("the first association")?;
    for p in &world.peers {
        assert_eq!(
            local_candidates(&p.pc),
            [p.addr],
            "before the new association"
        );
    }
    world.peers[0].pc.renew_dtls_association();
    world.exchange(0)?;
    Ok(world)
}

#[test]
fn a_new_association_drops_the_local_candidates_and_refuses_their_addresses() -> Result<()> {
    let mut world = renewed(|| SettingEngineBuilder::new().build())?;
    for (i, who) in ["the offerer", "the answerer"].into_iter().enumerate() {
        let peer = &mut world.peers[i];
        assert_eq!(
            local_candidates(&peer.pc),
            Vec::<SocketAddr>::new(),
            "{who} holds no candidate of the previous association"
        );
        let old = peer.candidate()?;
        match peer.pc.add_local_candidate(old) {
            Err(Error::ErrICECandidateAddressOfPreviousDtlsAssociation(addr)) => {
                assert_eq!(addr, peer.addr, "{who}")
            }
            other => panic!("{who}: the previous address is refused, got {other:?}"),
        }
    }
    // On new ports the new association is established and carries the data channel.
    world.peers[0].addr = A_NEW.parse()?;
    world.peers[1].addr = B_NEW.parse()?;
    world.trickle()?;
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the new 3-tuples")?;
    for p in &world.peers {
        assert_eq!(
            local_candidates(&p.pc),
            [p.addr],
            "after the new association"
        );
    }
    Ok(())
}

/// An ICE restart that keeps the DTLS association (RFC 8842 section 6: "an ICE restart does
/// not by default require a new DTLS association") keeps the local candidates.
#[test]
fn an_ice_restart_without_a_new_association_keeps_the_local_candidates() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    world.peers[0].pc.restart_ice();
    world.exchange(0)?;
    for p in &world.peers {
        assert_eq!(local_candidates(&p.pc), [p.addr], "an ICE restart alone");
    }
    world.ping_pong("after the ICE restart")?;
    Ok(())
}

/// `with_dtls_new_association_on_previous_addresses(true)`: the new association keeps the
/// local candidates and runs on the previous 3-tuples.
#[test]
fn with_dtls_new_association_on_previous_addresses_the_candidates_are_kept() -> Result<()> {
    let mut world = renewed(|| {
        SettingEngineBuilder::new()
            .with_dtls_new_association_on_previous_addresses(true)
            .build()
    })?;
    for p in &mut world.peers {
        assert!(
            candidates_needed(&take_events(&mut p.pc)).is_empty(),
            "no OnLocalCandidatesNeeded with the opt-out"
        );
        assert_eq!(local_candidates(&p.pc), [p.addr], "kept");
        let old = p.candidate()?;
        p.pc.add_local_candidate(old)?;
    }
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the previous 3-tuples")?;
    Ok(())
}

/// The application is told: the ICE restart of a new association fires
/// `OnLocalCandidatesNeeded` on each side when it is applied there (the offerer's
/// `set_local_description` of the offer, the answerer's of the answer), reason
/// `NewDtlsAssociation`, with the transport's ids and mid and the refused address, right
/// before the transport's `gatheringstatechange` to "gathering". RFC 9429 section 3.5.1: "When
/// a new gathering phase starts, the ICE agent will notify the application that gathering is
/// occurring through a state change event"; W3C webrtc-pc 5.6: the transport's gatherer is
/// "gathering" until the end-of-candidates indication, then "complete" ("It will not gather
/// candidates again until an ICE restart causes it to restart").
#[test]
fn a_new_association_tells_the_application_to_gather_on_new_addresses() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    // The first generation ends ("complete"), so that the new one's start is a change.
    for p in &mut world.peers {
        p.pc.add_local_candidate(RTCIceCandidateInit::default())?;
        assert_eq!(p.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    }
    world.run("the first generation ended", |_| true)?;
    world.peers[0].pc.renew_dtls_association();
    world.exchange(0)?;
    for (i, who) in ["the offerer", "the answerer"].into_iter().enumerate() {
        let peer = &mut world.peers[i];
        let events = take_events(&mut peer.pc);
        let needed = candidates_needed(&events);
        assert_eq!(needed.len(), 1, "{who}: {needed:?}");
        let needed = &needed[0];
        assert_eq!(
            needed.reason,
            RTCLocalCandidatesNeededReason::NewDtlsAssociation,
            "{who}"
        );
        assert_eq!(needed.refused_addresses, vec![peer.addr], "{who}");
        assert_eq!(needed.mids, vec!["0".to_owned()], "{who}: the data section");
        assert_eq!(needed.sdp_mline_index, Some(0), "{who}");
        let transport = peer.pc.sctp().expect("sctp").transport();
        assert_eq!(needed.dtls_transport, transport.id(), "{who}");
        assert_eq!(
            needed.ice_transport,
            transport.ice_transport().id(),
            "{who}"
        );
        let at = events
            .iter()
            .position(|e| matches!(e, RTCPeerConnectionEvent::OnLocalCandidatesNeeded(_)))
            .expect("the event");
        assert!(
            matches!(
                events.get(at + 1),
                Some(RTCPeerConnectionEvent::OnIceGathererStateChange(
                    RTCIceGatheringState::Gathering
                ))
            ),
            "{who}: right before the gathering begins: {:?}",
            &events[at..]
        );
        assert_eq!(
            peer.pc.ice_gathering_state(),
            RTCIceGatheringState::Gathering
        );
        // The application gathers on a new port and ends the generation.
        peer.addr = SocketAddr::new(peer.addr.ip(), peer.addr.port() + 1);
        let candidate = peer.candidate()?;
        peer.pc.add_local_candidate(candidate)?;
        assert_eq!(
            peer.pc.ice_gathering_state(),
            RTCIceGatheringState::Gathering,
            "{who}: until the end of candidates"
        );
        peer.pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        assert_eq!(
            peer.pc.ice_gathering_state(),
            RTCIceGatheringState::Complete,
            "{who}"
        );
    }
    for i in 0..2 {
        let candidate = world.peers[i].candidate()?;
        world.peers[1 - i].pc.add_remote_candidate(candidate)?;
    }
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the new 3-tuples")?;
    Ok(())
}

/// `with_discard_local_candidates_during_ice_restart(true)`: every ICE restart drops the
/// local candidates, so the application is told too (`DiscardedBySetting`), with no address
/// refused: the previous one is accepted again.
#[test]
fn a_restart_that_discards_the_candidates_asks_for_candidates_on_any_address() -> Result<()> {
    let settings = || {
        SettingEngineBuilder::new()
            .with_discard_local_candidates_during_ice_restart(true)
            .build()
    };
    let mut world = World::new(Peer::new(A, settings())?, Peer::new(B, settings())?);
    world.connect()?;
    world.peers[0].pc.restart_ice();
    world.exchange(0)?;
    for (i, who) in ["the offerer", "the answerer"].into_iter().enumerate() {
        let peer = &mut world.peers[i];
        let needed = candidates_needed(&take_events(&mut peer.pc));
        assert_eq!(needed.len(), 1, "{who}: {needed:?}");
        assert_eq!(
            needed[0].reason,
            RTCLocalCandidatesNeededReason::DiscardedBySetting,
            "{who}"
        );
        assert!(!needed[0].reason.needs_new_addresses());
        assert!(needed[0].refused_addresses.is_empty(), "{who}");
        let candidate = peer.candidate()?;
        peer.pc.add_local_candidate(candidate)?;
    }
    world.run("after the restart", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the same addresses")?;
    Ok(())
}

/// RFC 8445 section 5.1.1.2 after a new DTLS association: the engine gathers
/// server-reflexive candidates for each host candidate the application adds, so once the
/// application has added its candidate on a new port the engine asks the STUN server from
/// that port and announces the mapped address it reports (related address: the new port).
/// The probe from the refused port ends: nothing more is asked from it, and a late answer to
/// it is not announced (the candidate would send from the previous association's socket).
#[test]
fn after_a_new_association_the_engine_gathers_server_reflexive_candidates_from_the_new_port()
-> Result<()> {
    const SERVER: &str = "192.0.2.10:3478";
    let server: SocketAddr = SERVER.parse()?;
    let with_server = || {
        RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec![format!("stun:{SERVER}")],
                ..Default::default()
            }])
            .build()
    };
    let mut world = World::new(
        Peer::with_configuration(A, with_server(), SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    // The probe from the first host candidate: its request is on its way, unanswered.
    let first: SocketAddr = A.parse()?;
    let old_request = world
        .undelivered
        .iter()
        .filter(|(from, to, _)| *from == first && *to == server)
        .filter_map(|(_, _, data)| {
            let mut message = Message::new();
            message.unmarshal_binary(data).ok()?;
            (message.typ == BINDING_REQUEST).then_some(message)
        })
        .next_back()
        .expect("a Binding request from the first host candidate");
    world.peers[0].pc.renew_dtls_association();
    world.exchange(0)?;
    let a = &mut world.peers[0];
    let needed = candidates_needed(&take_events(&mut a.pc));
    assert_eq!(needed.len(), 1, "{needed:?}");
    let old = a.addr;
    a.addr = A_NEW.parse()?;
    let candidate = a.candidate()?;
    a.pc.add_local_candidate(candidate)?;
    let mut now = world.now;
    let mut request = None;
    for _ in 0..20 {
        while let Some(datagram) = a.pc.poll_write() {
            if datagram.transport.peer_addr != server {
                continue;
            }
            let mut message = Message::new();
            if message.unmarshal_binary(&datagram.message).is_ok() && message.typ == BINDING_REQUEST
            {
                assert_ne!(
                    datagram.transport.local_addr, old,
                    "nothing is asked from the refused address"
                );
                if datagram.transport.local_addr == a.addr {
                    request = Some(message);
                }
            }
        }
        if request.is_some() {
            break;
        }
        now += Duration::from_millis(50);
        a.pc.handle_timeout(now)?;
    }
    let request = request.expect("a Binding request from the new port");
    // The server answers both: the previous socket's request too late, the new one's.
    for (request, local, port) in [(&old_request, old, 61000), (&request, a.addr, 61001)] {
        let mut response = Message::new();
        let setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: "203.0.113.5".parse()?,
                port,
            }),
        ];
        response.build(&setters)?;
        a.pc.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: local,
                peer_addr: server,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: response.raw.as_slice().into(),
        })?;
    }
    let srflx: Vec<String> = take_events(&mut a.pc)
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(event) => event.candidate.as_ref(),
            _ => None,
        })
        .filter_map(|c| c.to_json().ok())
        .map(|c| c.candidate)
        .filter(|c| c.contains("typ srflx"))
        .collect();
    assert_eq!(srflx.len(), 1, "one server-reflexive candidate: {srflx:?}");
    assert!(
        srflx[0].contains("203.0.113.5 61001 typ srflx raddr 10.0.0.1 rport 5001"),
        "{}",
        srflx[0]
    );
    Ok(())
}
