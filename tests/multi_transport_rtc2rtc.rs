//! Several transports in one peer connection (RFC 9429 sections 4.1.1, 5.2.1, 5.3.1; RFC 9143
//! section 7), between two `rtc` peers on a simulated UDP network in virtual time.
//!
//! The offerer uses the `max-compat` bundle policy, so each m= section of its offer has a
//! transport of its own: its own ICE credentials, candidates, DTLS association and SRTP keys.
//! An answer that bundles the sections closes all but the first; an answer to an offer without
//! the BUNDLE group (a peer that does not bundle) keeps them, and media and data each travel on
//! their own transport.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::data_channel::RTCDataChannelId;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCBundlePolicy;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::{
    RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTransportEventKind,
};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState,
};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit, RTCIceTransportState, RTCTransportId,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use rtc::statistics::stats::transport::RTCTransportStats;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

struct Peer {
    pc: RTCPeerConnection,
    ip: IpAddr,
    /// The local addresses this peer gathered on, one per transport.
    addrs: Vec<SocketAddr>,
    connected: bool,
    ice_states: Vec<RTCIceConnectionState>,
    channel: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
    rtp: Vec<Header>,
    /// Every event the peer raised, in order.
    events: Vec<RTCPeerConnectionEvent>,
}

impl Peer {
    fn new(ip: &str, policy: RTCBundlePolicy) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_bundle_policy(policy)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            ip: ip.parse()?,
            addrs: vec![],
            connected: false,
            ice_states: vec![],
            channel: None,
            received: vec![],
            rtp: vec![],
            events: vec![],
        })
    }

    fn host_candidate(addr: SocketAddr, mid: &str, index: u16) -> Result<RTCIceCandidateInit> {
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
        let mut init = RTCIceCandidate::from(&candidate).to_json()?;
        init.sdp_mid = Some(mid.to_owned());
        init.sdp_mline_index = Some(index);
        Ok(init)
    }
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The (from, to) address pairs datagrams travelled between.
    paths: HashSet<(SocketAddr, SocketAddr)>,
}

impl World {
    fn new(offerer: RTCBundlePolicy) -> Result<Self> {
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1", offerer)?,
                Peer::new("10.0.0.2", RTCBundlePolicy::Balanced)?,
            ],
            now: Instant::now(),
            paths: HashSet::new(),
        })
    }

    /// Every transport of each peer gathers a host candidate on a port of its own and
    /// trickles it, with its section, to the other peer.
    fn gather(&mut self) -> Result<()> {
        for i in 0..2 {
            let sections = self.peers[i].pc.ice_transport_sections();
            for (k, (mid, index)) in sections.into_iter().enumerate() {
                let addr = SocketAddr::new(self.peers[i].ip, 5000 + k as u16);
                self.peers[i].addrs.push(addr);
                let candidate = Peer::host_candidate(addr, &mid, index)?;
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    fn step(&mut self) -> Result<bool> {
        let mut in_flight = vec![];
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
            self.paths.insert((from, to));
            peer.pc.handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: data,
            })?;
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                peer.events.push(event.clone());
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed");
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                    }
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                        peer.ice_states.push(state)
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        peer.channel = Some(id)
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::DataChannelMessage(_, m) => peer.received.push(m.data.to_vec()),
                    RTCMessage::RtpPacket(_, packet) => peer.rtp.push(packet.header),
                    _ => {}
                }
            }
        }
        Ok(delivered)
    }

    fn run(&mut self, what: &str, done: impl Fn(&[Peer; 2]) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let delivered = self.step()?;
            if done(&self.peers) {
                return Ok(());
            }
            if delivered {
                continue;
            }
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("{what}: not done within {CONNECT_WITHIN:?}");
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(self.now + Duration::from_millis(50));
            self.now = next.max(self.now + Duration::from_millis(1));
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
        }
    }

    /// The offerer adds an audio and a video sender and a data channel; the offer goes
    /// through `edit` before the answerer sees it.
    fn negotiate(
        &mut self,
        edit: impl Fn(String) -> String,
    ) -> Result<(Vec<RTCRtpSenderId>, String)> {
        self.negotiate_kinds(&[RtpCodecKind::Audio, RtpCodecKind::Video], edit)
    }

    /// `negotiate` with a sender of each of `kinds`.
    fn negotiate_kinds(
        &mut self,
        kinds: &[RtpCodecKind],
        edit: impl Fn(String) -> String,
    ) -> Result<(Vec<RTCRtpSenderId>, String)> {
        let mut senders = vec![];
        for kind in kinds.iter().copied() {
            let transceiver = self.peers[0].pc.add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendonly,
                    streams: vec![],
                    send_encodings: vec![RTCRtpEncodingParameters {
                        active: true,
                        ..Default::default()
                    }],
                }),
            )?;
            senders.push(
                self.peers[0]
                    .pc
                    .rtp_transceiver(transceiver)
                    .and_then(|t| t.sender())
                    .expect("a sendonly transceiver has a sender"),
            );
        }
        self.peers[0].pc.create_data_channel("data", None)?;
        let now = self.now;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(edit(offer.sdp.clone()))?)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        Ok((senders, offer.sdp))
    }

    fn ssrc(&mut self, sender: RTCRtpSenderId) -> u32 {
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC")
    }

    fn send_rtp(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let ssrc = self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        let payload_type = self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs[0]
            .payload_type;
        let header = Header {
            version: 2,
            payload_type,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        Ok(())
    }
}

fn ufrags(sdp: &str) -> HashSet<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .map(str::to_owned)
        .collect()
}

fn without_bundle_group(sdp: String) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=group:BUNDLE"))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

/// `max-compat`, answered by a peer that does not bundle (the offer reaches it without the
/// BUNDLE group): the audio section and the data section are two transports on both sides,
/// each with its own credentials and 5-tuple, and RTP and data channel messages each arrive
/// over their own.
#[test]
fn unbundled_sections_run_on_transports_of_their_own() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, offer) = world.negotiate(without_bundle_group)?;
    assert_eq!(
        ufrags(&offer).len(),
        3,
        "max-compat: each section of the offer has ICE credentials of its own:\n{offer}"
    );
    let answer = world.peers[1]
        .pc
        .local_description()
        .expect("an answer")
        .sdp;
    assert!(!answer.contains("a=group:BUNDLE"), "{answer}");
    assert_eq!(
        ufrags(&answer).len(),
        3,
        "the answer gives each section its own:\n{answer}"
    );
    for peer in &world.peers {
        assert_eq!(peer.pc.ice_transport_sections().len(), 3);
    }

    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    // One 5-tuple per transport: ICE, DTLS and SRTP or SCTP ran on three paths each way.
    assert_eq!(world.paths.len(), 6, "{:?}", world.paths);

    let mut ids = vec![];
    for sender in &senders {
        ids.push(
            world.peers[0]
                .pc
                .rtp_sender(*sender)
                .expect("sender")
                .transport()
                .expect("a negotiated sender has a transport")
                .id(),
        );
    }
    ids.push(
        world.peers[0]
            .pc
            .sctp()
            .expect("SCTP is negotiated")
            .transport()
            .id(),
    );
    let distinct: HashSet<_> = ids.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "audio, video and data on three transports"
    );

    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    let channel = world.peers[0]
        .channel
        .expect("the offerer's channel is open");
    world.peers[0]
        .pc
        .data_channel(channel)
        .expect("the channel")
        .send(world.now, BytesMut::from(&b"over the data transport"[..]))?;
    world.run("RTP of both senders and a message delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
            && !peers[1].received.is_empty()
    })?;
    assert_eq!(world.peers[1].received[0], b"over the data transport");
    for peer in &world.peers {
        assert_eq!(
            peer.pc.ice_connection_state(),
            RTCIceConnectionState::Connected
        );
    }
    Ok(())
}

/// `max-compat` answered by a peer that bundles: the answer's BUNDLE group puts both sections
/// on the transport of the tagged one (RFC 9143 section 7.4: the offerer "MUST associate"
/// the bundled sections with the tagged one's transport), the other transport is closed, and
/// both media and data run over the one that is left.
#[test]
fn a_bundling_answer_leaves_the_tagged_sections_transport_only() -> Result<()> {
    for policy in [RTCBundlePolicy::MaxCompat, RTCBundlePolicy::Balanced] {
        a_bundling_answer_leaves_one_transport(policy)?;
    }
    Ok(())
}

fn a_bundling_answer_leaves_one_transport(policy: RTCBundlePolicy) -> Result<()> {
    let mut world = World::new(policy)?;
    let (senders, offer) = world.negotiate(|sdp| sdp)?;
    assert_eq!(ufrags(&offer).len(), 3, "{policy:?}: {offer}");
    assert_eq!(
        world.peers[0].pc.ice_transport_sections().len(),
        1,
        "the bundled answer left one transport"
    );
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(world.paths.len(), 2, "{:?}", world.paths);
    let data_transport = world.peers[0].pc.sctp().expect("SCTP").transport().id();
    for sender in &senders {
        let media_transport = world.peers[0]
            .pc
            .rtp_sender(*sender)
            .expect("sender")
            .transport()
            .expect("a transport")
            .id();
        assert_eq!(media_transport, data_transport);
    }
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("RTP delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    Ok(())
}

/// The ICE and DTLS transport ids the `OnTransportEvent`s of `peer` name, with the kinds of
/// event fired at each.
fn transport_events(peer: &Peer) -> Vec<(RTCTransportId, RTCTransportId, RTCTransportEventKind)> {
    peer.events
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnTransportEvent(event) => Some((
                event.ice_transport,
                event.dtls_transport,
                event.event.clone(),
            )),
            _ => None,
        })
        .collect()
}

/// W3C webrtc-pc 5.5, 5.6: each `RTCIceTransport` and `RTCDtlsTransport` fires its own
/// `statechange`, `gatheringstatechange` and `selectedcandidatepairchange`. With three
/// transports each one's events name it, every one of them reaches "connected", and the
/// variants that name no transport report the default transport only.
#[test]
fn every_transport_fires_its_own_state_events() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    for peer in &world.peers {
        let events = transport_events(peer);
        let ice_ids: HashSet<RTCTransportId> = events.iter().map(|(ice, _, _)| *ice).collect();
        assert_eq!(ice_ids.len(), 3, "events of three transports: {events:?}");
        for ice in &ice_ids {
            let of = |f: &dyn Fn(&RTCTransportEventKind) -> bool| {
                events.iter().any(|(on, _, kind)| on == ice && f(kind))
            };
            assert!(of(&|k| matches!(
                k,
                RTCTransportEventKind::IceStateChange(RTCIceTransportState::Connected)
            )));
            assert!(of(&|k| matches!(
                k,
                RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connected)
            )));
            assert!(of(&|k| matches!(
                k,
                RTCTransportEventKind::SelectedCandidatePairChange(_)
            )));
            assert!(of(&|k| matches!(
                k,
                RTCTransportEventKind::GatheringStateChange(RTCIceGatheringState::Gathering)
            )));
            assert!(of(&|k| matches!(
                k,
                RTCTransportEventKind::CandidatePairAdd(_)
            )));
            // The ids lead back to the transport's handle, whose ICE transport is the one
            // the events name.
            let dtls = peer
                .pc
                .dtls_transport_by_id(*ice)
                .expect("the event names a transport of the connection");
            assert_eq!(dtls.ice_transport().id(), *ice);
            assert_eq!(dtls.state(), RTCDtlsTransportState::Connected);
            assert!(dtls.ice_transport().get_selected_candidate_pair().is_some());
        }
        // Each event's DTLS id is the DTLS transport over that ICE transport.
        for (ice, dtls, _) in &events {
            assert_eq!(
                peer.pc
                    .dtls_transport_by_id(*dtls)
                    .expect("a DTLS transport of the connection")
                    .ice_transport()
                    .id(),
                *ice
            );
        }
        // The variants naming no transport are the default transport's: one transport's
        // states, each reached once.
        let legacy_connected = peer
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnDtlsTransportStateChange(
                        RTCDtlsTransportState::Connected
                    )
                )
            })
            .count();
        assert_eq!(legacy_connected, 1, "{:?}", peer.events);
        let handles = peer.pc.dtls_transports();
        assert_eq!(handles.len(), 3);
        assert_eq!(
            handles.iter().map(|t| t.id()).collect::<HashSet<_>>().len(),
            3
        );
    }
    // The senders' transports are among them, each a distinct one.
    let ids: HashSet<RTCTransportId> = senders
        .iter()
        .map(|sender| {
            world.peers[0]
                .pc
                .rtp_sender(*sender)
                .expect("sender")
                .transport()
                .expect("a transport")
                .ice_transport()
                .id()
        })
        .collect();
    assert_eq!(ids.len(), 2);
    let fired: HashSet<RTCTransportId> = transport_events(&world.peers[0])
        .iter()
        .map(|(ice, _, _)| *ice)
        .collect();
    assert!(ids.is_subset(&fired));
    Ok(())
}

/// W3C 4.3.2: the connection's `iceGatheringState` is "gathering" while any transport gathers
/// and "complete" only once all have finished; the null `icecandidate` comes once, then. Each
/// transport's end-of-candidates indication names its transport.
#[test]
fn the_gathering_state_is_complete_when_every_transport_is() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("candidates announced", |_| true)?;
    let sections = world.peers[0].pc.ice_transport_sections();
    assert_eq!(sections.len(), 3);
    assert_eq!(
        world.peers[0].pc.ice_gathering_state(),
        RTCIceGatheringState::Gathering
    );
    let mut ends = vec![];
    for (k, (mid, index)) in sections.iter().enumerate() {
        world.peers[0].events.clear();
        world.peers[0].pc.add_local_candidate(RTCIceCandidateInit {
            sdp_mid: Some(mid.clone()),
            sdp_mline_index: Some(*index),
            ..Default::default()
        })?;
        world.run("events read", |_| true)?;
        let events = &world.peers[0].events;
        let end = events.iter().find_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(ice) => ice
                .candidate
                .as_ref()
                .filter(|c| c.end_of_candidates)
                .map(|c| (c.sdp_mid.clone(), ice.ice_transport)),
            _ => None,
        });
        let (end_mid, end_transport) = end.expect("the transport's end-of-candidates");
        assert_eq!(end_mid.as_deref(), Some(mid.as_str()));
        ends.push(end_transport.expect("it names its transport"));
        let null = events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnIceCandidateEvent(ice) if ice.candidate.is_none()
            )
        });
        let complete = events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(
                    RTCIceGatheringState::Complete
                )
            )
        });
        if k + 1 < sections.len() {
            assert_eq!(
                world.peers[0].pc.ice_gathering_state(),
                RTCIceGatheringState::Gathering,
                "a transport is still gathering"
            );
            assert!(!null && !complete, "{events:?}");
        } else {
            assert_eq!(
                world.peers[0].pc.ice_gathering_state(),
                RTCIceGatheringState::Complete
            );
            assert!(null && complete, "{events:?}");
        }
    }
    assert_eq!(ends.iter().collect::<HashSet<_>>().len(), 3);
    Ok(())
}

/// The candidates each transport announces name it: the `ice_transport` of an `icecandidate`
/// is the ICE transport that holds the candidate.
#[test]
fn local_candidate_events_name_their_transport() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("candidates announced", |_| true)?;
    let peer = &world.peers[0];
    let held: Vec<(RTCTransportId, Vec<(String, u16)>)> = peer
        .pc
        .dtls_transports()
        .iter()
        .map(|t| {
            let ice = t.ice_transport();
            let candidates = ice
                .get_local_candidates()
                .iter()
                .map(|c| (c.address.clone(), c.port))
                .collect();
            (ice.id(), candidates)
        })
        .collect();
    let mut named = HashSet::new();
    for event in &peer.events {
        let RTCPeerConnectionEvent::OnIceCandidateEvent(ice) = event else {
            continue;
        };
        let Some(candidate) = ice.candidate.as_ref().filter(|c| !c.end_of_candidates) else {
            continue;
        };
        let holder = held
            .iter()
            .find(|(_, candidates)| {
                candidates.contains(&(candidate.address.clone(), candidate.port))
            })
            .map(|(id, _)| *id)
            .expect("a transport holds the candidate");
        assert_eq!(ice.ice_transport, Some(holder), "{candidate:?}");
        named.insert(holder);
    }
    assert_eq!(named.len(), 3, "each transport announced its candidate");
    Ok(())
}

/// webrtc-stats 7.1: a `transport` object per transport, each with its selected candidate
/// pair, whose `candidate-pair` names it; the RTP streams' `transportId` is the transport of
/// their section.
#[test]
fn statistics_have_a_transport_object_per_transport() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("RTP delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    let now = world.now;
    let report = world.peers[0].pc.get_stats(now, StatsSelector::None);
    let transports: Vec<&RTCTransportStats> = report
        .iter()
        .filter_map(|e| match e {
            RTCStatsReportEntry::Transport(t) => Some(t),
            _ => None,
        })
        .collect();
    assert_eq!(transports.len(), 3, "{transports:?}");
    let ids: HashSet<&str> = transports.iter().map(|t| t.stats.id.as_str()).collect();
    assert_eq!(ids.len(), 3);
    for transport in &transports {
        let pair = report
            .candidate_pairs()
            .find(|p| p.stats.id == transport.selected_candidate_pair_id)
            .expect("the selected pair is in the report");
        assert_eq!(pair.transport_id, transport.stats.id);
        assert!(pair.packets_sent > 0, "{pair:?}");
    }
    for pair in report.candidate_pairs() {
        assert!(ids.contains(pair.transport_id.as_str()));
    }
    let streams: Vec<&str> = report
        .outbound_rtp_streams()
        .map(|s| {
            s.sent_rtp_stream_stats
                .rtp_stream_stats
                .transport_id
                .as_str()
        })
        .collect();
    assert_eq!(streams.len(), 2);
    assert_ne!(streams[0], streams[1], "audio and video on two transports");
    assert!(streams.iter().all(|id| ids.contains(id)));
    Ok(())
}

/// RFC 9429 section 4.1.1, `balanced`: "gather ICE candidates for each media type in use
/// (audio, video, and data). If the remote endpoint is not BUNDLE-aware, negotiate only one
/// audio and video track on separate transports." Section 5.2.1: the first section of each
/// type has its own ICE credentials and candidates, the later ones are bundle-only. Answered
/// by a peer that does not bundle, the bundle-only video section is rejected and audio, video
/// and data each run on their own transport.
#[test]
fn balanced_gives_each_media_type_a_transport_of_its_own() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::Balanced)?;
    let kinds = [
        RtpCodecKind::Audio,
        RtpCodecKind::Video,
        RtpCodecKind::Video,
    ];
    let (senders, offer) = world.negotiate_kinds(&kinds, without_bundle_group)?;
    assert_eq!(
        ufrags(&offer).len(),
        3,
        "audio, the first video and data have their own credentials:\n{offer}"
    );
    let sections: Vec<&str> = offer.split("\r\nm=").skip(1).collect();
    assert_eq!(sections.len(), 4, "{offer}");
    assert!(
        sections[2].contains("a=bundle-only") && !sections[2].contains("a=ice-ufrag"),
        "the second video section is bundle-only, without credentials:\n{offer}"
    );
    for section in [sections[0], sections[1], sections[3]] {
        assert!(!section.contains("a=bundle-only"), "{section}");
    }
    let answer = world.peers[1]
        .pc
        .local_description()
        .expect("an answer")
        .sdp;
    let answered: Vec<&str> = answer.split("\r\nm=").skip(1).collect();
    assert!(
        answered[2].starts_with("video 0 "),
        "the bundle-only section is rejected:\n{answer}"
    );
    assert_eq!(ufrags(&answer).len(), 3, "{answer}");
    for peer in &world.peers {
        assert_eq!(peer.pc.ice_transport_sections().len(), 3);
    }
    world.gather()?;
    // RFC 9143 section 7.2: each section that is not bundle-only has an address:port of its
    // own, its transport's default candidate; the bundle-only one has port zero.
    let local = world.peers[0]
        .pc
        .local_description()
        .expect("the offer")
        .sdp;
    let ports: Vec<u16> = local
        .split("\r\nm=")
        .skip(1)
        .map(|m| {
            m.split(' ')
                .nth(1)
                .and_then(|p| p.parse().ok())
                .unwrap_or(0)
        })
        .collect();
    assert_eq!(ports[2], 0, "{local}");
    let own: HashSet<u16> = [ports[0], ports[1], ports[3]].into_iter().collect();
    assert_eq!(own.len(), 3, "three unique ports: {local}");
    assert!(!own.contains(&9) && !own.contains(&0), "{local}");
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(world.paths.len(), 6, "{:?}", world.paths);
    let live = &senders[..2];
    let mut transports = HashSet::new();
    for sender in live {
        transports.insert(
            world.peers[0]
                .pc
                .rtp_sender(*sender)
                .expect("sender")
                .transport()
                .expect("a transport")
                .id(),
        );
    }
    transports.insert(world.peers[0].pc.sctp().expect("SCTP").transport().id());
    assert_eq!(
        transports.len(),
        3,
        "audio, video and data on three transports"
    );
    let ssrcs: Vec<u32> = live.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in live {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("RTP of the audio and the first video delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    Ok(())
}
