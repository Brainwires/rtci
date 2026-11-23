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
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, DefaultInterceptorHandles, DefaultInterceptorOptions,
    register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
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
    /// The handles of the default interceptors.
    handles: DefaultInterceptorHandles,
}

impl Peer {
    /// A peer whose transports have credentials of their own (`unique`) or share the first
    /// transport's (the default), with the default interceptors or `options`.
    fn with_options(
        ip: &str,
        policy: RTCBundlePolicy,
        unique: bool,
        options: Option<&DefaultInterceptorOptions>,
    ) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let (registry, handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            options.unwrap_or(&DefaultInterceptorOptions::default()),
        )?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_bundle_policy(policy)
                    .build(),
            )
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_unique_transport_credentials(unique)
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
            handles,
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
    /// Addresses whose datagrams, either way, are lost.
    blocked: HashSet<SocketAddr>,
}

impl World {
    fn new(offerer: RTCBundlePolicy) -> Result<Self> {
        Self::with_options(offerer, true, None)
    }

    /// Two peers whose transports have credentials of their own (`unique`) or share them.
    fn with_credentials(offerer: RTCBundlePolicy, unique: bool) -> Result<Self> {
        Self::with_options(offerer, unique, None)
    }

    fn with_options(
        offerer: RTCBundlePolicy,
        unique: bool,
        options: Option<&DefaultInterceptorOptions>,
    ) -> Result<Self> {
        Ok(Self {
            peers: [
                Peer::with_options("10.0.0.1", offerer, unique, options)?,
                Peer::with_options("10.0.0.2", RTCBundlePolicy::Balanced, unique, options)?,
            ],
            now: Instant::now(),
            paths: HashSet::new(),
            blocked: HashSet::new(),
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

    /// `gather`, with peer 0 on one local address for every transport (one socket), peer 1
    /// on a port per transport.
    fn gather_on_one_socket(&mut self) -> Result<()> {
        let shared = SocketAddr::new(self.peers[0].ip, 5000);
        self.peers[0].addrs.push(shared);
        for (mid, index) in self.peers[0].pc.ice_transport_sections() {
            let candidate = Peer::host_candidate(shared, &mid, index)?;
            self.peers[0].pc.add_local_candidate(candidate.clone())?;
            self.peers[1].pc.add_remote_candidate(candidate)?;
        }
        let sections = self.peers[1].pc.ice_transport_sections();
        for (k, (mid, index)) in sections.into_iter().enumerate() {
            let addr = SocketAddr::new(self.peers[1].ip, 5000 + k as u16);
            self.peers[1].addrs.push(addr);
            let candidate = Peer::host_candidate(addr, &mid, index)?;
            self.peers[1].pc.add_local_candidate(candidate.clone())?;
            self.peers[0].pc.add_remote_candidate(candidate)?;
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
            if self.blocked.contains(&from) || self.blocked.contains(&to) {
                continue;
            }
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
        self.run_within(what, CONNECT_WITHIN, done)
    }

    /// `run` with a limit of `within` of virtual time.
    fn run_within(
        &mut self,
        what: &str,
        within: Duration,
        done: impl Fn(&[Peer; 2]) -> bool,
    ) -> Result<()> {
        let start = self.now;
        loop {
            let delivered = self.step()?;
            if done(&self.peers) {
                return Ok(());
            }
            if delivered {
                continue;
            }
            if self.now.duration_since(start) >= within {
                bail!("{what}: not done within {within:?}");
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
    // RFC 8842 section 5: `tls-id` is IDENTICAL, the tagged section's in the offer's one
    // BUNDLE group; in the answer without a group each transport names its own association.
    let tls_ids = |sdp: &str| -> HashSet<String> {
        sdp.lines()
            .filter_map(|l| l.strip_prefix("a=tls-id:"))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(tls_ids(&offer).len(), 1, "{offer}");
    assert_eq!(tls_ids(&answer).len(), 3, "{answer}");

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

/// An application that gathers on one socket for the default transport only and ends its
/// gathering with an end-of-candidates naming no section: every transport finishes, so the
/// connection's gathering state is "complete" (W3C 4.3.2) and the null `icecandidate` comes,
/// as with one transport, though the other transports have no candidate.
#[test]
fn an_end_of_candidates_naming_no_section_finishes_every_transport() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::Balanced, false)?;
    world.negotiate(without_bundle_group)?;
    assert_eq!(world.peers[0].pc.ice_transport_sections().len(), 3);
    let addr = SocketAddr::new(world.peers[0].ip, 5000);
    let mut candidate = Peer::host_candidate(addr, "", 0)?;
    candidate.sdp_mid = None;
    candidate.sdp_mline_index = None;
    world.peers[0].pc.add_local_candidate(candidate)?;
    world.run("candidates announced", |_| true)?;
    assert_eq!(
        world.peers[0].pc.ice_gathering_state(),
        RTCIceGatheringState::Gathering
    );
    world.peers[0].events.clear();
    world.peers[0]
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    world.run("events read", |_| true)?;
    assert_eq!(
        world.peers[0].pc.ice_gathering_state(),
        RTCIceGatheringState::Complete
    );
    let events = &world.peers[0].events;
    let ends: HashSet<_> = events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(ice)
                if ice.candidate.as_ref().is_some_and(|c| c.end_of_candidates) =>
            {
                ice.ice_transport
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        ends.len(),
        3,
        "an end-of-candidates per transport: {events:?}"
    );
    let nulls = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnIceCandidateEvent(ice) if ice.candidate.is_none()
            )
        })
        .count();
    assert_eq!(nulls, 1, "{events:?}");
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
        // webrtc-stats 8.17: each transport counts the datagrams that crossed it, both ways,
        // and its own change to a selected pair.
        assert!(
            transport.packets_sent > 0
                && transport.packets_received > 0
                && transport.bytes_sent > 0
                && transport.bytes_received > 0,
            "{transport:?}"
        );
        assert!(
            transport.selected_candidate_pair_changes >= 1,
            "{transport:?}"
        );
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

/// The default credentials: the transports of a `balanced` offer, and of the answer from a
/// peer that does not bundle, share the first transport's `ice-ufrag` and `ice-pwd` (what the
/// browsers write, and what Pion and webrtc-rs 0.17 require of every section; RFC 8839
/// section 5.4 allows it). Each transport still has its own candidates, 5-tuple and DTLS
/// association, told apart by the local address, and audio, video and data each run on
/// their own.
#[test]
fn by_default_the_transports_share_credentials_and_still_run_apart() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::Balanced, false)?;
    let (senders, offer) = world.negotiate(without_bundle_group)?;
    assert_eq!(ufrags(&offer).len(), 1, "one set of credentials:\n{offer}");
    let sections: Vec<&str> = offer.split("\r\nm=").skip(1).collect();
    assert_eq!(sections.len(), 3, "{offer}");
    assert!(
        sections.iter().all(|m| m.contains("a=ice-ufrag:")),
        "every section of the initial offer carries them:\n{offer}"
    );
    let answer = world.peers[1]
        .pc
        .local_description()
        .expect("an answer")
        .sdp;
    assert!(!answer.contains("a=group:BUNDLE"), "{answer}");
    assert_eq!(ufrags(&answer).len(), 1, "{answer}");
    for peer in &world.peers {
        assert_eq!(peer.pc.ice_transport_sections().len(), 3);
    }
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(world.paths.len(), 6, "{:?}", world.paths);
    let mut transports = HashSet::new();
    for sender in &senders {
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
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("RTP of both senders delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    Ok(())
}

/// The offer of `negotiate` with its one BUNDLE group split in two: the RTP sections and the
/// data section.
fn two_bundle_groups(sdp: String) -> String {
    sdp.replace(
        "a=group:BUNDLE 0 1 2",
        "a=group:BUNDLE 0 1\r\na=group:BUNDLE 2",
    )
}

/// RFC 9143 section 5 (a description "can contain multiple BUNDLE groups"), RFC 5888: an
/// offer with two BUNDLE groups is answered with the same two, each group a transport of its
/// own with its own credentials (only in its tagged section), the media of the first and the
/// data of the second each over theirs. A later offer from the answerer keeps both groups
/// (RFC 9429 section 5.2.2).
#[test]
fn two_bundle_groups_run_on_two_transports() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let mut senders = vec![];
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
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
            world.peers[0]
                .pc
                .rtp_transceiver(transceiver)
                .and_then(|t| t.sender())
                .expect("a sender"),
        );
    }
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    // A JSEP endpoint offers one group (RFC 9429 sections 5.2.1, 5.2.2) and refuses a
    // changed offer of its own; the answerer is given the offer of an endpoint that offers
    // two. The offerer's answer check takes each of the answer's groups as a subset of its
    // one offered group.
    let local = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, local.clone())?;
    let offer = RTCSessionDescription::offer(two_bundle_groups(local.sdp))?;
    assert_eq!(
        offer.sdp.matches("a=group:BUNDLE").count(),
        2,
        "{}",
        offer.sdp
    );
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    let groups: Vec<&str> = answer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=group:BUNDLE"))
        .collect();
    assert_eq!(
        groups,
        ["a=group:BUNDLE 0 1", "a=group:BUNDLE 2"],
        "each offered group is answered on its own:\n{}",
        answer.sdp
    );
    assert_eq!(ufrags(&answer.sdp).len(), 2, "{}", answer.sdp);
    // The two sections of the first group share its credentials, the data section has the
    // second group's.
    let section_ufrags: Vec<HashSet<String>> = answer
        .sdp
        .split("\r\nm=")
        .skip(1)
        .map(|section| ufrags(section))
        .collect();
    assert_eq!(section_ufrags[0], section_ufrags[1], "{}", answer.sdp);
    assert!(
        section_ufrags[0].is_disjoint(&section_ufrags[2]),
        "{}",
        answer.sdp
    );
    world.peers[0].pc.set_remote_description(now, answer)?;
    for peer in &world.peers {
        assert_eq!(peer.pc.ice_transport_sections().len(), 2);
    }

    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(world.paths.len(), 4, "{:?}", world.paths);
    let media: Vec<RTCTransportId> = senders
        .iter()
        .map(|sender| {
            world.peers[0]
                .pc
                .rtp_sender(*sender)
                .expect("sender")
                .transport()
                .expect("a transport")
                .id()
        })
        .collect();
    let data = world.peers[0].pc.sctp().expect("SCTP").transport().id();
    assert_eq!(
        media[0], media[1],
        "audio and video share the first group's transport"
    );
    assert_ne!(media[0], data, "data is on the second group's");
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    let channel = world.peers[0].channel.expect("the offerer's channel");
    world.peers[0]
        .pc
        .data_channel(channel)
        .expect("the channel")
        .send(world.now, BytesMut::from(&b"over the second group"[..]))?;
    world.run("RTP of both senders and a message delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
            && !peers[1].received.is_empty()
    })?;

    // A later offer, by the answerer, keeps both groups.
    let reoffer = world.peers[1].pc.create_offer(None)?;
    let groups: Vec<&str> = reoffer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=group:BUNDLE"))
        .collect();
    assert_eq!(
        groups,
        ["a=group:BUNDLE 0 1", "a=group:BUNDLE 2"],
        "{}",
        reoffer.sdp
    );
    assert_eq!(ufrags(&reoffer.sdp).len(), 2, "{}", reoffer.sdp);
    // The other side, given it, answers both groups.
    let now = world.now;
    world.peers[1]
        .pc
        .set_local_description(now, reoffer.clone())?;
    world.peers[0].pc.set_remote_description(now, reoffer)?;
    let answer = world.peers[0].pc.create_answer(None)?;
    let groups: Vec<&str> = answer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=group:BUNDLE"))
        .collect();
    assert_eq!(
        groups,
        ["a=group:BUNDLE 0 1", "a=group:BUNDLE 2"],
        "{}",
        answer.sdp
    );
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[1].pc.set_remote_description(now, answer)?;
    for peer in &world.peers {
        assert_eq!(peer.pc.ice_transport_sections().len(), 2);
    }
    Ok(())
}

/// Each transport's (local ufrag, remote ufrag, has a selected pair), the default one first.
fn transport_ice(peer: &Peer) -> Vec<(String, String, bool)> {
    peer.pc
        .dtls_transports()
        .iter()
        .map(|dtls| {
            let ice = dtls.ice_transport();
            (
                ice.get_local_parameters()
                    .map(|p| p.username_fragment)
                    .unwrap_or_default(),
                ice.get_remote_parameters()
                    .map(|p| p.username_fragment)
                    .unwrap_or_default(),
                ice.get_selected_candidate_pair().is_some(),
            )
        })
        .collect()
}

/// W3C `restartIce` with several transports: the next offer restarts ICE on every one (RFC
/// 9429 section 5.2.2 per transport), each takes new local credentials on both sides, and
/// each selects a pair of the new generation; RTP of both senders still arrives. With
/// `unique` each transport's new credentials are its own, else they share one new pair.
#[test]
fn restart_ice_restarts_every_transport() -> Result<()> {
    for unique in [true, false] {
        let mut world = World::with_credentials(RTCBundlePolicy::MaxCompat, unique)?;
        let (senders, _) = world.negotiate(without_bundle_group)?;
        world.gather()?;
        world.run("connected with a data channel", |peers| {
            peers.iter().all(|p| p.connected && p.channel.is_some())
        })?;
        let before: Vec<Vec<(String, String, bool)>> =
            world.peers.iter().map(transport_ice).collect();
        assert!(before.iter().all(|t| t.len() == 3), "{before:?}");

        world.peers[0].pc.restart_ice();
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        let offered = ufrags(&offer.sdp);
        assert_eq!(offered.len(), if unique { 3 } else { 1 }, "{}", offer.sdp);
        assert!(
            before[0]
                .iter()
                .all(|(local, _, _)| !offered.contains(local)),
            "every transport offers new credentials:\n{}",
            offer.sdp
        );
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(
            now,
            RTCSessionDescription::offer(without_bundle_group(offer.sdp.clone()))?,
        )?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;

        world.run(
            "every transport selected a pair of the new generation",
            |peers| {
                peers.iter().enumerate().all(|(i, p)| {
                    let theirs: HashSet<String> = transport_ice(&peers[1 - i])
                        .into_iter()
                        .map(|(local, _, _)| local)
                        .collect();
                    transport_ice(p)
                        .iter()
                        .all(|(_, remote, selected)| *selected && theirs.contains(remote))
                })
            },
        )?;
        for (i, peer) in world.peers.iter().enumerate() {
            let after = transport_ice(peer);
            assert_eq!(after.len(), 3);
            for ((new, _, _), (old, _, _)) in after.iter().zip(&before[i]) {
                assert_ne!(new, old, "peer {i}: a transport kept its credentials");
            }
        }
        let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
        world.peers[1].rtp.clear();
        for seq in 100..=105 {
            for sender in &senders {
                world.send_rtp(*sender, seq)?;
            }
        }
        world.run("RTP of both senders after the restart", |peers| {
            ssrcs
                .iter()
                .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
        })?;
    }
    Ok(())
}

/// W3C 4.3.3 / 4.3.4 with one transport cut off: the path of one of three transports loses
/// every datagram, that transport's consent checks go unanswered and it goes "disconnected"
/// (RFC 7675), the others stay "connected", and the connection's ICE and connection states
/// are "disconnected", the aggregate of all three.
#[test]
fn one_transport_losing_its_path_disconnects_the_connection_only_through_it() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let cut = world.peers[0].addrs[1];
    world.blocked.insert(cut);
    // RFC 7675: consent lapses 30 s after the last answered check at the latest.
    world.run_within(
        "the connection disconnected",
        Duration::from_secs(40),
        |peers| peers[0].pc.connection_state() == RTCPeerConnectionState::Disconnected,
    )?;
    assert_eq!(
        world.peers[0].pc.ice_connection_state(),
        RTCIceConnectionState::Disconnected
    );
    let states: Vec<RTCIceTransportState> = world.peers[0]
        .pc
        .dtls_transports()
        .iter()
        .map(|t| t.ice_transport().state())
        .collect();
    assert_eq!(states.len(), 3);
    let down = states
        .iter()
        .filter(|s| **s == RTCIceTransportState::Disconnected)
        .count();
    let up = states
        .iter()
        .filter(|s| {
            matches!(
                s,
                RTCIceTransportState::Connected | RTCIceTransportState::Completed
            )
        })
        .count();
    assert_eq!((down, up), (1, 2), "{states:?}");
    Ok(())
}

/// Several transports on one local socket (RFC 8445 section 7.2.2; RFC 9429 section 5.2.1
/// asks for candidates per transport, not for sockets): peer 0 gathers every transport on one
/// address. With credentials of their own (`with_unique_transport_credentials(true)`) a
/// Binding request is routed by its ICE username, and the rest of the datagrams by the remote
/// address, which differs per transport (two transports on one 5-tuple cannot be told apart
/// once DTLS runs). All three transports connect, and RTP of both senders and a data
/// channel message arrive.
#[test]
fn three_transports_share_one_socket_with_unique_credentials() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather_on_one_socket()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let from_shared: HashSet<SocketAddr> = world
        .paths
        .iter()
        .filter(|(from, _)| *from == world.peers[0].addrs[0])
        .map(|(_, to)| *to)
        .collect();
    assert_eq!(
        from_shared.len(),
        3,
        "one socket, three 5-tuples: {:?}",
        world.paths
    );
    for peer in &world.peers {
        let connected = peer
            .pc
            .dtls_transports()
            .iter()
            .filter(|t| t.state() == RTCDtlsTransportState::Connected)
            .count();
        assert_eq!(connected, 3);
    }
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    for seq in 1..=5 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    let channel = world.peers[0].channel.expect("open");
    world.peers[0]
        .pc
        .data_channel(channel)
        .expect("the channel")
        .send(world.now, BytesMut::from(&b"one socket"[..]))?;
    world.run("RTP and the message delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
            && !peers[1].received.is_empty()
    })?;
    Ok(())
}

/// RFC 8839 section 4.4.3.1 for a stream with a transport of its own: once the section is
/// rejected (its transceiver stopped and the offer applied), its transport is released at
/// once on both sides (its ICE agent closed, its checks ended), while the other transports go
/// on: the connection stays connected and audio still arrives.
#[test]
fn a_rejected_section_releases_its_own_transport_at_once() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let video = world.peers[0]
        .pc
        .get_transceivers()
        .nth(1)
        .expect("the video transceiver");
    world.peers[0]
        .pc
        .rtp_transceiver(video)
        .expect("the transceiver")
        .stop()?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_eq!(
        world.peers[0].pc.dtls_transports().len(),
        2,
        "the offer that rejects the section releases its transport"
    );
    world.peers[1].pc.set_remote_description(
        now,
        RTCSessionDescription::offer(without_bundle_group(offer.sdp))?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    for peer in &world.peers {
        assert_eq!(peer.pc.dtls_transports().len(), 2);
        assert_eq!(
            peer.pc.connection_state(),
            RTCPeerConnectionState::Connected
        );
    }
    let audio = world.ssrc(senders[0]);
    world.peers[1].rtp.clear();
    for seq in 50..=55 {
        world.send_rtp(senders[0], seq)?;
    }
    world.run("audio after the rejection", |peers| {
        peers[1].rtp.iter().any(|h| h.ssrc == audio)
    })?;
    Ok(())
}

/// Transport-wide congestion control numbers the packets of one transport (draft-holmer
/// section 3.1: the sequence number is per transport, and the receiver reports each
/// transport's): audio and video on transports of their own each carry a sequence without
/// gaps, though their packets left interleaved. One numbering shared by the transports
/// would leave every other number missing on each, which the remote reports as lost.
#[test]
fn each_transport_numbers_its_packets_for_congestion_feedback_on_its_own() -> Result<()> {
    let mut options = DefaultInterceptorOptions::default();
    options.congestion_feedback = CongestionFeedback::Twcc;
    // Probes would take numbers of their own between the media packets.
    options.bandwidth_probing = false;
    let mut world = World::with_options(RTCBundlePolicy::MaxCompat, true, Some(&options))?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected))?;

    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    let extension_id = |world: &mut World, sender: RTCRtpSenderId| -> u8 {
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .find(|extension| extension.uri == rtc::sdp::extmap::TRANSPORT_CC_URI)
            .map(|extension| extension.id as u8)
            .expect("transport-cc negotiated")
    };
    let ids: Vec<u8> = senders
        .iter()
        .map(|s| extension_id(&mut world, *s))
        .collect();
    for seq in 1..=10 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("ten packets of each sender delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().filter(|h| h.ssrc == *ssrc).count() >= 10)
    })?;
    for (ssrc, id) in ssrcs.iter().zip(&ids) {
        let numbers: Vec<u16> = world.peers[1]
            .rtp
            .iter()
            .filter(|h| h.ssrc == *ssrc)
            .map(|h| {
                let raw = h
                    .get_extension(*id)
                    .expect("a transport-wide sequence number");
                u16::from_be_bytes([raw[0], raw[1]])
            })
            .collect();
        for pair in numbers.windows(2) {
            assert_eq!(
                pair[1],
                pair[0].wrapping_add(1),
                "SSRC {ssrc:#x}: one numbering per transport, without gaps: {numbers:?}"
            );
        }
    }
    Ok(())
}

/// The RTP session number of `sender`'s transport.
fn session_of(world: &mut World, sender: RTCRtpSenderId) -> usize {
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .transport()
        .expect("a transport")
        .rtp_session()
}

/// Sends `packets` RTP packets on each sender, stepping the world after each round.
fn send_for_a_while(world: &mut World, senders: &[RTCRtpSenderId], packets: u16) -> Result<()> {
    for seq in 1..=packets {
        for sender in senders {
            world.send_rtp(*sender, seq)?;
        }
        for _ in 0..5 {
            world.step()?;
        }
    }
    Ok(())
}

/// RFC 8083: the circuit breakers judge a flow by the RTCP of its RTP session. With two
/// transports each has its own breaker, which knows the flows on that transport only.
#[test]
fn each_transport_has_a_circuit_breaker_of_its_own() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected))?;
    send_for_a_while(&mut world, &senders, 20)?;
    let sessions: Vec<usize> = senders.iter().map(|s| session_of(&mut world, *s)).collect();
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    let handles = world.peers[0].handles.transports.clone();
    for (index, (ssrc, session)) in ssrcs.iter().zip(&sessions).enumerate() {
        let own = handles
            .circuit_breaker(*session)
            .expect("a breaker per transport");
        assert!(
            own.state(*ssrc).is_some(),
            "its own transport's breaker watches {ssrc:#x}"
        );
        let other = handles
            .circuit_breaker(sessions[1 - index])
            .expect("a breaker per transport");
        assert!(
            other.state(*ssrc).is_none(),
            "the other transport's breaker does not watch {ssrc:#x}"
        );
    }
    Ok(())
}
