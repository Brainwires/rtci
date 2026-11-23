//! Several transports in one peer connection (RFC 9429 sections 4.1.1, 5.2.1, 5.3.1; RFC 9143
//! section 7), between two `rtc` peers on a simulated UDP network in virtual time.
//!
//! The offerer uses the `max-compat` bundle policy, so each m= section of its offer has a
//! transport of its own: its own ICE credentials, candidates, DTLS association and SRTP keys.
//! An answer that bundles the sections closes all but the first; an answer to an offer without
//! the BUNDLE group (a peer that does not bundle) keeps them, and media and data each travel on
//! their own transport.

use anyhow::{Context, Result, bail};
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
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState, RTCSignalingState,
};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit, RTCIceCandidateType, RTCIceTransportState, RTCTransportId,
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
use stream_driver::sockets::UfragMux;

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
    /// What arrives on peer 0's shared address goes through the reference driver's mux for a
    /// shared port first (`rtc-stream-driver`'s `UfragMux`), as a server routes it.
    mux: Option<(SocketAddr, UfragMux<usize>)>,
    /// Datagrams the mux had no connection for.
    misrouted: usize,
    /// Remote candidates on their way to a peer: (peer, due, candidate).
    trickling: Vec<(usize, Instant, RTCIceCandidateInit)>,
    /// The (from address, SSRC, size) of each SRTP packet that travelled (the RTP header is in
    /// the clear).
    srtp: Vec<(SocketAddr, u32, usize)>,
    /// The (from, to) addresses of every RTCP datagram written, delivered or lost.
    rtcp: Vec<(SocketAddr, SocketAddr)>,
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
        Self::with_policies(offerer, RTCBundlePolicy::Balanced, unique, options)
    }

    /// `with_options` with the answerer's bundle policy too.
    fn with_policies(
        offerer: RTCBundlePolicy,
        answerer: RTCBundlePolicy,
        unique: bool,
        options: Option<&DefaultInterceptorOptions>,
    ) -> Result<Self> {
        Ok(Self {
            peers: [
                Peer::with_options("10.0.0.1", offerer, unique, options)?,
                Peer::with_options("10.0.0.2", answerer, unique, options)?,
            ],
            now: Instant::now(),
            paths: HashSet::new(),
            blocked: HashSet::new(),
            mux: None,
            misrouted: 0,
            trickling: vec![],
            srtp: vec![],
            rtcp: vec![],
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

    /// `gather` for the transports a later exchange added: the sections past those each peer
    /// gathered for already get a port of their own.
    fn gather_new(&mut self) -> Result<()> {
        for i in 0..2 {
            let sections = self.peers[i].pc.ice_transport_sections();
            let known = self.peers[i].addrs.len();
            for (k, (mid, index)) in sections.into_iter().enumerate().skip(known) {
                let addr = SocketAddr::new(self.peers[i].ip, 5000 + k as u16);
                self.peers[i].addrs.push(addr);
                let candidate = Peer::host_candidate(addr, &mid, index)?;
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    /// One offer from peer 0 and its answer, unchanged; returns the offer.
    fn renegotiate(&mut self) -> Result<String> {
        self.renegotiate_with(|sdp| sdp)
    }

    /// `renegotiate`, the offer going through `edit` before peer 1 sees it.
    fn renegotiate_with(&mut self, edit: impl Fn(String) -> String) -> Result<String> {
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
        Ok(offer.sdp)
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

    /// `gather_on_one_socket` through the driver's shared-port mux, with the transports
    /// sharing their credentials on both sides: peer 0 gathers every transport on one
    /// address, peer 1 a port per transport, and peer 1's candidates reach peer 0 only `late`
    /// after peer 1's first checks, so that those arrive from addresses no transport of
    /// peer 0 knows.
    fn gather_on_one_shared_port(&mut self, late: Duration) -> Result<()> {
        let shared = SocketAddr::new(self.peers[0].ip, 4000);
        self.peers[0].addrs.push(shared);
        let mut mux = UfragMux::new();
        for ufrag in self.peers[0].pc.ice_username_fragments() {
            mux.register(&ufrag, 0);
        }
        self.mux = Some((shared, mux));
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
            self.trickling.push((0, self.now + late, candidate));
        }
        Ok(())
    }

    fn step(&mut self) -> Result<bool> {
        let now = self.now;
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.trickling)
            .into_iter()
            .partition(|(_, at, _)| *at <= now);
        self.trickling = later;
        for (peer, _, candidate) in due {
            self.peers[peer].pc.add_remote_candidate(candidate)?;
        }
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
            // RFC 7983 / RFC 5761 section 4: a first byte of 128..=191 and a packet type of
            // 192..=223 is RTCP.
            if data.len() >= 8 && (128..=191).contains(&data[0]) && (192..=223).contains(&data[1]) {
                self.rtcp.push((from, to));
            }
            if self.blocked.contains(&from) || self.blocked.contains(&to) {
                continue;
            }
            if let Some((shared, mux)) = self.mux.as_mut()
                && to == *shared
                && mux.route(from, &data) != Some(0)
            {
                self.misrouted += 1;
                continue;
            }
            let Some(peer) = self.peers.iter_mut().find(|p| p.addrs.contains(&to)) else {
                continue;
            };
            self.paths.insert((from, to));
            // RFC 7983: 128..=191 is RTP or RTCP; RTCP has a packet type of 192..=223
            // (RFC 5761 section 4).
            if data.len() >= 12 && (128..=191).contains(&data[0]) && !(192..=223).contains(&data[1])
            {
                let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                self.srtp.push((from, ssrc, data.len()));
            }
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

    /// Runs for `by` of virtual time, whatever happens.
    fn advance(&mut self, by: Duration) -> Result<()> {
        let until = self.now + by;
        while self.now < until {
            if self.step()? {
                continue;
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(until)
                .min(until);
            self.now = next.max(self.now + Duration::from_millis(1));
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
        }
        Ok(())
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
        self.negotiate_media(kinds, true, edit)
    }

    /// `negotiate_kinds`, with the data channel only when `data`.
    fn negotiate_media(
        &mut self,
        kinds: &[RtpCodecKind],
        data: bool,
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
        if data {
            self.peers[0].pc.create_data_channel("data", None)?;
        }
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
    // W3C 4.4.1.6: the transports the answer left unused are closed, "and this results in
    // events firing on these objects": DTLS and then ICE "closed", at each of the two.
    let closed: Vec<(RTCTransportId, RTCTransportId, RTCTransportEventKind)> =
        transport_events(&world.peers[0])
            .into_iter()
            .filter(|(_, _, kind)| {
                matches!(
                    kind,
                    RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Closed)
                        | RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed)
                )
            })
            .collect();
    let closed_dtls: HashSet<RTCTransportId> = closed.iter().map(|(_, dtls, _)| *dtls).collect();
    assert_eq!(closed.len(), 4, "{policy:?}: {closed:?}");
    assert_eq!(closed_dtls.len(), 2, "{policy:?}: {closed:?}");
    assert!(
        !closed_dtls.contains(&data_transport),
        "{policy:?}: {closed:?}"
    );
    for pair in closed.chunks(2) {
        assert!(
            matches!(
                (&pair[0].2, &pair[1].2),
                (
                    RTCTransportEventKind::DtlsStateChange(_),
                    RTCTransportEventKind::IceStateChange(_)
                )
            ) && pair[0].1 == pair[1].1,
            "{policy:?}: DTLS, then its ICE transport: {closed:?}"
        );
    }
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
    let section_ufrags: Vec<HashSet<String>> =
        answer.sdp.split("\r\nm=").skip(1).map(ufrags).collect();
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

/// Several transports on one shared port with the DEFAULT credentials (shared by every
/// transport, on both sides), through the reference driver's shared-port path
/// (`rtc-stream-driver`'s `UfragMux`): the ICE username names peer 0's connection but not a
/// transport, so the engine routes by the rest of the USERNAME, the 5-tuple a transport used,
/// the remote candidates and the remote agent's tie-breaker (`TransportSet::route`). Peer 1's
/// candidates reach peer 0 late, so its first checks name no transport of peer 0 and are
/// dropped, not answered by a transport they are not for. All three transports connect, each
/// on a path of its own section (its selected pair's remote candidate is peer 1's host
/// candidate, never a peer-reflexive one learned from another transport's check), and RTP of
/// both senders and a data channel message arrive.
#[test]
fn three_transports_share_one_port_with_shared_credentials_through_the_drivers_mux() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::MaxCompat, false)?;
    let (senders, offer) = world.negotiate(without_bundle_group)?;
    assert_eq!(
        ufrags(&offer).len(),
        1,
        "the transports share their credentials"
    );
    world.gather_on_one_shared_port(Duration::from_millis(500))?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(
        world.misrouted, 0,
        "the mux found the connection for everything"
    );
    for (i, peer) in world.peers.iter().enumerate() {
        let transports = peer.pc.dtls_transports();
        assert_eq!(transports.len(), 3);
        let mut remotes = HashSet::new();
        for transport in &transports {
            assert_eq!(transport.state(), RTCDtlsTransportState::Connected);
            let pair = transport
                .ice_transport()
                .get_selected_candidate_pair()
                .expect("a selected pair");
            assert_eq!(
                pair.remote().typ,
                RTCIceCandidateType::Host,
                "peer {i}: a transport took another's path: {pair}"
            );
            remotes.insert((pair.remote().address.clone(), pair.remote().port));
        }
        assert_eq!(
            remotes.len(),
            if i == 0 { 3 } else { 1 },
            "peer {i}: {remotes:?}"
        );
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
        .send(world.now, BytesMut::from(&b"one port"[..]))?;
    world.run("RTP and the message delivered", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
            && !peers[1].received.is_empty()
    })?;
    Ok(())
}

/// The m= section of `mid` in `sdp`.
fn section_of<'a>(sdp: &'a str, mid: &str) -> &'a str {
    sdp.split("\r\nm=")
        .find(|section| section.contains(&format!("a=mid:{mid}\r\n")))
        .unwrap_or_default()
}

/// The mids of the BUNDLE group lines of `sdp`.
fn bundled_mids(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=group:BUNDLE "))
        .flat_map(|l| l.split(' ').map(str::to_owned))
        .collect()
}

/// RFC 9143 section 7.5.2, this side moving a section out of its BUNDLE group: the
/// application asks for it (`RTCRtpTransceiver::set_bundle_request(Some(false))`) and the next
/// offer leaves the video section's tag out of the group, without `a=bundle-only`, with
/// transport attributes of its own; the answer accepts it outside, both sides give it a
/// transport of its own, and video RTP travels on the new 5-tuple while audio stays on the
/// group's. `Some(true)` puts it back in the group at the next offer (section 7.5.1) and the
/// bundling answer closes its transport.
#[test]
fn this_side_moves_a_section_out_of_the_bundle_group_and_back() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::Balanced, false)?;
    let (senders, _) = world.negotiate(|sdp| sdp)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    for peer in &world.peers {
        assert_eq!(peer.pc.dtls_transports().len(), 1, "everything is bundled");
    }
    let video = world.peers[0]
        .pc
        .get_transceivers()
        .nth(1)
        .expect("the video transceiver");
    let video_mid = world.peers[0]
        .pc
        .rtp_transceiver(video)
        .and_then(|t| t.mid().clone())
        .expect("a mid");
    world.peers[0]
        .pc
        .rtp_transceiver(video)
        .expect("the transceiver")
        .set_bundle_request(Some(false));

    // The offer already gives the section a transport of its own (RFC 9143 7.5.2: "a unique
    // address:port"), before any answer: one for the application to gather for.
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_eq!(
        world.peers[0].pc.dtls_transports().len(),
        2,
        "{}",
        offer.sdp
    );
    assert_eq!(world.peers[0].pc.ice_transport_sections().len(), 2);
    world.peers[1]
        .pc
        .set_remote_description(now, offer.clone())?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    let offer = offer.sdp;
    assert!(
        !bundled_mids(&offer).contains(&video_mid),
        "the tag is out of the group:\n{offer}"
    );
    assert!(
        !bundled_mids(&offer).is_empty(),
        "the group stays:\n{offer}"
    );
    let section = section_of(&offer, &video_mid);
    assert!(!section.contains("a=bundle-only"), "{section}");
    assert!(section.contains("a=ice-ufrag:"), "{section}");
    for peer in &world.peers {
        assert_eq!(peer.pc.dtls_transports().len(), 2, "a transport of its own");
    }
    world.gather_new()?;
    world.run("the new transport connected on both sides", |peers| {
        peers.iter().all(|p| {
            p.pc.dtls_transports()
                .iter()
                .all(|t| t.state() == RTCDtlsTransportState::Connected)
        })
    })?;
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    world.paths.clear();
    for seq in 10..=15 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("audio and video after the move", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    let from: HashSet<SocketAddr> = world.paths.iter().map(|(from, _)| *from).collect();
    assert!(
        from.contains(&world.peers[0].addrs[0]) && from.contains(&world.peers[0].addrs[1]),
        "media leaves on both 5-tuples: {:?}",
        world.paths
    );

    world.peers[0]
        .pc
        .rtp_transceiver(video)
        .expect("the transceiver")
        .set_bundle_request(Some(true));
    let offer = world.renegotiate()?;
    assert!(
        bundled_mids(&offer).contains(&video_mid),
        "back in the group:\n{offer}"
    );
    for peer in &world.peers {
        assert_eq!(
            peer.pc.dtls_transports().len(),
            1,
            "the transport is closed"
        );
    }
    world.peers[1].rtp.clear();
    for seq in 20..=25 {
        world.send_rtp(senders[1], seq)?;
    }
    world.run("video on the group's transport again", |peers| {
        peers[1].rtp.iter().any(|h| h.ssrc == ssrcs[1])
    })?;
    Ok(())
}

/// Bandwidth probing per transport (RFC 8836 section 2, requirement 4; RFC 8835 section 4.2:
/// each transport its own congestion controller): two video senders on transports of their
/// own, each sending less than its target, and each transport's prober fills its own
/// clusters with padding on its own sender's RTX stream, sent on its own 5-tuple. With
/// probing off neither RTX stream carries a packet (nothing is lost here).
#[test]
fn each_transport_probes_its_own_path() -> Result<()> {
    for probing in [true, false] {
        let mut options = DefaultInterceptorOptions::default();
        options.congestion_feedback = CongestionFeedback::Twcc;
        options.bandwidth_probing = probing;
        // A `max-compat` answerer takes both video sections of an offer without a BUNDLE
        // group (a `balanced` one rejects the second of a type, RFC 9429 4.1.1).
        let mut world = World::with_policies(
            RTCBundlePolicy::MaxCompat,
            RTCBundlePolicy::MaxCompat,
            false,
            Some(&options),
        )?;
        let (senders, _) = world.negotiate_kinds(
            &[RtpCodecKind::Video, RtpCodecKind::Video],
            without_bundle_group,
        )?;
        world.gather()?;
        world.run("connected", |peers| peers.iter().all(|p| p.connected))?;
        let rtx: Vec<u32> = senders
            .iter()
            .map(|sender| {
                world.peers[0]
                    .pc
                    .rtp_sender(*sender)
                    .expect("sender")
                    .get_parameters()
                    .encodings[0]
                    .rtp_coding_parameters
                    .rtx
                    .as_ref()
                    .map(|rtx| rtx.ssrc)
                    .expect("an RTX stream")
            })
            .collect();
        let media: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
        world.srtp.clear();
        // A little media, far below any target: the probers find the senders application
        // limited and probe (`PROBE_APPLICATION_LIMITED_INTERVAL`, 5 s).
        for seq in 1..=120u16 {
            for sender in &senders {
                world.send_rtp(*sender, seq)?;
            }
            world.advance(Duration::from_millis(100))?;
        }
        // Each sender's media and RTX leave from one local address, and the two senders'
        // from two.
        let from = |ssrc: u32| -> HashSet<SocketAddr> {
            world
                .srtp
                .iter()
                .filter(|(_, s, _)| *s == ssrc)
                .map(|(from, _, _)| *from)
                .collect()
        };
        let media_from: Vec<HashSet<SocketAddr>> = media.iter().map(|s| from(*s)).collect();
        assert!(media_from.iter().all(|f| f.len() == 1), "{media_from:?}");
        assert_ne!(media_from[0], media_from[1], "two transports");
        for (i, ssrc) in rtx.iter().enumerate() {
            let sent = world.srtp.iter().filter(|(_, s, _)| s == ssrc).count();
            if probing {
                assert!(sent > 0, "transport {i} probed: no RTX packet on it");
                assert_eq!(
                    from(*ssrc),
                    media_from[i],
                    "transport {i}'s probes travel its own path"
                );
            } else {
                assert_eq!(sent, 0, "transport {i}: no probing, no RTX");
            }
        }
    }
    Ok(())
}

/// The `a=tls-id` values of `sdp`, in order.
fn tls_ids(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=tls-id:"))
        .map(str::to_owned)
        .collect()
}

/// RFC 8842 section 5.5 and RFC 5764 section 4.4 per transport: `renew_dtls_association`
/// (what the security stack's automatic re-keying calls before an SRTP key's lifetime ends)
/// gives each of three transports a new association: the next offer carries a new `tls-id` in
/// each transport's sections, every transport runs a new handshake ("connecting", then
/// "connected" again at its own DTLS transport), and RTP of both senders goes on under the new
/// keys (with the security stack's renewal, which also restarts ICE).
#[test]
fn renewing_the_dtls_association_renews_every_transport() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::MaxCompat, false)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    // Outside every group each transport speaks for itself: a tls-id each, kept by an offer
    // that asks for nothing new.
    let offer = world.renegotiate_with(without_bundle_group)?;
    let before = tls_ids(&offer);
    assert_eq!(before.len(), 3, "a tls-id per transport:\n{offer}");
    assert_eq!(before.iter().collect::<HashSet<_>>().len(), 3, "{before:?}");
    world.peers[0].events.clear();

    world.peers[0].pc.renew_dtls_association();
    let offer = world.renegotiate_with(without_bundle_group)?;
    let after = tls_ids(&offer);
    assert_eq!(after.len(), 3, "{offer}");
    assert!(
        after.iter().all(|id| !before.contains(id)),
        "every transport offers a new tls-id: {before:?} -> {after:?}"
    );
    let ids: Vec<RTCTransportId> = world.peers[0]
        .pc
        .dtls_transports()
        .iter()
        .map(|t| t.id())
        .collect();
    assert_eq!(ids.len(), 3);
    world.run("every transport ran a new handshake", |peers| {
        let events = transport_events(&peers[0]);
        ids.iter().all(|id| {
            let of: Vec<&RTCTransportEventKind> = events
                .iter()
                .filter(|(_, dtls, _)| dtls == id)
                .map(|(_, _, kind)| kind)
                .collect();
            let connecting = of.iter().position(|kind| {
                matches!(
                    kind,
                    RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connecting)
                )
            });
            connecting.is_some_and(|at| {
                of[at..].iter().any(|kind| {
                    matches!(
                        kind,
                        RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connected)
                    )
                })
            })
        })
    })?;
    // Media written while the remote's side of a new handshake is still finishing is lost (its
    // SRTP keys are not there yet): a packet per sender every 100 ms, up to two seconds.
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    for seq in 30..50u16 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
        world.advance(Duration::from_millis(100))?;
        if ssrcs
            .iter()
            .all(|ssrc| world.peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
        {
            return Ok(());
        }
    }
    let received: HashSet<u32> = world.peers[1].rtp.iter().map(|h| h.ssrc).collect();
    bail!("RTP of both senders under the new keys: sent {ssrcs:?}, received {received:?}")
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

/// The offer of `negotiate` with its video sections' tags taken out of the BUNDLE group: a
/// peer that answers only some sections bundled.
fn video_outside_the_group(sdp: String) -> String {
    let video: Vec<String> = sdp
        .split("\r\nm=")
        .skip(1)
        .filter(|section| section.starts_with("video "))
        .filter_map(|section| {
            section
                .lines()
                .find_map(|l| l.strip_prefix("a=mid:"))
                .map(str::to_owned)
        })
        .collect();
    sdp.lines()
        .map(|l| match l.strip_prefix("a=group:BUNDLE ") {
            Some(tags) => {
                let kept: Vec<&str> = tags
                    .split(' ')
                    .filter(|tag| !video.iter().any(|v| v == tag))
                    .collect();
                format!("a=group:BUNDLE {}\r\n", kept.join(" "))
            }
            None => format!("{l}\r\n"),
        })
        .collect()
}

/// Every DTLS transport of `peer`, by id, with its state.
fn dtls_states(peer: &Peer) -> Vec<(RTCTransportId, RTCDtlsTransportState)> {
    peer.pc
        .dtls_transports()
        .iter()
        .map(|t| (t.id(), t.state()))
        .collect()
}

/// RFC 9429 section 5.7 under `balanced` with transports of their own: peer 0's offer (a
/// transport per media type) reaches peer 1 through `edit` (no BUNDLE group, or the video
/// outside it), and media flows on the transports that gives. Then both peers offer at once:
/// peer 0, the polite one, rolls its offer back, answers peer 1's (which adds a receive-only
/// audio section in a BUNDLE group of its own, a transport of its own on both sides), and
/// offers again through `edit`. The rollback restores the transports as they were, the
/// exchanges after it close none of them, every transport there is connects (the connection
/// is "connected" again also when the re-offer's answer rejects the added section, as a peer
/// that does not bundle answers a second audio section, RFC 9429 4.1.1, and closes its
/// transport), and RTP of both senders still arrives over the transports it used before.
fn a_rollback_keeps_the_unbundled_transports(edit: fn(String) -> String) -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::Balanced, false)?;
    let (senders, _) = world.negotiate(edit)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    world.run("every transport connected", |peers| {
        peers.iter().all(|p| {
            p.pc.dtls_transports()
                .iter()
                .all(|t| t.state() == RTCDtlsTransportState::Connected)
        })
    })?;
    let before: Vec<_> = world.peers.iter().map(dtls_states).collect();
    assert!(
        before[0].len() >= 2,
        "more than one transport to keep: {before:?}"
    );
    let sender_transports = |world: &mut World| -> Vec<RTCTransportId> {
        senders
            .iter()
            .map(|s| {
                world.peers[0]
                    .pc
                    .rtp_sender(*s)
                    .expect("sender")
                    .transport()
                    .expect("a transport")
                    .id()
            })
            .collect()
    };
    let media_transports = sender_transports(&mut world);
    assert_ne!(
        media_transports[0], media_transports[1],
        "audio and video on two transports"
    );

    // Glare: peer 1's offer is applied there first; peer 0's crosses it.
    let now = world.now;
    world.peers[1].pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let theirs = world.peers[1].pc.create_offer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, theirs.clone())
        .context("peer 1 applies its offer")?;
    let ours = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, ours)
        .context("peer 0 applies its offer")?;
    world.peers[0]
        .pc
        .set_local_description(now, RTCSessionDescription::rollback(None)?)
        .context("peer 0 rolls its offer back")?;
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::Stable
    );
    assert_eq!(
        dtls_states(&world.peers[0]),
        before[0],
        "the rollback leaves the transports as they were"
    );
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(theirs.sdp.clone())?)
        .with_context(|| format!("peer 0 applies peer 1's offer:\n{}", theirs.sdp))?;
    let answer = world.peers[0].pc.create_answer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())
        .context("peer 0 applies its answer")?;
    world.peers[1]
        .pc
        .set_remote_description(now, answer.clone())
        .with_context(|| format!("peer 1 applies peer 0's answer:\n{}", answer.sdp))?;
    // Peer 0 offers again, its offer edited as the first was.
    let offer = world
        .renegotiate_with(edit)
        .context("peer 0 offers again")?;
    for peer in &world.peers {
        assert_eq!(peer.pc.signaling_state(), RTCSignalingState::Stable);
    }
    // A section new in peer 1's offer may have brought a transport of its own: it gathers
    // and connects too.
    world.gather_new()?;
    world.run("every transport connected after the exchanges", |peers| {
        peers.iter().all(|p| {
            p.pc.connection_state() == RTCPeerConnectionState::Connected
                && p.pc
                    .dtls_transports()
                    .iter()
                    .all(|t| t.state() == RTCDtlsTransportState::Connected)
        })
    })?;
    for (i, peer) in world.peers.iter().enumerate() {
        let after = dtls_states(peer);
        for kept in &before[i] {
            assert!(
                after.contains(kept),
                "peer {i} keeps {kept:?} connected: {after:?}\n{offer}"
            );
        }
        assert_eq!(
            peer.pc.connection_state(),
            RTCPeerConnectionState::Connected
        );
    }
    assert_eq!(
        sender_transports(&mut world),
        media_transports,
        "the senders keep their transports"
    );

    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    world.paths.clear();
    for seq in 30..=35 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("audio and video after the rollback", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
    let from: HashSet<SocketAddr> = world.paths.iter().map(|(from, _)| *from).collect();
    assert!(
        from.len() >= 2,
        "media still leaves on two 5-tuples: {:?}",
        world.paths
    );
    Ok(())
}

#[test]
fn balanced_answered_without_bundle_a_rollback_keeps_every_transport() -> Result<()> {
    a_rollback_keeps_the_unbundled_transports(without_bundle_group)
}

#[test]
fn balanced_video_answered_outside_the_group_a_rollback_keeps_both_transports() -> Result<()> {
    a_rollback_keeps_the_unbundled_transports(video_outside_the_group)
}

/// RFC 9429 section 5.7, a rollback of an offer that added a transport for a data section:
/// audio and video run on transports of their own (`balanced`, answered without BUNDLE, no
/// data channel yet); peer 0 opens a data channel and offers, the new `m=application` section
/// in a BUNDLE group of its own with a transport of its own (as the interop peer's offer in the
/// browser glare scenario), then rolls the offer back. The rollback takes that transport back:
/// the transports are the two there were, connected, and the data section is on none. A
/// following offer and answer open the data channel, and RTP of both senders still arrives.
#[test]
fn a_rollback_takes_back_the_transport_an_offer_gave_a_new_data_section() -> Result<()> {
    let mut world = World::with_credentials(RTCBundlePolicy::Balanced, false)?;
    let kinds = [RtpCodecKind::Audio, RtpCodecKind::Video];
    let (senders, _) = world.negotiate_media(&kinds, false, without_bundle_group)?;
    world.gather()?;
    world.run("both transports connected", |peers| {
        peers.iter().all(|p| {
            p.connected
                && p.pc.dtls_transports().len() == 2
                && p.pc
                    .dtls_transports()
                    .iter()
                    .all(|t| t.state() == RTCDtlsTransportState::Connected)
        })
    })?;
    let before = dtls_states(&world.peers[0]);

    let now = world.now;
    world.peers[0].pc.create_data_channel("late", None)?;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_eq!(
        world.peers[0].pc.dtls_transports().len(),
        3,
        "the data section has a transport of its own:\n{}",
        offer.sdp
    );
    world.peers[0]
        .pc
        .set_local_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(
        dtls_states(&world.peers[0]),
        before,
        "the rollback takes the data section's transport back"
    );
    assert_eq!(world.peers[0].pc.ice_transport_sections().len(), 2);

    world.renegotiate()?;
    world.gather_new()?;
    world.run("the data channel open on both sides", |peers| {
        peers.iter().all(|p| p.channel.is_some())
    })?;
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    for seq in 40..=45 {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
    }
    world.run("audio and video after the rollback", |peers| {
        ssrcs
            .iter()
            .all(|ssrc| peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
    })?;
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

/// Sends a packet on each sender every 20 ms for `duration` of virtual time, delivering what
/// is in flight and running both peers' timers (RTCP reports, congestion feedback) as it goes.
fn send_media_for(world: &mut World, senders: &[RTCRtpSenderId], duration: Duration) -> Result<()> {
    let end = world.now + duration;
    let mut next_send = world.now;
    let mut seq = 1u16;
    while world.now < end {
        if world.now >= next_send {
            for sender in senders {
                world.send_rtp(*sender, seq)?;
            }
            seq = seq.wrapping_add(1);
            next_send += Duration::from_millis(20);
        }
        while world.step()? {}
        let next = world
            .peers
            .iter_mut()
            .filter_map(|p| p.pc.poll_timeout())
            .min()
            .map_or(next_send, |at| at.min(next_send));
        world.now = next.max(world.now + Duration::from_millis(1));
        let now = world.now;
        for peer in world.peers.iter_mut() {
            peer.pc.handle_timeout(now)?;
        }
    }
    Ok(())
}

/// webrtc-stats 8.20 `availableOutgoingBitrate`: the bitrate the congestion control estimates
/// for the outgoing RTP streams on the pair. With audio and video on transports of their own,
/// each transport has a congestion controller of its own (RFC 8836 section 2: each path has
/// its own capacity), and each transport's selected pair reports that transport's estimate,
/// not another's and not the sum.
#[test]
fn each_transport_s_selected_pair_reports_its_own_estimate() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected))?;
    let sessions: Vec<usize> = senders.iter().map(|s| session_of(&mut world, *s)).collect();
    assert_ne!(
        sessions[0], sessions[1],
        "audio and video in two RTP sessions"
    );
    // Each transport's controller held at a limit of its own, so the two estimates differ
    // and one transport's estimate on the other's pair shows.
    let handles = world.peers[0].handles.transports.clone();
    for (session, limit) in sessions.iter().zip([150_000.0, 90_000.0]) {
        handles
            .congestion_control(*session)
            .expect("a congestion controller per transport")
            .set_session_bitrate_limit(Some(limit));
    }
    // Long enough for the receiver's congestion feedback to reach the sender on each
    // transport, and for the controllers' timers to run.
    send_media_for(&mut world, &senders, Duration::from_secs(3))?;
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    let now = world.now;
    let report = world.peers[0].pc.get_stats(now, StatsSelector::None);
    let mut pairs = HashSet::new();
    let mut reported_estimates = vec![];
    for (ssrc, session) in ssrcs.iter().zip(&sessions) {
        let transport_id = report
            .outbound_rtp_streams()
            .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == *ssrc)
            .map(|s| {
                s.sent_rtp_stream_stats
                    .rtp_stream_stats
                    .transport_id
                    .clone()
            })
            .expect("an outbound stream per sender");
        let transport = report
            .iter()
            .find_map(|e| match e {
                RTCStatsReportEntry::Transport(t) if t.stats.id == transport_id => Some(t),
                _ => None,
            })
            .expect("the stream's transport is in the report");
        let pair = report
            .candidate_pairs()
            .find(|p| p.stats.id == transport.selected_candidate_pair_id)
            .expect("the transport's selected pair is in the report");
        let own = handles
            .congestion_control(*session)
            .expect("a congestion controller per transport")
            .target_bitrate();
        let reported = pair
            .available_outgoing_bitrate
            .unwrap_or_else(|| panic!("transport {transport_id} has no estimate: {pair:?}"));
        assert_eq!(
            reported, own,
            "the pair of {ssrc:#x}'s transport reports its own controller's estimate"
        );
        pairs.insert(pair.stats.id.clone());
        reported_estimates.push(reported);
    }
    assert_eq!(pairs.len(), 2, "two transports, two selected pairs");
    assert_ne!(
        reported_estimates[0], reported_estimates[1],
        "each transport at a limit of its own: {reported_estimates:?}"
    );
    Ok(())
}

/// RFC 3550 section 6, RFC 8834 section 4.4: an RTCP session runs on each transport that
/// carries RTP m= sections, and on no other. Audio, video and data on three transports (the
/// answer has no BUNDLE group): RTCP flows both ways on the audio and the video transport and
/// never on the data transport, a receive-only endpoint's reports included (their reporting
/// SSRC is no section's, and they go down their own session's transport). With the video
/// transport's path cut, its DTLS association never completes: its RTCP session does not
/// start, and nothing of it leaves on another transport.
#[test]
fn rtcp_runs_on_each_media_transport_and_never_on_the_data_transport() -> Result<()> {
    for cut_video in [false, true] {
        let what = format!("video path cut: {cut_video}");
        let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
        world.negotiate(without_bundle_group)?;
        world.gather()?;
        for peer in &world.peers {
            assert_eq!(3, peer.addrs.len(), "{what}: audio, video and data");
        }
        let addr = |world: &World, peer: usize, section: usize| world.peers[peer].addrs[section];
        let (audio, video, data) = (0, 1, 2);
        if cut_video {
            let cut = addr(&world, 1, video);
            world.blocked.insert(cut);
            world.advance(Duration::from_secs(8))?;
        } else {
            world.run("connected with a data channel", |peers| {
                peers.iter().all(|p| p.connected && p.channel.is_some())
            })?;
            world.advance(Duration::from_secs(8))?;
        }
        let on = |world: &World, section: usize| -> [usize; 2] {
            let mut counts = [0; 2];
            for (from, to) in &world.rtcp {
                for (i, count) in counts.iter_mut().enumerate() {
                    if *from == addr(world, i, section) || *to == addr(world, i, section) {
                        *count += 1;
                    }
                }
            }
            counts
        };
        let from = |world: &World, peer: usize, section: usize| {
            world
                .rtcp
                .iter()
                .filter(|(from, _)| *from == addr(world, peer, section))
                .count()
        };
        assert_eq!(
            [0, 0],
            on(&world, data),
            "{what}: RTCP on the data transport"
        );
        for peer in 0..2 {
            assert!(
                from(&world, peer, audio) >= 2,
                "{what}: peer {peer} on the audio transport: {:?}",
                world.rtcp
            );
            let video_rtcp = from(&world, peer, video);
            if cut_video {
                assert_eq!(0, video_rtcp, "{what}: peer {peer}, video not keyed");
            } else {
                assert!(
                    video_rtcp >= 2,
                    "{what}: peer {peer} on the video transport"
                );
            }
        }
    }
    Ok(())
}

/// RFC 9143 section 7.2: "When the offerer assigns unique addresses:ports to multiple bundled
/// 'm=' sections, the offerer needs to be prepared to receive bundled media on each unique
/// address:port until it receives the associated answer". Under `max-compat` a later offer
/// stages a transport of its own for the video section it adds, and lists the section in the
/// BUNDLE group; the answerer bundles it and sends its video on the group's transport at
/// once. That media reaches the offerer before the answer that says where the section went
/// (RFC 3264 section 5.1): it is delivered, on the transport it arrived on, and the answer
/// then moves the section there and closes the staged transport.
#[test]
fn media_for_a_section_staged_on_its_own_transport_arrives_on_the_groups_before_the_answer()
-> Result<()> {
    const VIDEO_SSRC: u32 = 0x00ea_7301;
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    world.negotiate_media(&[RtpCodecKind::Audio], true, |sdp| sdp)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(world.peers[0].pc.ice_transport_sections().len(), 1);

    world.peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    assert_eq!(
        world.peers[0].pc.ice_transport_sections().len(),
        2,
        "the offer stages a transport for the section it adds"
    );
    let video_mid = offer
        .sdp
        .split("\r\nm=")
        .find(|section| section.starts_with("video"))
        .and_then(|section| {
            section
                .lines()
                .find_map(|l| l.strip_prefix("a=mid:").map(str::to_owned))
        })
        .context("the video section's mid")?;
    assert!(
        bundled_mids(&offer.sdp).contains(&video_mid),
        "{}",
        offer.sdp
    );

    world.peers[1]
        .pc
        .set_remote_description(now, offer.clone())?;
    let sender = world.peers[1]
        .pc
        .add_track(rtc::media_stream::MediaStreamTrack::new(
            "early-stream".to_owned(),
            "early".to_owned(),
            "early".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: rtc::rtp_transceiver::rtp_sender::RTCRtpCodingParameters {
                    ssrc: Some(VIDEO_SSRC),
                    ..Default::default()
                },
                active: true,
                ..Default::default()
            }],
        ))?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert!(
        bundled_mids(&answer.sdp).contains(&video_mid),
        "{}",
        answer.sdp
    );
    let payload_type = world.peers[1]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs[0]
        .payload_type;

    let send = |world: &mut World, first: u16, count: u16| -> Result<()> {
        for seq in first..first + count {
            let now = world.now;
            world.peers[1]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: Header {
                            version: 2,
                            payload_type,
                            sequence_number: seq,
                            timestamp: u32::from(seq) * 3000,
                            ssrc: VIDEO_SSRC,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 100]),
                    },
                )?;
            world.advance(Duration::from_millis(20))?;
        }
        world.advance(Duration::from_millis(100))
    };
    let received = |world: &World| -> Vec<u16> {
        world.peers[0]
            .rtp
            .iter()
            .filter(|header| header.ssrc == VIDEO_SSRC)
            .map(|header| header.sequence_number)
            .collect()
    };

    // The answer is half a second away.
    send(&mut world, 1, 25)?;
    assert_eq!(received(&world), (1..=25).collect::<Vec<u16>>());
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);

    let now = world.now;
    world.peers[0].pc.set_remote_description(now, answer)?;
    assert_eq!(
        world.peers[0].pc.ice_transport_sections().len(),
        1,
        "the answer bundles the section: its staged transport is closed"
    );
    send(&mut world, 26, 5)?;
    assert_eq!(received(&world), (1..=30).collect::<Vec<u16>>());
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    Ok(())
}
