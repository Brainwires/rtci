//! Several transports in one peer connection (RFC 9429 sections 4.1.1, 5.2.1, 5.3.1; RFC 9143
//! section 7), between two `rtci` peers on a simulated UDP network in virtual time.
//!
//! The offerer uses the `max-compat` bundle policy, so each m= section of its offer has a
//! transport of its own: its own ICE credentials, candidates, DTLS association and SRTP keys.
//! An answer that bundles the sections closes all but the first; an answer to an offer without
//! the BUNDLE group (a peer that does not bundle) keeps them, and media and data each travel on
//! their own transport.

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::data_channel::RTCDataChannelId;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCBundlePolicy;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, DefaultInterceptorHandles, DefaultInterceptorOptions,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{
    RTCDataChannelEvent, RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason,
    RTCPeerConnectionEvent, RTCTransportEventKind,
};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::{
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState, RTCSignalingState,
};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit, RTCIceCandidateType, RTCIceTransportState, RTCTransportId,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::error::Error;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use rtci::statistics::stats::transport::RTCTransportStats;
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
    /// The `World::step` each of `events` was raised in.
    event_steps: Vec<u64>,
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
        Self::with_setting_engine(
            ip,
            policy,
            options,
            SettingEngineBuilder::new().with_unique_transport_credentials(unique),
        )
    }

    /// `with_options` with the setting engine `setting_engine`.
    fn with_setting_engine(
        ip: &str,
        policy: RTCBundlePolicy,
        options: Option<&DefaultInterceptorOptions>,
        setting_engine: SettingEngineBuilder,
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
            .with_setting_engine(setting_engine.build())
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
            event_steps: vec![],
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
    /// Datagrams to this address are held back, not delivered (a path slower in one
    /// direction).
    held_to: Option<SocketAddr>,
    /// What arrives on peer 0's shared address goes through the reference driver's mux for a
    /// shared port first (`rtci-stream-driver`'s `UfragMux`), as a server routes it.
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
    /// How many steps ran.
    steps: u64,
    /// Every DTLS datagram written (RFC 7983: a first byte of 20..=63), delivered or lost,
    /// with the step it was written in: (step, from, to, datagram).
    dtls: Vec<(u64, SocketAddr, SocketAddr, BytesMut)>,
    /// A peer connection that fails does not end the run.
    tolerate_failure: bool,
    /// DTLS datagrams are lost (recorded in `dtls`, not delivered).
    drop_dtls: bool,
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
            held_to: None,
            mux: None,
            misrouted: 0,
            trickling: vec![],
            srtp: vec![],
            rtcp: vec![],
            steps: 0,
            dtls: vec![],
            tolerate_failure: false,
            drop_dtls: false,
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

    /// Two peers built from `settings` (each its own setting engine), the offerer under
    /// `offerer`, the answerer under `balanced`.
    fn with_setting_engines(
        offerer: RTCBundlePolicy,
        settings: impl Fn() -> SettingEngineBuilder,
    ) -> Result<Self> {
        let mut world = Self::new(offerer)?;
        world.peers = [
            Peer::with_setting_engine("10.0.0.1", offerer, None, settings())?,
            Peer::with_setting_engine("10.0.0.2", RTCBundlePolicy::Balanced, None, settings())?,
        ];
        Ok(world)
    }

    /// The application's gathering after an ICE restart that dropped the local candidates
    /// (`with_discard_local_candidates_during_ice_restart`, or a new DTLS association: RFC
    /// 8842 section 5.1, a new 3-tuple): every transport of each peer gathers a host
    /// candidate on a new port (`base` plus its index) and trickles it, with its section, to
    /// the other peer. The previous ports stay open. (Not from 6000: a remote candidate on
    /// a bad port, X11's 6000 among them, is administratively prohibited, W3C webrtc-pc
    /// 4.4.2, and never checked.)
    fn regather(&mut self, base: u16) -> Result<()> {
        for i in 0..2 {
            let sections = self.peers[i].pc.ice_transport_sections();
            for (k, (mid, index)) in sections.into_iter().enumerate() {
                let addr = SocketAddr::new(self.peers[i].ip, base + k as u16);
                self.peers[i].addrs.push(addr);
                let candidate = Peer::host_candidate(addr, &mid, index)?;
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    /// The application's gathering driven by `OnLocalCandidatesNeeded` alone: each event a
    /// peer raised (since the last step) gets a host candidate on a new port (`base` plus its
    /// position) for the event's first mid, trickled to the other peer. Before that, the
    /// event's first refused address is offered for the same mid and must be refused with
    /// `ErrICECandidateAddressOfPreviousDtlsAssociation` (the per-transport route of
    /// `add_local_candidate`). Returns each peer's events.
    fn regather_on_events(&mut self, base: u16) -> Result<[Vec<RTCLocalCandidatesNeededEvent>; 2]> {
        let marks = [self.peers[0].events.len(), self.peers[1].events.len()];
        self.step()?;
        let mut all: [Vec<RTCLocalCandidatesNeededEvent>; 2] = [vec![], vec![]];
        for i in 0..2 {
            let needed: Vec<RTCLocalCandidatesNeededEvent> = self.peers[i].events[marks[i]..]
                .iter()
                .filter_map(|event| match event {
                    RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => Some(needed.clone()),
                    _ => None,
                })
                .collect();
            for (k, event) in needed.iter().enumerate() {
                let mid = event.mids.first().context("the event names a section")?;
                let index = event.sdp_mline_index.context("and its index")?;
                if let Some(old) = event.refused_addresses.first() {
                    let refused = Peer::host_candidate(*old, mid, index)?;
                    match self.peers[i].pc.add_local_candidate(refused) {
                        Err(Error::ErrICECandidateAddressOfPreviousDtlsAssociation(addr))
                            if addr == *old => {}
                        other => bail!("peer {i}: {old} is refused for {mid}, got {other:?}"),
                    }
                }
                let addr = SocketAddr::new(self.peers[i].ip, base + k as u16);
                self.peers[i].addrs.push(addr);
                let candidate = Peer::host_candidate(addr, mid, index)?;
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
            all[i] = needed;
        }
        Ok(all)
    }

    /// `run`, and on failure the state of every transport of both peers
    /// ([`World::trace`]).
    fn run_traced(&mut self, what: &str, done: impl Fn(&[Peer; 2]) -> bool) -> Result<()> {
        if let Err(err) = self.run(what, done) {
            bail!("{err}\n{}", self.trace());
        }
        Ok(())
    }

    /// Per peer and transport: the ICE credentials (local, remote), the ICE state, the local
    /// candidates the agent holds, the remote candidates of the description, the pairs
    /// formed with their checks and nomination, and the selected pair.
    fn trace(&mut self) -> String {
        let now = self.now;
        let mut out = String::new();
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let report = peer.pc.get_stats(now, StatsSelector::None);
            let address_of = |id: &str| {
                report
                    .iter()
                    .find_map(|e| match e {
                        RTCStatsReportEntry::LocalCandidate(c)
                        | RTCStatsReportEntry::RemoteCandidate(c)
                            if c.stats.id == id =>
                        {
                            Some(format!(
                                "{}:{} ufrag {}",
                                c.address.clone().unwrap_or_default(),
                                c.port,
                                c.username_fragment
                            ))
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| id.to_owned())
            };
            for (k, dtls) in peer.pc.dtls_transports().iter().enumerate() {
                let ice = dtls.ice_transport();
                let port = |c: &RTCIceCandidate| format!("{}:{}", c.address, c.port);
                out += &format!(
                    "peer {i} transport {k} ({}): local {:?} remote {:?} ice {:?} dtls {:?}\n  \
                     local candidates {:?}\n  remote candidates {:?}\n  selected {:?}\n",
                    ice.id(),
                    ice.get_local_parameters().map(|p| p.username_fragment),
                    ice.get_remote_parameters().map(|p| p.username_fragment),
                    ice.state(),
                    dtls.state(),
                    ice.get_local_candidates()
                        .iter()
                        .map(port)
                        .collect::<Vec<_>>(),
                    ice.get_remote_candidates()
                        .iter()
                        .map(port)
                        .collect::<Vec<_>>(),
                    ice.get_selected_candidate_pair()
                        .map(|p| (port(p.local()), port(p.remote()))),
                );
            }
            for pair in report.candidate_pairs() {
                {
                    out += &format!(
                        "  pair on {}: {} -> {}: {:?} nominated {} requests sent {} received {} \
                         responses received {}\n",
                        pair.transport_id,
                        address_of(&pair.local_candidate_id),
                        address_of(&pair.remote_candidate_id),
                        pair.state,
                        pair.nominated,
                        pair.requests_sent,
                        pair.requests_received,
                        pair.responses_received
                    );
                }
            }
        }
        out
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

    /// `renegotiate_with`, the offer made by peer `offerer` and answered by the other.
    fn exchange_from(&mut self, offerer: usize, edit: impl Fn(String) -> String) -> Result<String> {
        let now = self.now;
        let answerer = 1 - offerer;
        let offer = self.peers[offerer].pc.create_offer(None)?;
        self.peers[offerer]
            .pc
            .set_local_description(now, offer.clone())?;
        self.peers[answerer]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(edit(offer.sdp.clone()))?)?;
        let answer = self.peers[answerer].pc.create_answer(None)?;
        self.peers[answerer]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[offerer].pc.set_remote_description(now, answer)?;
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
        self.steps += 1;
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
            if data.first().is_some_and(|first| (20..=63).contains(first)) {
                self.dtls.push((self.steps, from, to, data.clone()));
                if self.drop_dtls {
                    continue;
                }
            }
            if self.blocked.contains(&from)
                || self.blocked.contains(&to)
                || self.held_to == Some(to)
            {
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
                peer.event_steps.push(self.steps);
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed && !self.tolerate_failure {
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
        self.negotiate_media_and_answer(kinds, data, edit, |sdp| sdp)
    }

    /// `negotiate_media`, the answer going through `edit_answer` before peer 0 sees it.
    fn negotiate_media_and_answer(
        &mut self,
        kinds: &[RtpCodecKind],
        data: bool,
        edit: impl Fn(String) -> String,
        edit_answer: impl Fn(String) -> String,
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
        self.peers[0]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(edit_answer(answer.sdp))?)?;
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
                rtci::rtp::Packet {
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
/// (`rtci-stream-driver`'s `UfragMux`): the ICE username names peer 0's connection but not a
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
    // RFC 8842 section 5.1: each new association runs on a new 3-tuple; the restart that
    // comes with it dropped every transport's local candidates, and the application gathers
    // on new ports.
    world.regather(7000)?;
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
    world.run_traced("every transport ran a new handshake", |peers| {
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
    world.run_traced(
        "every transport selected a pair on the new ports",
        |peers| peers.iter().all(|p| selected_on_new_ports(p, 7000)),
    )?;
    media_and_data_arrive(&mut world, &senders, "the new associations")
}

/// Whether every transport of `peer` has selected a pair whose two candidates are on ports
/// from `base` up (the generation `World::regather` gathered).
fn selected_on_new_ports(peer: &Peer, base: u16) -> bool {
    peer.pc.dtls_transports().iter().all(|t| {
        t.ice_transport()
            .get_selected_candidate_pair()
            .is_some_and(|p| p.local().port >= base && p.remote().port >= base)
    })
}

/// Media of every sender in `senders` and a data channel message from peer 0 reach peer 1.
fn media_and_data_arrive(world: &mut World, senders: &[RTCRtpSenderId], what: &str) -> Result<()> {
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    world.peers[1].received.clear();
    let channel = world.peers[0].channel.context("the offerer's channel")?;
    let message = format!("after {what}");
    world.peers[0]
        .pc
        .data_channel(channel)
        .context("the channel")?
        .send(world.now, BytesMut::from(message.as_bytes()))?;
    // Media written while the remote side of a new handshake is still finishing is lost (its
    // SRTP keys are not there yet): a packet per sender every 100 ms, up to three seconds.
    for seq in 0..30u16 {
        for sender in senders {
            world.send_rtp(*sender, 1000 + seq)?;
        }
        world.advance(Duration::from_millis(100))?;
        if ssrcs
            .iter()
            .all(|ssrc| world.peers[1].rtp.iter().any(|h| h.ssrc == *ssrc))
            && world.peers[1]
                .received
                .iter()
                .any(|m| m == message.as_bytes())
        {
            return Ok(());
        }
    }
    let received: HashSet<u32> = world.peers[1].rtp.iter().map(|h| h.ssrc).collect();
    let messages = world.peers[1].received.clone();
    bail!(
        "{what}: media of every sender and the message: sent {ssrcs:?}, received {received:?}, \
         messages {messages:?}\n{}",
        world.trace()
    )
}

/// RFC 8445 section 9 on every transport of a connection whose sections are not bundled
/// (RFC 9429 section 5.2.1: a transport per section): `restartIce` restarts each transport
/// (RFC 9429 section 5.2.2), the restart drops each transport's local candidates
/// (`with_discard_local_candidates_during_ice_restart`), and the application gathers new
/// ones on new ports for every section. Each transport, on both sides, pairs its new
/// candidates with the peer's new ones for that section, selects a pair on the new ports and
/// takes new credentials; media of every sender and data channel messages continue. With two
/// and with three transports, credentials shared (the default) and unique.
#[test]
fn a_restart_that_drops_the_local_candidates_reconnects_every_transport() -> Result<()> {
    let three = [RtpCodecKind::Audio, RtpCodecKind::Video];
    for kinds in [&three[..1], &three[..]] {
        for unique in [false, true] {
            let what = format!(
                "{} transports, unique credentials {unique}",
                kinds.len() + 1
            );
            let mut world = World::with_setting_engines(
                RTCBundlePolicy::MaxCompat,
                dropping_candidates(unique),
            )?;
            let (senders, _) = world.negotiate_media(kinds, true, without_bundle_group)?;
            world.gather()?;
            world.run_traced(&format!("{what}: connected"), |peers| {
                peers.iter().all(|p| p.connected && p.channel.is_some())
            })?;
            for peer in &world.peers {
                assert_eq!(peer.pc.dtls_transports().len(), kinds.len() + 1, "{what}");
            }
            restart_dropping_candidates(&mut world, 0, without_bundle_group, &senders, &what)?;
        }
    }
    Ok(())
}

/// `restartIce` on peer `restarter`, its offer going through `edit`, with the local
/// candidates of every transport dropped (the peers are built with
/// `with_discard_local_candidates_during_ice_restart`): after the exchange no transport of
/// either peer holds a local candidate; the application gathers on new ports
/// (`World::regather`); every transport of both peers then selects a pair on the new ports
/// with new credentials on both sides, and media of every sender in `senders` and a data
/// channel message from peer 0 arrive.
fn restart_dropping_candidates(
    world: &mut World,
    restarter: usize,
    edit: impl Fn(String) -> String,
    senders: &[RTCRtpSenderId],
    what: &str,
) -> Result<()> {
    let before: Vec<Vec<(String, String, bool)>> = world.peers.iter().map(transport_ice).collect();
    world.peers[restarter].pc.restart_ice();
    world.exchange_from(restarter, edit)?;
    for (i, peer) in world.peers.iter().enumerate() {
        for t in peer.pc.dtls_transports() {
            assert!(
                t.ice_transport().get_local_candidates().is_empty(),
                "{what}: peer {i}: the restart dropped the local candidates"
            );
        }
    }
    world.regather(7000)?;
    world.run_traced(
        &format!("{what}: every transport selected a pair on the new ports"),
        |peers| peers.iter().all(|p| selected_on_new_ports(p, 7000)),
    )?;
    for (i, peer) in world.peers.iter().enumerate() {
        let after = transport_ice(peer);
        assert_eq!(after.len(), before[i].len(), "{what}: peer {i}");
        for ((local, remote, _), (old_local, old_remote, _)) in after.iter().zip(&before[i]) {
            assert_ne!(local, old_local, "{what}: peer {i}: new local credentials");
            assert_ne!(
                remote, old_remote,
                "{what}: peer {i}: new remote credentials"
            );
        }
    }
    media_and_data_arrive(world, senders, what)
}

/// The settings of a peer whose ICE restarts drop the local candidates, with credentials of
/// its own per transport (`unique`) or shared.
fn dropping_candidates(unique: bool) -> impl Fn() -> SettingEngineBuilder {
    move || {
        SettingEngineBuilder::new()
            .with_unique_transport_credentials(unique)
            .with_discard_local_candidates_during_ice_restart(true)
    }
}

/// `two_bundle_groups_run_on_two_transports`'s setup: peer 0 adds an audio and a video
/// sender and a data channel, and its offer reaches peer 1 with two BUNDLE groups (the RTP
/// sections, the data section); the answer keeps both. Returns the senders.
fn negotiate_two_bundle_groups(world: &mut World) -> Result<Vec<RTCRtpSenderId>> {
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
                .context("a sender")?,
        );
    }
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    let local = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, local.clone())?;
    world.peers[1].pc.set_remote_description(
        now,
        RTCSessionDescription::offer(two_bundle_groups(local.sdp))?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    Ok(senders)
}

/// `a_restart_that_drops_the_local_candidates_reconnects_every_transport` with BUNDLE: two
/// BUNDLE groups (RFC 9143 section 5: each group a transport of its own), restarted by the
/// peer that offered them again (a JSEP endpoint keeps both groups, RFC 9429 section
/// 5.2.2); and a mix of a bundled group (audio and data, RFC 9143) and an unbundled section
/// (video outside the group), restarted by the other peer, credentials shared and unique.
/// Each transport selects a pair on the new ports and media and data continue.
#[test]
fn a_restart_that_drops_the_local_candidates_reconnects_bundle_groups_and_unbundled_sections()
-> Result<()> {
    let mut world =
        World::with_setting_engines(RTCBundlePolicy::MaxCompat, dropping_candidates(true))?;
    let senders = negotiate_two_bundle_groups(&mut world)?;
    world.gather()?;
    world.run_traced("two BUNDLE groups: connected", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    for peer in &world.peers {
        assert_eq!(peer.pc.dtls_transports().len(), 2, "a transport per group");
    }
    restart_dropping_candidates(&mut world, 1, |sdp| sdp, &senders, "two BUNDLE groups")?;

    for unique in [false, true] {
        let what = format!("a group and an unbundled section, unique credentials {unique}");
        let mut world =
            World::with_setting_engines(RTCBundlePolicy::Balanced, dropping_candidates(unique))?;
        let (senders, _) = world.negotiate(video_outside_the_group)?;
        world.gather()?;
        world.run_traced(&format!("{what}: connected"), |peers| {
            peers.iter().all(|p| p.connected && p.channel.is_some())
        })?;
        for peer in &world.peers {
            assert_eq!(
                peer.pc.dtls_transports().len(),
                2,
                "{what}: the group's transport and the video's"
            );
        }
        restart_dropping_candidates(&mut world, 0, video_outside_the_group, &senders, &what)?;
    }
    Ok(())
}

/// RFC 5764 section 4.4 ("Once the key lifetime has been reached, a new DTLS session SHOULD
/// be established") end to end with three transports (two audio sections and data, outside
/// any BUNDLE group), with the default settings, so each new association runs on a new 3-tuple
/// (RFC 8842 section 5.1). Peer 0's SRTP keys have a lifetime of 320 packets: before one
/// runs out the engine raises negotiation-needed by itself, the application only answers it
/// (a new offer, and gathering on new ports for each transport an `OnLocalCandidatesNeeded`
/// names: reason `SrtpRekeying` on peer 0, `NewDtlsAssociation` on peer 1, the previous
/// address refused through the section's mid), and every transport gets a new association
/// with new ICE credentials. Every
/// packet of both senders arrives across the renewals, every transport ends on a pair of the
/// latest ports, and the data channel opened at the start still carries messages.
#[test]
fn automatic_srtp_re_keying_renews_every_transport_on_new_addresses() -> Result<()> {
    const PACKETS: u16 = 900;
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let lifetime = Some(rtci::srtp::keying::KeyLifetime {
        srtp_packets: 320,
        srtcp_packets: 1 << 31,
    });
    world.peers = [
        Peer::with_setting_engine(
            "10.0.0.1",
            RTCBundlePolicy::MaxCompat,
            None,
            SettingEngineBuilder::new().with_srtp_key_lifetime(lifetime),
        )?,
        Peer::with_setting_engine(
            "10.0.0.2",
            RTCBundlePolicy::MaxCompat,
            None,
            SettingEngineBuilder::new(),
        )?,
    ];
    // Two audio senders: with a video sender, the video transport's key ran out within the
    // 20 ms step that brought the notice (more than the twenty packets of notice the engine
    // gives, a sixteenth of this short lifetime, left in that step), before the application
    // could answer negotiation-needed.
    let (senders, _) = world.negotiate_media(
        &[RtpCodecKind::Audio, RtpCodecKind::Audio],
        true,
        without_bundle_group,
    )?;
    world.gather()?;
    world.run_traced("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let local_sdp = |world: &World| {
        world.peers[0]
            .pc
            .local_description()
            .map(|d| d.sdp)
            .unwrap_or_default()
    };
    let first_tls_ids = tls_ids(&world.renegotiate_with(without_bundle_group)?);
    assert_eq!(first_tls_ids.len(), 3, "a tls-id per transport");
    let first: Vec<Vec<(String, String, bool)>> = world.peers.iter().map(transport_ice).collect();
    let ssrcs: Vec<u32> = senders.iter().map(|s| world.ssrc(*s)).collect();
    world.peers[1].rtp.clear();
    let mut seen = world.peers[0].events.len();
    let mut renegotiations = 0u16;
    for seq in 1..=PACKETS {
        for sender in &senders {
            world.send_rtp(*sender, seq)?;
        }
        if let Err(err) = world.advance(Duration::from_millis(20)) {
            let events: Vec<String> = world.peers[0]
                .events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { .. }
                            | RTCPeerConnectionEvent::OnNegotiationNeededEvent
                            | RTCPeerConnectionEvent::OnConnectionStateChangeEvent(_)
                            | RTCPeerConnectionEvent::OnTransportEvent(_)
                    )
                })
                .map(|e| format!("{e:?}"))
                .collect();
            bail!(
                "{err} at packet {seq} after {renegotiations} renegotiations\n{}\npeer 0 events: {events:#?}",
                world.trace()
            );
        }
        let raised = world.peers[0].events[seen..]
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent));
        seen = world.peers[0].events.len();
        if raised
            && world
                .peers
                .iter()
                .all(|p| p.pc.signaling_state() == RTCSignalingState::Stable)
        {
            world.renegotiate_with(without_bundle_group)?;
            renegotiations += 1;
            // The application gathers from the events alone: every transport of both peers
            // asks, peer 0 for the re-keying it started, peer 1 for the new association the
            // offer asked for.
            let needed = world.regather_on_events(7000 + 100 * renegotiations)?;
            for (i, reason) in [
                RTCLocalCandidatesNeededReason::SrtpRekeying,
                RTCLocalCandidatesNeededReason::NewDtlsAssociation,
            ]
            .into_iter()
            .enumerate()
            {
                let reasons: Vec<_> = needed[i].iter().map(|e| e.reason).collect();
                assert_eq!(reasons, vec![reason; 3], "peer {i}: every transport");
                let mids: HashSet<&String> = needed[i].iter().map(|e| &e.mids[0]).collect();
                assert_eq!(mids.len(), 3, "peer {i}: a transport each: {needed:?}");
            }
        }
    }
    world.advance(Duration::from_secs(1))?;
    assert!(
        world.peers[0]
            .events
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { .. })),
        "the key lifetime event"
    );
    assert!(renegotiations >= 1, "the engine asked for a renegotiation");
    let last_tls_ids = tls_ids(&local_sdp(&world));
    assert_eq!(last_tls_ids.len(), 3, "{}", local_sdp(&world));
    assert!(
        last_tls_ids.iter().all(|id| !first_tls_ids.contains(id)),
        "every transport has a new association: {first_tls_ids:?} -> {last_tls_ids:?}"
    );
    for (i, peer) in world.peers.iter().enumerate() {
        for ((local, _, _), (old, _, _)) in transport_ice(peer).iter().zip(&first[i]) {
            assert_ne!(local, old, "peer {i}: an ICE restart on every transport");
        }
    }
    let latest = 7000 + 100 * renegotiations;
    if !world.peers.iter().all(|p| selected_on_new_ports(p, latest)) {
        bail!(
            "every transport on the latest ports {latest}\n{}",
            world.trace()
        );
    }
    for ssrc in &ssrcs {
        let received: HashSet<u16> = world.peers[1]
            .rtp
            .iter()
            .filter(|h| h.ssrc == *ssrc)
            .map(|h| h.sequence_number)
            .collect();
        let missing: Vec<u16> = (1..=PACKETS).filter(|s| !received.contains(s)).collect();
        assert!(
            missing.is_empty(),
            "SSRC {ssrc}: {} packets lost across {renegotiations} renewals: {missing:?}",
            missing.len()
        );
    }
    media_and_data_arrive(&mut world, &senders, "the renewals")
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
            .find(|extension| extension.uri == rtci::sdp::extmap::TRANSPORT_CC_URI)
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
        .add_track(rtci::media_stream::MediaStreamTrack::new(
            "early-stream".to_owned(),
            "early".to_owned(),
            "early".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: rtci::rtp_transceiver::rtp_sender::RTCRtpCodingParameters {
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
                    rtci::rtp::Packet {
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

/// RFC 8445 section 9 and 12.2 across the end of an ICE restart for a new DTLS association
/// (RFC 8842 section 5.1, new ports): each side selects the new pair on its own, the controlled
/// one when the nomination request reaches it, the controlling one when the response comes
/// back. In between, the controlling side still sends on the previous pair, and the controlled
/// side, which has selected the new one, takes that data: the previous path is still taken for
/// a few seconds after the new pair is selected. Here the response is held back while peer 0
/// (controlling) sends a packet: peer 1 reads it at once. (Before, it was dropped as data on
/// an address the transport no longer has a candidate on: one packet lost at each renewal,
/// seen through `rtci-stream-driver` on real sockets.)
#[test]
fn data_sent_on_the_previous_pair_after_the_peer_selected_the_new_one_is_received() -> Result<()> {
    let mut world = World::new(RTCBundlePolicy::Balanced)?;
    let (senders, _) = world.negotiate_media(&[RtpCodecKind::Audio], false, |sdp| sdp)?;
    world.gather()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected))?;
    for seq in 1..=5 {
        world.send_rtp(senders[0], seq)?;
        world.advance(Duration::from_millis(20))?;
    }
    world.peers[0].pc.renew_dtls_association();
    world.renegotiate_with(|sdp| sdp)?;
    world.regather_on_events(7000)?;
    let selected_port = |peer: &Peer| {
        peer.pc.dtls_transports()[0]
            .ice_transport()
            .get_selected_candidate_pair()
            .map(|pair| pair.local().port)
    };
    let mut steps = 0;
    while selected_port(&world.peers[1]) < Some(7000) {
        if !world.step()? {
            world.now += Duration::from_millis(5);
            for peer in world.peers.iter_mut() {
                peer.pc.handle_timeout(world.now)?;
            }
        }
        steps += 1;
        assert!(
            steps < 10_000,
            "peer 1 never selected a new pair\n{}",
            world.trace()
        );
    }
    // Peer 1 has selected the new pair; its response to the nomination is held back, so peer
    // 0 still sends on the previous one.
    world.held_to = Some(SocketAddr::new(world.peers[0].ip, 7000));
    assert!(
        selected_port(&world.peers[0]) < Some(7000),
        "peer 0 has not selected the new pair yet"
    );
    let before = world.peers[1].rtp.len();
    world.send_rtp(senders[0], 6)?;
    world.step()?;
    let received: Vec<u16> = world.peers[1].rtp[before..]
        .iter()
        .map(|h| h.sequence_number)
        .collect();
    assert_eq!(
        received,
        vec![6],
        "the packet on the previous pair, read at once"
    );
    world.held_to = None;
    world.run_traced("both on the new pair", |peers| {
        peers.iter().all(|p| selected_on_new_ports(p, 7000))
    })
}

/// One DTLS handshake as the wire showed it, from its plaintext messages: the client's
/// address and the server's, the step of the client's first ClientHello, whether a ClientHello
/// offered to resume (a DTLS 1.3 `pre_shared_key`, a DTLS 1.2 session id or ticket), whether
/// the server answered with a ServerHello (not a HelloRetryRequest), and whether it resumed (its ServerHello selected the PSK in DTLS 1.3;
/// in DTLS 1.2, no Certificate came from it).
#[derive(Debug, Clone)]
struct WireHandshake {
    client: SocketAddr,
    server: SocketAddr,
    first_hello: u64,
    offered: bool,
    answered: bool,
    resumed: bool,
}

/// The extension types of a hello's extensions block, from `at`.
fn hello_extensions(body: &[u8], mut at: usize) -> Vec<(u16, Vec<u8>)> {
    let mut extensions = vec![];
    if at + 2 > body.len() {
        return extensions;
    }
    let end = (at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]))).min(body.len());
    at += 2;
    while at + 4 <= end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        let data = body.get(at + 4..at + 4 + len).unwrap_or_default().to_vec();
        extensions.push((kind, data));
        at += 4 + len;
    }
    extensions
}

/// The DTLS handshakes of `world`'s wire, one per client address (its latest association
/// when `latest_from` is given: only datagrams of steps from it count).
fn wire_handshakes(world: &World, latest_from: u64) -> Vec<WireHandshake> {
    use std::collections::HashMap;
    const PRE_SHARED_KEY: u16 = 41;
    const SUPPORTED_VERSIONS: u16 = 43;
    const SESSION_TICKET: u16 = 35;
    // (from, to, message_seq, type) -> (step, body, bytes received)
    type Message = (u64, Vec<u8>, usize);
    let mut messages: HashMap<(SocketAddr, SocketAddr, u16, u8), Message> = HashMap::new();
    for (step, from, to, datagram) in &world.dtls {
        if *step < latest_from {
            continue;
        }
        let mut rest = &datagram[..];
        // Plaintext records only (DTLSPlaintext, RFC 6347 4.1 / RFC 9147 4): a record of the
        // unified header comes encrypted, and the datagram's records after it are its own.
        while rest.len() >= 13 && (20..=23).contains(&rest[0]) && rest[1] == 0xfe {
            let length = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
            let Some(record) = rest.get(13..13 + length) else {
                break;
            };
            let epoch = u16::from_be_bytes([rest[3], rest[4]]);
            if rest[0] == 22 && epoch == 0 {
                let mut fragments = record;
                while fragments.len() >= 12 {
                    let u24 = |b: &[u8]| {
                        (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
                    };
                    let kind = fragments[0];
                    let total = u24(&fragments[1..4]);
                    let seq = u16::from_be_bytes([fragments[4], fragments[5]]);
                    let offset = u24(&fragments[6..9]);
                    let size = u24(&fragments[9..12]);
                    let Some(bytes) = fragments.get(12..12 + size) else {
                        break;
                    };
                    let entry = messages
                        .entry((*from, *to, seq, kind))
                        .or_insert_with(|| (*step, vec![0; total], 0));
                    if offset + size <= entry.1.len() {
                        entry.1[offset..offset + size].copy_from_slice(bytes);
                        entry.2 += size;
                    }
                    fragments = &fragments[12 + size..];
                }
            }
            rest = &rest[13 + length..];
        }
    }
    let mut by_client: HashMap<SocketAddr, WireHandshake> = HashMap::new();
    let mut certificates_from: HashSet<SocketAddr> = HashSet::new();
    for ((from, to, _, kind), (step, body, received)) in &messages {
        if *received < body.len() {
            continue;
        }
        match kind {
            1 => {
                // ClientHello: version, random, session id, cookie, suites, compression.
                let session_id = usize::from(body[34]);
                let mut at = 35 + session_id;
                at += 1 + usize::from(body[at]);
                at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
                at += 1 + usize::from(body[at]);
                let extensions = hello_extensions(body, at);
                let offered = session_id > 0
                    || extensions.iter().any(|(kind, data)| {
                        *kind == PRE_SHARED_KEY || (*kind == SESSION_TICKET && !data.is_empty())
                    });
                let entry = by_client.entry(*from).or_insert(WireHandshake {
                    client: *from,
                    server: *to,
                    first_hello: *step,
                    offered: false,
                    answered: false,
                    resumed: false,
                });
                entry.first_hello = entry.first_hello.min(*step);
                entry.offered |= offered;
            }
            11 => {
                certificates_from.insert(*from);
            }
            _ => {}
        }
    }
    for ((from, to, _, kind), (_, body, received)) in &messages {
        if *kind != 2 || *received < body.len() {
            continue;
        }
        // ServerHello: version, random, session id, suite, compression. A HelloRetryRequest
        // (RFC 8446 section 4.1.3: the ServerHello with this random) answers nothing yet.
        const HELLO_RETRY_REQUEST: [u8; 32] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];
        if body.get(2..34) == Some(&HELLO_RETRY_REQUEST[..]) {
            continue;
        }
        let at = 35 + usize::from(body[34]) + 3;
        let extensions = hello_extensions(body, at);
        let Some(handshake) = by_client.get_mut(to) else {
            continue;
        };
        let dtls13 = extensions
            .iter()
            .any(|(kind, _)| *kind == SUPPORTED_VERSIONS);
        handshake.answered = true;
        handshake.resumed |= if dtls13 {
            extensions.iter().any(|(kind, _)| *kind == PRE_SHARED_KEY)
        } else {
            !certificates_from.contains(from)
        };
    }
    let mut handshakes: Vec<WireHandshake> = by_client.into_values().collect();
    handshakes.sort_by_key(|h| (h.first_hello, h.client));
    handshakes
}

/// The peer that sent the ClientHellos (the DTLS client of every transport).
fn dtls_client(world: &World, handshakes: &[WireHandshake]) -> usize {
    let client = handshakes.first().expect("a handshake").client;
    usize::from(!world.peers[0].addrs.contains(&client))
}

/// The step at which `peer`'s DTLS transport whose selected pair has the local address
/// `local` was first "connected" after `from`.
fn connected_step(peer: &Peer, local: SocketAddr, from: u64) -> Option<u64> {
    let id = peer
        .pc
        .dtls_transports()
        .iter()
        .find(|t| {
            t.ice_transport()
                .get_selected_candidate_pair()
                .is_some_and(|pair| {
                    pair.local().address == local.ip().to_string()
                        && pair.local().port == local.port()
                })
        })?
        .id();
    peer.events
        .iter()
        .zip(&peer.event_steps)
        .find_map(|(event, step)| match event {
            RTCPeerConnectionEvent::OnTransportEvent(event)
                if *step >= from
                    && event.dtls_transport == id
                    && matches!(
                        event.event,
                        RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connected)
                    ) =>
            {
                Some(*step)
            }
            _ => None,
        })
}

/// Two peers under `max-compat`, answered without bundling (three transports: audio, video,
/// data), with `with_dtls_session_resumption(resumption)` on both, connected.
fn three_unbundled_transports(resumption: bool) -> Result<(World, Vec<RTCRtpSenderId>)> {
    let mut world = World::with_setting_engines(RTCBundlePolicy::MaxCompat, || {
        SettingEngineBuilder::new().with_dtls_session_resumption(resumption)
    })?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run_traced("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    Ok((world, senders))
}

/// RFC 5764 section 3: "a single DTLS association is established, and all other DTLS
/// associations wait until that connection is established before proceeding with their
/// handshakes. This establishes a single session and all other associations can take
/// advantage of TLS session resumption." Three transports: the first client transport runs a
/// full handshake; each of the two others sends its first ClientHello only after the first
/// is connected, offers the session's ticket, and the server resumes it. Media and data go on
/// every transport.
#[test]
fn unbundled_transports_wait_for_the_first_and_resume_its_dtls_session() -> Result<()> {
    let mut world = World::with_setting_engines(RTCBundlePolicy::MaxCompat, || {
        SettingEngineBuilder::new().with_dtls_session_resumption(true)
    })?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    // DTLS is lost until every transport has selected its pair: each could start its
    // handshake by then, and only the first does.
    world.drop_dtls = true;
    world.run_traced("every transport selected a pair", |peers| {
        peers.iter().all(|p| {
            let transports = p.pc.dtls_transports();
            transports.len() == 3
                && transports
                    .iter()
                    .all(|t| t.ice_transport().get_selected_candidate_pair().is_some())
        })
    })?;
    world.advance(Duration::from_millis(100))?;
    world.drop_dtls = false;
    world.run_traced("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    let handshakes = wire_handshakes(&world, 0);
    assert_eq!(
        handshakes.len(),
        3,
        "a handshake per transport: {handshakes:?}"
    );
    let client = dtls_client(&world, &handshakes);
    let (leader, others) = handshakes.split_first().expect("handshakes");
    assert!(
        !leader.offered && leader.answered && !leader.resumed,
        "the first is a full handshake: {leader:?}"
    );
    let leader_connected = connected_step(&world.peers[client], leader.client, 0)
        .context("the first transport connected")?;
    for handshake in others {
        assert!(
            handshake.first_hello > leader_connected,
            "{handshake:?} started only after the first was connected (step {leader_connected})"
        );
        assert!(
            handshake.offered && handshake.resumed,
            "the others resume its session: {handshakes:?}"
        );
    }
    media_and_data_arrive(&mut world, &senders, "the resumed associations")
}

/// `with_dtls_session_resumption(false)`: every transport runs a full handshake, none offers
/// a session.
#[test]
fn without_dtls_session_resumption_every_transport_runs_a_full_handshake() -> Result<()> {
    let (mut world, senders) = three_unbundled_transports(false)?;
    let handshakes = wire_handshakes(&world, 0);
    assert_eq!(handshakes.len(), 3, "{handshakes:?}");
    for handshake in &handshakes {
        assert!(
            !handshake.offered && handshake.answered && !handshake.resumed,
            "{handshakes:?}"
        );
    }
    media_and_data_arrive(&mut world, &senders, "full handshakes")
}

/// RFC 5764 section 4.4 / RFC 8842: once the connection's transports have resumed its
/// session, a new association of each (`renew_dtls_association`, what automatic SRTP re-keying
/// calls) runs a full handshake with a fresh key exchange: no ClientHello offers a session and
/// no server resumes one.
#[test]
fn a_new_dtls_association_after_a_resumed_one_is_a_full_handshake() -> Result<()> {
    // As `renewing_the_dtls_association_renews_every_transport`, with the default settings
    // (session resumption on).
    let mut world = World::with_credentials(RTCBundlePolicy::MaxCompat, false)?;
    let (senders, _) = world.negotiate(without_bundle_group)?;
    world.gather()?;
    world.run("connected with a data channel", |peers| {
        peers.iter().all(|p| p.connected && p.channel.is_some())
    })?;
    assert_eq!(
        wire_handshakes(&world, 0)
            .iter()
            .filter(|h| h.resumed)
            .count(),
        2,
        "two transports resumed"
    );
    world.renegotiate_with(without_bundle_group)?;
    world.peers[0].events.clear();
    world.peers[0].event_steps.clear();
    let from = world.steps + 1;
    world.peers[0].pc.renew_dtls_association();
    world.renegotiate_with(without_bundle_group)?;
    world.regather(7000)?;
    let ids: Vec<RTCTransportId> = world.peers[0]
        .pc
        .dtls_transports()
        .iter()
        .map(|t| t.id())
        .collect();
    world.run_traced("every transport ran a new handshake", |peers| {
        let events = transport_events(&peers[0]);
        ids.iter().all(|id| {
            events.iter().any(|(_, dtls, kind)| {
                dtls == id
                    && matches!(
                        kind,
                        RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connected)
                    )
            })
        })
    })?;
    world.run_traced(
        "every transport selected a pair on the new ports",
        |peers| peers.iter().all(|p| selected_on_new_ports(p, 7000)),
    )?;
    media_and_data_arrive(&mut world, &senders, "the new associations")?;
    let renewed = wire_handshakes(&world, from);
    assert_eq!(
        renewed.len(),
        3,
        "a new handshake per transport: {renewed:?}"
    );
    for handshake in &renewed {
        assert!(
            !handshake.offered && handshake.answered && !handshake.resumed,
            "{renewed:?}"
        );
    }
    Ok(())
}

/// `sdp` with the second m= section's `a=fingerprint` naming the certificate `fingerprint`.
fn second_section_fingerprint(sdp: &str, fingerprint: &str) -> String {
    let mut section = 0;
    let mut out = String::new();
    for line in sdp.lines() {
        if line.starts_with("m=") {
            section += 1;
        }
        if section == 2 && line.starts_with("a=fingerprint:") {
            out.push_str(&format!("a=fingerprint:{fingerprint}\r\n"));
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// The `algorithm value` of a new certificate's SHA-256 fingerprint.
fn another_certificates_fingerprint() -> Result<String> {
    use rtci::crypto::SignatureScheme;
    use rtci::peer_connection::certificate::RTCCertificate;
    let provider = rtci::crypto::default_provider()?;
    let certificate = RTCCertificate::generate_certificate(
        provider.crypto(),
        SignatureScheme::EcdsaP256Sha256,
        None,
        std::time::SystemTime::now(),
    )?;
    let fingerprint = certificate
        .get_fingerprints(provider.crypto())?
        .into_iter()
        .next()
        .context("a fingerprint")?;
    // RFC 8122 section 5: upper-case hex.
    Ok(format!(
        "{} {}",
        fingerprint.algorithm,
        fingerprint.value.to_uppercase()
    ))
}

/// The second section of the offer (`in_offer`, seen by the DTLS client) or of the answer
/// (seen by the DTLS server) names another certificate's fingerprint, with
/// `with_dtls_session_resumption(resumption)`: that transport fails with
/// `fingerprint-failure` at the peer that checks it, after a full handshake (its client
/// offered no session when it is the one told the wrong fingerprint, and the server resumed
/// nothing), and the two other transports connect. Returns the failing handshake.
fn wrong_fingerprint_in_the_second_section(
    in_offer: bool,
    resumption: bool,
) -> Result<WireHandshake> {
    use rtci::peer_connection::rtc_error::RTCErrorDetailType;
    let fingerprint = another_certificates_fingerprint()?;
    let mut world = World::with_setting_engines(RTCBundlePolicy::MaxCompat, || {
        SettingEngineBuilder::new().with_dtls_session_resumption(resumption)
    })?;
    world.tolerate_failure = true;
    let tamper = |sdp: String, here: bool| {
        if here {
            second_section_fingerprint(&sdp, &fingerprint)
        } else {
            sdp
        }
    };
    world.negotiate_media_and_answer(
        &[RtpCodecKind::Audio, RtpCodecKind::Video],
        true,
        |sdp| tamper(without_bundle_group(sdp), in_offer),
        |sdp| tamper(sdp, !in_offer),
    )?;
    world.gather()?;
    // The checking peer: the one that was told the wrong fingerprint.
    let checking = usize::from(in_offer);
    let second = |peer: &Peer| -> Result<SocketAddr> {
        let at = peer
            .pc
            .ice_transport_sections()
            .iter()
            .position(|(_, index)| *index == 1)
            .context("the second section's transport")?;
        Ok(peer.addrs[at])
    };
    let failing_local = second(&world.peers[checking])?;
    // The second transport's path comes up once the others are connected, so that a
    // session is there for it to resume, were it allowed to.
    let held = [second(&world.peers[0])?, second(&world.peers[1])?];
    world.blocked.extend(held);
    world.run_traced("the two other transports connected", |peers| {
        peers.iter().all(|p| {
            p.pc.dtls_transports()
                .iter()
                .filter(|t| t.state() == RTCDtlsTransportState::Connected)
                .count()
                == 2
        })
    })?;
    world.blocked.clear();
    world.run_traced(
        "the second transport failed, the others connected",
        |peers| {
            let states = |p: &Peer| -> Vec<(SocketAddr, RTCDtlsTransportState)> {
                p.pc.dtls_transports()
                    .iter()
                    .filter_map(|t| {
                        let pair = t.ice_transport().get_selected_candidate_pair()?;
                        let local =
                            SocketAddr::new(pair.local().address.parse().ok()?, pair.local().port);
                        Some((local, t.state()))
                    })
                    .collect()
            };
            let mine = states(&peers[checking]);
            mine.len() == 3
                && mine.iter().all(|(local, state)| {
                    if *local == failing_local {
                        *state == RTCDtlsTransportState::Failed
                    } else {
                        *state == RTCDtlsTransportState::Connected
                    }
                })
                && states(&peers[1 - checking])
                    .iter()
                    .filter(|(_, state)| *state == RTCDtlsTransportState::Connected)
                    .count()
                    == 2
        },
    )?;
    let error = world.peers[checking]
        .events
        .iter()
        .find_map(|event| match event {
            RTCPeerConnectionEvent::OnTransportEvent(event) => match &event.event {
                RTCTransportEventKind::DtlsError(error) => Some(error.clone()),
                _ => None,
            },
            _ => None,
        })
        .context("the failing transport's error")?;
    assert_eq!(
        error.error_detail,
        RTCErrorDetailType::FingerprintFailure,
        "{error:?}"
    );
    let handshakes = wire_handshakes(&world, 0);
    assert_eq!(handshakes.len(), 3, "{handshakes:?}");
    let failing = handshakes
        .iter()
        .find(|h| h.client == failing_local || h.server == failing_local)
        .context("the second transport's handshake")?
        .clone();
    assert!(
        failing.answered && !failing.resumed,
        "a full handshake, as without resumption: {failing:?}"
    );
    if in_offer {
        assert!(
            !failing.offered,
            "its client offered no session: {failing:?}"
        );
    }
    Ok(failing)
}

/// RFC 5764 section 3 does not weaken RFC 8122 / RFC 8827 section 6.5: a section of the
/// offer that names another certificate than the session's (as the DTLS client sees it)
/// takes no part in the session: its transport runs a full handshake and fails with
/// `fingerprint-failure`, exactly as without resumption, while the others connect.
#[test]
fn a_section_naming_another_certificate_does_not_resume_as_the_dtls_client() -> Result<()> {
    let with = wrong_fingerprint_in_the_second_section(true, true)?;
    let without = wrong_fingerprint_in_the_second_section(true, false)?;
    assert_eq!(
        (with.offered, with.answered, with.resumed),
        (without.offered, without.answered, without.resumed)
    );
    Ok(())
}

/// The same for a section of the answer, as the DTLS server sees it: it accepts no session
/// for that transport (a full handshake, whose client certificate fails the section's
/// fingerprint), exactly as without resumption.
#[test]
fn a_section_naming_another_certificate_does_not_resume_as_the_dtls_server() -> Result<()> {
    let with = wrong_fingerprint_in_the_second_section(false, true)?;
    let without = wrong_fingerprint_in_the_second_section(false, false)?;
    assert_eq!(
        (with.answered, with.resumed),
        (without.answered, without.resumed)
    );
    Ok(())
}
