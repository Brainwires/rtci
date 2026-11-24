//! SRTP re-keying when both peers ask for a new DTLS association at once (glare).
//!
//! Two `rtci` peers send each other audio on a virtual clock with the same short SRTP key
//! lifetime, so both reach the lifetime warning (RFC 5764 section 4.4) in the same step and
//! both want a re-keying offer: a new `a=tls-id` (RFC 8842 section 5.5) with an ICE restart
//! and a new 3-tuple (section 5.1). The application does what the W3C webrtc-pc "perfect
//! negotiation" example does: on an offer collision the polite peer rolls back its own offer
//! and answers the other one, the impolite peer ignores the incoming offer. It gathers from
//! `OnLocalCandidatesNeeded` (a host candidate on a new port) and trickles every local
//! candidate over the signalling channel, which delivers in order after a delay.
//!
//! RFC 9429 section 5.7: on rollback "any resources or candidates that were allocated by the
//! abandoned local description are discarded"; RFC 8842 section 5.3: an answer that sets up
//! a new association carries "a new unique" `tls-id`. The call goes on: every packet of both
//! senders arrives, the connection never fails, and each renewal is one new association.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use rtci::peer_connection::event::{
    RTCDataChannelEvent, RTCPeerConnectionEvent, RTCPeerConnectionIceEvent, RTCTransportEvent,
    RTCTransportEventKind,
};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtci::peer_connection::state::{RTCPeerConnectionState, RTCSignalingState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::srtp::keying::KeyLifetime;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// SRTP packets per master key: the warning comes with 20 left.
const LIFETIME: u64 = 320;
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// How the polite peer abandons its own offer on a collision.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Rollback {
    /// `setLocalDescription({type: "rollback"})`, then the remote offer.
    Explicit,
    /// The remote offer alone (W3C implicit rollback).
    Implicit,
}

#[derive(Clone, Debug)]
enum Signal {
    Description(Box<RTCSessionDescription>),
    Candidate(RTCIceCandidateInit),
}

struct Peer {
    name: &'static str,
    pc: RTCPeerConnection,
    polite: bool,
    ignore_offer: bool,
    ip: IpAddr,
    next_port: u16,
    /// The addresses of the sockets the application has open.
    bound: Vec<SocketAddr>,
    inbox: Vec<TaggedBytesMut>,
    events: Vec<RTCPeerConnectionEvent>,
    /// Sequence numbers of the peer's audio received.
    received: BTreeSet<u16>,
    ssrc: u32,
    remote_ssrc: u32,
    senders: Vec<RTCRtpSenderId>,
    /// `a=tls-id` values of every offer this peer sent, and of every answer.
    offered_tls_ids: Vec<String>,
    answered_tls_ids: Vec<String>,
    /// Errors of `add_remote_candidate` while the peer was not ignoring an offer.
    candidate_errors: Vec<String>,
    write_errors: usize,
    channel_closed: bool,
    channel_open: bool,
}

fn attribute(sdp: &str, key: &str) -> Vec<String> {
    let prefix = format!("a={key}:");
    sdp.lines()
        .filter_map(|line| line.trim_end().strip_prefix(prefix.as_str()))
        .map(str::to_owned)
        .collect()
}

fn summary(sdp: &str) -> String {
    let fingerprint = attribute(sdp, "fingerprint")
        .first()
        .map(|f| f.chars().take(22).collect::<String>())
        .unwrap_or_default();
    format!(
        "tls-id={:?} setup={:?} ufrag={:?} pwd={:?} fp={fingerprint}",
        attribute(sdp, "tls-id"),
        attribute(sdp, "setup"),
        attribute(sdp, "ice-ufrag"),
        attribute(sdp, "ice-pwd")
            .iter()
            .map(|p| p.chars().take(6).collect::<String>())
            .collect::<Vec<_>>(),
    )
}

fn audio_track(ssrc: u32, id: &str) -> MediaStreamTrack {
    MediaStreamTrack::new(
        format!("stream-{id}"),
        id.to_owned(),
        id.to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                ..Default::default()
            },
            ..Default::default()
        }],
    )
}

fn host(addr: SocketAddr, mid: Option<&str>, index: Option<u16>) -> Result<RTCIceCandidateInit> {
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
    if mid.is_some() {
        init.sdp_mid = mid.map(str::to_owned);
        init.sdp_mline_index = index;
    }
    Ok(init)
}

/// What a scenario sets.
struct Scenario {
    /// Peer `i`'s setting engine.
    settings: [SettingEngineBuilder; 2],
    /// The polite peer.
    polite: usize,
    rollback: Rollback,
    /// One-way delay of the signalling channel.
    signal_delay: Duration,
    /// Audio packets each peer sends.
    packets: u16,
    /// Bundle policy of both peers; with `MaxCompat` the offers reach the other peer without
    /// their BUNDLE group, so each section runs on a transport of its own.
    policy: RTCBundlePolicy,
    /// Audio senders per peer.
    tracks: usize,
    /// DTLS datagrams to this peer, once first connected, arrive this much later than the
    /// rest (a path that delays the handshake's last flight behind the media).
    delay_dtls_to: Option<(usize, Duration)>,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            settings: [SettingEngineBuilder::new(), SettingEngineBuilder::new()],
            polite: 1,
            rollback: Rollback::Explicit,
            signal_delay: Duration::from_millis(25),
            packets: 700,
            policy: RTCBundlePolicy::Balanced,
            tracks: 1,
            delay_dtls_to: None,
        }
    }
}

fn lifetime(packets: u64) -> Option<KeyLifetime> {
    Some(KeyLifetime {
        srtp_packets: packets,
        srtcp_packets: 1 << 31,
    })
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    start: Instant,
    signals: VecDeque<(Instant, usize, Signal)>,
    signal_delay: Duration,
    rollback: Rollback,
    unbundle: bool,
    trace: String,
    /// Offers each peer made after the first connection.
    offers: [usize; 2],
    /// Offers each peer ignored (impolite), rolled back (polite).
    ignored: [usize; 2],
    rolled_back: [usize; 2],
    /// Datagrams sent to an address nobody has open.
    unroutable: usize,
    /// `ignored` and `rolled_back` when the first connection completed.
    collisions_at_connection: [usize; 2],
    /// `Scenario::delay_dtls_to`, active once first connected.
    delay_dtls_to: Option<(usize, Duration)>,
    delay_active: bool,
    /// Delayed datagrams: (due, peer, datagram).
    delayed: Vec<(Instant, usize, TaggedBytesMut)>,
}

impl World {
    fn new(scenario: Scenario, start: Instant) -> Result<Self> {
        let [s0, s1] = scenario.settings;
        let mut peers = Vec::new();
        for (i, settings) in [s0, s1].into_iter().enumerate() {
            let mut media_engine = MediaEngine::default();
            media_engine.register_default_codecs()?;
            let pc = RTCPeerConnectionBuilder::new()
                .with_configuration(
                    RTCConfigurationBuilder::new()
                        .with_bundle_policy(scenario.policy)
                        .build(),
                )
                .with_media_engine(media_engine)
                .with_setting_engine(settings.build())
                .build(start)?;
            peers.push(Peer {
                name: if i == 0 { "A" } else { "B" },
                pc,
                polite: i == scenario.polite,
                ignore_offer: false,
                ip: format!("10.0.2.{}", i + 1).parse()?,
                next_port: 5000,
                bound: vec![],
                inbox: vec![],
                events: vec![],
                received: BTreeSet::new(),
                ssrc: 7000 + i as u32,
                remote_ssrc: 7000 + (1 - i) as u32,
                senders: vec![],
                offered_tls_ids: vec![],
                answered_tls_ids: vec![],
                candidate_errors: vec![],
                write_errors: 0,
                channel_closed: false,
                channel_open: false,
            });
        }
        let [p0, p1]: [Peer; 2] = peers.try_into().map_err(|_| anyhow::anyhow!("two"))?;
        let mut world = Self {
            peers: [p0, p1],
            now: start,
            start,
            signals: VecDeque::new(),
            signal_delay: scenario.signal_delay,
            rollback: scenario.rollback,
            unbundle: scenario.policy == RTCBundlePolicy::MaxCompat,
            trace: String::new(),
            offers: [0; 2],
            ignored: [0; 2],
            rolled_back: [0; 2],
            unroutable: 0,
            collisions_at_connection: [0; 2],
            delay_dtls_to: scenario.delay_dtls_to,
            delay_active: false,
            delayed: vec![],
        };
        for i in 0..2 {
            for k in 0..scenario.tracks {
                let ssrc = world.peers[i].ssrc + 100 * k as u32;
                let sender = world.peers[i]
                    .pc
                    .add_track(audio_track(ssrc, &format!("audio-{i}-{k}")))?;
                world.peers[i].senders.push(sender);
            }
        }
        world.peers[0].pc.create_data_channel("survives", None)?;
        Ok(world)
    }

    fn log(&mut self, line: String) {
        let at = self.now.duration_since(self.start).as_millis();
        let _ = writeln!(self.trace, "{at:>6} ms {line}");
    }

    fn send(&mut self, from: usize, signal: Signal) {
        let due = self.now + self.signal_delay;
        self.signals.push_back((due, 1 - from, signal));
    }

    fn send_description(&mut self, from: usize, mut description: RTCSessionDescription) {
        let name = self.peers[from].name;
        let line = format!(
            "{name} sends {:?} {}",
            description.sdp_type,
            summary(&description.sdp)
        );
        self.log(line);
        let tls_ids = attribute(&description.sdp, "tls-id");
        match description.sdp_type {
            RTCSdpType::Offer => self.peers[from].offered_tls_ids.extend(tls_ids),
            RTCSdpType::Answer => self.peers[from].answered_tls_ids.extend(tls_ids),
            _ => {}
        }
        if self.unbundle && description.sdp_type == RTCSdpType::Offer {
            description = RTCSessionDescription::offer(
                description
                    .sdp
                    .lines()
                    .filter(|l| !l.starts_with("a=group:BUNDLE"))
                    .map(|l| format!("{l}\r\n"))
                    .collect(),
            )
            .expect("an offer");
        }
        self.send(from, Signal::Description(Box::new(description)));
    }

    /// W3C perfect negotiation, `onnegotiationneeded`.
    fn make_offer(&mut self, i: usize) -> Result<()> {
        let offer = self.peers[i].pc.create_offer(None)?;
        self.peers[i]
            .pc
            .set_local_description(self.now, offer.clone())?;
        self.send_description(i, offer);
        Ok(())
    }

    /// W3C perfect negotiation, `onmessage`.
    fn on_signal(&mut self, i: usize, signal: Signal) -> Result<()> {
        let name = self.peers[i].name;
        match signal {
            Signal::Description(description) => {
                let description = *description;
                let collision = description.sdp_type == RTCSdpType::Offer
                    && self.peers[i].pc.signaling_state() != RTCSignalingState::Stable;
                self.peers[i].ignore_offer = !self.peers[i].polite && collision;
                if self.peers[i].ignore_offer {
                    self.ignored[i] += 1;
                    self.log(format!("{name} (impolite) ignores the colliding offer"));
                    return Ok(());
                }
                if collision {
                    self.rolled_back[i] += 1;
                    if self.rollback == Rollback::Explicit {
                        self.log(format!("{name} (polite) rolls back its offer"));
                        self.peers[i].pc.set_local_description(
                            self.now,
                            RTCSessionDescription::rollback(None)?,
                        )?;
                        self.check_rolled_back(i);
                    } else {
                        self.log(format!(
                            "{name} (polite) takes the offer (implicit rollback)"
                        ));
                    }
                }
                let sdp_type = description.sdp_type;
                self.peers[i]
                    .pc
                    .set_remote_description(self.now, description)?;
                if sdp_type == RTCSdpType::Offer {
                    let answer = self.peers[i].pc.create_answer(None)?;
                    self.peers[i]
                        .pc
                        .set_local_description(self.now, answer.clone())?;
                    self.send_description(i, answer);
                }
            }
            Signal::Candidate(candidate) => {
                if let Err(err) = self.peers[i].pc.add_remote_candidate(candidate.clone()) {
                    let line = format!(
                        "{name} add_remote_candidate {} (ufrag {:?}): {err}",
                        candidate.candidate, candidate.username_fragment
                    );
                    self.log(line.clone());
                    if !self.peers[i].ignore_offer {
                        self.peers[i].candidate_errors.push(line);
                    }
                }
            }
        }
        Ok(())
    }

    /// RFC 9429 section 5.7: after the rollback the local description is the current one
    /// again (its `tls-id`, ICE credentials), and the ICE agent is back on its credentials.
    fn check_rolled_back(&mut self, i: usize) {
        let pc = &mut self.peers[i].pc;
        let Some(current) = pc.current_local_description().map(|d| d.sdp) else {
            return;
        };
        let local = pc.local_description().map(|d| d.sdp).unwrap_or_default();
        let mut problems = vec![];
        for key in ["tls-id", "ice-ufrag", "ice-pwd"] {
            if attribute(&local, key) != attribute(&current, key) {
                problems.push(format!(
                    "{key} of the local description is not the current one"
                ));
            }
        }
        let stats = pc
            .get_stats(self.now, rtci::statistics::StatsSelector::None)
            .transport()
            .map(|t| t.ice_local_username_fragment.clone());
        if stats
            .as_ref()
            .is_some_and(|ufrag| !attribute(&current, "ice-ufrag").contains(ufrag))
        {
            problems.push(format!(
                "the ICE agent's ufrag {stats:?} is not the current one"
            ));
        }
        for problem in problems {
            let line = format!("{}: after the rollback: {problem}", self.peers[i].name);
            self.log(line.clone());
            self.peers[i].candidate_errors.push(line);
        }
    }

    /// The application opens a socket on a new port and gives the engine its candidate.
    fn gather(&mut self, i: usize, mid: Option<&str>, index: Option<u16>) -> Result<()> {
        let port = self.peers[i].next_port;
        self.peers[i].next_port += 1;
        let addr = SocketAddr::new(self.peers[i].ip, port);
        self.peers[i].bound.push(addr);
        let name = self.peers[i].name;
        match self.peers[i]
            .pc
            .add_local_candidate(host(addr, mid, index)?)
        {
            Ok(()) => self.log(format!("{name} gathers {addr} for {mid:?}")),
            Err(err) => bail!("{name}: add_local_candidate {addr}: {err}"),
        }
        Ok(())
    }

    fn handle_events(&mut self, i: usize) -> Result<()> {
        while let Some(event) = self.peers[i].pc.poll_event() {
            let name = self.peers[i].name;
            match &event {
                RTCPeerConnectionEvent::OnNegotiationNeededEvent => {
                    // B makes no offer of its own before A's first one reached it: the call
                    // is set up by A (B's track goes in its answer), so that the only
                    // collisions are the re-keying ones under test. Back in stable after
                    // its answer, negotiation-needed fires again if anything is left.
                    let waits = i == 1 && self.peers[i].pc.remote_description().is_none();
                    if self.peers[i].pc.signaling_state() == RTCSignalingState::Stable && !waits {
                        self.log(format!("{name} negotiation-needed: offers"));
                        self.offers[i] += 1;
                        self.make_offer(i)?;
                    }
                }
                RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => {
                    self.log(format!(
                        "{name} candidates needed {:?} for {:?}, refused {:?}",
                        needed.reason, needed.mids, needed.refused_addresses
                    ));
                    let mid = needed.mids.first().cloned();
                    self.gather(i, mid.as_deref(), needed.sdp_mline_index)?;
                }
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: Some(candidate),
                    ..
                }) => {
                    let init = candidate.to_json()?;
                    if !init.candidate.is_empty() {
                        self.send(i, Signal::Candidate(init));
                    }
                }
                RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { outbound, .. } => {
                    self.log(format!("{name} key lifetime expiring, outbound {outbound}"));
                }
                RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
                    self.log(format!("{name} signaling {state}"));
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    self.log(format!("{name} connection {state}"));
                }
                RTCPeerConnectionEvent::OnTransportEvent(RTCTransportEvent {
                    dtls_transport,
                    event: RTCTransportEventKind::DtlsStateChange(state),
                    ..
                }) => {
                    let role = self.peers[i]
                        .pc
                        .get_stats(self.now, rtci::statistics::StatsSelector::None)
                        .transport()
                        .map(|t| t.dtls_role);
                    self.log(format!(
                        "{name} dtls {dtls_transport} {state} (default transport role {role:?})"
                    ));
                }
                RTCPeerConnectionEvent::OnTransportEvent(RTCTransportEvent {
                    ice_transport,
                    event: RTCTransportEventKind::SelectedCandidatePairChange(pair),
                    ..
                }) => {
                    self.log(format!("{name} ice {ice_transport} selects {pair}"));
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    self.peers[i].channel_open = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(
                    RTCDataChannelEvent::OnClose(_) | RTCDataChannelEvent::OnClosing(_),
                ) => {
                    self.peers[i].channel_closed = true;
                }
                _ => {}
            }
            self.peers[i].events.push(event);
        }
        Ok(())
    }

    /// One turn of peer `i`: its datagrams, events, received media, and what it writes.
    fn turn(&mut self, i: usize) -> Result<()> {
        let inbox = std::mem::take(&mut self.peers[i].inbox);
        for datagram in inbox {
            self.peers[i].pc.handle_read(datagram)?;
        }
        self.handle_events(i)?;
        let remote_ssrc = self.peers[i].remote_ssrc;
        while let Some(message) = self.peers[i].pc.poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = message.message
                && packet.header.ssrc == remote_ssrc
            {
                self.peers[i].received.insert(packet.header.sequence_number);
            }
        }
        while let Some(datagram) = self.peers[i].pc.poll_write() {
            let to = datagram.transport.peer_addr;
            let target = 1 - i;
            if !self.peers[target].bound.contains(&to) {
                self.unroutable += 1;
                continue;
            }
            let delivered = TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: datagram.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            };
            // DTLS records start with a content type of 20 to 63 (RFC 7983).
            let dtls = delivered
                .message
                .first()
                .is_some_and(|b| (20..=63).contains(b));
            match self.delay_dtls_to {
                Some((peer, delay)) if self.delay_active && peer == target && dtls => {
                    self.delayed.push((self.now + delay, target, delivered));
                }
                _ => self.peers[target].inbox.push(delivered),
            }
        }
        Ok(())
    }

    /// Hands the delayed datagrams that are due to their peers.
    fn deliver_delayed(&mut self) {
        let now = self.now;
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.delayed)
            .into_iter()
            .partition(|(at, _, _)| *at <= now);
        self.delayed = later;
        for (_, peer, mut datagram) in due {
            datagram.now = now;
            self.peers[peer].inbox.push(datagram);
        }
    }

    fn ignored_after_connected(&self) -> usize {
        self.ignored.iter().sum::<usize>() - self.collisions_at_connection[0]
    }

    fn rolled_back_after_connected(&self) -> usize {
        self.rolled_back.iter().sum::<usize>() - self.collisions_at_connection[1]
    }

    fn connected(&self) -> bool {
        self.peers
            .iter()
            .all(|p| p.pc.connection_state() == RTCPeerConnectionState::Connected)
            && self.peers[1].channel_open
    }
}

struct Outcome {
    world: World,
    sent: u16,
    /// Each peer's `(tls-ids, ufrags)` of its local description once first connected.
    first: [(Vec<String>, Vec<String>); 2],
    failed: bool,
    /// Each peer's `unsent_media_packets` once first connected.
    unsent_at_connection: [u64; 2],
}

/// Connects peer A (first offerer, with a data channel) to peer B, then has both send
/// `packets` audio packets each, one every 20 ms, answering negotiation-needed and the
/// peer's descriptions as the perfect negotiation example does.
fn run(scenario: Scenario) -> Result<Outcome> {
    let start = Instant::now();
    let packets = scenario.packets;
    let mut world = World::new(scenario, start)?;
    // The first exchange: A offers; each peer gathers once it has a local description.
    world.offers[0] = 0;
    world.make_offer(0)?;
    let mut gathered = [false; 2];
    let mut renegotiated = false;
    let mut first = None;
    let mut next_packet = start;
    let mut sent = 0u16;
    let mut failed = false;
    let mut unsent_at_connection = [0u64; 2];
    for _ in 0..2_000_000 {
        for (i, gathered) in gathered.iter_mut().enumerate() {
            if !*gathered && world.peers[i].pc.local_description().is_some() {
                *gathered = true;
                for (mid, index) in world.peers[i].pc.ice_transport_sections() {
                    world.gather(i, Some(&mid), Some(index))?;
                }
            }
        }
        world.deliver_delayed();
        world.turn(0)?;
        world.turn(1)?;
        if world
            .peers
            .iter()
            .any(|p| p.pc.connection_state() == RTCPeerConnectionState::Failed)
        {
            failed = true;
            break;
        }
        let stable = world
            .peers
            .iter()
            .all(|p| p.pc.signaling_state() == RTCSignalingState::Stable);
        // Unbundled: the first offer had its BUNDLE group taken away on the way, so its
        // sections other than the tagged one carried no `tls-id` (IDENTICAL, written once on
        // the BUNDLE tag, RFC 8842 section 4) and their associations have none on B's side. A
        // later offer gives each transport its own; one plain exchange records them before
        // the re-keying starts.
        if first.is_none() && world.connected() && stable && world.unbundle && !renegotiated {
            renegotiated = true;
            world.log("renegotiates once (unbundled)".to_owned());
            world.make_offer(0)?;
            continue;
        }
        if first.is_none() && world.connected() && stable && (renegotiated || !world.unbundle) {
            world.log("connected".to_owned());
            first = Some([0, 1].map(|i| {
                let sdp = world.peers[i]
                    .pc
                    .local_description()
                    .map(|d| d.sdp)
                    .unwrap_or_default();
                (attribute(&sdp, "tls-id"), attribute(&sdp, "ice-ufrag"))
            }));
            world.offers = [0; 2];
            world.delay_active = true;
            unsent_at_connection = [0, 1].map(|i| world.peers[i].pc.unsent_media_packets());
            world.collisions_at_connection =
                [world.ignored.iter().sum(), world.rolled_back.iter().sum()];
            next_packet = world.now;
        }
        if !world.peers[0].inbox.is_empty() || !world.peers[1].inbox.is_empty() {
            continue;
        }
        if let Some(&(due, _, _)) = world.signals.front()
            && due <= world.now
        {
            let (_, to, signal) = world.signals.pop_front().expect("a signal");
            world.on_signal(to, signal)?;
            continue;
        }
        if first.is_some() && world.now >= next_packet {
            if sent == packets {
                break;
            }
            sent += 1;
            next_packet = world.now + PACKET_INTERVAL;
            for i in 0..2 {
                let senders = world.peers[i].senders.clone();
                for (k, sender) in senders.into_iter().enumerate() {
                    let ssrc = world.peers[i].ssrc + 100 * k as u32;
                    let now = world.now;
                    let written = world.peers[i]
                        .pc
                        .rtp_sender(sender)
                        .expect("sender")
                        .write_rtp(
                            now,
                            rtci::rtp::Packet {
                                header: rtci::rtp::header::Header {
                                    version: 2,
                                    payload_type: 111,
                                    sequence_number: sent,
                                    timestamp: u32::from(sent) * 960,
                                    ssrc,
                                    ..Default::default()
                                },
                                payload: Bytes::from_static(&[0xF8, 0xFF, 0xFE]),
                            },
                        );
                    if written.is_err() {
                        world.peers[i].write_errors += 1;
                    }
                }
            }
            continue;
        }
        let mut next = [
            world.peers[0].pc.poll_timeout(),
            world.peers[1].pc.poll_timeout(),
            world.signals.front().map(|(due, _, _)| *due),
            world.delayed.iter().map(|(due, _, _)| *due).min(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(world.now + PACKET_INTERVAL);
        if first.is_some() {
            next = next.min(next_packet);
        }
        world.now = next.max(world.now);
        for p in world.peers.iter_mut() {
            p.pc.handle_timeout(world.now)?;
        }
    }
    let Some(first) = first else {
        bail!("the peers never connected\n{}", world.trace)
    };
    Ok(Outcome {
        world,
        sent,
        first,
        failed,
        unsent_at_connection,
    })
}

/// The checks every glare scenario makes; on failure, the trace of both peers.
fn check_call(outcome: &Outcome, scenario_packets: u16, renewals: usize) {
    let world = &outcome.world;
    let mut problems = vec![];
    if outcome.failed {
        problems.push("a connection failed".to_owned());
    }
    if outcome.sent != scenario_packets {
        problems.push(format!("sent {} of {scenario_packets}", outcome.sent));
    }
    for (i, p) in world.peers.iter().enumerate() {
        let missing: Vec<u16> = (1..=outcome.sent)
            .filter(|seq| !p.received.contains(seq))
            .collect();
        if !missing.is_empty() {
            problems.push(format!(
                "{}: {} packets of the peer lost, first {:?}",
                p.name,
                missing.len(),
                &missing[..missing.len().min(10)]
            ));
        }
        if p.write_errors > 0 {
            problems.push(format!("{}: {} writes refused", p.name, p.write_errors));
        }
        if !p.candidate_errors.is_empty() {
            problems.push(format!(
                "{}: candidate errors {:?}",
                p.name, p.candidate_errors
            ));
        }
        // Nothing written after the connection went unsent (no path, a reused SRTP index).
        if p.pc.unsent_media_packets() != outcome.unsent_at_connection[i] {
            problems.push(format!(
                "{}: {} media packets not sent",
                p.name,
                p.pc.unsent_media_packets() - outcome.unsent_at_connection[i]
            ));
        }
        if p.channel_closed {
            problems.push(format!("{}: the data channel closed", p.name));
        }
        let sdp = p.pc.local_description().map(|d| d.sdp).unwrap_or_default();
        let (first_tls, first_ufrag) = &outcome.first[i];
        let tls = attribute(&sdp, "tls-id");
        if tls.iter().any(|t| first_tls.contains(t)) {
            problems.push(format!(
                "{}: no new association: {first_tls:?} -> {tls:?}",
                p.name
            ));
        }
        if attribute(&sdp, "ice-ufrag")
            .iter()
            .any(|u| first_ufrag.contains(u))
        {
            problems.push(format!("{}: no ICE restart", p.name));
        }
        // Every DTLS transport became connected once per renewal after the first
        // connection: one new association per transport and renewal, no more.
        let transports = first_tls.len().max(1);
        let connected = p
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnTransportEvent(RTCTransportEvent {
                        event: RTCTransportEventKind::DtlsStateChange(
                            RTCDtlsTransportState::Connected
                        ),
                        ..
                    })
                )
            })
            .count();
        if connected != transports * (renewals + 1) {
            problems.push(format!(
                "{}: {connected} DTLS transports connected, expected {} ({transports} transports, \
                 {renewals} renewals)",
                p.name,
                transports * (renewals + 1)
            ));
        }
        // RFC 8842 section 5.3 with RFC 9429 section 5.7: an answer's tls-id is new, not the
        // one of an offer of this side that was rolled back.
        let offered: HashSet<&String> = p.offered_tls_ids.iter().collect();
        for answered in &p.answered_tls_ids {
            if offered.contains(answered) {
                problems.push(format!(
                    "{}: an answer carries the tls-id {answered} of its own rolled-back offer",
                    p.name
                ));
            }
        }
    }
    if !problems.is_empty() {
        panic!(
            "{}\noffers {:?} ignored {:?} rolled back {:?} unroutable {}\n--- trace ---\n{}",
            problems.join("\n"),
            world.offers,
            world.ignored,
            world.rolled_back,
            world.unroutable,
            world.trace
        );
    }
}

/// `check_call`, and each renewal was one collision: both peers offered once per renewal and
/// no more (a `negotiationneeded` queued at the rollback, while the renewal was still
/// wanted, is not handed out once the answer to the peer's offer has given it: W3C
/// webrtc-pc "Updating the Negotiation-Needed flag": the queued task checks again whether
/// negotiation is needed when it runs).
fn check_glare(outcome: &Outcome, scenario_packets: u16, renewals: usize) {
    check_call(outcome, scenario_packets, renewals);
    let world = &outcome.world;
    assert_eq!(
        (
            world.offers,
            world.ignored_after_connected(),
            world.rolled_back_after_connected()
        ),
        ([renewals; 2], renewals, renewals),
        "one collision per renewal, one offer each\n{}",
        world.trace
    );
}

/// Both peers with the same short lifetime, each asking at the lifetime warning
/// (`with_srtp_rekeying_dtls_client_first(false)`): their offers cross.
fn both_short() -> [SettingEngineBuilder; 2] {
    [0, 0].map(|extra| short(LIFETIME + extra).with_srtp_rekeying_dtls_client_first(false))
}

fn short(packets: u64) -> SettingEngineBuilder {
    SettingEngineBuilder::new().with_srtp_key_lifetime(lifetime(packets))
}

/// Both peers want a re-keying offer in the same step, twice in the call; the polite one
/// (B, the DTLS client) rolls back with an explicit rollback.
#[test]
fn glare_re_keying_polite_dtls_client_explicit_rollback_keeps_the_call() -> Result<()> {
    let scenario = Scenario {
        settings: both_short(),
        polite: 1,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_glare(&outcome, packets, 2);
    Ok(())
}

/// The same with A, the DTLS server, polite.
#[test]
fn glare_re_keying_polite_dtls_server_explicit_rollback_keeps_the_call() -> Result<()> {
    let scenario = Scenario {
        settings: both_short(),
        polite: 0,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_glare(&outcome, packets, 2);
    Ok(())
}

/// The polite peer lets `set_remote_description` roll its offer back (W3C implicit
/// rollback).
#[test]
fn glare_re_keying_implicit_rollback_keeps_the_call() -> Result<()> {
    let scenario = Scenario {
        settings: both_short(),
        polite: 1,
        rollback: Rollback::Implicit,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_glare(&outcome, packets, 2);
    Ok(())
}

/// Staggered: B's warning comes one packet (20 ms) after A's, and its offer leaves before
/// A's arrives (50 ms on the signalling channel): the offers still cross.
#[test]
fn staggered_re_keying_offers_cross_and_the_call_goes_on() -> Result<()> {
    let scenario = Scenario {
        settings: [
            short(LIFETIME).with_srtp_rekeying_dtls_client_first(false),
            short(LIFETIME + 1).with_srtp_rekeying_dtls_client_first(false),
        ],
        polite: 1,
        signal_delay: Duration::from_millis(50),
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_glare(&outcome, packets, 2);
    Ok(())
}

/// Several transports (sections outside a BUNDLE group): each has an association of its own,
/// and each is renewed once per glare.
#[test]
fn glare_re_keying_renews_every_transport_once() -> Result<()> {
    let scenario = Scenario {
        settings: both_short(),
        polite: 1,
        policy: RTCBundlePolicy::MaxCompat,
        tracks: 2,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_glare(&outcome, packets, 2);
    Ok(())
}

/// The default tie-break (`with_srtp_rekeying_dtls_client_first(true)`): with the same
/// lifetime on both sides only the DTLS client of the association (B, which answered the
/// first offer with `a=setup:active`) offers; the server answers it, and no offers cross.
#[test]
fn by_default_only_the_dtls_client_starts_the_re_keying() -> Result<()> {
    let scenario = Scenario {
        settings: [short(LIFETIME), short(LIFETIME)],
        polite: 1,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_call(&outcome, packets, 2);
    let world = &outcome.world;
    assert_eq!(
        (
            world.offers,
            world.ignored_after_connected(),
            world.rolled_back_after_connected()
        ),
        ([0, 2], 0, 0),
        "only B offered, nothing collided\n{}",
        world.trace
    );
    Ok(())
}

/// RFC 5764 section 4.3: "DTLS-SRTP implementations SHOULD store multiple SRTP keys sets
/// during a rekey in order to avoid the need for receivers to drop packets for which they lack
/// a key." The DTLS server of the new association (A) completes its handshake when the
/// client's last flight arrives and protects its next packets with the new keys at once; the
/// path delays DTLS to the client (B) by 50 ms, so B receives those packets before the
/// server's last flight gives it the keys. B holds them and reads them once its handshake
/// completes: every packet arrives.
#[test]
fn packets_under_the_new_keys_before_the_handshake_completes_are_held_not_dropped() -> Result<()> {
    let scenario = Scenario {
        settings: [short(LIFETIME), short(LIFETIME)],
        polite: 1,
        delay_dtls_to: Some((1, Duration::from_millis(50))),
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_call(&outcome, packets, 2);
    Ok(())
}

/// A packet the engine cannot send is counted, not lost unseen: a different RTP packet with a
/// sequence number already sent (its SRTP index protects one packet only, RFC 3711 section
/// 3.3.1) is not sent and `unsent_media_packets` says so.
#[test]
fn a_packet_that_cannot_be_sent_is_counted() -> Result<()> {
    let scenario = Scenario {
        packets: 20,
        ..Default::default()
    };
    let mut outcome = run(scenario)?;
    let before = outcome.world.peers[0].pc.unsent_media_packets();
    let now = outcome.world.now;
    let peer = &mut outcome.world.peers[0];
    let sender = peer.senders[0];
    let ssrc = peer.ssrc;
    peer.pc.rtp_sender(sender).expect("sender").write_rtp(
        now,
        rtci::rtp::Packet {
            header: rtci::rtp::header::Header {
                version: 2,
                payload_type: 111,
                sequence_number: 5,
                timestamp: 5 * 960,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0xF8, 0xFF, 0x00, 0x01]),
        },
    )?;
    while peer.pc.poll_write().is_some() {}
    assert_eq!(peer.pc.unsent_media_packets(), before + 1);
    Ok(())
}

/// ParolNet's relayed call (`turn_rekey::a_relay_only_call_re_keys_on_new_allocations`): only
/// A, the DTLS server, has a short key lifetime, so only A re-keys; B never will. A re-keying
/// takes seconds on this path (1.2 s each way for the offer, the answer and the candidates,
/// like a relayed path). Lifetimes are local, so A cannot know B will not re-key: its wait
/// for B's offer is bounded in time (at most 500 ms, at most an eighth of the time its keys
/// have left) and never takes half the margin, as the wait until a thirty-second of the
/// lifetime did (2 s of margin left there, for a re-keying that needs about 2.5 s: the key ran
/// out and the transport failed). Every packet arrives across the renewal.
#[test]
fn a_dtls_server_alone_with_a_short_lifetime_re_keys_in_time_on_a_slow_path() -> Result<()> {
    let scenario = Scenario {
        settings: [short(3200), SettingEngineBuilder::new()],
        polite: 1,
        signal_delay: Duration::from_millis(1200),
        packets: 3400,
        ..Default::default()
    };
    let packets = scenario.packets;
    let outcome = run(scenario)?;
    check_call(&outcome, packets, 1);
    Ok(())
}
