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
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
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
        let mut senders = vec![];
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
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
    let mut world = World::new(RTCBundlePolicy::MaxCompat)?;
    let (senders, offer) = world.negotiate(|sdp| sdp)?;
    assert_eq!(ufrags(&offer).len(), 3, "{offer}");
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
