//! Two `rtc` peers on an in-memory network and a virtual clock, for the DTLS / SDP tests
//! (`dtls_association_*.rs`, `dtls_fingerprint_*.rs`, `dtls_tls_id.rs`, `dtls_use_srtp.rs`,
//! `security_architecture.rs`). No sockets and no wall clock: a run is deterministic.

#![allow(dead_code)]

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::{RTCConfiguration, RTCConfigurationBuilder};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time a step gets: enough for an ICE check, a DTLS handshake whose flight is
/// retransmitted three times (RFC 6347 section 4.2.4.1: 1 s, doubling, so 1, 3 and 7 seconds
/// in) and an SCTP handshake. ICE consent is answered throughout, so its timeouts do not run.
pub const STEP: Duration = Duration::from_secs(20);

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    /// Every peer connection state it reported, in order.
    pub states: Vec<RTCPeerConnectionState>,
    /// The data channel that opened last.
    pub channel: Option<RTCDataChannelId>,
    /// The data channel messages it received.
    pub received: Vec<Vec<u8>>,
    /// Every datagram it wrote, in order.
    pub written: Vec<Vec<u8>>,
    /// Every event it raised, as its `Debug` form.
    pub events: Vec<String>,
    /// The RTP packets it received, as (payload type, SSRC), in order.
    pub rtp: Vec<(u8, u32)>,
    /// The RTP packets it received, as (the id of the track they were delivered to, header),
    /// in order.
    pub packets: Vec<(String, rtc::rtp::header::Header)>,
}

impl Peer {
    pub fn new(addr: &str, setting_engine: SettingEngine) -> Result<Self> {
        Self::with_configuration(addr, RTCConfigurationBuilder::new().build(), setting_engine)
    }

    pub fn with_configuration(
        addr: &str,
        configuration: RTCConfiguration,
        setting_engine: SettingEngine,
    ) -> Result<Self> {
        // The default codecs, for the tests that negotiate a media section.
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build(Instant::now())?;
        Self::from_connection(addr, pc)
    }

    /// A peer at `addr` around a connection the test built itself.
    pub fn from_connection(addr: &str, pc: RTCPeerConnection) -> Result<Self> {
        Ok(Self {
            pc,
            addr: addr.parse()?,
            states: Vec::new(),
            channel: None,
            received: Vec::new(),
            written: Vec::new(),
            events: Vec::new(),
            rtp: Vec::new(),
            packets: Vec::new(),
        })
    }

    pub fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }

    /// The last connection state it reported is `connected`.
    pub fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
    }

    pub fn failed(&self) -> bool {
        self.states.contains(&RTCPeerConnectionState::Failed)
    }

    /// `RTCTransportStats.dtlsState`.
    pub fn dtls_state(&mut self, now: Instant) -> RTCDtlsTransportState {
        self.pc
            .get_stats(now, StatsSelector::None)
            .transport()
            .map(|transport| transport.dtls_state)
            .unwrap_or_default()
    }

    /// `RTCTransportStats.dtlsRole`: the role of the association whose handshake completed
    /// last.
    pub fn dtls_role(&mut self, now: Instant) -> RTCDtlsRole {
        self.pc
            .get_stats(now, StatsSelector::None)
            .transport()
            .map(|transport| transport.dtls_role)
            .unwrap_or_default()
    }

    /// `RTCTransportStats.srtpCipher`.
    pub fn srtp_cipher(&mut self, now: Instant) -> String {
        self.pc
            .get_stats(now, StatsSelector::None)
            .transport()
            .map(|transport| transport.srtp_cipher.clone())
            .unwrap_or_default()
    }

    /// The DER of the certificate the peer presented in the DTLS handshake.
    pub fn remote_certificate(&self) -> Option<Vec<u8>> {
        self.pc
            .sctp()
            .and_then(|sctp| sctp.transport().get_remote_certificates().first().cloned())
    }
}

/// The values of every `a=<key>:` line of an SDP, in order.
pub fn attribute_values(sdp: &str, key: &str) -> Vec<String> {
    let prefix = format!("a={key}:");
    sdp.lines()
        .filter_map(|line| line.trim_end().strip_prefix(prefix.as_str()))
        .map(str::to_owned)
        .collect()
}

/// The SDP with every line that starts with `prefix` replaced by `replacement` (`None` removes
/// the line), CRLF line ends.
pub fn replace_lines(sdp: &str, prefix: &str, replacement: Option<&str>) -> String {
    let mut out = String::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        if line.starts_with(prefix) {
            if let Some(replacement) = replacement {
                out.push_str(replacement);
                out.push_str("\r\n");
            }
        } else {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out
}

/// The session-level part of an SDP: everything before the first `m=` line.
pub fn session_part(sdp: &str) -> &str {
    &sdp[..sdp.find("\r\nm=").expect("an m= line") + 2]
}

/// The SDP with `line` added at session level (before the first `m=` line).
pub fn with_session_line(sdp: &str, line: &str) -> String {
    let at = session_part(sdp).len();
    format!("{}{line}\r\n{}", &sdp[..at], &sdp[at..])
}

pub fn keep(sdp: &str) -> String {
    sdp.to_owned()
}

pub struct World {
    pub peers: Vec<Peer>,
    pub now: Instant,
    /// Whether datagrams are delivered; `false` cuts the network.
    pub connected: bool,
    /// The datagrams sent to an address no peer has (a STUN server, say): (from, to, data).
    pub undelivered: Vec<(SocketAddr, SocketAddr, BytesMut)>,
}

impl World {
    pub fn new(a: Peer, b: Peer) -> Self {
        Self {
            peers: vec![a, b],
            now: Instant::now(),
            connected: true,
            undelivered: Vec::new(),
        }
    }

    /// Runs both peers until `done`; `false` if `limit` of virtual time passes first.
    pub fn run_for(&mut self, limit: Duration, done: impl Fn(&mut [Peer]) -> bool) -> bool {
        let start = self.now;
        loop {
            let mut in_flight = Vec::new();
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
                    peer.written.push(msg.message.to_vec());
                    in_flight.push((
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            let delivered = !in_flight.is_empty();
            for (from, to, data) in in_flight {
                if !self.connected {
                    continue;
                }
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                    self.undelivered.push((from, to, data));
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
                    peer.events.push(format!("{event:?}"));
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            peer.states.push(state);
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
                        RTCMessage::RtpPacket(track, packet) => {
                            peer.rtp
                                .push((packet.header.payload_type, packet.header.ssrc));
                            peer.packets.push((track, packet.header));
                        }
                        _ => {}
                    }
                }
            }
            if done(&mut self.peers) {
                return true;
            }
            if delivered {
                continue;
            }
            if self.now.duration_since(start) >= limit {
                return false;
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

    /// Runs both peers until `done`, or fails after `STEP` of virtual time.
    pub fn run(&mut self, what: &str, done: impl Fn(&mut [Peer]) -> bool) -> Result<()> {
        if self.run_for(STEP, done) {
            Ok(())
        } else {
            bail!(
                "{what}: not done after {STEP:?} of virtual time (states {:?} / {:?})",
                self.peers[0].states,
                self.peers[1].states
            )
        }
    }

    /// Gives each peer its host candidate and signals it to the other.
    pub fn trickle(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    /// The application's gathering after a new DTLS association: a peer whose ICE transport
    /// holds no local candidate any more (the new association dropped them, RFC 8842 section
    /// 5.1: it runs on a new 3-tuple) moves to the next port and gives that candidate to
    /// itself and to the other peer. A peer that kept its candidates is left alone. Returns
    /// whether any peer moved.
    pub fn regather(&mut self) -> Result<bool> {
        let mut moved = false;
        for i in 0..2 {
            let holds_none = self.peers[i]
                .pc
                .dtls_transports()
                .iter()
                .all(|t| t.ice_transport().get_local_candidates().is_empty());
            if !holds_none {
                continue;
            }
            let addr = self.peers[i].addr;
            self.peers[i].addr = SocketAddr::new(addr.ip(), addr.port() + 1);
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            moved = true;
        }
        Ok(moved)
    }

    /// One offer/answer exchange started by `offerer`; the offer and the answer go through
    /// `munge_offer` / `munge_answer` on their way to the other peer. Returns the offer and the
    /// answer as their authors wrote them.
    pub fn exchange_with(
        &mut self,
        offerer: usize,
        munge_offer: impl Fn(&str) -> String,
        munge_answer: impl Fn(&str) -> String,
    ) -> Result<(String, String)> {
        let answerer = 1 - offerer;
        let now = self.now;
        let offer = self.peers[offerer].pc.create_offer(None)?;
        self.peers[offerer]
            .pc
            .set_local_description(now, offer.clone())?;
        self.peers[answerer]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(munge_offer(&offer.sdp))?)?;
        let answer = self.peers[answerer].pc.create_answer(None)?;
        self.peers[answerer]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[offerer].pc.set_remote_description(
            now,
            RTCSessionDescription::answer(munge_answer(&answer.sdp))?,
        )?;
        Ok((offer.sdp, answer.sdp))
    }

    pub fn exchange(&mut self, offerer: usize) -> Result<(String, String)> {
        self.exchange_with(offerer, keep, keep)
    }

    /// The first exchange (peer 0 offers, with a data channel), the candidates, and the run
    /// until both peers are connected and the channel is open. Returns the offer and answer.
    pub fn connect(&mut self) -> Result<(String, String)> {
        self.peers[0].pc.create_data_channel("data", None)?;
        let descriptions = self.exchange(0)?;
        self.trickle()?;
        self.run("the first connection", |peers| {
            peers.iter().all(|p| p.connected() && p.channel.is_some())
        })?;
        Ok(descriptions)
    }

    /// A message each way over the data channel; both must arrive within `STEP`.
    pub fn ping_pong(&mut self, what: &str) -> Result<()> {
        for from in 0..2 {
            let to = 1 - from;
            let payload = format!("{what} / {from} to {to}").into_bytes();
            let before = self.peers[to].received.len();
            let Some(channel) = self.peers[from].channel else {
                bail!("{what}: peer {from} has no open channel");
            };
            self.peers[from]
                .pc
                .data_channel(channel)
                .expect("the channel")
                .send(self.now, BytesMut::from(&payload[..]))?;
            self.run(&format!("{what}: a message from peer {from}"), |peers| {
                peers[to].received.len() > before
            })?;
            assert_eq!(self.peers[to].received.last(), Some(&payload), "{what}");
        }
        Ok(())
    }
}
