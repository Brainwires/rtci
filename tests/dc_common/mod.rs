//! Two peer connections exchanging datagrams in memory on a virtual clock, for the data
//! channel and SCTP conformance tests: no socket, no wall-clock wait, the same run every time.

#![allow(dead_code)]

use anyhow::Result;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How far the virtual clock may run before a wait gives up.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// A bound on the turns of one wait, should a timer keep firing without the clock moving.
pub const MAX_TURNS: usize = 20_000;

/// A message a peer's application received: the channel, whether it is a string, its bytes.
pub type Received = (RTCDataChannelId, bool, Vec<u8>);

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    /// Datagrams that reached this peer and that it has not read yet.
    inbox: Vec<TaggedBytesMut>,
    /// Every data channel event this peer raised, in order.
    pub events: Vec<RTCDataChannelEvent>,
    /// Every state the peer connection reported, in order.
    pub connection_states: Vec<RTCPeerConnectionState>,
    /// Every message this peer's application received, in order.
    pub received: Vec<Received>,
    /// While set, every datagram this peer writes is lost on the way.
    pub drop_outgoing: bool,
}

impl Peer {
    pub fn new(addr: SocketAddr, answering_dtls_role: RTCDtlsRole, now: Instant) -> Result<Self> {
        Self::with_setting_engine(
            addr,
            SettingEngineBuilder::new().with_answering_dtls_role(answering_dtls_role),
            now,
        )
    }

    pub fn with_setting_engine(
        addr: SocketAddr,
        setting_engine: SettingEngineBuilder,
        now: Instant,
    ) -> Result<Self> {
        // The default codecs, for the tests that negotiate a media section beside the data.
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(setting_engine.build())
            .with_media_engine(media_engine)
            .build(now)?;
        let host = CandidateHostConfig {
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
        pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            events: Vec::new(),
            connection_states: Vec::new(),
            received: Vec::new(),
            drop_outgoing: false,
        })
    }

    /// One turn: everything that reached this peer, then its events and reads. Returns the
    /// datagrams it wrote.
    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnDataChannel(event) => self.events.push(event),
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    self.connection_states.push(state)
                }
                _ => {}
            }
        }
        while let Some(read) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, message) = read.message {
                self.received
                    .push((id, message.is_string, message.data.to_vec()));
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        if self.drop_outgoing {
            written.clear();
        }
        Ok(written)
    }

    /// Hands this peer the datagrams `from` wrote to it, as its socket would.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            assert_eq!(
                datagram.transport.peer_addr, self.addr,
                "{from} wrote to an address other than its peer's"
            );
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }

    /// Whether the peer connection is `connected`.
    pub fn connected(&self) -> bool {
        self.connection_states.last() == Some(&RTCPeerConnectionState::Connected)
    }

    /// The channels this peer announced open, in order.
    pub fn opened(&self) -> Vec<RTCDataChannelId> {
        self.events
            .iter()
            .filter_map(|event| match event {
                RTCDataChannelEvent::OnOpen(id) => Some(*id),
                _ => None,
            })
            .collect()
    }

    /// Whether this peer announced channel `id` closed.
    pub fn closed(&self, id: RTCDataChannelId) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, RTCDataChannelEvent::OnClose(closed) if *closed == id))
    }

    /// The events this peer raised for channel `id`, in order.
    pub fn events_of(&self, id: RTCDataChannelId) -> Vec<RTCDataChannelEvent> {
        self.events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    RTCDataChannelEvent::OnOpen(of)
                        | RTCDataChannelEvent::OnError(of)
                        | RTCDataChannelEvent::OnClosing(of)
                        | RTCDataChannelEvent::OnClose(of) if *of == id
                )
            })
            .cloned()
            .collect()
    }
}

pub struct Pair {
    pub offerer: Peer,
    pub answerer: Peer,
    pub start: Instant,
    pub now: Instant,
}

impl Pair {
    /// Two peers; `answerer_role` is the DTLS role the answerer takes (the offerer offers
    /// `actpass`), so `Client` makes the offerer the DTLS server.
    pub fn new(answerer_role: RTCDtlsRole) -> Result<Self> {
        let now = Instant::now();
        let offerer_role = match answerer_role {
            RTCDtlsRole::Client => RTCDtlsRole::Server,
            _ => RTCDtlsRole::Client,
        };
        Ok(Self {
            offerer: Peer::new("127.0.0.1:50010".parse()?, offerer_role, now)?,
            answerer: Peer::new("127.0.0.1:50011".parse()?, answerer_role, now)?,
            start: now,
            now,
        })
    }

    /// A pair connected over one data channel, `label`, that the offerer opened. Returns the
    /// offerer's handle of it; the answerer's is its first opened channel.
    pub fn connected(answerer_role: RTCDtlsRole, label: &str) -> Result<(Self, RTCDataChannelId)> {
        let mut pair = Self::new(answerer_role)?;
        let first = pair.offerer.pc.create_data_channel(label, None)?.id();
        pair.negotiate()?;
        assert!(
            pair.run_until(|p| !p.offerer.opened().is_empty() && !p.answerer.opened().is_empty())?,
            "the first channel never opened"
        );
        Ok((pair, first))
    }

    /// A full offer/answer exchange started by the offerer. Returns the offer and the answer.
    pub fn negotiate(&mut self) -> Result<(RTCSessionDescription, RTCSessionDescription)> {
        let offer = self.offerer.pc.create_offer(None)?;
        self.offerer
            .pc
            .set_local_description(self.now, offer.clone())?;
        self.answerer
            .pc
            .set_remote_description(self.now, offer.clone())?;
        let answer = self.answerer.pc.create_answer(None)?;
        self.answerer
            .pc
            .set_local_description(self.now, answer.clone())?;
        self.offerer
            .pc
            .set_remote_description(self.now, answer.clone())?;
        Ok((offer, answer))
    }

    /// Runs both peers, moving the clock to the next timer whenever nothing is in flight,
    /// until `done` holds. Returns whether it came to hold before the deadline.
    pub fn run_until(&mut self, done: impl Fn(&Pair) -> bool) -> Result<bool> {
        let deadline = self.now + DEADLINE;
        let mut turns = 0;
        while !done(self) {
            if self.now >= deadline || turns >= MAX_TURNS {
                return Ok(false);
            }
            turns += 1;
            let written = self.offerer.turn()?;
            self.answerer.deliver(self.offerer.addr, written, self.now);
            let written = self.answerer.turn()?;
            self.offerer.deliver(self.answerer.addr, written, self.now);

            if self.offerer.inbox.is_empty() && self.answerer.inbox.is_empty() && !done(self) {
                let next = [
                    self.offerer.pc.poll_timeout(),
                    self.answerer.pc.poll_timeout(),
                ]
                .into_iter()
                .flatten()
                .min();
                let Some(next) = next else {
                    return Ok(done(self));
                };
                self.now = self.now.max(next);
                self.offerer.pc.handle_timeout(self.now)?;
                self.answerer.pc.handle_timeout(self.now)?;
            }
        }
        Ok(true)
    }

    /// Runs both peers for `span` of virtual time, whatever happens.
    pub fn run_for(&mut self, span: Duration) -> Result<()> {
        let until = self.now + span;
        let mut turns = 0;
        while self.now < until && turns < MAX_TURNS {
            turns += 1;
            let written = self.offerer.turn()?;
            self.answerer.deliver(self.offerer.addr, written, self.now);
            let written = self.answerer.turn()?;
            self.offerer.deliver(self.answerer.addr, written, self.now);

            if self.offerer.inbox.is_empty() && self.answerer.inbox.is_empty() {
                let next = [
                    self.offerer.pc.poll_timeout(),
                    self.answerer.pc.poll_timeout(),
                ]
                .into_iter()
                .flatten()
                .min()
                .map_or(until, |next| next.min(until));
                self.now = self.now.max(next);
                self.offerer.pc.handle_timeout(self.now)?;
                self.answerer.pc.handle_timeout(self.now)?;
            }
        }
        Ok(())
    }
}
