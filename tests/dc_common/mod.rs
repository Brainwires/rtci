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
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
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
    /// The size of every datagram this peer wrote, in order (lost ones included).
    pub written_sizes: Vec<usize>,
    /// The address every datagram this peer wrote went to, in the order of `written_sizes`.
    pub written_to: Vec<SocketAddr>,
    /// The first byte of every datagram this peer wrote, in the same order: a STUN message's,
    /// or the content type of the first DTLS record in it (RFC 7983 section 7).
    pub written_first_bytes: Vec<u8>,
    /// Whether a datagram the peer connection refuses is passed over instead of failing the
    /// run: while a DTLS association is being replaced, records of the old one still arrive.
    pub tolerate_read_errors: bool,
    /// The largest datagram that reaches this peer; larger ones are lost on the way, as on
    /// a path with that MTU and the DF bit set. `None`: any size arrives.
    pub max_datagram: Option<usize>,
    /// The addresses this peer had before [`Peer::move_to`].
    earlier_addrs: Vec<SocketAddr>,
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
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(setting_engine.build())
            .with_media_engine(media_engine)
            .build(now)?;
        let mut peer = Self {
            pc,
            addr,
            inbox: Vec::new(),
            events: Vec::new(),
            connection_states: Vec::new(),
            received: Vec::new(),
            drop_outgoing: false,
            written_sizes: Vec::new(),
            written_to: Vec::new(),
            written_first_bytes: Vec::new(),
            tolerate_read_errors: false,
            max_datagram: None,
            earlier_addrs: Vec::new(),
        };
        let candidate = peer.candidate()?;
        peer.pc.add_local_candidate(candidate)?;
        Ok(peer)
    }

    /// This peer's host candidate, as it is signalled.
    pub fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let host = CandidateHostConfig {
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
        Ok(RTCIceCandidate::from(&host).to_json()?)
    }

    /// One turn: everything that reached this peer, then its events and reads. Returns the
    /// datagrams it wrote.
    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            let read = self.pc.handle_read(datagram);
            if !self.tolerate_read_errors {
                read?;
            }
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
            self.written_sizes.push(datagram.message.len());
            self.written_to.push(datagram.transport.peer_addr);
            self.written_first_bytes
                .push(datagram.message.first().copied().unwrap_or(0));
            written.push(datagram);
        }
        if self.drop_outgoing {
            written.clear();
        }
        Ok(written)
    }

    /// Hands this peer the datagrams `from` wrote to it, as its sockets would: each arrives
    /// at the address it was written to, from the address it was written from.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            if self
                .max_datagram
                .is_some_and(|max| datagram.message.len() > max)
            {
                continue;
            }
            let to = datagram.transport.peer_addr;
            assert!(
                to == self.addr || self.earlier_addrs.contains(&to),
                "{from} wrote to {to}, an address its peer never had"
            );
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: datagram.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }

    /// Moves this peer to `addr`: its next candidate is there. What is still written to the
    /// address it had arrives there, as on a host that keeps both interfaces.
    pub fn move_to(&mut self, addr: SocketAddr) {
        self.earlier_addrs.push(self.addr);
        self.addr = addr;
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

    /// A pair of the two given peers, built at `now`.
    pub fn of(offerer: Peer, answerer: Peer, now: Instant) -> Self {
        Self {
            offerer,
            answerer,
            start: now,
            now,
        }
    }

    /// Two peers at `offerer_addr` and `answerer_addr`, built from the given setting engines.
    pub fn with_setting_engines(
        offerer_addr: &str,
        offerer: SettingEngineBuilder,
        answerer_addr: &str,
        answerer: SettingEngineBuilder,
    ) -> Result<Self> {
        let now = Instant::now();
        Ok(Self::of(
            Peer::with_setting_engine(offerer_addr.parse()?, offerer, now)?,
            Peer::with_setting_engine(answerer_addr.parse()?, answerer, now)?,
            now,
        ))
    }

    /// Opens `label` from the offerer, negotiates and runs until it is open on both sides.
    /// Returns the offerer's handle of it; the answerer's is its last opened channel.
    pub fn open_channel(&mut self, label: &str) -> Result<RTCDataChannelId> {
        let before = self.answerer.opened().len();
        let id = self.offerer.pc.create_data_channel(label, None)?.id();
        self.negotiate()?;
        anyhow::ensure!(
            self.run_until(
                |p| p.offerer.opened().contains(&id) && p.answerer.opened().len() > before
            )?,
            "channel {label} never opened"
        );
        Ok(id)
    }

    /// Gives each peer its host candidate again and signals it to the other: after an ICE
    /// restart the candidates of the new generation are trickled.
    pub fn trickle(&mut self) -> Result<()> {
        let offerer = self.offerer.candidate()?;
        let answerer = self.answerer.candidate()?;
        self.offerer.pc.add_local_candidate(offerer.clone())?;
        self.answerer.pc.add_remote_candidate(offerer)?;
        self.answerer.pc.add_local_candidate(answerer.clone())?;
        self.offerer.pc.add_remote_candidate(answerer)?;
        Ok(())
    }

    /// An offer/answer exchange started by the offerer, or by the answerer when
    /// `from_answerer`; the offer goes through `munge_offer` and the answer through
    /// `munge_answer` on their way to the other peer. Returns the offer and the answer as
    /// their authors wrote them.
    pub fn exchange_with(
        &mut self,
        from_answerer: bool,
        munge_offer: impl Fn(&str) -> String,
        munge_answer: impl Fn(&str) -> String,
    ) -> Result<(String, String)> {
        let now = self.now;
        let (first, second) = if from_answerer {
            (&mut self.answerer, &mut self.offerer)
        } else {
            (&mut self.offerer, &mut self.answerer)
        };
        let offer = first.pc.create_offer(None)?;
        first.pc.set_local_description(now, offer.clone())?;
        second
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(munge_offer(&offer.sdp))?)?;
        let answer = second.pc.create_answer(None)?;
        second.pc.set_local_description(now, answer.clone())?;
        first.pc.set_remote_description(
            now,
            RTCSessionDescription::answer(munge_answer(&answer.sdp))?,
        )?;
        Ok((offer.sdp, answer.sdp))
    }

    /// Sends `payload` as a binary message on the offerer's channel `from` and waits for it
    /// on the answerer, or the other way round when `from_answerer`. Returns whether it
    /// arrived before the deadline.
    pub fn deliver(
        &mut self,
        from_answerer: bool,
        channel: RTCDataChannelId,
        payload: &[u8],
    ) -> Result<bool> {
        let now = self.now;
        let (sender, before) = if from_answerer {
            (&mut self.answerer, self.offerer.received.len())
        } else {
            (&mut self.offerer, self.answerer.received.len())
        };
        sender
            .pc
            .data_channel(channel)
            .ok_or_else(|| anyhow::anyhow!("no such channel"))?
            .send(now, bytes::BytesMut::from(payload))?;
        let arrived = self.run_until(|p| {
            let receiver = if from_answerer {
                &p.offerer
            } else {
                &p.answerer
            };
            receiver.received.len() > before
        })?;
        let receiver = if from_answerer {
            &self.offerer
        } else {
            &self.answerer
        };
        Ok(arrived
            && receiver
                .received
                .last()
                .is_some_and(|(_, _, data)| data == payload))
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
