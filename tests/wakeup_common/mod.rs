//! A driver that runs peer connections in the order the crate's event loop has
//! (`poll_write`, `poll_event`, `poll_read`, then `poll_timeout` and sleep, `src/lib.rs`), on
//! a virtual clock, and checks at every sleep the invariant that order relies on: **when
//! `poll_write` has something, `poll_timeout` is not later than now**. A datagram that only
//! appears after the driver's `poll_write` (made while it served `poll_event` or `poll_read`)
//! would otherwise wait for whatever wakes the driver next: a timer, possibly seconds away, or
//! the next datagram.
//!
//! Used by `tests/driver_wakeup_rtc2rtc.rs`; [`Loop::late`] lists every datagram that was
//! waiting when the driver was told it could sleep.

#![allow(dead_code)]

use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    pub states: Vec<RTCPeerConnectionState>,
    pub channel: Option<rtci::data_channel::RTCDataChannelId>,
    pub received: usize,
    pub rtp: usize,
}

impl Peer {
    pub fn new(addr: &str, pc: RTCPeerConnection) -> Self {
        Self {
            pc,
            addr: addr.parse().expect("an address"),
            states: Vec::new(),
            channel: None,
            received: 0,
            rtp: 0,
        }
    }

    pub fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
    }
}

/// A datagram that was waiting in `poll_write` when `poll_timeout` said to sleep.
#[derive(Debug, Clone)]
pub struct Late {
    /// Which peer.
    pub peer: usize,
    /// The virtual time, from the start.
    pub at: Duration,
    /// What it is: STUN, DTLS (with its content type), RTP or RTCP.
    pub kind: String,
    /// What `poll_timeout` said instead (from the start), `None` for no deadline.
    pub timeout: Option<Duration>,
}

/// The kind of a datagram, from its first bytes (RFC 7983 section 7).
pub fn kind(data: &[u8]) -> String {
    match data.first() {
        Some(0..=3) => "STUN".to_owned(),
        Some(20) => "DTLS change_cipher_spec".to_owned(),
        Some(21) => "DTLS alert".to_owned(),
        Some(22) => "DTLS handshake".to_owned(),
        Some(23) => "DTLS application data (SCTP)".to_owned(),
        Some(24..=63) => "DTLS".to_owned(),
        Some(128..=191) if data.len() > 1 && (192..=223).contains(&data[1]) => "RTCP".to_owned(),
        Some(128..=191) => "RTP".to_owned(),
        _ => "other".to_owned(),
    }
}

pub struct Loop {
    pub peers: Vec<Peer>,
    pub start: Instant,
    pub now: Instant,
    pub late: Vec<Late>,
}

impl Loop {
    pub fn new(peers: Vec<Peer>, start: Instant) -> Self {
        Self {
            peers,
            start,
            now: start,
            late: Vec::new(),
        }
    }

    /// One pass of the event loop for every peer, then the datagrams are delivered. Returns
    /// whether any datagram was written.
    fn pass(&mut self) -> bool {
        let mut in_flight: Vec<(SocketAddr, SocketAddr, bytes::BytesMut)> = Vec::new();
        for (index, peer) in self.peers.iter_mut().enumerate() {
            // 1. poll_write
            while let Some(msg) = peer.pc.poll_write() {
                in_flight.push((
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    msg.message,
                ));
            }
            // 2. poll_event
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        peer.states.push(state)
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        peer.channel = Some(id)
                    }
                    _ => {}
                }
            }
            // 3. poll_read
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::DataChannelMessage(..) => peer.received += 1,
                    RTCMessage::RtpPacket(..) => peer.rtp += 1,
                    _ => {}
                }
            }
            // 4. poll_timeout: the driver would sleep until it. Whatever poll_write has now
            // waits that long.
            let timeout = peer.pc.poll_timeout();
            while let Some(msg) = peer.pc.poll_write() {
                if timeout.is_none_or(|t| t > self.now) {
                    self.late.push(Late {
                        peer: index,
                        at: self.now.saturating_duration_since(self.start),
                        kind: kind(&msg.message),
                        timeout: timeout.map(|t| t.saturating_duration_since(self.start)),
                    });
                }
                in_flight.push((
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    msg.message,
                ));
            }
        }
        let wrote = !in_flight.is_empty();
        for (from, to, data) in in_flight {
            if let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) {
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
        }
        wrote
    }

    /// Runs until `done` or for `limit` of virtual time; `true` if `done`.
    pub fn run_for(&mut self, limit: Duration, done: impl Fn(&[Peer]) -> bool) -> bool {
        let end = self.now + limit;
        loop {
            let wrote = self.pass();
            if done(&self.peers) {
                return true;
            }
            if wrote {
                continue;
            }
            if self.now >= end {
                return false;
            }
            let next = self
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(self.now + Duration::from_millis(50))
                .min(end);
            // A deadline at or before now is handled now (the event loop's "immediate
            // timeout"); time still moves on by at least a microsecond so a deadline that does
            // not advance ends the run instead of hanging it.
            self.now = next.max(self.now + Duration::from_micros(1));
            for peer in self.peers.iter_mut() {
                let _ = peer.pc.handle_timeout(self.now);
            }
        }
    }
}
