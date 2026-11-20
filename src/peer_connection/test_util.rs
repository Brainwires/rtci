//! Test-only helpers that drive two [`RTCPeerConnection`]s against each other in memory.
//!
//! The peer connection reads no clock and opens no socket, so a pair can be connected without
//! either: every datagram one side queues is handed to the other's `handle_read`, and when
//! neither has anything to send the simulated clock jumps to the earlier of their deadlines.
//! A session that takes seconds of protocol time (ICE checks, the DTLS handshake) runs in
//! milliseconds and the same way every time.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sansio::Protocol;
use shared::error::Result;
use shared::{TaggedBytesMut, TransportContext};

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use crate::peer_connection::state::RTCPeerConnectionState;
use crate::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use crate::rtp_transceiver::{RTCRtpSenderId, SSRC};

/// The address the offering side's host candidate names.
pub(crate) const OFFERER_ADDR: &str = "127.0.0.1:41000";
/// The address the answering side's host candidate names.
pub(crate) const ANSWERER_ADDR: &str = "127.0.0.1:42000";

/// A media engine with the default codecs.
pub(crate) fn default_media_engine() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs register");
    media_engine
}

/// Builds a peer connection that announces one UDP host candidate at `addr`.
pub(crate) fn new_peer(
    media_engine: MediaEngine,
    setting_engine: SettingEngine,
    registry: Option<interceptor::Registry>,
    addr: &str,
) -> Result<RTCPeerConnection> {
    let addr: SocketAddr = addr.parse().expect("test address parses");
    let mut builder = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(setting_engine);
    if let Some(registry) = registry {
        builder = builder.with_interceptor_registry(registry);
    }
    let mut pc = builder.build(Instant::now())?;

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
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
    Ok(pc)
}

/// Builds an offerer and an answerer with the given media engines and no interceptors.
pub(crate) fn new_pair_with(
    offerer_media_engine: MediaEngine,
    answerer_media_engine: MediaEngine,
) -> Result<(RTCPeerConnection, RTCPeerConnection)> {
    let offerer = new_peer(
        offerer_media_engine,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        None,
        OFFERER_ADDR,
    )?;
    let answerer = new_peer(
        answerer_media_engine,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .build(),
        None,
        ANSWERER_ADDR,
    )?;
    Ok((offerer, answerer))
}

/// Builds an offerer and an answerer that both have the default codecs.
pub(crate) fn new_pair() -> Result<(RTCPeerConnection, RTCPeerConnection)> {
    new_pair_with(default_media_engine(), default_media_engine())
}

/// Runs one full offer/answer exchange, `offerer` offering.
pub(crate) fn signal_pair(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> Result<()> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(())
}

/// What one side of a [`Pair`] has surfaced so far.
#[derive(Default)]
pub(crate) struct Observed {
    pub(crate) events: Vec<RTCPeerConnectionEvent>,
    pub(crate) reads: Vec<RTCMessage>,
}

impl Observed {
    pub(crate) fn connected(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(
                event,
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected
                )
            )
        })
    }
}

/// Two peer connections wired back to back over a simulated network.
pub(crate) struct Pair {
    pub(crate) offerer: RTCPeerConnection,
    pub(crate) answerer: RTCPeerConnection,
    pub(crate) offerer_seen: Observed,
    pub(crate) answerer_seen: Observed,
    pub(crate) now: Instant,
    offerer_addr: SocketAddr,
    answerer_addr: SocketAddr,
}

impl Pair {
    /// Wraps two peer connections built by [`new_pair`] / [`new_pair_with`].
    pub(crate) fn new(offerer: RTCPeerConnection, answerer: RTCPeerConnection) -> Self {
        Self {
            offerer,
            answerer,
            offerer_seen: Observed::default(),
            answerer_seen: Observed::default(),
            now: Instant::now(),
            offerer_addr: OFFERER_ADDR.parse().expect("test address parses"),
            answerer_addr: ANSWERER_ADDR.parse().expect("test address parses"),
        }
    }

    /// Moves every queued datagram to the other side and collects what each side surfaced.
    /// Returns whether anything moved.
    fn shuttle(&mut self) -> Result<bool> {
        let mut progressed = false;

        for from_offerer in [true, false] {
            let (from, to, to_addr) = if from_offerer {
                (&mut self.offerer, &mut self.answerer, self.answerer_addr)
            } else {
                (&mut self.answerer, &mut self.offerer, self.offerer_addr)
            };
            while let Some(datagram) = from.poll_write() {
                progressed = true;
                if datagram.transport.peer_addr != to_addr {
                    // Addressed to a candidate this network does not have; dropped, as a real
                    // network would.
                    continue;
                }
                // The receiving side may refuse a datagram (a check it no longer wants); that is
                // the protocol's business, not a failure of the network.
                let _ = to.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: datagram.transport.peer_addr,
                        peer_addr: datagram.transport.local_addr,
                        transport_protocol: datagram.transport.transport_protocol,
                        ecn: datagram.transport.ecn,
                    },
                    message: datagram.message,
                });
            }
        }

        for (pc, seen) in [
            (&mut self.offerer, &mut self.offerer_seen),
            (&mut self.answerer, &mut self.answerer_seen),
        ] {
            while let Some(event) = pc.poll_event() {
                progressed = true;
                seen.events.push(event);
            }
            while let Some(TaggedRTCMessage { message, .. }) = pc.poll_read() {
                progressed = true;
                seen.reads.push(message);
            }
        }

        Ok(progressed)
    }

    /// Drives both sides until `done` holds, or until `limit` of simulated time has passed.
    /// Returns whether `done` held.
    pub(crate) fn run_until(
        &mut self,
        limit: Duration,
        mut done: impl FnMut(&mut Pair) -> bool,
    ) -> Result<bool> {
        let deadline = self.now + limit;
        // A runaway guard: the simulated clock only moves when both sides are idle, so a pair
        // that kept talking forever would otherwise never reach `deadline`.
        for _ in 0..1_000_000 {
            if done(self) {
                return Ok(true);
            }
            if self.shuttle()? {
                continue;
            }
            if self.now >= deadline {
                return Ok(done(self));
            }
            let next = [self.offerer.poll_timeout(), self.answerer.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(deadline)
                .min(deadline);
            // Never stand still: a deadline already due is served at a strictly later instant,
            // so the loop cannot spin on it.
            self.now = next.max(self.now + Duration::from_micros(1));
            self.offerer.handle_timeout(self.now)?;
            self.answerer.handle_timeout(self.now)?;
        }
        Ok(done(self))
    }

    /// Drives both sides until each reports [`RTCPeerConnectionState::Connected`].
    pub(crate) fn connect(&mut self) -> Result<()> {
        let connected = self.run_until(Duration::from_secs(30), |pair| {
            pair.offerer_seen.connected() && pair.answerer_seen.connected()
        })?;
        assert!(
            connected,
            "the pair did not connect; offerer events {:?}, answerer events {:?}",
            self.offerer_seen.events, self.answerer_seen.events
        );
        Ok(())
    }

    /// Closes both sides.
    pub(crate) fn close(&mut self) -> Result<()> {
        self.offerer.close()?;
        self.answerer.close()?;
        Ok(())
    }
}

/// Writes one-byte RTP packets (`marker`) on `ssrc` with `payload_type` until the answerer has
/// read one ending in `marker`; returns that packet.
pub(crate) fn send_until_seen(
    pair: &mut Pair,
    sender_id: RTCRtpSenderId,
    ssrc: SSRC,
    payload_type: u8,
    marker: u8,
    sequence_number: &mut u16,
) -> rtp::Packet {
    for _ in 0..50 {
        *sequence_number = sequence_number.wrapping_add(1);
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type,
                sequence_number: *sequence_number,
                timestamp: u32::from(*sequence_number) * 3000,
                ssrc,
                ..Default::default()
            },
            payload: bytes::Bytes::from(vec![marker]),
        };
        let now = pair.now;
        pair.offerer
            .rtp_sender(sender_id)
            .expect("sender")
            .write_rtp(now, packet)
            .expect("write_rtp");

        let seen = |pair: &mut Pair| {
            pair.answerer_seen.reads.iter().any(
                |m| matches!(m, RTCMessage::RtpPacket(_, p) if p.payload.last() == Some(&marker)),
            )
        };
        if pair
            .run_until(Duration::from_millis(100), seen)
            .expect("drive pair")
        {
            return pair
                .answerer_seen
                .reads
                .iter()
                .rev()
                .find_map(|m| match m {
                    RTCMessage::RtpPacket(_, p) if p.payload.last() == Some(&marker) => {
                        Some(p.clone())
                    }
                    _ => None,
                })
                .expect("seen");
        }
    }
    panic!("no packet ending in {marker:#04x} reached the answerer");
}

/// What a [`RecordingInterceptor`] was told, shared with the test that installed it.
#[derive(Default, Clone)]
pub(crate) struct StreamLog {
    pub(crate) bound_local: std::sync::Arc<std::sync::Mutex<Vec<interceptor::StreamInfo>>>,
    pub(crate) unbound_local: std::sync::Arc<std::sync::Mutex<Vec<interceptor::StreamInfo>>>,
    pub(crate) bound_remote: std::sync::Arc<std::sync::Mutex<Vec<interceptor::StreamInfo>>>,
}

/// A pass-through interceptor that records every stream the peer connection binds and unbinds.
pub(crate) struct RecordingInterceptor {
    log: StreamLog,
    read_queue: std::collections::VecDeque<interceptor::TaggedPacket>,
    write_queue: std::collections::VecDeque<interceptor::TaggedPacket>,
}

impl RecordingInterceptor {
    /// A registry holding only a recorder, and the log it writes to.
    pub(crate) fn registry() -> (interceptor::Registry, StreamLog) {
        let log = StreamLog::default();
        let recorder = RecordingInterceptor {
            log: log.clone(),
            read_queue: Default::default(),
            write_queue: Default::default(),
        };
        (
            interceptor::Registry::new().with(interceptor::Slot::Custom(500), recorder),
            log,
        )
    }
}

impl Protocol<interceptor::TaggedPacket, interceptor::TaggedPacket, ()> for RecordingInterceptor {
    type Rout = interceptor::TaggedPacket;
    type Wout = interceptor::TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: interceptor::TaggedPacket) -> Result<()> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: interceptor::TaggedPacket) -> Result<()> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl interceptor::Interceptor for RecordingInterceptor {
    fn bind_local_stream(&mut self, info: &interceptor::StreamInfo) {
        self.log.bound_local.lock().unwrap().push(info.clone());
    }

    fn unbind_local_stream(&mut self, info: &interceptor::StreamInfo) {
        self.log.unbound_local.lock().unwrap().push(info.clone());
    }

    fn bind_remote_stream(&mut self, info: &interceptor::StreamInfo) {
        self.log.bound_remote.lock().unwrap().push(info.clone());
    }

    fn unbind_remote_stream(&mut self, _info: &interceptor::StreamInfo) {}
}
