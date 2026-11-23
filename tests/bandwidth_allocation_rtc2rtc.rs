//! W3C webrtc 5.2.5 `maxBitrate` and webrtc-priority 3.2 over a connection: the
//! congestion controller's target divided among the senders, frames dropped above an
//! encoding's maximum; and webrtc 5.3 `jitterBufferTarget` reaching the jitter buffer.

#![allow(dead_code)]

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::{
    AdaptiveJitterBufferBuilder, Interceptor, PassThroughInterceptor, Registry, Slot,
};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::cell::Cell;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

thread_local! {
    /// Whether the receiving peer of the next `World` has a jitter buffer.
    static JITTER_BUFFER: Cell<bool> = const { Cell::new(false) };
}

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The RTP packets `poll_read` yielded.
    read_rtp: Vec<rtc::rtp::Packet>,
    /// The FIR entries (SSRC, sequence number) of the RTCP packets `poll_read` yielded.
    read_fir: Vec<(u32, u8)>,
    /// The events other than connection state changes.
    events: Vec<RTCPeerConnectionEvent>,
}

impl Peer {
    fn new(addr: &str, jitter_buffer: bool) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        if jitter_buffer {
            registry = registry.with(
                Slot::JitterBuffer,
                PassThroughInterceptor::new().with(
                    AdaptiveJitterBufferBuilder::new()
                        .with_min_delay(Duration::from_millis(10))
                        .with_max_delay(Duration::from_millis(1000))
                        .with_initial_delay(Duration::from_millis(20))
                        .build(),
                ),
            );
        }
        media_engine.register_header_extension(
            rtc::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability {
                uri: rtc::rtp::extension::ABS_CAPTURE_TIME_URI.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read_rtp: Vec::new(),
            read_fir: Vec::new(),
            events: Vec::new(),
        })
    }

    fn candidate(&self) -> Result<RTCIceCandidateInit> {
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
}

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear, RFC
/// 3711 section 3.1, apart from RFC 6904 elements), or `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The headers of the RTP packets the first peer put on the wire.
    wire: Vec<Header>,
    /// The SSRC `send` writes on.
    media_ssrc: Option<u32>,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((
                        i,
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (i, from, to, data) in in_flight {
                if i == 0
                    && let Some(header) = wire_rtp_header(&data)
                {
                    self.wire.push(header);
                }
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
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
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a peer's connection failed: {:?}", peer.states);
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                    peer.states.push(state);
                } else {
                    peer.events.push(event);
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtpPacket(_, packet) => peer.read_rtp.push(packet),
                    RTCMessage::RtcpPacket(_, packets) => {
                        for packet in packets {
                            if let Some(fir) = packet.as_any().downcast_ref::<
                                rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest,
                            >() {
                                peer.read_fir
                                    .extend(fir.fir.iter().map(|e| (e.ssrc, e.sequence_number)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The headers on the wire of the stream `send` writes (not RTX, FEC or probes).
    fn media_wire(&self) -> Vec<&Header> {
        self.wire
            .iter()
            .filter(|h| Some(h.ssrc) == self.media_ssrc)
            .collect()
    }

    fn run_until(&mut self, until: Instant) -> Result<()> {
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// The first peer sends `kind`; the second answers, its answer passed through `edit`
    /// before the first applies it. Connected over host candidates.
    fn connected(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_edited(kind, |offer| offer, edit)
    }

    /// `connected`, the offer changed by `edit_offer` on its way to the receiver and the
    /// answer by `edit` on its way to the sender.
    fn connected_edited(
        kind: RtpCodecKind,
        edit_offer: impl Fn(String) -> String,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_prepared_edited(kind, edit_offer, edit, |_| {})
    }

    /// [`Self::connected`], each peer passed through `prepare` before the offer.
    fn connected_prepared(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
        prepare: impl Fn(&mut RTCPeerConnection),
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_prepared_edited(kind, |offer| offer, edit, prepare)
    }

    fn connected_prepared_edited(
        kind: RtpCodecKind,
        edit_offer: impl Fn(String) -> String,
        edit: impl Fn(String) -> String,
        prepare: impl Fn(&mut RTCPeerConnection),
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", false)?,
                Peer::new("10.0.0.2:5000", JITTER_BUFFER.with(|j| j.get()))?,
            ],
            now: Instant::now(),
            wire: Vec::new(),
            media_ssrc: None,
        };
        for peer in world.peers.iter_mut() {
            // The tests read the header extensions on the wire: in the clear unless a test
            // asks for Cryptex (whose default policy, "negotiate", would encrypt them).
            peer.pc
                .set_rtp_header_encryption_policy(
                    rtc::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy::Disable,
                )
                .expect("before any description");
            prepare(&mut peer.pc);
        }
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
        let sender = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");

        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(edit_offer(offer.sdp))?)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(edit(answer.sdp))?)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// Writes a packet on the sender's stream with the given header extension elements.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16, elements: &[(u8, &[u8])]) -> Result<()> {
        let now = self.now;
        let (ssrc, pt) = {
            let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
            let parameters = sender.get_parameters();
            (
                parameters.encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
                parameters.rtp_parameters.codecs[0].payload_type,
            )
        };
        self.media_ssrc = Some(ssrc);
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        for (id, value) in elements {
            header.set_extension_upgrading(*id, Bytes::copy_from_slice(value))?;
        }
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
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

fn ssrc_and_pt(world: &mut World, sender: RTCRtpSenderId) -> (u32, u8) {
    let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
    let parameters = sender.get_parameters();
    (
        parameters.encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC"),
        parameters.rtp_parameters.codecs[0].payload_type,
    )
}

fn set_max_bitrate(world: &mut World, sender: RTCRtpSenderId, max_bitrate: u32) -> Result<()> {
    let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
    let mut parameters = sender.get_parameters().clone();
    parameters.encodings[0].max_bitrate = max_bitrate;
    sender.set_parameters(parameters, None)?;
    Ok(())
}

/// Sends `seconds` of 30 frame/s video, two 250-byte packets a frame (about 120 kbit/s), and
/// returns the RTP timestamps of the frames the receiver read with how many packets each.
fn send_video(
    world: &mut World,
    sender: RTCRtpSenderId,
    seconds: u32,
) -> Result<Vec<(u32, usize)>> {
    let (ssrc, pt) = ssrc_and_pt(world, sender);
    let mut seq = 1u16;
    for frame in 0..30 * seconds {
        let now = world.now;
        for part in 0..2 {
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: seq,
                            timestamp: frame * 3000,
                            ssrc,
                            marker: part == 1,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x42u8; 250]),
                    },
                )?;
            seq = seq.wrapping_add(1);
        }
        world.pump()?;
        world.run_until(now + Duration::from_micros(33_333))?;
    }
    world.run_until(world.now + Duration::from_millis(200))?;
    let mut frames: Vec<(u32, usize)> = Vec::new();
    for packet in world.peers[1]
        .read_rtp
        .iter()
        .filter(|p| p.header.ssrc == ssrc)
    {
        match frames
            .iter_mut()
            .find(|(ts, _)| *ts == packet.header.timestamp)
        {
            Some(frame) => frame.1 += 1,
            None => frames.push((packet.header.timestamp, 1)),
        }
    }
    Ok(frames)
}

/// W3C webrtc 5.2.5: with `maxBitrate` 40 kbit/s the sender drops whole frames (never part of
/// one) so that what leaves stays under the maximum; one frame always goes. Without it every
/// frame arrives.
#[test]
fn frames_above_max_bitrate_are_dropped_whole() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let unlimited = send_video(&mut world, sender, 1)?;
    assert_eq!(unlimited.len(), 30, "every frame without a maximum");

    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    set_max_bitrate(&mut world, sender, 40_000)?;
    let limited = send_video(&mut world, sender, 2)?;
    assert!(!limited.is_empty(), "a frame always goes");
    assert!(
        limited.iter().all(|&(_, packets)| packets == 2),
        "frames are dropped whole: {limited:?}"
    );
    // Each packet is 12 + 250 bytes; two seconds at 40 kbit/s is 80 kbit, plus the frame
    // the budget lets start.
    let bits: usize = limited.iter().map(|&(_, packets)| packets * 262 * 8).sum();
    assert!(bits <= 80_000 + 2 * 262 * 8, "{bits} bits in two seconds");
    assert!(
        limited.len() < 60 / 2,
        "most frames were dropped: {}",
        limited.len()
    );
    Ok(())
}

/// W3C webrtc 5.2.5 `maxFramerate`: of a 30 frame/s source the sender lets 10 frames a
/// second go with `maxFramerate` 10, each whole, every third one.
#[test]
fn frames_above_max_framerate_are_dropped_whole() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let mut parameters = sender.get_parameters().clone();
        parameters.encodings[0].max_framerate = Some(10.0);
        sender.set_parameters(parameters, None)?;
    }
    let limited = send_video(&mut world, sender, 1)?;
    assert!(
        limited.iter().all(|&(_, packets)| packets == 2),
        "frames are dropped whole: {limited:?}"
    );
    let timestamps: Vec<u32> = limited.iter().map(|&(ts, _)| ts).collect();
    assert_eq!(
        timestamps,
        (0..10).map(|frame| frame * 9000).collect::<Vec<_>>(),
        "every third frame"
    );
    Ok(())
}

/// W3C webrtc-priority 3.2 / webrtc 5.2.5 with the default interceptors: the congestion
/// controller's target reaches the sender as its share (`target_bitrates`), at most its
/// `maxBitrate`, and the outbound stream's `targetBitrate` statistic reports the same.
#[test]
fn the_congestion_target_reaches_the_sender_capped_at_max_bitrate() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    set_max_bitrate(&mut world, sender, 150_000)?;
    let _ = send_video(&mut world, sender, 2)?;
    let shares = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .target_bitrates();
    let (ssrc, _) = ssrc_and_pt(&mut world, sender);
    assert_eq!(shares.len(), 1, "one encoding, one share: {shares:?}");
    assert_eq!(shares[0].0, ssrc);
    assert!(shares[0].1 > 0.0 && shares[0].1 <= 150_000.0, "{shares:?}");
    let report = world.peers[0]
        .pc
        .get_stats(world.now, rtc::statistics::StatsSelector::None);
    let target = report
        .outbound_rtp_streams()
        .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
        .and_then(|s| s.target_bitrate);
    assert_eq!(target, Some(shares[0].1));
    Ok(())
}

/// W3C webrtc 5.3 jitterBufferTarget: the receiver's target reaches the jitter buffer of
/// its chain, which holds the stream's packets for it (here 300 ms against a 20 ms adaptive
/// start), and `None` gives the adaptive delay back.
#[test]
fn the_jitter_buffer_target_holds_the_receivers_packets() -> Result<()> {
    JITTER_BUFFER.with(|j| j.set(true));
    let result = (|| -> Result<()> {
        let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
        let (ssrc, pt) = ssrc_and_pt(&mut world, sender);
        let receiver = world.peers[1]
            .pc
            .get_receivers()
            .next()
            .expect("a receiver");
        let send_one = |world: &mut World, seq: u16| -> Result<Instant> {
            let now = world.now;
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: seq,
                            timestamp: u32::from(seq) * 90_000,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x42u8; 100]),
                    },
                )?;
            world.pump()?;
            Ok(now)
        };
        let read = |world: &World, seq: u16| {
            world.peers[1]
                .read_rtp
                .iter()
                .any(|p| p.header.ssrc == ssrc && p.header.sequence_number == seq)
        };

        world.peers[1]
            .pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .set_jitter_buffer_target(Some(Duration::from_millis(300)))?;
        let sent = send_one(&mut world, 1)?;
        world.run_until(sent + Duration::from_millis(250))?;
        assert!(!read(&world, 1), "held for the target");
        world.run_until(sent + Duration::from_millis(400))?;
        assert!(read(&world, 1), "released after it");

        world.peers[1]
            .pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .set_jitter_buffer_target(None)?;
        world.run_until(world.now + Duration::from_secs(1))?;
        let sent = send_one(&mut world, 2)?;
        world.run_until(sent + Duration::from_millis(100))?;
        assert!(read(&world, 2), "the adaptive delay again");
        Ok(())
    })();
    JITTER_BUFFER.with(|j| j.set(false));
    result
}
