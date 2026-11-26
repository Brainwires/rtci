//! Video in RED with ULPFEC between two `rtci` peer connections of the `Chrome` behaviour
//! profile, in virtual time, with frames of several packets and a receiving application that
//! puts frames together (`rtci-media`'s `SampleBuilder`).
//!
//! ULPFEC in RED packets of its own takes sequence numbers of the media stream (RFC 2198 with
//! RFC 5109 section 14.2, the form browsers send). Two things keep a frame-assembling receiver
//! whole: the sender places those packets behind the last packet of a frame, never inside one
//! (libwebrtc `ulpfec_generator.cc:134,157-159` at a222406d), and the receiving engine delivers
//! each of them to the application as a packet without a payload, so its sequence number is
//! present and is not a missing media packet (libwebrtc `rtp_video_stream_receiver2.cc:1603-1637`,
//! `NotifyReceiverOfEmptyPacket`).

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media::io::sample_builder::SampleBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::behaviour_profile::BehaviourProfile;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::codec::vp8::Vp8Packet;
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
/// The `Chrome` profile's payload types: VP8, and video `red`.
const VP8_PT: u8 = 96;
const RED_PT: u8 = 116;
/// Media packets in a frame: more than the five a FEC block holds, so blocks close inside it.
const PACKETS_PER_FRAME: u16 = 8;
/// Octets of VP8 payload in a packet, behind the one-octet payload descriptor.
const PAYLOAD: usize = 60;
/// 30 frames a second on the 90 kHz clock.
const FRAME_TICKS: u32 = 3000;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The application's frame assembly: every RTP packet of the video's payload type goes
    /// in, with or without a payload.
    builder: SampleBuilder<Vp8Packet>,
    /// The RTP timestamps of the frames that came out whole, in order, with the media packets
    /// each reports dropped before it (padding left out).
    frames: Vec<(u32, u16)>,
    /// Frames whose data is not what was sent.
    damaged: usize,
    /// Packets without a payload delivered to the application.
    empty_packets: u64,
    /// Whether the builder ever asked for a key frame.
    key_frame_requested: bool,
}

impl Peer {
    /// The `Chrome` behaviour profile's codecs and interceptors, nothing added by hand.
    fn chrome(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Chrome);
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_behaviour_profile(BehaviourProfile::Chrome)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            builder: SampleBuilder::new(256, Vp8Packet::default(), 90_000),
            frames: Vec::new(),
            damaged: 0,
            empty_packets: 0,
            key_frame_requested: false,
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

    /// Every frame the builder has ready.
    fn take_frames(&mut self, now: Instant) {
        while let Some(sample) = self.builder.pop(now) {
            if sample.data[..] != frame_data(sample.packet_timestamp / FRAME_TICKS)[..] {
                self.damaged += 1;
            }
            self.frames.push((
                sample.packet_timestamp,
                sample
                    .prev_dropped_packets
                    .saturating_sub(sample.prev_padding_packets),
            ));
        }
        self.key_frame_requested |= self.builder.take_key_frame_request();
    }
}

/// The VP8 payload of packet `index` of frame `frame`, behind its payload descriptor: the
/// first octet of a frame's first packet is the VP8 payload header with P=1 (an interframe).
fn packet_data(frame: u32, index: u16) -> Vec<u8> {
    let mut data: Vec<u8> = (0..PAYLOAD)
        .map(|octet| (octet as u8) ^ (frame as u8).wrapping_mul(31) ^ (index as u8))
        .collect();
    if index == 0 {
        data[0] |= 0x01;
    }
    data
}

/// The frame as the depacketizer gives it back: every packet's payload behind the descriptor.
fn frame_data(frame: u32) -> Vec<u8> {
    (0..PACKETS_PER_FRAME)
        .flat_map(|index| packet_data(frame, index))
        .collect()
}

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear), or
/// `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Every RED packet the first peer put on the wire: sequence number to (timestamp,
    /// marker). SRTP hides whether its block is media or FEC; the header says where in a
    /// frame it lies.
    wire: BTreeMap<u16, (u32, bool)>,
    /// How many packets of each frame (by timestamp) have crossed the wire, and the frames
    /// whose last media packet (the marker) has: what follows it with the same timestamp is
    /// FEC.
    seen: HashMap<u32, u16>,
    ended: HashSet<u32>,
    /// Lose the second media packet of every fourth frame.
    lossy: bool,
    lost_media: u64,
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
                    && header.payload_type == RED_PT
                {
                    self.wire
                        .insert(header.sequence_number, (header.timestamp, header.marker));
                    if !self.ended.contains(&header.timestamp) {
                        let index = self.seen.entry(header.timestamp).or_insert(0);
                        *index += 1;
                        if header.marker {
                            self.ended.insert(header.timestamp);
                        }
                        if self.lossy && *index == 2 && (header.timestamp / FRAME_TICKS) % 4 == 1 {
                            self.lost_media += 1;
                            continue;
                        }
                    }
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
        let now = self.now;
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a peer's connection failed: {:?}", peer.states);
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                    peer.states.push(state);
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message
                    && packet.header.payload_type == VP8_PT
                {
                    if packet.payload.is_empty() {
                        peer.empty_packets += 1;
                    }
                    peer.builder.push(now, packet);
                }
            }
            peer.take_frames(now);
        }
        Ok(())
    }

    fn run_until(&mut self, until: Instant) -> Result<()> {
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
                // The receiver's own clock: a gap that has waited its bound is given up.
                if let Some(deadline) = peer.builder.poll_timeout() {
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

    fn connected(lossy: bool) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::chrome("10.0.0.1:5000")?,
                Peer::chrome("10.0.0.2:5000")?,
            ],
            now: Instant::now(),
            wire: BTreeMap::new(),
            seen: HashMap::new(),
            ended: HashSet::new(),
            lossy,
            lost_media: 0,
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
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
        world.peers[1].pc.set_remote_description(now, offer)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected: {:?}", world.peers[0].states);
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// Writes frame `frame`: [`PACKETS_PER_FRAME`] VP8 packets, the marker on the last, and
    /// lets a frame interval pass.
    fn send_frame(&mut self, sender: RTCRtpSenderId, frame: u32) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let ssrc = rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        for index in 0..PACKETS_PER_FRAME {
            // RFC 7741 section 4.2: S=1 and PID=0 on the first packet of a frame.
            let mut payload = vec![if index == 0 { 0x10u8 } else { 0x00 }];
            payload.extend(packet_data(frame, index));
            rtp_sender.write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: VP8_PT,
                        sequence_number: 1000 + (frame as u16) * PACKETS_PER_FRAME + index,
                        timestamp: frame * FRAME_TICKS,
                        ssrc,
                        marker: index + 1 == PACKETS_PER_FRAME,
                        ..Default::default()
                    },
                    payload: Bytes::from(payload),
                },
            )?;
        }
        self.pump()?;
        self.run_until(now + Duration::from_millis(33))
    }

    /// For each frame on the wire, in sequence-number order: how many packets up to and
    /// including the one with the marker bit, and how many behind it with the frame's
    /// timestamp (FEC).
    fn frames_on_the_wire(&self) -> Vec<(u32, usize, usize)> {
        let mut frames: Vec<(u32, usize, usize)> = Vec::new();
        let mut ended = false;
        // Sequence numbers do not wrap in these calls (they start at 1000).
        for (timestamp, marker) in self.wire.values() {
            match frames.last_mut() {
                Some((current, media, fec)) if current == timestamp => {
                    if ended {
                        *fec += 1;
                    } else {
                        *media += 1;
                        ended = *marker;
                    }
                }
                _ => {
                    frames.push((*timestamp, 1, 0));
                    ended = *marker;
                }
            }
        }
        frames
    }
}

/// On an open link every frame reaches the application whole and in order, without a wait
/// and without a key-frame request, while FEC is being sent: no FEC packet lies between two
/// packets of a frame on the wire, and each FEC packet reaches the application as a packet
/// without a payload, in its place.
#[test]
fn in_the_chrome_profile_every_frame_is_whole_while_fec_is_sent() -> Result<()> {
    const FRAMES: u32 = 90;
    let (mut world, sender) = World::connected(false)?;
    for frame in 0..FRAMES {
        world.send_frame(sender, frame)?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    let on_the_wire = world.frames_on_the_wire();
    let fec_on_the_wire: usize = on_the_wire.iter().map(|(_, _, fec)| fec).sum();
    assert!(fec_on_the_wire > 0, "FEC was sent: {on_the_wire:?}");
    assert_eq!(FRAMES as usize, on_the_wire.len(), "{on_the_wire:?}");
    assert!(
        on_the_wire
            .iter()
            .all(|(_, media, _)| *media == usize::from(PACKETS_PER_FRAME)),
        "between a frame's first packet and its last there is media only: {on_the_wire:?}"
    );
    let sent = world.peers[0].pc.fec_stats().sent;
    assert_eq!(
        fec_on_the_wire as u64, sent[0].fec_packets_sent,
        "what follows a frame's last packet with its timestamp is its FEC"
    );

    let receiver = &world.peers[1];
    assert_eq!(
        fec_on_the_wire as u64, receiver.empty_packets,
        "each FEC packet reached the application as a packet without a payload"
    );
    // The last frame waits for a successor that says how long it lasts.
    let expected: Vec<(u32, u16)> = (0..FRAMES - 1)
        .map(|frame| (frame * FRAME_TICKS, 0))
        .collect();
    assert_eq!(
        expected, receiver.frames,
        "every frame, in order, nothing dropped before any"
    );
    assert_eq!(0, receiver.damaged, "each frame is what was sent");
    assert_eq!(0, receiver.builder.skipped_gaps(), "no gap was waited out");
    assert!(!receiver.key_frame_requested, "no key frame was asked for");
    Ok(())
}

/// With media lost on the way, FEC rebuilds it and the frames stay whole: the only gaps the
/// receiver ever gives up are media packets that were lost and not rebuilt, never a sequence
/// number that a FEC packet took.
#[test]
fn in_the_chrome_profile_a_gap_is_lost_media_never_a_fec_sequence_number() -> Result<()> {
    const FRAMES: u32 = 150;
    let (mut world, sender) = World::connected(true)?;
    for frame in 0..FRAMES {
        world.send_frame(sender, frame)?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert!(world.lost_media > 0, "the network lost media");
    let on_the_wire = world.frames_on_the_wire();
    assert!(
        on_the_wire
            .iter()
            .all(|(_, media, _)| *media == usize::from(PACKETS_PER_FRAME)),
        "between a frame's first packet and its last there is media only: {on_the_wire:?}"
    );
    let received = world.peers[1].pc.fec_stats().received;
    assert_eq!(received.len(), 1, "{received:?}");
    let rebuilt = received[0].packets_recovered;
    assert!(rebuilt > 0, "FEC rebuilt lost media: {received:?}");

    let receiver = &world.peers[1];
    let not_rebuilt = world.lost_media.saturating_sub(rebuilt);
    assert!(
        receiver.builder.skipped_gaps() <= not_rebuilt,
        "{} gaps given up, {} media packets lost and not rebuilt ({} lost, {rebuilt} rebuilt)",
        receiver.builder.skipped_gaps(),
        not_rebuilt,
        world.lost_media,
    );
    assert!(
        receiver.frames.len() as u64 + not_rebuilt + 1 >= u64::from(FRAMES),
        "{} frames of {FRAMES} came out whole with {not_rebuilt} packets lost for good",
        receiver.frames.len(),
    );
    assert_eq!(
        0, receiver.damaged,
        "each frame that came out is what was sent"
    );
    Ok(())
}
