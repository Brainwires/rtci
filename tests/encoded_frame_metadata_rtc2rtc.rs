//! W3C webrtc-encoded-transform 4: the metadata of received encoded frames
//! (`RTCRtpReceiver::encoded_frame_metadata`), rtc to rtc: what the frame's packets say, and
//! what the receiver recorded as they arrived (receive time, capture time, the Dependency
//! Descriptor's frame ids).

#![allow(dead_code)]

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
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
use rtc::rtp::codec::dependency_descriptor::{
    DEPENDENCY_DESCRIPTOR_URI, DecodeTargetIndication, DependencyDescriptorWriter,
    FrameDependencyStructure, FrameDependencyTemplate, RenderResolution,
};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_receiver::{RTCEncodedFrameMetadataKind, RTCEncodedVideoFrameType};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

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
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
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
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
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

/// The sender's SSRC, payload type and the negotiated id of `uri`.
fn sender_stream(world: &mut World, sender: RTCRtpSenderId, uri: &str) -> (u32, u8, u8) {
    let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
    let parameters = sender.get_parameters();
    let id = parameters
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == uri)
        .map(|e| e.id as u8)
        .unwrap_or_else(|| panic!("{uri} is negotiated"));
    (
        parameters.encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC"),
        parameters.rtp_parameters.codecs[0].payload_type,
        id,
    )
}

fn receiver_metadata(
    world: &mut World,
    packets: &[rtc::rtp::Packet],
) -> Result<RTCEncodedFrameMetadataKind, Error> {
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .encoded_frame_metadata(packets)
}

/// The packets the second peer read with RTP timestamp `timestamp`.
fn read_frame(world: &World, timestamp: u32) -> Vec<rtc::rtp::Packet> {
    world.peers[1]
        .read_rtp
        .iter()
        .filter(|p| p.header.timestamp == timestamp)
        .cloned()
        .collect()
}

fn l1t3() -> FrameDependencyStructure {
    let template = |temporal_id, fdiffs: &[u16], chain: u8, dtis: &str| FrameDependencyTemplate {
        spatial_id: 0,
        temporal_id,
        dtis: DecodeTargetIndication::from_symbols(dtis).expect("indications"),
        fdiffs: fdiffs.to_vec(),
        chain_fdiffs: vec![chain],
    };
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 3,
        num_chains: 1,
        decode_target_protected_by: vec![0, 0, 0],
        resolutions: vec![RenderResolution {
            width: 640,
            height: 360,
        }],
        templates: vec![
            template(0, &[], 0, "SSS"),
            template(0, &[4], 4, "SSS"),
            template(1, &[2], 2, "SD-"),
            template(2, &[1], 1, "D--"),
            template(2, &[1], 3, "D--"),
        ],
    }
}

/// A VP8 payload: descriptor (S at the start of the frame), then a key frame header of
/// `size` or a delta frame tag.
fn vp8_payload(start: bool, key: Option<(u16, u16)>) -> Bytes {
    let mut payload = vec![if start { 0x10 } else { 0x00 }];
    match key {
        Some((width, height)) if start => {
            payload.extend([0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a]);
            payload.extend(width.to_le_bytes());
            payload.extend(height.to_le_bytes());
        }
        _ if start => payload.extend([0x11, 0x02, 0x00]),
        _ => {}
    }
    payload.extend([0x55u8; 60]);
    Bytes::from(payload)
}

/// webrtc-encoded-transform 4.1, 4.2, 4.3 over a connection: a VP8 key frame in two packets
/// and a delta frame, with the Dependency Descriptor and `abs-capture-time`. The key frame's
/// metadata has the SSRC, payload type, RTP timestamp, `video/VP8`, its receive time (its
/// last packet's arrival), the capture time and offset, frame id = the descriptor's frame
/// number, no dependencies, the descriptor's layers and resolution and type key; the delta
/// frame (with CSRCs) refers to the key frame's id, keeps the stream's size, reads its CSRCs,
/// an interpolated capture time, and is a delta frame.
#[test]
fn received_video_frames_carry_their_metadata() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, dd_id) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let structure = l1t3();
    let mut writer = DependencyDescriptorWriter::new(structure.clone(), 41)?;
    let key = writer.next_frame(&structure.templates[0], true)?;
    let delta = writer.next_frame(&structure.templates[3], false)?;

    let capture_ntp: u64 = (1000u64 << 32) | (1u64 << 30);
    let offset: i64 = -(1 << 31);
    let packet = |seq: u16, timestamp: u32, marker: bool, dd: Bytes, payload: Bytes| {
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp,
            ssrc,
            marker,
            ..Default::default()
        };
        header
            .set_extension_upgrading(dd_id, dd)
            .expect("an element");
        rtc::rtp::Packet { header, payload }
    };

    let sent_at = world.now;
    let first = packet(
        1,
        90_000,
        false,
        key.packet(true, false)?,
        vp8_payload(true, Some((320, 180))),
    );
    let second = packet(
        2,
        90_000,
        true,
        key.packet(false, true)?,
        vp8_payload(false, None),
    );
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_capture_time(sent_at, first, capture_ntp, Some(offset))?;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(sent_at, second)?;
    world.pump()?;
    world.run_until(sent_at + Duration::from_millis(50))?;

    let mut third = packet(
        3,
        93_000,
        true,
        delta.packet(true, true)?,
        vp8_payload(true, None),
    );
    third.header.csrc = vec![11, 12];
    let delta_sent_at = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(delta_sent_at, third)?;
    world.pump()?;
    world.run_until(delta_sent_at + Duration::from_millis(100))?;

    let key_packets = read_frame(&world, 90_000);
    assert_eq!(key_packets.len(), 2, "the key frame's packets were read");
    let RTCEncodedFrameMetadataKind::Video(key_meta) = receiver_metadata(&mut world, &key_packets)?
    else {
        bail!("a video frame");
    };
    assert_eq!(key_meta.frame.synchronization_source, ssrc);
    assert_eq!(key_meta.frame.payload_type, pt);
    assert_eq!(key_meta.frame.rtp_timestamp, 90_000);
    assert_eq!(key_meta.frame.mime_type.to_ascii_lowercase(), "video/vp8");
    assert!(key_meta.frame.contributing_sources.is_empty());
    let received = key_meta.frame.receive_time.expect("a receive time");
    assert!(received >= sent_at && received <= delta_sent_at);
    assert_eq!(key_meta.frame.capture_time, Some(1_000_250.0));
    assert_eq!(key_meta.frame.sender_capture_time_offset, Some(-500.0));
    assert_eq!(key_meta.frame_type, RTCEncodedVideoFrameType::Key);
    assert_eq!(key_meta.frame_id, Some(41));
    assert!(key_meta.dependencies.is_empty());
    assert_eq!(
        (key_meta.width, key_meta.height),
        (Some(640), Some(360)),
        "the descriptor's resolution"
    );
    assert_eq!(
        (key_meta.spatial_index, key_meta.temporal_index),
        (Some(0), Some(0))
    );

    let delta_packets = read_frame(&world, 93_000);
    let RTCEncodedFrameMetadataKind::Video(delta_meta) =
        receiver_metadata(&mut world, &delta_packets)?
    else {
        bail!("a video frame");
    };
    assert_eq!(delta_meta.frame_type, RTCEncodedVideoFrameType::Delta);
    assert_eq!(delta_meta.frame_id, Some(42));
    assert_eq!(delta_meta.dependencies, vec![41]);
    assert_eq!(delta_meta.temporal_index, Some(2));
    assert_eq!(
        (delta_meta.width, delta_meta.height),
        (Some(640), Some(360))
    );
    assert_eq!(delta_meta.frame.contributing_sources, vec![11, 12]);
    // 3000 ticks at 90 kHz after the stamped frame, the offset kept.
    let interpolated = delta_meta.frame.capture_time.expect("a capture time");
    assert!((interpolated - (1_000_250.0 + 3000.0 / 90.0)).abs() < 1e-6);
    assert_eq!(delta_meta.frame.sender_capture_time_offset, Some(-500.0));
    assert!(delta_meta.frame.receive_time.expect("a receive time") >= delta_sent_at);

    // Not one frame: refused.
    let mixed = [key_packets[0].clone(), delta_packets[0].clone()];
    assert!(matches!(
        receiver_metadata(&mut world, &mixed),
        Err(Error::TypeError(_))
    ));
    assert!(matches!(
        receiver_metadata(&mut world, &[]),
        Err(Error::TypeError(_))
    ));
    Ok(())
}

/// webrtc-encoded-transform 4.4: an audio frame's `sequenceNumber`, and its `audioLevel`
/// converted from the RFC 6464 level of its packet (10^(-level/20), 127 is 0); absent when
/// the packet has no level.
#[test]
fn received_audio_frames_carry_their_sequence_number_and_level() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let (ssrc, pt, level_id) = sender_stream(&mut world, sender, AUDIO_LEVEL);
    let packet = |seq: u16, level: Option<u8>| {
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        if let Some(level) = level {
            header
                .set_extension_upgrading(level_id, Bytes::from(vec![0x80 | level]))
                .expect("an element");
        }
        rtc::rtp::Packet {
            header,
            payload: Bytes::from(vec![0x10u8; 80]),
        }
    };
    for (seq, level) in [(10u16, Some(20u8)), (11, Some(127)), (12, None)] {
        let now = world.now;
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(now, packet(seq, level))?;
        world.pump()?;
        world.run_until(now + Duration::from_millis(30))?;
    }
    let mut levels = Vec::new();
    for seq in [10u32, 11, 12] {
        let frame = read_frame(&world, seq * 960);
        assert_eq!(frame.len(), 1, "packet {seq} was read");
        let RTCEncodedFrameMetadataKind::Audio(meta) = receiver_metadata(&mut world, &frame)?
        else {
            bail!("an audio frame");
        };
        assert_eq!(meta.sequence_number, Some(seq as u16));
        assert_eq!(meta.frame.synchronization_source, ssrc);
        assert!(
            meta.frame
                .mime_type
                .to_ascii_lowercase()
                .starts_with("audio/")
        );
        assert!(meta.frame.receive_time.is_some());
        levels.push(meta.audio_level);
    }
    assert!(
        (levels[0].expect("a level") - 0.1).abs() < 1e-12,
        "10^(-20/20)"
    );
    assert_eq!(levels[1], Some(0.0), "127 is silence");
    assert_eq!(levels[2], None, "no extension, no level");

    // 4.4.1, a locally sourced frame: its source's level, written as the RFC 6464 element
    // (0.5 is 6 dBov), reaches the peer's metadata and its synchronization source with the
    // voice activity flag.
    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_audio_level(now, packet(13, None), 0.5, Some(true))?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(30))?;
    let frame = read_frame(&world, 13 * 960);
    let RTCEncodedFrameMetadataKind::Audio(meta) = receiver_metadata(&mut world, &frame)? else {
        bail!("an audio frame");
    };
    let expected = 10f64.powf(-6.0 / 20.0);
    assert!((meta.audio_level.expect("a level") - expected).abs() < 1e-12);
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    let source = world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_synchronization_sources()
        .find(|s| s.source == ssrc)
        .map(|s| s.voice_activity_flag);
    assert_eq!(source, Some(Some(true)));
    Ok(())
}

fn key_frame_requests(peer: &mut Peer) -> Vec<(RTCRtpSenderId, Option<String>)> {
    std::mem::take(&mut peer.events)
        .into_iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnKeyFrameRequest { sender, rid } => Some((sender, rid)),
            _ => None,
        })
        .collect()
}

fn request_key_frame(world: &mut World) -> Result<bool, Error> {
    let now = world.now;
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .send_key_frame_request(now)
}

/// webrtc-encoded-transform 6.5 "send request key frame" and 6.4 `keyframerequest`: a video
/// receiver that does not receive sends nothing; one that does, a Full Intra Request for the
/// stream,
/// with a sequence number one more per request (RFC 5104 4.3.1.2), which reaches the sender's
/// peer as the FIR and as a key frame request for its sender (no RID: not simulcast).
#[test]
fn a_key_frame_request_reaches_the_sender_as_a_fir_and_an_event() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    // The sending peer's own receiver does not receive (its transceiver is sendonly): the
    // request resolves with nothing sent.
    let now = world.now;
    let own_receiver = world.peers[0]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    assert!(
        !world.peers[0]
            .pc
            .rtp_receiver(own_receiver)
            .expect("receiver")
            .send_key_frame_request(now)?,
        "not receiving"
    );
    world.run_until(world.now + Duration::from_millis(50))?;
    assert!(world.peers[1].read_fir.is_empty());

    let (ssrc, pt, _) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
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
                    sequence_number: 1,
                    timestamp: 1,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: vp8_payload(true, Some((320, 180))),
            },
        )?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(50))?;
    let _ = key_frame_requests(&mut world.peers[0]);

    // RFC 4585 section 3.5.2: after an early RTCP packet the next one waits for the regular
    // RTCP interval, so each request is given time to go out.
    assert!(request_key_frame(&mut world)?);
    world.pump()?;
    world.run_until(world.now + Duration::from_secs(3))?;
    assert!(request_key_frame(&mut world)?);
    world.pump()?;
    world.run_until(world.now + Duration::from_secs(3))?;
    let firs: Vec<(u32, u8)> = world.peers[0]
        .read_fir
        .iter()
        .copied()
        .filter(|(s, _)| *s == ssrc)
        .collect();
    assert_eq!(firs.len(), 2, "two requests: {:?}", world.peers[0].read_fir);
    assert_eq!(
        firs[1].1,
        firs[0].1.wrapping_add(1),
        "a new request, a new number"
    );
    assert_eq!(
        key_frame_requests(&mut world.peers[0]),
        vec![(sender, None), (sender, None)]
    );
    Ok(())
}

/// webrtc-encoded-transform 6.5: on an audio receiver the request is an InvalidStateError.
#[test]
fn an_audio_receiver_cannot_request_a_key_frame() -> Result<()> {
    let (mut world, _) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    assert!(matches!(
        request_key_frame(&mut world),
        Err(Error::InvalidStateError)
    ));
    Ok(())
}

/// webrtc-encoded-transform 4.3.2: "For SVC, each spatial layer is transformed separately".
/// The sender payloads each spatial layer's frame of a VP9 picture on its own
/// (`Vp9Payloader::payload_layer_frame`); the receiver gives each layer's packets their own
/// metadata: the layer's spatial index and the scalability structure's size for that layer,
/// one RTP timestamp for the picture.
#[test]
fn each_spatial_layer_of_an_svc_picture_is_its_own_frame() -> Result<()> {
    use rtc::rtp::codec::vp9::{Vp9FrameInfo, Vp9Packet, Vp9Payloader, Vp9ScalabilityStructure};
    use rtc::rtp::packetizer::Depacketizer;
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, _, _) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let vp9_pt = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        sender
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("video/VP9"))
            .map(|c| c.payload_type)
            .expect("VP9 is negotiated")
    };
    let mut payloader = Vp9Payloader::default();
    payloader.set_scalability_structure(Some(Vp9ScalabilityStructure {
        spatial_layers: 2,
        resolutions: vec![(320, 180), (640, 360)],
        picture_group: vec![],
    }))?;
    let mut payloads = Vec::new();
    for layer in 0..2u8 {
        let info = Vp9FrameInfo {
            spatial_id: layer,
            inter_layer_dependency: layer == 1,
            end_of_picture: layer == 1,
            key_frame: Some(layer == 0),
            inter_picture_predicted: Some(false),
            ..Default::default()
        };
        let frame = Bytes::from(vec![0x80 | layer; 300]);
        for payload in payloader.payload_layer_frame(1200, &frame, &info)? {
            payloads.push(payload);
        }
    }
    let now = world.now;
    let count = payloads.len();
    for (i, payload) in payloads.into_iter().enumerate() {
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: vp9_pt,
                        sequence_number: 100 + i as u16,
                        timestamp: 45_000,
                        ssrc,
                        marker: i + 1 == count,
                        ..Default::default()
                    },
                    payload,
                },
            )?;
    }
    world.pump()?;
    world.run_until(now + Duration::from_millis(50))?;

    let picture = read_frame(&world, 45_000);
    assert_eq!(picture.len(), count, "the picture's packets were read");
    let layer_of = |packet: &rtc::rtp::Packet| {
        let mut descriptor = Vp9Packet::default();
        descriptor
            .depacketize(&packet.payload)
            .expect("a VP9 payload");
        descriptor.sid
    };
    let mut seen = Vec::new();
    for layer in 0..2u8 {
        let packets: Vec<_> = picture
            .iter()
            .filter(|p| layer_of(p) == layer)
            .cloned()
            .collect();
        assert!(!packets.is_empty(), "layer {layer} has packets");
        let RTCEncodedFrameMetadataKind::Video(meta) = receiver_metadata(&mut world, &packets)?
        else {
            bail!("a video frame");
        };
        seen.push((
            meta.spatial_index,
            meta.width,
            meta.height,
            meta.frame.rtp_timestamp,
        ));
    }
    assert_eq!(
        seen,
        vec![
            (Some(0), Some(320), Some(180), 45_000),
            (Some(1), Some(640), Some(360), 45_000),
        ]
    );
    Ok(())
}

/// webrtc-extensions 15 "remote capture timestamp": a received frame's capture time
/// translated to the receiver's clock by the stream's RTCP sender reports (RFC 3550 section
/// 6.4.1). Frames the sender wrote at 30 frame/s for three seconds, with RTP timestamps on
/// the 90 kHz clock that run with the sender's clock: once a sender report has arrived, each
/// frame's remote capture time is the instant it was written (the link has no delay), within
/// a few milliseconds; before the first report there is none.
#[test]
fn a_frames_remote_capture_time_is_on_the_receivers_clock() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, _) = sender_stream(&mut world, sender, rtc::rtp::extension::SDES_MID_URI);
    let start = world.now;
    let base = 90_000u32;
    let mut written = vec![];
    for frame in 0..90u32 {
        let now = world.now;
        let timestamp =
            base.wrapping_add((now.duration_since(start).as_secs_f64() * 90_000.0) as u32);
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
                        sequence_number: 500 + frame as u16,
                        timestamp,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: vp8_payload(true, None),
                },
            )?;
        written.push((timestamp, now));
        world.pump()?;
        world.run_until(now + Duration::from_micros(33_333))?;
    }
    let mut before_report = 0;
    let mut placed = 0;
    for (timestamp, at) in written {
        let packets = read_frame(&world, timestamp);
        if packets.is_empty() {
            continue;
        }
        let RTCEncodedFrameMetadataKind::Video(video) = receiver_metadata(&mut world, &packets)?
        else {
            panic!("a video frame");
        };
        match video.frame.remote_capture_time {
            None => before_report += 1,
            Some(remote) => {
                let error = if remote > at {
                    remote - at
                } else {
                    at - remote
                };
                assert!(
                    error < Duration::from_millis(5),
                    "frame {timestamp}: {error:?} off"
                );
                placed += 1;
            }
        }
    }
    assert!(
        placed > 30,
        "{placed} frames placed, {before_report} before a report"
    );
    Ok(())
}
