//! W3C webrtc-priority and RFC 8837: the `priority` / `networkPriority` of encodings and the
//! priority of data channels, and the DSCP `RTCPeerConnection::dscp` gives each datagram the
//! connection writes.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use bytes::Bytes;
use rtc::data_channel::RTCDataChannelInit;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::priority::RTCPriorityType;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::Instant;

const AUDIO_SSRC: u32 = 4242;
const VIDEO_SSRC: u32 = 5353;

/// A datagram written: its first byte, its RTP SSRC if it is RTP, the DSCP it is marked with.
type Mark = (u8, Option<u32>, u8);

fn host(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
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
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    inbox: Vec<TaggedBytesMut>,
    events: Vec<(Instant, RTCPeerConnectionEvent)>,
    rtp: Vec<(Instant, rtc::rtp::Packet)>,
    /// What this peer wrote: (first byte, the RTP SSRC if any, the DSCP to mark it with).
    marked: Vec<Mark>,
}

impl Peer {
    fn new(addr: SocketAddr, role: RTCDtlsRole, now: Instant) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(role)
                    .build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            events: Vec::new(),
            rtp: Vec::new(),
            marked: Vec::new(),
        })
    }

    fn turn(&mut self, now: Instant) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            self.events.push((now, event));
        }
        while let Some(message) = self.pc.poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = message.message {
                self.rtp.push((now, packet));
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            let bytes = &datagram.message;
            let ssrc = (bytes.len() >= 12
                && (128..=191).contains(&bytes[0])
                && !(192..=223).contains(&bytes[1]))
            .then(|| u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]));
            let dscp = self.pc.dscp(&datagram);
            self.marked.push((bytes[0], ssrc, dscp));
            written.push(datagram);
        }
        Ok(written)
    }

    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
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
}

fn track(
    kind: RtpCodecKind,
    ssrc: u32,
    mime: &str,
    clock_rate: u32,
    channels: u16,
) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_owned(),
        format!("{kind}"),
        format!("{kind}"),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: mime.to_owned(),
                clock_rate,
                channels,
                ..Default::default()
            },
            ..Default::default()
        }],
    )
}

fn rtp(ssrc: u32, payload_type: u8, seq: u16) -> rtc::rtp::Packet {
    rtc::rtp::Packet {
        header: rtc::rtp::header::Header {
            version: 2,
            payload_type,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            ..Default::default()
        },
        payload: Bytes::from_static(&[0x10, 0x02, 0x03]),
    }
}

/// W3C webrtc-priority 3.2 and RFC 8837 Table 1: an audio encoding at `high` is marked EF
/// (46); a video encoding whose `networkPriority` is `medium` is marked AF42 (36), whatever its
/// `priority`; the SCTP association carries the highest-priority data channel's codepoint
/// (`high`: AF21, 18) on every DTLS datagram; STUN goes with DF. Over TCP every flow shares
/// the highest codepoint. A `priority` set later with setParameters takes effect.
#[test]
fn datagrams_are_marked_by_their_flows_priority() -> Result<()> {
    let now = Instant::now();
    let mut caller = Peer::new("127.0.0.1:54010".parse()?, RTCDtlsRole::Client, now)?;
    let mut callee = Peer::new("127.0.0.1:54011".parse()?, RTCDtlsRole::Server, now)?;
    let audio = caller.pc.add_track(track(
        RtpCodecKind::Audio,
        AUDIO_SSRC,
        MIME_TYPE_OPUS,
        48000,
        2,
    ))?;
    let video = caller.pc.add_track(track(
        RtpCodecKind::Video,
        VIDEO_SSRC,
        "video/VP8",
        90000,
        0,
    ))?;
    {
        let mut sender = caller.pc.rtp_sender(video).expect("video");
        let mut parameters = sender.get_parameters().clone();
        parameters.encodings[0].priority = RTCPriorityType::VeryLow;
        parameters.encodings[0].network_priority = Some(RTCPriorityType::Medium);
        sender.set_parameters(parameters, None)?;
        let mut sender = caller.pc.rtp_sender(audio).expect("audio");
        let mut parameters = sender.get_parameters().clone();
        assert_eq!(
            parameters.encodings[0].priority,
            RTCPriorityType::Low,
            "low by default"
        );
        parameters.encodings[0].priority = RTCPriorityType::High;
        sender.set_parameters(parameters, None)?;
    }
    caller.pc.create_data_channel(
        "bulk",
        Some(RTCDataChannelInit {
            priority: RTCPriorityType::VeryLow.dcep_priority(),
            ..Default::default()
        }),
    )?;
    let urgent = caller.pc.create_data_channel(
        "urgent",
        Some(RTCDataChannelInit {
            priority: RTCPriorityType::High.dcep_priority(),
            ..Default::default()
        }),
    )?;
    assert_eq!(urgent.priority_type(), RTCPriorityType::High);

    let offer = caller.pc.create_offer(None)?;
    caller.pc.set_local_description(now, offer.clone())?;
    callee.pc.set_remote_description(now, offer)?;
    let answer = callee.pc.create_answer(None)?;
    callee.pc.set_local_description(now, answer.clone())?;
    caller.pc.set_remote_description(now, answer)?;
    let (a, b) = (caller.addr, callee.addr);
    caller.pc.add_local_candidate(host(a)?)?;
    callee.pc.add_local_candidate(host(b)?)?;
    caller.pc.add_remote_candidate(host(b)?)?;
    callee.pc.add_remote_candidate(host(a)?)?;

    let mut now = now;
    let mut sent = 0u16;
    for _ in 0..20_000 {
        let written = caller.turn(now)?;
        callee.deliver(caller.addr, written, now);
        let written = callee.turn(now)?;
        caller.deliver(callee.addr, written, now);
        if caller.pc.connection_state() == RTCPeerConnectionState::Connected && sent < 3 {
            sent += 1;
            caller
                .pc
                .rtp_sender(audio)
                .expect("audio")
                .write_rtp(now, rtp(AUDIO_SSRC, 111, sent))?;
            caller
                .pc
                .rtp_sender(video)
                .expect("video")
                .write_rtp(now, rtp(VIDEO_SSRC, 96, sent))?;
            continue;
        }
        if sent >= 3 && caller.inbox.is_empty() && callee.inbox.is_empty() {
            break;
        }
        if caller.inbox.is_empty() && callee.inbox.is_empty() {
            let next = [caller.pc.poll_timeout(), callee.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            caller.pc.handle_timeout(now)?;
            callee.pc.handle_timeout(now)?;
        }
    }

    let of = |pred: &dyn Fn(&Mark) -> bool| -> Vec<u8> {
        caller
            .marked
            .iter()
            .filter(|m| pred(m))
            .map(|m| m.2)
            .collect()
    };
    let audio_marks = of(&|m| m.1 == Some(AUDIO_SSRC));
    assert!(
        !audio_marks.is_empty() && audio_marks.iter().all(|d| *d == 46),
        "{audio_marks:?}"
    );
    let video_marks = of(&|m| m.1 == Some(VIDEO_SSRC));
    assert!(
        !video_marks.is_empty() && video_marks.iter().all(|d| *d == 36),
        "{video_marks:?}"
    );
    let dtls_marks = of(&|m| (20..=63).contains(&m.0));
    assert!(
        !dtls_marks.is_empty() && dtls_marks.iter().all(|d| *d == 18),
        "{dtls_marks:?}"
    );
    let stun_marks = of(&|m| m.0 <= 3);
    assert!(
        !stun_marks.is_empty() && stun_marks.iter().all(|d| *d == 0),
        "{stun_marks:?}"
    );

    // One TCP connection: every flow shares the highest codepoint (audio at high: EF).
    let tcp = TaggedBytesMut {
        now,
        transport: TransportContext {
            transport_protocol: TransportProtocol::TCP,
            ..Default::default()
        },
        message: bytes::BytesMut::from(&[0u8, 1, 0, 0][..]),
    };
    assert_eq!(caller.pc.dscp(&tcp), 46);

    // A later setParameters takes effect: audio at very-low is Lower Effort (LE, 1, not CS1).
    let mut sender = caller.pc.rtp_sender(audio).expect("audio");
    let mut parameters = sender.get_parameters().clone();
    parameters.encodings[0].priority = RTCPriorityType::VeryLow;
    sender.set_parameters(parameters, None)?;
    let mut packet = bytes::BytesMut::from(&[0x80u8, 111, 0, 9, 0, 0, 0, 0][..]);
    packet.extend_from_slice(&AUDIO_SSRC.to_be_bytes());
    let datagram = TaggedBytesMut {
        now,
        transport: TransportContext::default(),
        message: packet,
    };
    assert_eq!(caller.pc.dscp(&datagram), 1);
    Ok(())
}
