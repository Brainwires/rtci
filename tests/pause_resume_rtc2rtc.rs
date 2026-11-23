//! RTP stream pause and resume (RFC 7728) between two `rtc` peers, in virtual time: the offer
//! and answer negotiate `a=rtcp-fb:<pt> ccm pause` (section 9), the receiver asks the sender to
//! pause a stream and to resume it, and the sender's media stops and starts again on the wire.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::{
    PauseResumeBuilder, PauseResumeHandle, PauseState, Registry, RemotePauseState,
};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_pause_resume, configure_pause_resume_with, configure_rtcp_reports,
};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;

/// How a peer negotiates pause: not at all, the default line, or with `nowait`.
#[derive(Clone, Copy, PartialEq)]
enum Pause {
    Off,
    On,
    NoWait,
}

struct Peer {
    pc: RTCPeerConnection,
    handle: Option<PauseResumeHandle>,
    addr: SocketAddr,
    connected: bool,
    /// The sequence numbers of the RTP packets delivered to the application.
    received: Vec<u16>,
}

impl Peer {
    fn new(addr: &str, pause: Pause) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        let registry = configure_rtcp_reports(Registry::new());
        let (registry, handle) = match pause {
            Pause::Off => (registry, None),
            Pause::On => {
                let (registry, handle) = configure_pause_resume(registry, &mut media_engine);
                (registry, Some(handle))
            }
            Pause::NoWait => {
                let (registry, handle) = configure_pause_resume_with(
                    registry,
                    &mut media_engine,
                    PauseResumeBuilder::new(),
                    true,
                );
                (registry, Some(handle))
            }
        };
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            handle,
            addr: addr.parse()?,
            connected: false,
            received: vec![],
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

/// The SSRC and sequence number of an SRTP packet on the wire (its RTP header is in the clear).
fn wire_rtp(datagram: &[u8]) -> Option<(u32, u16)> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[2], datagram[3]]);
    let ssrc = u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]);
    Some((ssrc, seq))
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    sender: RTCRtpSenderId,
    ssrc: u32,
    next_seq: u16,
    /// The sequence numbers of the sender's media on the wire.
    on_the_wire: Vec<u16>,
    offer: String,
    answer: String,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((i, msg.transport, msg.message));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (i, transport, data) in in_flight {
                if i == 0
                    && let Some((ssrc, seq)) = wire_rtp(&data)
                    && ssrc == self.ssrc
                {
                    self.on_the_wire.push(seq);
                }
                let now = self.now;
                if let Some(peer) = self
                    .peers
                    .iter_mut()
                    .find(|p| p.addr == transport.peer_addr)
                {
                    let _ = peer.pc.handle_read(TaggedBytesMut {
                        now,
                        transport: TransportContext {
                            local_addr: transport.peer_addr,
                            peer_addr: transport.local_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: data,
                    });
                }
            }
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a connection failed");
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.received.push(packet.header.sequence_number);
                }
            }
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
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// The offerer sends video to the answerer; both connected.
    fn connected(offerer: Pause, answerer: Pause) -> Result<Self> {
        let mut peers = [
            Peer::new("10.0.0.1:5000", offerer)?,
            Peer::new("10.0.0.2:5000", answerer)?,
        ];
        let transceiver = peers[0].pc.add_transceiver_from_kind(
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
        let sender = peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sender");
        let now = Instant::now();
        let offer = peers[0].pc.create_offer(None)?;
        peers[0].pc.set_local_description(now, offer.clone())?;
        peers[1].pc.set_remote_description(now, offer.clone())?;
        let answer = peers[1].pc.create_answer(None)?;
        peers[1].pc.set_local_description(now, answer.clone())?;
        peers[0].pc.set_remote_description(now, answer.clone())?;
        let mut world = World {
            peers,
            now,
            sender,
            ssrc: 0,
            next_seq: 5000,
            on_the_wire: vec![],
            offer: offer.sdp,
            answer: answer.sdp,
        };
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected");
            }
            let until = world.now + Duration::from_millis(20);
            world.run_until(until)?;
        }
        let mut handle = world.peers[0].pc.rtp_sender(sender).expect("sender");
        world.ssrc = handle.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        Ok(world)
    }

    /// The application writes `count` packets, 20 ms apart.
    fn send(&mut self, count: u16) -> Result<()> {
        for _ in 0..count {
            let now = self.now;
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            self.peers[0]
                .pc
                .rtp_sender(self.sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: rtc::rtp::header::Header {
                            version: 2,
                            payload_type: VP8_PT,
                            sequence_number: seq,
                            timestamp: u32::from(seq) * 1800,
                            ssrc: self.ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 100]),
                    },
                )?;
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }

    fn handle(&self, peer: usize) -> &PauseResumeHandle {
        self.peers[peer].handle.as_ref().expect("pause configured")
    }
}

fn pause_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|l| l.starts_with("a=rtcp-fb:") && l.contains(" ccm pause"))
        .collect()
}

/// Section 9: the offer carries `ccm pause` for its formats; an answerer that implements it
/// answers it, one that does not leaves it out, and only then can the stream be paused.
#[test]
fn ccm_pause_is_offered_and_answered() -> Result<()> {
    let world = World::connected(Pause::On, Pause::On)?;
    assert_eq!(pause_lines(&world.offer), vec!["a=rtcp-fb:96 ccm pause"]);
    assert_eq!(pause_lines(&world.answer), vec!["a=rtcp-fb:96 ccm pause"]);

    let without = World::connected(Pause::On, Pause::Off)?;
    assert!(
        pause_lines(&without.answer).is_empty(),
        "{}",
        without.answer
    );
    assert_eq!(
        without.handle(0).state(without.ssrc),
        None,
        "not negotiated"
    );
    Ok(())
}

/// Sections 6 and 8 end to end: the receiver's PAUSE pauses the stream after the hold-off
/// period (1 s: twice the 500 ms default round trip), no media crosses the wire while it is
/// paused though the application keeps writing, the receiver learns from PAUSED; its RESUME
/// plays the stream again, and the packets on the wire go on from the sequence number after
/// the last one sent.
#[test]
fn the_receiver_pauses_and_resumes_the_senders_stream() -> Result<()> {
    let mut world = World::connected(Pause::On, Pause::On)?;
    world.send(10)?;
    assert_eq!(world.on_the_wire.len(), 10);
    let ssrc = world.ssrc;
    world.handle(1).pause(ssrc);
    world.send(25)?;
    assert_eq!(world.handle(0).state(ssrc), Some(PauseState::Paused));
    assert_eq!(
        world.handle(1).remote_state(ssrc),
        Some(RemotePauseState::Paused)
    );
    let before_pause = world.on_the_wire.len();
    assert!(
        (58..=63).contains(&before_pause),
        "media flows during the 1 s hold-off, about 50 packets: {before_pause}"
    );
    world.send(20)?;
    assert_eq!(
        world.on_the_wire.len(),
        before_pause,
        "paused: nothing sent"
    );

    world.handle(1).resume(ssrc);
    world.send(10)?;
    assert_eq!(world.handle(0).state(ssrc), Some(PauseState::Playing));
    assert_eq!(
        world.handle(1).remote_state(ssrc),
        Some(RemotePauseState::Playing)
    );
    let wire = &world.on_the_wire;
    assert!(wire.len() > before_pause, "playing again");
    for pair in wire.windows(2) {
        assert_eq!(pair[1], pair[0].wrapping_add(1), "no gap: {wire:?}");
    }
    let received = &world.peers[1].received;
    assert_eq!(received.len(), wire.len(), "every packet sent arrives");
    Ok(())
}

/// Section 6.2 with `nowait` offered and answered: the stream pauses without a hold-off.
#[test]
fn with_nowait_negotiated_the_stream_pauses_at_once() -> Result<()> {
    let mut world = World::connected(Pause::NoWait, Pause::NoWait)?;
    assert_eq!(
        pause_lines(&world.answer),
        vec!["a=rtcp-fb:96 ccm pause nowait"]
    );
    world.send(5)?;
    let ssrc = world.ssrc;
    world.handle(1).pause(ssrc);
    world.send(3)?;
    assert_eq!(world.handle(0).state(ssrc), Some(PauseState::Paused));
    assert!(world.on_the_wire.len() <= 6, "{:?}", world.on_the_wire);
    Ok(())
}

/// Section 9.1: "The answerer MUST NOT add "nowait" on the "pause" line in the answer unless
/// it is present on the "pause" line in the offer": an answerer that would offer it answers
/// an offer without it without it, and the hold-off period applies.
#[test]
fn nowait_is_answered_only_when_offered() -> Result<()> {
    let mut world = World::connected(Pause::On, Pause::NoWait)?;
    assert_eq!(pause_lines(&world.answer), vec!["a=rtcp-fb:96 ccm pause"]);
    world.send(5)?;
    let ssrc = world.ssrc;
    world.handle(1).pause(ssrc);
    world.send(5)?;
    assert_eq!(world.handle(0).state(ssrc), Some(PauseState::Pausing));
    Ok(())
}

/// Section 6.4 end to end: the sender pauses its own stream; the receiver learns it from the
/// unsolicited PAUSED, and the stream plays again when the sender ends the pause.
#[test]
fn a_local_pause_reaches_the_receiver() -> Result<()> {
    let mut world = World::connected(Pause::On, Pause::On)?;
    world.send(5)?;
    let ssrc = world.ssrc;
    world.handle(0).local_pause(ssrc);
    world.send(5)?;
    assert_eq!(world.handle(0).state(ssrc), Some(PauseState::LocalPaused));
    assert_eq!(
        world.handle(1).remote_state(ssrc),
        Some(RemotePauseState::Paused)
    );
    assert_eq!(world.on_the_wire.len(), 5);
    world.handle(0).local_resume(ssrc);
    world.send(5)?;
    assert_eq!(world.on_the_wire.len(), 10);
    assert_eq!(
        world.handle(1).remote_state(ssrc),
        Some(RemotePauseState::Playing)
    );
    Ok(())
}

/// RFC 8853 section 5.2: `~` (a stream initially paused) "MUST" go with RFC 7728 signalled for
/// the section. An offer that carries `ccm pause` writes `~` for an inactive simulcast
/// encoding; one without it does not (unless `with_rid_pause_marks`).
#[test]
fn an_inactive_simulcast_encoding_is_marked_paused_when_pause_is_offered() -> Result<()> {
    use rtc::media_stream::MediaStreamTrack;
    use rtc::rtp_transceiver::rtp_sender::RTCRtpCodingParameters;
    for pause in [Pause::Off, Pause::On] {
        let mut peer = Peer::new("10.0.0.1:5000", pause)?;
        let encodings = ["f", "h"]
            .into_iter()
            .enumerate()
            .map(|(i, rid)| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: rid.to_owned(),
                    ssrc: Some(0x0707_0100 + i as u32),
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect();
        let sender = peer.pc.add_track(MediaStreamTrack::new(
            "stream".to_owned(),
            "simulcast".to_owned(),
            "simulcast".to_owned(),
            RtpCodecKind::Video,
            encodings,
        ))?;
        let mut s = peer.pc.rtp_sender(sender).expect("sender");
        let mut params = s.get_parameters().clone();
        params.encodings[1].active = false;
        s.set_parameters(params, None)?;
        let offer = peer.pc.create_offer(None)?;
        let expected = if pause == Pause::On {
            "a=simulcast:send f;~h"
        } else {
            "a=simulcast:send f;h"
        };
        assert!(offer.sdp.contains(expected), "{}", offer.sdp);
    }
    Ok(())
}
