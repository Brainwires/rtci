//! RFC 4585 section 4.2: "If no "rtcp-fb" attribute is specified, the RTP receivers MAY send
//! feedback using other suitable RTCP feedback packets as defined for the respective media
//! type. The RTP receivers MUST NOT rely on the RTP senders reacting to any of the FB
//! messages."
//!
//! A call between two `rtci` peers in virtual time where the session negotiated no feedback:
//! the sender's media engine lists VP8 and Opus without any `a=rtcp-fb`, and it has no
//! interceptors at all (no NACK responder; nothing that would make a key frame on a PLI): it
//! reacts to nothing. The receiver has the default interceptor set and codecs (which offer
//! `nack`, `nack pli`, `ccm fir`, `transport-cc` and `goog-remb`), so its answer could only
//! drop them. The sender sends VP8 at 30 frames a second, one packet a frame, a key frame every
//! 30 frames on its own schedule, and Opus every 20 ms; the link loses the packet of video frame
//! 35 and one audio packet, for good.
//!
//! The receiving application uses `rtci-media`'s `SampleBuilder` as it comes (`new`, no other
//! setting) and sends a PLI with `RTCRtpReceiver::write_rtcp` whenever the builder asks for a
//! key frame, as `docs/receiver-gap-policy.md` says. What is asserted:
//!
//! - the receiving engine puts no feedback message on the wire (no RTPFB, no PSFB), and the
//!   application's PLI is refused as not negotiated (RFC 4585 section 4.2's other MUSTs, with
//!   their own rows: `nack_integration.rs::test_nack_generator_ignores_streams_without_nack_support`,
//!   `avpf_feedback_negotiation.rs::application_feedback_the_section_did_not_negotiate_is_refused`);
//! - every audio packet the engine receives reaches the application in the same `handle_read`
//!   that brought it, those after the lost one included: the engine core waits for nothing;
//! - every video frame after the lost packet reaches the application within the builder's
//!   bound (`DEFAULT_MAX_GAP_WAIT`) of its arrival, and a decoder that needs every reference
//!   resumes at the sender's next scheduled key frame: nothing waits for a retransmission or
//!   for an answer to the PLI.

#![allow(clippy::needless_range_loop)]

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media::io::sample_builder::{DEFAULT_MAX_GAP_WAIT, SampleBuilder};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtp::codec::vp8::Vp8Packet;
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const VP8_PT: u8 = 96;
const OPUS_PT: u8 = 111;
const VIDEO_SSRC: u32 = 0x1111_2222;
const AUDIO_SSRC: u32 = 0x3333_4444;
const FRAMES: usize = 120;
const KEY_FRAME_INTERVAL: usize = 30;
const LOST_FRAME: usize = 35;
const AUDIO_PACKETS: u16 = 150;
const LOST_AUDIO: u16 = 60;
const LINK_DELAY: Duration = Duration::from_millis(20);
const STEP: Duration = Duration::from_micros(500);

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

fn opus() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
}

impl Peer {
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

/// A sender that knows no feedback and reacts to none.
fn sender(now: Instant) -> Result<Peer> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8(),
            payload_type: VP8_PT,
        },
        RtpCodecKind::Video,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: opus(),
            payload_type: OPUS_PT,
        },
        RtpCodecKind::Audio,
    )?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(Registry::new())
        .build(now)?;
    Ok(Peer {
        pc,
        addr: "10.0.0.1:5000".parse()?,
        connected: false,
    })
}

/// A receiver with the default codecs and interceptors.
fn receiver(now: Instant) -> Result<Peer> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(now)?;
    Ok(Peer {
        pc,
        addr: "10.0.0.2:5000".parse()?,
        connected: false,
    })
}

fn is_media(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

/// The packet type of the first RTCP packet of an SRTCP datagram (in the clear, RFC 3711
/// section 3.4), `None` for anything else.
fn rtcp_type(data: &[u8]) -> Option<u8> {
    (is_media(data) && data.len() > 1 && (192..=223).contains(&data[1])).then(|| data[1])
}

/// The SSRC and sequence number of an SRTP packet (the header is in the clear).
fn rtp_id(data: &[u8]) -> Option<(u32, u16)> {
    (is_media(data) && rtcp_type(data).is_none() && data.len() >= 12).then(|| {
        (
            u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            u16::from_be_bytes([data[2], data[3]]),
        )
    })
}

/// Frame `i` as one RTP packet (RFC 7741): sequence number `1000 + i`, timestamp `3000 i`,
/// the payload descriptor with S=1 and PID 0, then the frame, whose first byte carries the VP8
/// frame tag's key-frame bit (RFC 6386 section 9.1: 0 for a key frame).
fn frame(i: usize) -> rtci::rtp::Packet {
    let mut payload = vec![0x10u8; 201];
    payload[1] = if i.is_multiple_of(KEY_FRAME_INTERVAL) {
        0x10
    } else {
        0x11
    };
    payload[2..10].copy_from_slice(&(i as u64).to_be_bytes());
    rtci::rtp::Packet {
        header: Header {
            version: 2,
            payload_type: VP8_PT,
            sequence_number: 1000 + i as u16,
            timestamp: 3000 * i as u32,
            ssrc: VIDEO_SSRC,
            marker: true,
            ..Default::default()
        },
        payload: Bytes::from(payload),
    }
}

/// The frame a video packet or sample belongs to.
fn frame_of_timestamp(timestamp: u32) -> usize {
    (timestamp / 3000) as usize
}

struct InFlight {
    at: Instant,
    from: SocketAddr,
    to: SocketAddr,
    data: bytes::BytesMut,
}

/// What the receiving application saw.
struct Call {
    answer: String,
    /// RTCP packet types of the receiver's datagrams.
    receiver_rtcp: Vec<u8>,
    /// Per audio sequence number: when the engine was handed the datagram, when the
    /// application read the packet.
    audio: BTreeMap<u16, (Instant, Instant)>,
    /// Per video frame: when its packet reached the application.
    video_arrival: BTreeMap<usize, Instant>,
    /// Per video frame the builder produced: when, and the packets dropped before it.
    video_samples: Vec<(usize, Instant, u16)>,
    key_frame_requests: usize,
    refused_plis: usize,
}

fn call() -> Result<Call> {
    let start = Instant::now();
    let mut peers = [sender(start)?, receiver(start)?];
    let track = |kind: RtpCodecKind, ssrc: u32, codec: RTCRtpCodec, id: &str| {
        MediaStreamTrack::new(
            "stream".to_owned(),
            id.to_owned(),
            id.to_owned(),
            kind,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec,
                ..Default::default()
            }],
        )
    };
    let video_sender =
        peers[0]
            .pc
            .add_track(track(RtpCodecKind::Video, VIDEO_SSRC, vp8(), "video"))?;
    let audio_sender =
        peers[0]
            .pc
            .add_track(track(RtpCodecKind::Audio, AUDIO_SSRC, opus(), "audio"))?;
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(start, offer.clone())?;
    peers[1].pc.set_remote_description(start, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    let answer_sdp = answer.sdp.clone();
    peers[1].pc.set_local_description(start, answer.clone())?;
    peers[0].pc.set_remote_description(start, answer)?;
    for i in 0..2 {
        let c = peers[i].candidate()?;
        peers[i].pc.add_local_candidate(c.clone())?;
        peers[1 - i].pc.add_remote_candidate(c)?;
    }

    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let mut lost_seq: Option<u16> = None;
    let mut out = Call {
        answer: answer_sdp,
        receiver_rtcp: vec![],
        audio: BTreeMap::new(),
        video_arrival: BTreeMap::new(),
        video_samples: vec![],
        key_frame_requests: 0,
        refused_plis: 0,
    };
    let mut in_flight: Vec<InFlight> = vec![];
    let mut next_frame = 0usize;
    let mut next_audio = 0u16;
    let mut media_start: Option<Instant> = None;
    let mut now = start;
    loop {
        for i in 0..2 {
            while let Some(m) = peers[i].pc.poll_write() {
                let data = m.message;
                if i == 1
                    && let Some(pt) = rtcp_type(&data)
                {
                    out.receiver_rtcp.push(pt);
                }
                if i == 0
                    && let Some((ssrc, seq)) = rtp_id(&data)
                    && ((ssrc == VIDEO_SSRC && Some(seq) == lost_seq)
                        || (ssrc == AUDIO_SSRC && seq == LOST_AUDIO))
                {
                    continue;
                }
                in_flight.push(InFlight {
                    at: now + LINK_DELAY,
                    from: m.transport.local_addr,
                    to: m.transport.peer_addr,
                    data,
                });
            }
            let addr = peers[i].addr;
            let mut k = 0;
            while k < in_flight.len() {
                if in_flight[k].to == addr && in_flight[k].at <= now {
                    let d = in_flight.remove(k);
                    let audio_seq = (i == 1)
                        .then(|| rtp_id(&d.data))
                        .flatten()
                        .filter(|(ssrc, _)| *ssrc == AUDIO_SSRC)
                        .map(|(_, seq)| seq);
                    let _ = peers[i].pc.handle_read(TaggedBytesMut {
                        now,
                        transport: TransportContext {
                            local_addr: d.to,
                            peer_addr: d.from,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: d.data,
                    });
                    // Whatever the engine delivers for this datagram, it delivers now.
                    while let Some(m) = peers[i].pc.poll_read() {
                        if i != 1 {
                            continue;
                        }
                        if let RTCMessage::RtpPacket(_, pkt) = m.message {
                            if pkt.header.ssrc == AUDIO_SSRC {
                                out.audio
                                    .entry(pkt.header.sequence_number)
                                    .or_insert((now, now));
                            } else if pkt.header.ssrc == VIDEO_SSRC {
                                out.video_arrival
                                    .entry(frame_of_timestamp(pkt.header.timestamp))
                                    .or_insert(now);
                                builder.push(now, pkt);
                            }
                        }
                    }
                    if let Some(seq) = audio_seq
                        && !out.audio.contains_key(&seq)
                    {
                        bail!(
                            "audio packet {seq} was not delivered by the handle_read that brought it"
                        );
                    }
                } else {
                    k += 1;
                }
            }
            if peers[i].pc.poll_timeout().is_some_and(|t| t <= now) {
                let _ = peers[i].pc.handle_timeout(now);
            }
            while let Some(event) = peers[i].pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("peer {i} failed");
                    }
                    peers[i].connected = state == RTCPeerConnectionState::Connected;
                }
            }
            while let Some(m) = peers[i].pc.poll_read() {
                if i == 1
                    && let RTCMessage::RtpPacket(_, pkt) = m.message
                    && pkt.header.ssrc == VIDEO_SSRC
                {
                    out.video_arrival
                        .entry(frame_of_timestamp(pkt.header.timestamp))
                        .or_insert(now);
                    builder.push(now, pkt);
                }
            }
        }

        // The receiving application: samples out, and a PLI when the builder asks.
        while let Some(sample) = builder.pop(now) {
            out.video_samples.push((
                frame_of_timestamp(sample.packet_timestamp),
                now,
                sample.prev_dropped_packets,
            ));
        }
        if builder.take_key_frame_request() {
            out.key_frame_requests += 1;
            let ids: Vec<_> = peers[1].pc.get_receivers().collect();
            for id in ids {
                let pli: Vec<Box<dyn rtci::rtcp::Packet>> = vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: VIDEO_SSRC,
                })];
                if peers[1]
                    .pc
                    .rtp_receiver(id)
                    .expect("receiver")
                    .write_rtcp(now, pli)
                    .is_err()
                {
                    out.refused_plis += 1;
                }
            }
        }

        // The sender, on its own schedule: a frame every 33 ms, audio every 20 ms.
        if peers[0].connected && peers[1].connected && media_start.is_none() {
            media_start = Some(now);
        }
        if let Some(t0) = media_start {
            let due_frame = ((now - t0).as_millis() / 33) as usize;
            while next_frame <= due_frame && next_frame < FRAMES {
                let packet = frame(next_frame);
                if next_frame == LOST_FRAME {
                    lost_seq = Some(packet.header.sequence_number);
                }
                peers[0]
                    .pc
                    .rtp_sender(video_sender)
                    .expect("sender")
                    .write_rtp(now, packet)?;
                next_frame += 1;
            }
            let due_audio = ((now - t0).as_millis() / 20) as u16;
            while next_audio <= due_audio && next_audio < AUDIO_PACKETS {
                let header = Header {
                    version: 2,
                    payload_type: OPUS_PT,
                    sequence_number: next_audio,
                    timestamp: u32::from(next_audio) * 960,
                    ssrc: AUDIO_SSRC,
                    ..Default::default()
                };
                peers[0]
                    .pc
                    .rtp_sender(audio_sender)
                    .expect("sender")
                    .write_rtp(
                        now,
                        rtci::rtp::Packet {
                            header,
                            payload: Bytes::from(vec![0x78, next_audio as u8, 0x55, 0xaa]),
                        },
                    )?;
                next_audio += 1;
            }
            if next_frame == FRAMES
                && next_audio == AUDIO_PACKETS
                && now - t0 > Duration::from_millis(33 * FRAMES as u64 + 1_000)
            {
                break;
            }
        }
        if now - start > Duration::from_secs(30) {
            bail!("not done after 30 s (sent {next_frame} frames)");
        }
        now += STEP;
    }
    Ok(out)
}

#[test]
fn a_receiver_does_not_rely_on_feedback_that_was_not_negotiated() -> Result<()> {
    let call = call()?;

    // The session negotiated no feedback, and the receiving engine sends none.
    assert!(
        !call.answer.contains("a=rtcp-fb"),
        "the answer lists no feedback: {}",
        call.answer
    );
    assert!(
        call.receiver_rtcp.iter().all(|pt| *pt != 205 && *pt != 206),
        "the receiver sent feedback (RTPFB 205 / PSFB 206): {:?}",
        call.receiver_rtcp
    );

    // Audio: delivered as it arrived (checked per datagram in the loop), the loss included.
    assert!(!call.audio.contains_key(&LOST_AUDIO));
    let after: Vec<u16> = call
        .audio
        .keys()
        .copied()
        .filter(|seq| *seq > LOST_AUDIO)
        .collect();
    assert_eq!(
        (LOST_AUDIO + 1..AUDIO_PACKETS).collect::<Vec<u16>>(),
        after,
        "every audio packet after the lost one reaches the application"
    );

    // Video: every frame after the gap within the bound of its arrival (the last frame waits
    // for a successor to end it, and has none).
    for f in LOST_FRAME + 1..FRAMES - 1 {
        let arrived = call.video_arrival[&f];
        let Some((_, at, _)) = call.video_samples.iter().find(|(g, _, _)| *g == f) else {
            panic!("frame {f} never reached the application");
        };
        assert!(
            *at <= arrived + DEFAULT_MAX_GAP_WAIT + STEP,
            "frame {f} held {:?} after its arrival",
            *at - arrived
        );
    }
    assert!(
        call.key_frame_requests >= 1,
        "the builder asks for a key frame"
    );
    assert!(
        call.refused_plis >= 1,
        "and the PLI the application sends is refused: it was not negotiated"
    );

    // A decoder that needs every reference resumes at the sender's next scheduled key frame.
    let mut decoded = Vec::new();
    let mut previous: Option<usize> = None;
    for (f, _, dropped) in &call.video_samples {
        let decodable =
            f.is_multiple_of(KEY_FRAME_INTERVAL) || (*dropped == 0 && previous == Some(f - 1));
        previous = decodable.then_some(*f);
        if decodable {
            decoded.push(*f);
        }
    }
    let after_gap: Vec<usize> = decoded.into_iter().filter(|f| *f > LOST_FRAME).collect();
    let next_key = LOST_FRAME.next_multiple_of(KEY_FRAME_INTERVAL);
    assert_eq!(
        Some(&next_key),
        after_gap.first(),
        "decoding resumes at frame {next_key}"
    );
    assert_eq!(
        (next_key..FRAMES - 1).collect::<Vec<usize>>(),
        after_gap,
        "and every frame from it decodes"
    );
    Ok(())
}
