//! What RTCP two `rtc` peer connections put on the wire during a call, packet by packet, in
//! virtual time, under the `Rfc` (default) and `Performance` behaviour profiles.
//!
//! A tap below the RTCP session (`Slot::Custom(100)`) records every compound or reduced-size
//! packet the session writes; the world counts the SRTP and SRTCP datagrams on the wire. Each
//! packet is classified by what it carries: a full compound packet without feedback is the
//! regular report timer's; one with feedback is the feedback's (reduced-size when it starts
//! with no SR / RR, minimal when its one report has no blocks). Rates are per second of media;
//! shares are SRTCP bytes over SRTP bytes on the wire (IP and UDP not counted), both ways.
//!
//! `trace_rtcp_of_a_call` (ignored; run with `-- --ignored --nocapture`) prints the table
//! below. Measured in the container (`rust:1.92`), 30 s of media each, 20 ms each way:
//!
//! ```text
//! scenario                          profile     |  s reg   s SR |  r reg   r cc cc gap   blk/s blk gap |  kbit/s  rtcp%  nack
//! 1 Mbit/s A+V one way, rsize       rfc         |  13.20  27.32 |  12.20  20.00     50   12.20     214 |  1143.6   4.20   120
//! 1 Mbit/s A+V one way, rsize       performance |   1.40   3.80 |   1.20  20.00     50    1.20    1362 |  1169.9   1.45   120
//! 1 Mbit/s A+V one way, no rsize    rfc         |  11.32  23.40 |  12.04  20.00     50   12.04     213 |  1149.9   4.41   120
//! 1 Mbit/s A+V one way, no rsize    performance |   1.36   3.52 |   1.28  20.00     50    1.28     993 |  1159.1   1.96   114
//! 1 Mbit/s A+V both ways, rsize     rfc         |  19.36  39.52 |  19.48  20.00     50   19.48      76 |  2296.8   4.91   120
//! 1 Mbit/s A+V both ways, rsize     performance |   1.48   3.92 |   1.48  20.00     50    1.48     848 |  2297.4   1.44   114
//! 1 Mbit/s A+V both ways, no rsize  rfc         |  15.88  52.76 |  15.76  20.00     50   15.76      96 |  2312.5   5.03   120
//! 1 Mbit/s A+V both ways, no rsize  performance |   1.36  23.44 |   1.36  20.00     50    1.36    1112 |  2296.0   2.25   114
//! 100 kbit/s A+V one way, rsize     rfc         |   1.64   3.88 |   1.44  12.24    137    1.44    1510 |   203.1   5.96   120
//! 100 kbit/s A+V one way, rsize     performance |   0.72   1.80 |   0.32   4.32    399    0.32    4444 |   204.0   2.75   120
//! 24 kbit/s audio one way, rsize    rfc         |   2.08   2.08 |   1.92   4.00    250    1.92     657 |    38.5  12.15     -
//! 24 kbit/s audio one way, rsize    performance |   0.20   0.20 |   0.20   2.00    500    0.20    5220 |    38.5   4.49     -
//! 24 kbit/s audio one way, no rsize rfc         |   1.68   1.68 |   1.84   4.00    250    1.84     651 |    38.5  14.34     -
//! 24 kbit/s audio one way, no rsize performance |   0.24   0.24 |   0.20   2.00    500    0.20    5874 |    38.5   6.06     -
//! ```
//!
//! Columns, from 5 s to the end: the sender's regular packets and SRs per second; the
//! receiver's regular packets and congestion control feedback packets per second, and the
//! longest gap between two of those (ms); regular packets with report blocks reaching the
//! sender per second and their longest gap (ms); media both ways (kbit/s on the wire); all
//! RTCP over all media; ms from a lost video packet to the receiver's NACK. In "both ways,
//! no rsize" each feedback packet travels in a minimal compound packet with an SR (23 SR/s
//! under `Performance`: 20 of them carry feedback).
//!
//! The other tests pin what the `Performance` profile saves and that `Rfc` is unchanged, on
//! shorter runs.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::{Interceptor, Packet, Registry, Slot, StreamInfo, TaggedPacket};
use rtc::peer_connection::configuration::BehaviourProfile;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::receiver_report::ReceiverReport;
use rtc::rtcp::sender_report::SenderReport;
use rtc::rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtc::rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtc::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Tap = Arc<Mutex<Vec<(Instant, Vec<Box<dyn rtc::rtcp::Packet>>)>>>;

/// Below the RTCP session: every compound (or reduced-size) packet the session writes.
struct TapInterceptor {
    tap: Tap,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TapInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        if let Packet::Rtcp(packets) = &msg.message.packet
            && !packets.is_empty()
        {
            self.tap
                .lock()
                .expect("tap")
                .push((msg.now, packets.clone()));
        }
        self.write_queue.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for TapInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

struct Peer {
    pc: RTCPeerConnection,
    tap: Tap,
    addr: SocketAddr,
    connected: bool,
    /// (time, datagram length) of each SRTP and SRTCP datagram this peer sent.
    wire_rtp: Vec<(Instant, usize)>,
    wire_rtcp: Vec<(Instant, usize)>,
}

impl Peer {
    fn new(addr: &str, profile: BehaviourProfile) -> Result<Self> {
        let mut media_engine = MediaEngine::for_profile(profile);
        media_engine.register_default_codecs()?;
        let tap = Tap::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?.with(
            Slot::Custom(100),
            TapInterceptor {
                tap: tap.clone(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
        );
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_behaviour_profile(profile)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            tap,
            addr: addr.parse()?,
            connected: false,
            wire_rtp: vec![],
            wire_rtcp: vec![],
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

fn is_media(d: &[u8]) -> bool {
    matches!(d.first(), Some(128..=191))
}
fn is_rtcp(d: &[u8]) -> bool {
    is_media(d) && d.len() > 1 && (192..=223).contains(&d[1])
}
fn wire_rtp(d: &[u8]) -> Option<(u32, u16)> {
    (is_media(d) && !is_rtcp(d) && d.len() >= 12).then(|| {
        (
            u32::from_be_bytes([d[8], d[9], d[10], d[11]]),
            u16::from_be_bytes([d[2], d[3]]),
        )
    })
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    delay: Duration,
    in_flight: Vec<(Instant, u64, SocketAddr, SocketAddr, bytes::BytesMut)>,
    order: u64,
    /// Drop the first peer's RTP packet with this SSRC and sequence number once, and when.
    drop_once: Option<(u32, u16)>,
    dropped_at: Option<Instant>,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        for i in 0..2 {
            while let Some(msg) = self.peers[i].pc.poll_write() {
                let len = msg.message.len();
                if is_rtcp(&msg.message) {
                    self.peers[i].wire_rtcp.push((self.now, len));
                } else if is_media(&msg.message) {
                    self.peers[i].wire_rtp.push((self.now, len));
                }
                if i == 0
                    && let Some(rtp) = wire_rtp(&msg.message)
                    && self.drop_once == Some(rtp)
                {
                    self.drop_once = None;
                    self.dropped_at = Some(self.now);
                    continue;
                }
                self.order += 1;
                self.in_flight.push((
                    self.now + self.delay,
                    self.order,
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    msg.message,
                ));
            }
        }
        let now = self.now;
        let mut due = vec![];
        let mut i = 0;
        while i < self.in_flight.len() {
            if self.in_flight[i].0 <= now {
                due.push(self.in_flight.swap_remove(i));
            } else {
                i += 1;
            }
        }
        due.sort_by_key(|d| (d.0, d.1));
        for (_, _, from, to, data) in due {
            let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                continue;
            };
            let _ = peer.pc.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: data,
            });
        }
        for i in 0..2 {
            while let Some(event) = self.peers[i].pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("peer {i} failed");
                    }
                    self.peers[i].connected = state == RTCPeerConnectionState::Connected;
                }
            }
            while self.peers[i].pc.poll_read().is_some() {}
        }
        Ok(())
    }

    fn advance(&mut self, to: Instant) -> Result<()> {
        while self.now < to {
            let mut next = to;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            if let Some(at) = self.in_flight.iter().map(|d| d.0).min() {
                next = next.min(at);
            }
            self.now = next.max(self.now + Duration::from_micros(100)).min(to);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    name: &'static str,
    /// Payload octets per 20 ms of audio; 0: no audio.
    audio_bytes: usize,
    /// Payload octets per 20 ms of video; 0: no video.
    video_bytes: usize,
    /// Whether the answerer sends the same back.
    both_ways: bool,
    /// Whether `a=rtcp-rsize` stays in the offer.
    rsize: bool,
    seconds: u64,
}

const BASE: Scenario = Scenario {
    name: "",
    audio_bytes: 160,
    video_bytes: 2340,
    both_ways: false,
    rsize: true,
    seconds: 30,
};

/// (sender, ssrc, pt, clock rate, payload octets per 20 ms) of each stream a peer sends.
type Streams = Vec<(RTCRtpSenderId, u32, u8, u32, usize)>;

fn senders_of(pc: &mut RTCPeerConnection, wanted: &[(RtpCodecKind, usize)]) -> Streams {
    let ids: Vec<_> = pc.get_transceivers().collect();
    let mut streams = vec![];
    for id in ids {
        let t = pc.rtp_transceiver(id).expect("transceiver");
        let Some(sender) = t.sender() else { continue };
        let mut s = pc.rtp_sender(sender).expect("sender");
        let parameters = s.get_parameters();
        let Some(codec) = parameters.rtp_parameters.codecs.first() else {
            continue;
        };
        let kind = if codec
            .rtp_codec
            .mime_type
            .to_ascii_lowercase()
            .starts_with("audio/")
        {
            RtpCodecKind::Audio
        } else {
            RtpCodecKind::Video
        };
        let Some(bytes) = wanted.iter().find(|(k, _)| *k == kind).map(|(_, b)| *b) else {
            continue;
        };
        let Some(ssrc) = parameters.encodings[0].rtp_coding_parameters.ssrc else {
            continue;
        };
        streams.push((
            sender,
            ssrc,
            codec.payload_type,
            codec.rtp_codec.clock_rate,
            bytes,
        ));
    }
    streams
}

fn has<T: 'static>(packets: &[Box<dyn rtc::rtcp::Packet>]) -> bool {
    packets.iter().any(|p| p.as_any().is::<T>())
}

fn is_feedback(packets: &[Box<dyn rtc::rtcp::Packet>]) -> bool {
    has::<TransportLayerCc>(packets)
        || has::<CcFeedbackReport>(packets)
        || has::<TransportLayerNack>(packets)
}

fn is_congestion_feedback(packets: &[Box<dyn rtc::rtcp::Packet>]) -> bool {
    has::<TransportLayerCc>(packets) || has::<CcFeedbackReport>(packets)
}

fn report_blocks(packets: &[Box<dyn rtc::rtcp::Packet>]) -> usize {
    packets
        .iter()
        .map(|p| {
            let a = p.as_any();
            a.downcast_ref::<SenderReport>()
                .map(|s| s.reports.len())
                .or_else(|| a.downcast_ref::<ReceiverReport>().map(|r| r.reports.len()))
                .unwrap_or(0)
        })
        .sum()
}

/// What one side of one run measured, over the media window (the first `skip` seconds left out).
#[derive(Debug, Default, Clone, Copy)]
struct Side {
    /// Regular (full compound, no feedback) packets per second.
    regular: f64,
    /// SR packets per second, in anything.
    srs: f64,
    /// Congestion control feedback packets per second.
    cc: f64,
    /// The longest gap between two congestion control feedback packets, ms.
    cc_gap_ms: f64,
    /// Regular packets with report blocks per second (RTT samples, loss reports, the RTP
    /// circuit breaker's input), and the longest gap between two, ms.
    blocks: f64,
    blocks_gap_ms: f64,
    /// SRTCP octets per second on the wire.
    rtcp_octets: f64,
    /// SRTP octets per second on the wire.
    media_octets: f64,
}

#[derive(Debug, Clone, Copy)]
struct Measured {
    sides: [Side; 2],
    /// All SRTCP over all SRTP, both ways.
    share: f64,
    /// From the dropped packet to the receiver's NACK for it, ms.
    nack_ms: Option<f64>,
}

fn measure(sc: Scenario, profile: BehaviourProfile, drop_at: Option<u64>) -> Result<Measured> {
    let mut world = World {
        peers: [
            Peer::new("10.0.0.1:5000", profile)?,
            Peer::new("10.0.0.2:5000", profile)?,
        ],
        now: Instant::now(),
        delay: Duration::from_millis(20),
        in_flight: vec![],
        order: 0,
        drop_once: None,
        dropped_at: None,
    };
    let mut kinds = vec![];
    if sc.audio_bytes > 0 {
        kinds.push((RtpCodecKind::Audio, sc.audio_bytes));
    }
    if sc.video_bytes > 0 {
        kinds.push((RtpCodecKind::Video, sc.video_bytes));
    }
    let direction = if sc.both_ways {
        RTCRtpTransceiverDirection::Sendrecv
    } else {
        RTCRtpTransceiverDirection::Sendonly
    };
    for (kind, _) in &kinds {
        world.peers[0].pc.add_transceiver_from_kind(
            *kind,
            Some(RTCRtpTransceiverInit {
                direction,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
    }
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    let offer_sdp = if sc.rsize {
        offer.sdp.clone()
    } else {
        offer.sdp.replace("a=rtcp-rsize\r\n", "")
    };
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer_sdp)?)?;
    if sc.both_ways {
        let ids: Vec<_> = world.peers[1].pc.get_transceivers().collect();
        for id in ids {
            world.peers[1]
                .pc
                .rtp_transceiver(id)
                .expect("transceiver")
                .set_direction(RTCRtpTransceiverDirection::Sendrecv)?;
        }
    }
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
        if world.now.duration_since(start) > Duration::from_secs(10) {
            bail!("not connected");
        }
        let t = world.now + Duration::from_millis(10);
        world.advance(t)?;
    }
    let mut senders = vec![senders_of(&mut world.peers[0].pc, &kinds)];
    if sc.both_ways {
        senders.push(senders_of(&mut world.peers[1].pc, &kinds));
    }
    for s in &senders {
        assert_eq!(kinds.len(), s.len(), "a sender per kind");
    }

    let t0 = world.now;
    let mut seq = [[1u16; 2]; 2];
    for frame in 0..sc.seconds * 50 {
        let now = t0 + Duration::from_millis(frame * 20);
        world.advance(now)?;
        for (peer, streams) in senders.iter().enumerate() {
            for (k, (sender, ssrc, pt, clock, bytes)) in streams.iter().enumerate() {
                let parts = bytes.div_ceil(1100).max(1);
                for part in 0..parts {
                    if peer == 0 && k + 1 == streams.len() && Some(frame) == drop_at.map(|s| s * 50)
                    {
                        world.drop_once = Some((*ssrc, seq[peer][k]));
                    }
                    let header = Header {
                        version: 2,
                        payload_type: *pt,
                        sequence_number: seq[peer][k],
                        timestamp: (frame as u32).wrapping_mul(clock / 50),
                        ssrc: *ssrc,
                        marker: part + 1 == parts,
                        ..Default::default()
                    };
                    seq[peer][k] = seq[peer][k].wrapping_add(1);
                    world.peers[peer]
                        .pc
                        .rtp_sender(*sender)
                        .expect("sender")
                        .write_rtp(
                            now,
                            rtc::rtp::Packet {
                                header,
                                payload: Bytes::from(vec![0x5au8; bytes / parts]),
                            },
                        )?;
                }
            }
        }
        world.pump()?;
    }
    let t1 = t0 + Duration::from_secs(sc.seconds);
    world.advance(t1)?;

    // The first five seconds are the start-up (the nominal bandwidth, the congestion
    // controller's ramp); what is measured is the call after it.
    let from = t0 + Duration::from_secs(5);
    let secs = t1.duration_since(from).as_secs_f64();
    let within = |at: &Instant| *at >= from && *at < t1;
    let mut sides = [Side::default(); 2];
    for (i, peer) in world.peers.iter().enumerate() {
        let tap = peer.tap.lock().expect("tap");
        let packets: Vec<_> = tap.iter().filter(|(at, _)| within(at)).collect();
        let gap = |times: &[Instant]| -> f64 {
            let mut edges = vec![from];
            edges.extend_from_slice(times);
            edges.push(t1);
            edges
                .windows(2)
                .map(|w| w[1].duration_since(w[0]).as_secs_f64() * 1000.0)
                .fold(0.0, f64::max)
        };
        let regular: Vec<Instant> = packets
            .iter()
            .filter(|(_, p)| {
                !is_feedback(p) && (has::<SenderReport>(p) || has::<ReceiverReport>(p))
            })
            .map(|(at, _)| *at)
            .collect();
        let cc: Vec<Instant> = packets
            .iter()
            .filter(|(_, p)| is_congestion_feedback(p))
            .map(|(at, _)| *at)
            .collect();
        let blocks: Vec<Instant> = packets
            .iter()
            .filter(|(_, p)| report_blocks(p) > 0)
            .map(|(at, _)| *at)
            .collect();
        let srs: usize = packets
            .iter()
            .map(|(_, p)| p.iter().filter(|x| x.as_any().is::<SenderReport>()).count())
            .sum();
        sides[i] = Side {
            regular: regular.len() as f64 / secs,
            srs: srs as f64 / secs,
            cc: cc.len() as f64 / secs,
            cc_gap_ms: if cc.is_empty() { 0.0 } else { gap(&cc) },
            blocks: blocks.len() as f64 / secs,
            blocks_gap_ms: if blocks.is_empty() { 0.0 } else { gap(&blocks) },
            rtcp_octets: peer
                .wire_rtcp
                .iter()
                .filter(|(at, _)| within(at))
                .map(|(_, l)| *l as f64)
                .sum::<f64>()
                / secs,
            media_octets: peer
                .wire_rtp
                .iter()
                .filter(|(at, _)| within(at))
                .map(|(_, l)| *l as f64)
                .sum::<f64>()
                / secs,
        };
    }
    let rtcp: f64 = sides.iter().map(|s| s.rtcp_octets).sum();
    let media: f64 = sides.iter().map(|s| s.media_octets).sum();
    let nack_ms = world.dropped_at.and_then(|dropped| {
        let tap = world.peers[1].tap.lock().expect("tap");
        tap.iter()
            .find(|(at, p)| *at >= dropped && has::<TransportLayerNack>(p))
            .map(|(at, _)| at.duration_since(dropped).as_secs_f64() * 1000.0)
    });
    Ok(Measured {
        sides,
        share: rtcp / media.max(1.0),
        nack_ms,
    })
}

fn print_header() {
    println!(
        "{:<44} {:<11} | {:>6} {:>6} | {:>6} {:>6} {:>6} {:>7} {:>7} | {:>7} {:>6} {:>6}",
        "scenario",
        "profile",
        "s reg",
        "s SR",
        "r reg",
        "r cc",
        "cc gap",
        "blk/s",
        "blk gap",
        "kbit/s",
        "rtcp%",
        "nack"
    );
}

fn print_row(sc: &Scenario, profile: BehaviourProfile, m: &Measured) {
    let [s, r] = m.sides;
    let media_kbps = (s.media_octets + r.media_octets) * 8.0 / 1000.0;
    // Report blocks the sender receives come from the receiver (index 1).
    println!(
        "{:<44} {:<11} | {:>6.2} {:>6.2} | {:>6.2} {:>6.2} {:>6.0} {:>7.2} {:>7.0} | {:>7.1} {:>6.2} {:>6}",
        sc.name,
        profile.name(),
        s.regular,
        s.srs,
        r.regular,
        r.cc,
        r.cc_gap_ms,
        r.blocks,
        r.blocks_gap_ms,
        media_kbps,
        m.share * 100.0,
        m.nack_ms.map_or("-".to_owned(), |ms| format!("{ms:.0}"))
    );
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "1 Mbit/s A+V one way, rsize",
            ..BASE
        },
        Scenario {
            name: "1 Mbit/s A+V one way, no rsize",
            rsize: false,
            ..BASE
        },
        Scenario {
            name: "1 Mbit/s A+V both ways, rsize",
            both_ways: true,
            ..BASE
        },
        Scenario {
            name: "1 Mbit/s A+V both ways, no rsize",
            both_ways: true,
            rsize: false,
            ..BASE
        },
        Scenario {
            name: "100 kbit/s A+V one way, rsize",
            audio_bytes: 60,
            video_bytes: 190,
            ..BASE
        },
        Scenario {
            name: "24 kbit/s audio one way, rsize",
            audio_bytes: 60,
            video_bytes: 0,
            ..BASE
        },
        Scenario {
            name: "24 kbit/s audio one way, no rsize",
            audio_bytes: 60,
            video_bytes: 0,
            rsize: false,
            ..BASE
        },
    ]
}

/// The table of the module documentation. A video packet is dropped at 15 s to time the NACK.
#[test]
#[ignore]
fn trace_rtcp_of_a_call() -> Result<()> {
    print_header();
    for sc in scenarios() {
        for profile in [BehaviourProfile::Rfc, BehaviourProfile::Performance] {
            let measured = measure(sc, profile, Some(15))?;
            print_row(&sc, profile, &measured);
        }
    }
    Ok(())
}

/// 1 Mbit/s of audio and video one way with `a=rtcp-rsize`, 12 s, a video packet lost at 8 s.
const ONE_MBIT: Scenario = Scenario {
    name: "1 Mbit/s A+V one way, rsize",
    seconds: 12,
    ..BASE
};

/// 24 kbit/s of audio one way with `a=rtcp-rsize`, 15 s.
const AUDIO_24K: Scenario = Scenario {
    name: "24 kbit/s audio one way, rsize",
    audio_bytes: 60,
    video_bytes: 0,
    seconds: 15,
    ..BASE
};

/// `rtcp.t-rr-interval`: the default (`Rfc`) sends the regular reports RFC 3550's 5% allows
/// with `T_rr_interval` zero, a dozen a second from each side at 1 Mbit/s; `Performance`
/// (`T_rr_interval` one second, RFC 4585 3.4 / 3.5.3) sends about one a second. RTCP falls
/// from about 4% of the media to under 2%. Early feedback is untouched: the receiver's NACK
/// for a lost packet leaves as fast, and its congestion control feedback as often.
#[test]
fn the_performance_profile_sends_regular_reports_about_once_a_second() -> Result<()> {
    let rfc = measure(ONE_MBIT, BehaviourProfile::Rfc, Some(8))?;
    let performance = measure(ONE_MBIT, BehaviourProfile::Performance, Some(8))?;
    print_row(&ONE_MBIT, BehaviourProfile::Rfc, &rfc);
    print_row(&ONE_MBIT, BehaviourProfile::Performance, &performance);
    // The default pinned: RFC 3550 6.2 timing with T_rr_interval zero.
    assert!(rfc.sides[0].regular >= 8.0, "{rfc:?}");
    assert!(rfc.sides[1].regular >= 8.0, "{rfc:?}");
    assert!(rfc.share >= 0.03, "{rfc:?}");
    // About once a second, dithered over [0.5, 1.5] s.
    for side in performance.sides {
        assert!((0.6..=2.0).contains(&side.regular), "{performance:?}");
    }
    assert!(performance.share <= 0.02, "{performance:?}");
    // Feedback is not held: as many congestion control reports, the NACK as fast.
    assert!(
        (performance.sides[1].cc - rfc.sides[1].cc).abs() <= 1.0,
        "{rfc:?} / {performance:?}"
    );
    let (Some(a), Some(b)) = (rfc.nack_ms, performance.nack_ms) else {
        bail!("no NACK: {rfc:?} / {performance:?}");
    };
    assert!((a - b).abs() <= 20.0, "NACK after {a} ms / {b} ms");
    Ok(())
}

/// `rtcp.congestion-feedback-in-budget`, `rtcp.minimum-session-bandwidth`,
/// `cc.feedback-share`, `cc.feedback-max-interval`: at 24 kbit/s of audio the default's RTCP is
/// over 10% of the media (the regular reports take 5% of a 64 kbit/s floor, the congestion
/// control feedback 5% of the media on top); under `Performance` both share RFC 3550's 5% of
/// the media, and the sender still hears feedback every half second.
#[test]
fn the_performance_profile_keeps_low_rate_rtcp_inside_five_percent() -> Result<()> {
    let rfc = measure(AUDIO_24K, BehaviourProfile::Rfc, None)?;
    let performance = measure(AUDIO_24K, BehaviourProfile::Performance, None)?;
    print_row(&AUDIO_24K, BehaviourProfile::Rfc, &rfc);
    print_row(&AUDIO_24K, BehaviourProfile::Performance, &performance);
    assert!(rfc.share >= 0.10, "{rfc:?}");
    assert!(performance.share <= 0.05, "{performance:?}");
    assert!(performance.sides[1].cc >= 1.8, "{performance:?}");
    assert!(performance.sides[1].cc_gap_ms <= 550.0, "{performance:?}");
    // Regular reports go on (RFC 5506 4: compound RTCP is kept up), at most five seconds apart.
    assert!(performance.sides[1].regular > 0.0, "{performance:?}");
    Ok(())
}
