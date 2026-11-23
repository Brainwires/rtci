//! Audio formats that ride an audio stream, between two `rtc` peer connections in virtual
//! time: comfort noise (RFC 3389) is sent only when its format was negotiated.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::{
    AudioRedundancy, Interceptor, Packet, Registry, Slot, StreamInfo, TaggedPacket,
};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::goodbye::Goodbye;
use rtc::rtcp::sender_report::SenderReport;
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

/// What a tap at the network end of the chain saw: each RTCP compound packet written, with
/// when, and the local streams bound and unbound.
#[derive(Default)]
struct Tapped {
    rtcp: Vec<(Instant, Vec<Box<dyn rtc::rtcp::Packet>>)>,
    bound: Vec<(u32, u32)>,
    unbound: Vec<u32>,
}

type Tap = Arc<Mutex<Tapped>>;

/// An interceptor below the RTCP session (written packets pass it after the session): it
/// records and passes everything on.
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
                .rtcp
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
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let mut tap = self.tap.lock().expect("tap");
        tap.bound.push((info.ssrc, info.clock_rate));
    }
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.tap.lock().expect("tap").unbound.push(info.ssrc);
    }
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

struct Peer {
    pc: RTCPeerConnection,
    /// What the network end of its interceptor chain saw.
    tap: Tap,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    fn new(addr: &str, ssrc_per_clock_rate: bool) -> Result<Self> {
        Self::with_audio_redundancy(addr, ssrc_per_clock_rate, AudioRedundancy::default())
    }

    fn with_audio_redundancy(
        addr: &str,
        ssrc_per_clock_rate: bool,
        audio_redundancy: AudioRedundancy,
    ) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let tap = Tap::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?.with(
            Slot::Custom(250),
            TapInterceptor {
                tap: tap.clone(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
        );
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_ssrc_per_clock_rate(ssrc_per_clock_rate)
                    .with_audio_redundancy(audio_redundancy)
                    .build(),
            )
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            tap,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read_rtp: Vec::new(),
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
    /// The size of each of those packets on the wire (the SRTP datagram), in step with `wire`.
    wire_sizes: Vec<usize>,
    /// Sequence numbers of the first peer's RTP packets the network loses.
    lose: Vec<u16>,
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
                    let lost = self.lose.contains(&header.sequence_number);
                    self.wire.push(header);
                    self.wire_sizes.push(data.len());
                    if lost {
                        continue;
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
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read_rtp.push(packet.header);
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

    /// The first peer sends `kind`; the second answers, its answer passed through `edit`
    /// before the first applies it. Connected over host candidates.
    fn connected(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with(kind, edit, false)
    }

    /// [`Self::connected`], the sender built with `with_ssrc_per_clock_rate(true)`: the RFC
    /// 7160 section 4.1 form.
    fn connected_ssrc_per_clock_rate(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with(kind, edit, true)
    }

    fn connected_with(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
        ssrc_per_clock_rate: bool,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with_redundancy(
            kind,
            edit,
            ssrc_per_clock_rate,
            [AudioRedundancy::default(); 2],
        )
    }

    /// [`Self::connected`], each peer built with `with_audio_redundancy` of `redundancy`
    /// (the sender's first).
    fn connected_with_audio_redundancy(
        edit: impl Fn(String) -> String,
        redundancy: [AudioRedundancy; 2],
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with_redundancy(RtpCodecKind::Audio, edit, false, redundancy)
    }

    fn connected_with_redundancy(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
        ssrc_per_clock_rate: bool,
        redundancy: [AudioRedundancy; 2],
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::with_audio_redundancy("10.0.0.1:5000", ssrc_per_clock_rate, redundancy[0])?,
                Peer::with_audio_redundancy("10.0.0.2:5000", ssrc_per_clock_rate, redundancy[1])?,
            ],
            now: Instant::now(),
            wire: Vec::new(),
            wire_sizes: Vec::new(),
            lose: Vec::new(),
        };
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
        world.peers[1].pc.set_remote_description(now, offer)?;
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

    /// Writes a packet with payload type `pt` on the sender's stream.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16, pt: u8) -> Result<()> {
        self.send_sized(sender, seq, pt, 100)
    }

    /// Writes a packet with payload type `pt` and a payload of `size` octets on the sender's
    /// stream, then lets 20 ms pass.
    fn send_sized(&mut self, sender: RTCRtpSenderId, seq: u16, pt: u8, size: usize) -> Result<()> {
        let now = self.now;
        let ssrc = self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        let header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; size]),
                },
            )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

/// The payload types on the wire of an audio stream that writes a PCMU packet, a comfort
/// noise packet (payload type 13) and another PCMU packet, its answer edited by `edit`.
fn payload_types_on_the_wire(edit: impl Fn(String) -> String) -> Result<Vec<u8>> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, edit)?;
    world.send(sender, 1, 0)?;
    world.send(sender, 2, 13)?;
    world.send(sender, 3, 0)?;
    Ok(world.wire.iter().map(|h| h.payload_type).collect())
}

/// The answer of a peer that takes PCMU only: every other format removed from `m=audio`.
fn pcmu_only(sdp: String) -> String {
    let lines: Vec<String> = sdp
        .lines()
        .filter(|l| {
            !(l.starts_with("a=rtpmap:") || l.starts_with("a=fmtp:") || l.starts_with("a=rtcp-fb:"))
                || l.starts_with("a=rtpmap:0 ")
        })
        .map(|l| {
            if l.starts_with("m=audio ") {
                let mut parts: Vec<&str> = l.split(' ').take(3).collect();
                parts.push("0");
                parts.join(" ")
            } else {
                l.to_owned()
            }
        })
        .collect();
    lines.join("\r\n") + "\r\n"
}

/// RFC 3389 section 5.1: "If no CN payload type is present on the m= line, then the CN format
/// is not used". A comfort noise packet the application writes then is not sent: rewritten to
/// the media payload type, its noise parameters would be decoded as PCMU. With CN negotiated
/// (the default audio formats have it, RFC 7874 section 3), it goes out as payload type 13.
#[test]
fn comfort_noise_is_sent_only_when_negotiated() -> Result<()> {
    assert_eq!(vec![0, 13, 0], payload_types_on_the_wire(|sdp| sdp)?);
    assert_eq!(vec![0, 0], payload_types_on_the_wire(pcmu_only)?);
    Ok(())
}

/// RFC 8834 section 4.3: an endpoint "MUST be prepared to accept data in any of the payload
/// formats that were signalled ... at any time". The sender switches between Opus, PCMU and
/// PCMA (each clock rate on an SSRC of its own, RFC 7160 section 4.1, which the receiver's
/// track follows); every packet reaches the receiving application with the format it was sent
/// in, in order.
#[test]
fn every_negotiated_format_is_received_at_any_time() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let sent = [111u8, 111, 0, 0, 8, 111, 0];
    for (seq, pt) in sent.iter().enumerate() {
        world.send(sender, seq as u16 + 1, *pt)?;
    }
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    assert_eq!(received, sent, "every format, at any time");
    Ok(())
}

/// By default a stream keeps its SSRC across clock rates (RFC 7160 section 4.1's SSRC per
/// clock rate is the setting `with_ssrc_per_clock_rate(true)`): libwebrtc's receivers
/// (Chromium, WebKit) keep the track on the signalled SSRC and stop counting packets at a
/// switch to a new one. Opus, PCMU, PCMA and Opus again go out on one SSRC, no BYE is sent,
/// and the receiver reads every packet.
#[test]
fn by_default_a_stream_keeps_one_ssrc_across_clock_rates() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let sent = [111u8, 111, 0, 8, 111, 0];
    for (seq, pt) in sent.iter().enumerate() {
        world.send(sender, seq as u16 + 1, *pt)?;
    }
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;
    let ssrcs = wire_ssrcs(&world);
    assert_eq!(ssrcs.len(), sent.len(), "{ssrcs:?}");
    let distinct: HashSet<u32> = ssrcs.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "one SSRC for every clock rate: {ssrcs:?}"
    );
    let tap = world.peers[0].tap.lock().expect("tap");
    let goodbyes = tap
        .rtcp
        .iter()
        .flat_map(|(_, packets)| packets)
        .filter(|packet| packet.as_any().is::<Goodbye>())
        .count();
    assert_eq!(goodbyes, 0, "no BYE while the stream is sent");
    drop(tap);
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    assert_eq!(received, sent, "every packet, in order");
    Ok(())
}

/// The RTP SSRC of each packet the first peer put on the wire, in order.
fn wire_ssrcs(world: &World) -> Vec<u32> {
    world.wire.iter().map(|header| header.ssrc).collect()
}

/// RFC 7160 section 4.1: "An RTP Sender with RTCP turned on MUST use a different SSRC for each
/// different clock rate. An RTCP BYE MUST be sent and a new SSRC MUST be used if the clock rate
/// switches back to a value already seen in the RTP stream." Opus (48 kHz), PCMU and PCMA
/// (8 kHz), Opus and PCMU again on one audio sender: four SSRCs, PCMA on PCMU's; each return
/// to a rate says BYE for the SSRC that used it before; the receiving application gets every
/// packet, in order, on its one track. The RFC form is `with_ssrc_per_clock_rate(true)`.
#[test]
fn each_clock_rate_is_sent_with_an_ssrc_of_its_own() -> Result<()> {
    let (mut world, sender) = World::connected_ssrc_per_clock_rate(RtpCodecKind::Audio, |sdp| sdp)?;
    let sent = [111u8, 111, 0, 8, 111, 0];
    for (seq, pt) in sent.iter().enumerate() {
        world.send(sender, seq as u16 + 1, *pt)?;
    }
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;
    let ssrcs = wire_ssrcs(&world);
    assert_eq!(ssrcs.len(), sent.len(), "{ssrcs:?}");
    assert_eq!(ssrcs[0], ssrcs[1], "one clock rate, one SSRC");
    assert_ne!(ssrcs[1], ssrcs[2], "8 kHz after 48 kHz: another SSRC");
    assert_eq!(ssrcs[2], ssrcs[3], "PCMA has PCMU's clock rate");
    let distinct: HashSet<u32> = ssrcs.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        4,
        "a return to a rate takes a new SSRC: {ssrcs:?}"
    );

    let tap = world.peers[0].tap.lock().expect("tap");
    let goodbyes: HashSet<u32> = tap
        .rtcp
        .iter()
        .flat_map(|(_, packets)| packets)
        .filter_map(|packet| packet.as_any().downcast_ref::<Goodbye>())
        .flat_map(|goodbye| goodbye.sources.iter().copied())
        .collect();
    assert!(
        goodbyes.contains(&ssrcs[0]) && goodbyes.contains(&ssrcs[2]),
        "BYE for the SSRC of each rate returned to: {goodbyes:?} of {ssrcs:?}"
    );
    assert!(
        !goodbyes.contains(&ssrcs[4]) && !goodbyes.contains(&ssrcs[5]),
        "the SSRCs in use say no BYE: {goodbyes:?}"
    );
    drop(tap);

    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    assert_eq!(
        received, sent,
        "the receiver follows the stream to each SSRC"
    );
    let current = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings[0]
        .rtp_coding_parameters
        .ssrc;
    assert_eq!(
        current,
        Some(ssrcs[5]),
        "the encoding is sent with the SSRC of its current clock rate"
    );
    Ok(())
}

/// RFC 7160 section 4.1: "the next compound RTCP packet sent by the RTP sender MUST contain
/// multiple SR packets, the first one containing the mapping for the current clock rate and
/// the subsequent SR packet(s) containing the mapping for the other clock rates seen during the
/// last period". After a switch from Opus to PCMU the first compound packet leads with the
/// PCMU SSRC's sender report, and the Opus SSRC's follows it.
#[test]
fn after_a_clock_rate_switch_the_sender_reports_lead_with_the_current_rate() -> Result<()> {
    let (mut world, sender) = World::connected_ssrc_per_clock_rate(RtpCodecKind::Audio, |sdp| sdp)?;
    for seq in 1..=5 {
        world.send(sender, seq, 111)?;
    }
    let switched_at = world.now;
    world.send(sender, 6, 0)?;
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;
    let ssrcs = wire_ssrcs(&world);
    let (opus, pcmu) = (ssrcs[0], ssrcs[5]);
    assert_ne!(opus, pcmu);
    let tap = world.peers[0].tap.lock().expect("tap");
    let next = tap
        .rtcp
        .iter()
        .filter(|(at, _)| *at >= switched_at)
        .find(|(_, packets)| {
            packets
                .first()
                .is_some_and(|first| first.as_any().is::<SenderReport>())
        })
        .map(|(_, packets)| {
            packets
                .iter()
                .filter_map(|packet| packet.as_any().downcast_ref::<SenderReport>())
                .map(|sr| sr.ssrc)
                .collect::<Vec<u32>>()
        })
        .expect("a compound packet after the switch");
    assert_eq!(
        next,
        vec![pcmu, opus],
        "the current clock rate's sender report first, the other one's behind it"
    );
    Ok(())
}

/// The answer of a peer without RED: the `red` format removed from `m=audio`.
fn without_red(sdp: String) -> String {
    let red = sdp
        .lines()
        .find_map(|l| {
            l.strip_prefix("a=rtpmap:")
                .filter(|rest| rest.contains(" red/"))
                .and_then(|rest| rest.split(' ').next())
        })
        .map(str::to_owned);
    let Some(red) = red else {
        return sdp;
    };
    let lines: Vec<String> = sdp
        .lines()
        .filter(|l| {
            !l.starts_with(&format!("a=rtpmap:{red} ")) && !l.starts_with(&format!("a=fmtp:{red} "))
        })
        .map(|l| {
            if l.starts_with("m=audio ") {
                l.split(' ')
                    .filter(|part| *part != red)
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                l.to_owned()
            }
        })
        .collect();
    lines.join("\r\n") + "\r\n"
}

/// The answer with its `red` format moved ahead of every other format on `m=audio`: a peer
/// that prefers redundancy (RFC 3264 section 6.1, the answerer's order of preference).
fn red_first(sdp: String) -> String {
    let red = sdp.lines().find_map(|l| {
        l.strip_prefix("a=rtpmap:")
            .filter(|rest| rest.contains(" red/"))
            .and_then(|rest| rest.split(' ').next())
            .map(str::to_owned)
    });
    let Some(red) = red else {
        return sdp;
    };
    let lines: Vec<String> = sdp
        .lines()
        .map(|l| {
            if l.starts_with("m=audio ") {
                let parts: Vec<&str> = l.split(' ').collect();
                let mut out: Vec<&str> = parts[..3].to_vec();
                out.push(&red);
                out.extend(parts[3..].iter().filter(|part| **part != red));
                out.join(" ")
            } else {
                l.to_owned()
            }
        })
        .collect();
    lines.join("\r\n") + "\r\n"
}

/// The first `m=audio` line's formats.
fn audio_formats(sdp: &str) -> Vec<String> {
    sdp.lines()
        .find(|l| l.starts_with("m=audio "))
        .map(|l| l.split(' ').skip(3).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// 24 kbit/s Opus in 20 ms packets: 60 octets of payload, 50 packets a second.
const OPUS_24K_PAYLOAD: usize = 60;

/// What a one-second, 24 kbit/s Opus call put on the wire with the sender's answer edited by
/// `edit` and each peer's `with_audio_redundancy`, the packet with sequence number 4 lost:
/// (the wire payload types, the media octets on the wire, what the receiving application got
/// as (sequence number, timestamp, payload type)).
type Call = (Vec<u8>, usize, Vec<(u16, u32, u8)>);

fn opus_call(edit: impl Fn(String) -> String, redundancy: [AudioRedundancy; 2]) -> Result<Call> {
    let (mut world, sender) = World::connected_with_audio_redundancy(edit, redundancy)?;
    let local = world.peers[0].pc.local_description().expect("offer").sdp;
    assert!(local.contains("a=rtpmap:63 red/48000/2\r\n"), "{local}");
    assert!(local.contains("a=fmtp:63 111/111\r\n"), "{local}");
    world.lose = vec![4];
    for seq in 1..=50u16 {
        world.send_sized(sender, seq, 111, OPUS_24K_PAYLOAD)?;
    }
    let on_wire: Vec<u8> = world.wire.iter().map(|h| h.payload_type).collect();
    let octets: usize = world
        .wire
        .iter()
        .zip(&world.wire_sizes)
        .filter(|(h, _)| matches!(h.payload_type, 111 | 63))
        .map(|(_, size)| size)
        .sum();
    let received = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| (h.sequence_number, h.timestamp, h.payload_type))
        .collect();
    Ok((on_wire, octets, received))
}

/// The answer the sender applied, edited by `edit`.
fn answer_applied(edit: impl Fn(String) -> String) -> Result<String> {
    let (world, _) = World::connected(RtpCodecKind::Audio, edit)?;
    Ok(world.peers[0]
        .pc
        .remote_description()
        .expect("answer")
        .sdp
        .clone())
}

/// The Opus packets 1 to 50 as the receiving application gets them, without `missing`.
fn opus_packets_without(missing: &[u16]) -> Vec<(u16, u32, u8)> {
    (1..=50u16)
        .filter(|seq| !missing.contains(seq))
        .map(|seq| (seq, u32::from(seq) * 960, 111))
        .collect()
}

/// RFC 3264 sections 5.1 and 6.1: the formats of an m= line are "listed in order of
/// preference", and the sender "SHOULD use the format with the highest preference". Both
/// peers offer and answer RED after Opus (the default formats, Chromium's and WebKit's order),
/// so the sender sends Opus: payload type 111 on the wire, the same octets as a call whose
/// answer has no RED, and a loss stays a loss (Opus's in-band FEC is the codec's, RFC 8854
/// section 4.1).
#[test]
fn red_negotiated_after_opus_sends_opus_at_the_bitrate_of_a_call_without_red() -> Result<()> {
    let answer = answer_applied(|sdp| sdp)?;
    assert_eq!(audio_formats(&answer)[..2], ["111", "63"], "{answer}");
    let default = [AudioRedundancy::default(); 2];
    let (red_wire, red_octets, red_received) = opus_call(|sdp| sdp, default)?;
    let (plain_wire, plain_octets, plain_received) = opus_call(without_red, default)?;
    println!(
        "24 kbit/s Opus, RED negotiated after Opus: {} octets/s on the wire ({:.1} kbit/s); \
         without RED: {} octets/s ({:.1} kbit/s); ratio {:.3}",
        red_octets,
        red_octets as f64 * 8.0 / 1000.0,
        plain_octets,
        plain_octets as f64 * 8.0 / 1000.0,
        red_octets as f64 / plain_octets as f64
    );
    assert_eq!(red_wire, vec![111; 50], "RED after Opus: Opus on the wire");
    assert_eq!(plain_wire, vec![111; 50]);
    assert_eq!(
        red_octets, plain_octets,
        "the same octets on the wire as a call without RED (ratio 1)"
    );
    assert_eq!(red_received, opus_packets_without(&[4]));
    assert_eq!(plain_received, opus_packets_without(&[4]));
    Ok(())
}

/// RFC 3264 section 6.1, RFC 2198 section 5: an answer that lists RED first prefers it, and
/// the sender sends RED (payload type 63) carrying a copy of the packet before; the network
/// loses one, and the receiving application still gets every Opus packet, the lost one
/// recovered from the next packet's copy, with its sequence number and timestamp. The wire
/// carries about twice the octets of the Opus call.
#[test]
fn red_first_in_the_answer_sends_red_and_recovers_a_lost_packet() -> Result<()> {
    let default = [AudioRedundancy::default(); 2];
    let (wire, octets, received) = opus_call(red_first, default)?;
    let (_, plain_octets, _) = opus_call(without_red, default)?;
    println!(
        "24 kbit/s Opus, RED first in the answer: {} octets/s on the wire ({:.1} kbit/s); \
         without RED: {} octets/s; ratio {:.3}",
        octets,
        octets as f64 * 8.0 / 1000.0,
        plain_octets,
        octets as f64 / plain_octets as f64
    );
    assert_eq!(wire, vec![63; 50], "RED first: RED on the wire");
    assert_eq!(received, opus_packets_without(&[]), "the loss recovered");
    assert!(
        octets as f64 > 1.5 * plain_octets as f64,
        "a copy of the packet before in each: {octets} vs {plain_octets}"
    );
    Ok(())
}

/// `with_audio_redundancy(Always)`, the application's request (RFC 8854 section 8): RED on
/// the wire whatever the answer's order, and the loss recovered. `Never`: Opus even when the
/// answer prefers RED.
#[test]
fn audio_redundancy_always_sends_red_in_any_order_and_never_sends_none() -> Result<()> {
    for (policy, red_is_first, expected) in [
        (AudioRedundancy::Always, false, 63u8),
        (AudioRedundancy::Always, true, 63),
        (AudioRedundancy::Never, true, 111),
    ] {
        let (wire, octets, received) = if red_is_first {
            opus_call(red_first, [policy, AudioRedundancy::default()])?
        } else {
            opus_call(|sdp| sdp, [policy, AudioRedundancy::default()])?
        };
        println!(
            "24 kbit/s Opus, {policy:?}, RED first: {red_is_first}: {} octets/s ({:.1} kbit/s)",
            octets,
            octets as f64 * 8.0 / 1000.0
        );
        assert_eq!(
            wire,
            vec![expected; 50],
            "{policy:?}, RED first: {red_is_first}"
        );
        let missing: &[u16] = if expected == 63 { &[] } else { &[4] };
        assert_eq!(
            received,
            opus_packets_without(missing),
            "{policy:?}, RED first: {red_is_first}"
        );
    }
    Ok(())
}

/// The setting is about sending: a receiver takes RED apart and recovers a loss whatever its
/// own `with_audio_redundancy` (RFC 8854 section 7: an endpoint "MUST be able to receive and
/// make use of" the FEC formats it indicated).
#[test]
fn received_red_is_decoded_in_every_mode() -> Result<()> {
    for receiver in [
        AudioRedundancy::WhenPreferred,
        AudioRedundancy::Always,
        AudioRedundancy::Never,
    ] {
        let (wire, _, received) = opus_call(|sdp| sdp, [AudioRedundancy::Always, receiver])?;
        assert_eq!(wire, vec![63; 50], "receiver {receiver:?}");
        assert_eq!(
            received,
            opus_packets_without(&[]),
            "receiver {receiver:?}: every packet, the lost one recovered"
        );
    }
    Ok(())
}

/// The payload type a sender's parameters give `mime`.
fn send_payload_type(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId, mime: &str) -> Option<u8> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime))
        .map(|c| c.payload_type)
}

/// W3C webrtc 4.4.1.4 / 5.4: `setCodecPreferences` names formats (the capabilities it takes
/// them from carry no payload type) and does not set the codecs a sender sends with; only
/// negotiation does. A sender whose transceiver has preferences reads, before the answer, the
/// payload types the engine gives those formats in its offer (Opus 111, PCMU 0, PCMA 8), never
/// the 0 every preference carries; after negotiation, new preferences leave the negotiated
/// codecs alone until the next answer. (An application that took Opus's number from the
/// parameters before the answer otherwise sent Opus as PCMU: the browser interop matrix's
/// clock-rate cells with Rust offering.)
#[test]
fn codec_preferences_do_not_renumber_the_formats_a_sender_sends() -> Result<()> {
    let mut pc = Peer::new("10.0.0.1:5000", false)?.pc;
    let transceiver = pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
    let sender = pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .expect("a sendonly transceiver has a sender");
    let preferences = |pc: &mut RTCPeerConnection, mimes: &[&str]| -> Vec<RTCRtpCodecParameters> {
        let capabilities = pc
            .rtp_sender(sender)
            .and_then(|s| s.get_capabilities(RtpCodecKind::Audio))
            .map(|c| c.codecs)
            .unwrap_or_default();
        mimes
            .iter()
            .flat_map(|mime| {
                capabilities
                    .iter()
                    .filter(|c| c.mime_type.eq_ignore_ascii_case(mime))
                    .map(|rtp_codec| RTCRtpCodecParameters {
                        rtp_codec: rtp_codec.clone(),
                        payload_type: 0,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let wanted = preferences(&mut pc, &["audio/opus", "audio/PCMU", "audio/PCMA"]);
    pc.rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_codec_preferences(wanted)?;
    assert_eq!(
        (
            send_payload_type(&mut pc, sender, "audio/opus"),
            send_payload_type(&mut pc, sender, "audio/PCMU"),
            send_payload_type(&mut pc, sender, "audio/PCMA"),
        ),
        (Some(111), Some(0), Some(8)),
        "before the answer: the engine's numbers for the preferred formats"
    );

    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let negotiated = send_payload_type(&mut world.peers[0].pc, sender, "audio/opus");
    assert_eq!(negotiated, Some(111));
    let transceiver = RTCRtpTransceiverId::from(sender);
    let pcmu_first = preferences(&mut world.peers[0].pc, &["audio/PCMU", "audio/opus"]);
    world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_codec_preferences(pcmu_first)?;
    assert_eq!(
        send_payload_type(&mut world.peers[0].pc, sender, "audio/opus"),
        Some(111),
        "negotiated: the preferences wait for the next negotiation"
    );
    let first = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .first()
        .map(|c| c.rtp_codec.mime_type.to_ascii_lowercase());
    assert_eq!(first.as_deref(), Some("audio/opus"), "the negotiated order");
    Ok(())
}
