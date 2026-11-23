//! Payload type numbers per direction (RFC 3264 sections 5.1 and 6.1, RFC 9429 sections 5.9
//! to 5.11), between two `rtc` peer connections in virtual time.
//!
//! RFC 3264 section 5.1: an offer's payload type numbers "indicate the value of the payload
//! type field the offerer expects to receive", and "the answer might indicate different
//! payload type numbers for the same codecs, in which case, the offerer MUST send with the
//! payload type numbers from the answer". Section 6.1, the answerer when it sends: "it MUST
//! use the payload type numbers from the offer, even if they differ from those in the
//! answer". RFC 9429 section 5.11: "The payload type mapping from the remote description is
//! used to determine payload types for the outgoing RTP streams".
//!
//! The answerer here numbers every format its own way
//! (`SettingEngineBuilder::with_own_payload_types_in_answers`), and the two numberings cross:
//! the offerer's VP8 number is the answerer's RTX number and the reverse, so an endpoint that
//! kept one numbering for both directions would read media as retransmissions. Audio is Opus
//! in RED (RFC 2198), video VP8 with RTX (RFC 4588) and FlexFEC-03.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::{FlexFec03ReceiveBuilder, FlexFec03SendBuilder, Registry, Slot};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_OPUS, MIME_TYPE_RED, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const FEC_FMTP: &str = "repair-window=10000000";

/// One endpoint's payload type numbers.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Numbers {
    opus: u8,
    red: u8,
    vp8: u8,
    rtx: u8,
    fec: u8,
}

/// The offerer's.
const OFFERER: Numbers = Numbers {
    opus: 111,
    red: 63,
    vp8: 96,
    rtx: 97,
    fec: 49,
};
/// The answerer's: none is the offerer's number for the same format, and VP8 and RTX are
/// the offerer's the other way round.
const ANSWERER: Numbers = Numbers {
    opus: 100,
    red: 101,
    vp8: 97,
    rtx: 96,
    fec: 98,
};
/// A third numbering, for a later description.
const THIRD: Numbers = Numbers {
    opus: 120,
    red: 121,
    vp8: 122,
    rtx: 123,
    fec: 124,
};

fn codec(mime_type: &str, clock_rate: u32, channels: u16, fmtp: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    }
}

fn media_engine(numbers: Numbers) -> Result<MediaEngine> {
    let mut media_engine = MediaEngine::default();
    for (rtp_codec, payload_type) in [
        (
            codec(MIME_TYPE_OPUS, 48000, 2, "minptime=10;useinbandfec=1"),
            numbers.opus,
        ),
        (
            codec(MIME_TYPE_RED, 48000, 2, &format!("{0}/{0}", numbers.opus)),
            numbers.red,
        ),
    ] {
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec,
                payload_type,
            },
            RtpCodecKind::Audio,
        )?;
    }
    for (rtp_codec, payload_type) in [
        (codec(MIME_TYPE_VP8, 90000, 0, ""), numbers.vp8),
        (
            codec(MIME_TYPE_RTX, 90000, 0, &format!("apt={}", numbers.vp8)),
            numbers.rtx,
        ),
        (codec(MIME_TYPE_FLEX_FEC03, 90000, 0, FEC_FMTP), numbers.fec),
    ] {
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec,
                payload_type,
            },
            RtpCodecKind::Video,
        )?;
    }
    Ok(media_engine)
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    audio: RTCRtpTransceiverId,
    video: RTCRtpTransceiverId,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    /// A peer that sends and receives audio and video, with the default interceptors (NACK
    /// and its responder among them, audio RED) and FlexFEC-03 at a fixed rate of one repair
    /// packet per five media packets.
    fn new(addr: &str, numbers: Numbers, own_payload_types_in_answers: bool) -> Result<Self> {
        let mut media_engine = media_engine(numbers)?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?
            .with(
                Slot::FecEncoder,
                FlexFec03SendBuilder::new()
                    .with_num_media_packets(5)
                    .with_num_fec_packets(1)
                    .with_adaptive_rate(false)
                    .build(),
            )
            .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build());
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_own_payload_types_in_answers(own_payload_types_in_answers)
                    .build(),
            )
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        let mut transceiver = |kind| {
            pc.add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendrecv,
                    streams: vec![],
                    send_encodings: vec![RTCRtpEncodingParameters {
                        active: true,
                        ..Default::default()
                    }],
                }),
            )
        };
        let audio = transceiver(RtpCodecKind::Audio)?;
        let video = transceiver(RtpCodecKind::Video)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            audio,
            video,
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

    /// The codecs of the sender's parameters: what this endpoint sends with.
    fn send_codecs(&mut self, transceiver: RTCRtpTransceiverId) -> Vec<RTCRtpCodecParameters> {
        let sender = self
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("sender");
        self.pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs
            .clone()
    }

    /// The codecs of the receiver's parameters: what this endpoint receives with.
    fn receive_codecs(&mut self, transceiver: RTCRtpTransceiverId) -> Vec<RTCRtpCodecParameters> {
        let receiver = self
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.receiver())
            .expect("receiver");
        self.pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .get_parameters()
            .rtp_parameters
            .codecs
            .clone()
    }

    /// The numbers the sender's parameters give the formats.
    fn send_numbers(&mut self) -> Numbers {
        numbers_of(&self.send_codecs(self.audio), &self.send_codecs(self.video))
    }

    /// The numbers the receiver's parameters give the formats.
    fn receive_numbers(&mut self) -> Numbers {
        numbers_of(
            &self.receive_codecs(self.audio),
            &self.receive_codecs(self.video),
        )
    }

    /// The SSRCs of the transceiver's sender: media, RTX, FEC.
    fn ssrcs(&mut self, transceiver: RTCRtpTransceiverId) -> (u32, Option<u32>, Option<u32>) {
        let sender = self
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("sender");
        let mut sender = self.pc.rtp_sender(sender).expect("sender");
        let coding = &sender.get_parameters().encodings[0].rtp_coding_parameters;
        (
            coding.ssrc.expect("an SSRC"),
            coding.rtx.as_ref().map(|rtx| rtx.ssrc),
            coding.fec.as_ref().map(|fec| fec.ssrc),
        )
    }

    fn write(
        &mut self,
        now: Instant,
        transceiver: RTCRtpTransceiverId,
        header: Header,
    ) -> Result<()> {
        let sender = self
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("sender");
        self.pc.rtp_sender(sender).expect("sender").write_rtp(
            now,
            rtc::rtp::Packet {
                header,
                payload: Bytes::from(vec![0x10u8; 100]),
            },
        )?;
        Ok(())
    }
}

/// The payload type of `mime` in `codecs`, 0 when it is not there.
fn number(codecs: &[RTCRtpCodecParameters], mime: &str) -> u8 {
    codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime))
        .map_or(0, |c| c.payload_type)
}

fn numbers_of(audio: &[RTCRtpCodecParameters], video: &[RTCRtpCodecParameters]) -> Numbers {
    Numbers {
        opus: number(audio, MIME_TYPE_OPUS),
        red: number(audio, MIME_TYPE_RED),
        vp8: number(video, MIME_TYPE_VP8),
        rtx: number(video, MIME_TYPE_RTX),
        fec: number(video, MIME_TYPE_FLEX_FEC03),
    }
}

/// The `a=fmtp` parameters of `mime` in `codecs`.
fn fmtp(codecs: &[RTCRtpCodecParameters], mime: &str) -> String {
    codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime))
        .map(|c| c.rtp_codec.sdp_fmtp_line.clone())
        .unwrap_or_default()
}

/// The numbers a description gives the formats, from its `a=rtpmap` lines, and the `a=fmtp`
/// lines of RTX and RED.
fn described(sdp: &str) -> (Numbers, String, String) {
    let of = |encoding: &str| -> u8 {
        sdp.lines()
            .filter_map(|l| l.strip_prefix("a=rtpmap:"))
            .find_map(|rest| {
                let (pt, name) = rest.split_once(' ')?;
                name.to_ascii_lowercase()
                    .starts_with(encoding)
                    .then(|| pt.parse().ok())?
            })
            .unwrap_or(0)
    };
    let numbers = Numbers {
        opus: of("opus/"),
        red: of("red/"),
        vp8: of("vp8/"),
        rtx: of("rtx/"),
        fec: of("flexfec-03/"),
    };
    let fmtp_of = |pt: u8| {
        sdp.lines()
            .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
            .unwrap_or_default()
            .to_owned()
    };
    (numbers, fmtp_of(numbers.rtx), fmtp_of(numbers.red))
}

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear), or
/// `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

/// What the network loses of a peer's RTP.
#[derive(Clone, Copy)]
enum Loss {
    /// One packet of a stream.
    Packet { from: usize, ssrc: u32, seq: u16 },
    /// Every packet of a stream.
    Stream { from: usize, ssrc: u32 },
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The header of every RTP packet put on the wire, with the peer that sent it.
    wire: Vec<(usize, Header)>,
    lose: Vec<Loss>,
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
                if let Some(header) = wire_rtp_header(&data) {
                    let lost = self.lose.iter().any(|loss| match *loss {
                        Loss::Packet { from, ssrc, seq } => {
                            from == i && ssrc == header.ssrc && seq == header.sequence_number
                        }
                        Loss::Stream { from, ssrc } => from == i && ssrc == header.ssrc,
                    });
                    self.wire.push((i, header));
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

    fn run_for(&mut self, duration: Duration) -> Result<()> {
        let until = self.now + duration;
        self.run_until(until)
    }

    /// The first peer offers with [`OFFERER`]'s numbers; the second, whose codecs are
    /// registered with [`ANSWERER`]'s, answers with the offer's (`renumbering` false) or its
    /// own. Not connected yet. Returns the offer and the answer.
    fn negotiated(renumbering: bool) -> Result<(Self, String, String)> {
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", OFFERER, false)?,
                Peer::new("10.0.0.2:5000", ANSWERER, renumbering)?,
            ],
            now: Instant::now(),
            wire: Vec::new(),
            lose: Vec::new(),
        };
        let (offer, answer) = world.exchange(0)?;
        Ok((world, offer, answer))
    }

    /// An offer from peer `offerer`, answered by the other; both applied.
    fn exchange(&mut self, offerer: usize) -> Result<(String, String)> {
        let now = self.now;
        let answerer = 1 - offerer;
        let offer = self.peers[offerer].pc.create_offer(None)?;
        self.peers[offerer]
            .pc
            .set_local_description(now, offer.clone())?;
        self.peers[answerer]
            .pc
            .set_remote_description(now, offer.clone())?;
        let answer = self.peers[answerer].pc.create_answer(None)?;
        self.peers[answerer]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[offerer]
            .pc
            .set_remote_description(now, answer.clone())?;
        Ok((offer.sdp, answer.sdp))
    }

    fn connect(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = self.now;
        while !self.peers.iter().all(|p| p.connected) {
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected: {:?} / {:?}",
                    self.peers[0].states,
                    self.peers[1].states
                );
            }
            self.run_for(Duration::from_millis(10))?;
        }
        Ok(())
    }

    /// Peer `from` writes one packet of `mime` on its `audio` or video stream, numbered as
    /// its sender's parameters number the format, and `step` passes.
    fn send(&mut self, from: usize, audio: bool, seq: u16, step: Duration) -> Result<()> {
        let now = self.now;
        let peer = &mut self.peers[from];
        let transceiver = if audio { peer.audio } else { peer.video };
        let codecs = peer.send_codecs(transceiver);
        let (ssrc, _, _) = peer.ssrcs(transceiver);
        let (payload_type, clock_step) = if audio {
            (number(&codecs, MIME_TYPE_OPUS), 960)
        } else {
            (number(&codecs, MIME_TYPE_VP8), 3000)
        };
        peer.write(
            now,
            transceiver,
            Header {
                version: 2,
                payload_type,
                sequence_number: seq,
                timestamp: u32::from(seq) * clock_step,
                ssrc,
                marker: true,
                ..Default::default()
            },
        )?;
        self.pump()?;
        self.run_until(now + step)
    }

    /// The payload types peer `from` put on the wire with `ssrc`.
    fn wire_payload_types(&self, from: usize, ssrc: u32) -> Vec<u8> {
        let mut payload_types: Vec<u8> = self
            .wire
            .iter()
            .filter(|(peer, header)| *peer == from && header.ssrc == ssrc)
            .map(|(_, header)| header.payload_type)
            .collect();
        payload_types.sort_unstable();
        payload_types.dedup();
        payload_types
    }

    /// The sequence numbers the application of peer `at` read from `ssrc`, in order, each
    /// once, with the payload types they came with.
    fn read_from(&self, at: usize, ssrc: u32) -> (Vec<u16>, Vec<u8>) {
        let mut sequence_numbers: Vec<u16> = vec![];
        let mut payload_types: Vec<u8> = vec![];
        for header in self.peers[at].read_rtp.iter().filter(|h| h.ssrc == ssrc) {
            if !sequence_numbers.contains(&header.sequence_number) {
                sequence_numbers.push(header.sequence_number);
            }
            if !payload_types.contains(&header.payload_type) {
                payload_types.push(header.payload_type);
            }
        }
        sequence_numbers.sort_unstable();
        (sequence_numbers, payload_types)
    }
}

/// RFC 3264 section 5.1 (the offerer "MUST send with the payload type numbers from the
/// answer") and section 6.1 (the answerer "MUST use the payload type numbers from the offer"),
/// RFC 9429 sections 5.9 to 5.11, as the parameters show them (W3C webrtc-pc 5.2:
/// a sender's codecs are those "negotiated for sending", a receiver's those it "is prepared
/// to receive"): each side's sender lists the other side's numbers, its receiver its own,
/// with RTX `apt` and RED's encodings in the numbering of their list.
#[test]
fn each_direction_of_a_section_has_the_numbers_of_the_description_that_governs_it() -> Result<()> {
    let (mut world, offer, answer) = World::negotiated(true)?;

    let (offered, offered_apt, offered_red) = described(&offer);
    assert_eq!(
        offered, OFFERER,
        "the offer has the offerer's numbers:\n{offer}"
    );
    assert_eq!(offered_apt, format!("apt={}", OFFERER.vp8));
    assert_eq!(offered_red, format!("{0}/{0}", OFFERER.opus));
    let (answered, answered_apt, answered_red) = described(&answer);
    assert_eq!(
        answered, ANSWERER,
        "the answer renumbers every format:\n{answer}"
    );
    assert_eq!(
        answered_apt,
        format!("apt={}", ANSWERER.vp8),
        "the answer's RTX names its own VP8 number:\n{answer}"
    );
    assert_eq!(
        answered_red,
        format!("{0}/{0}", ANSWERER.opus),
        "the answer's RED names its own Opus number:\n{answer}"
    );

    for (i, (own, other)) in [(OFFERER, ANSWERER), (ANSWERER, OFFERER)]
        .into_iter()
        .enumerate()
    {
        let peer = &mut world.peers[i];
        assert_eq!(
            peer.send_numbers(),
            other,
            "peer {i} sends with the other side's numbers"
        );
        assert_eq!(
            peer.receive_numbers(),
            own,
            "peer {i} receives with its own numbers"
        );
        let (send_audio, send_video) = (peer.send_codecs(peer.audio), peer.send_codecs(peer.video));
        assert_eq!(
            fmtp(&send_video, MIME_TYPE_RTX),
            format!("apt={}", other.vp8)
        );
        assert_eq!(
            fmtp(&send_audio, MIME_TYPE_RED),
            format!("{0}/{0}", other.opus)
        );
        let (receive_audio, receive_video) = (
            peer.receive_codecs(peer.audio),
            peer.receive_codecs(peer.video),
        );
        assert_eq!(
            fmtp(&receive_video, MIME_TYPE_RTX),
            format!("apt={}", own.vp8)
        );
        assert_eq!(
            fmtp(&receive_audio, MIME_TYPE_RED),
            format!("{0}/{0}", own.opus)
        );
    }
    Ok(())
}

/// The same on the wire, both ways at once: every flow of each side (Opus in RED, VP8, its
/// retransmissions, its FEC) carries the payload types the OTHER side's description gave the
/// formats, and the receiving application gets every packet, the lost ones included, under
/// its own numbers: an audio packet recovered from the next RED packet's copy (RFC 2198), a
/// video packet resent over RTX after a NACK (RFC 4588), and one rebuilt from FlexFEC while
/// the retransmissions are lost too.
#[test]
fn media_and_repair_flows_carry_the_other_sides_numbers_both_ways() -> Result<()> {
    let (mut world, _, _) = World::negotiated(true)?;
    world.connect()?;

    let streams: Vec<_> = (0..2)
        .map(|i| {
            let peer = &mut world.peers[i];
            let (audio, _, _) = peer.ssrcs(peer.audio);
            let (video, rtx, fec) = peer.ssrcs(peer.video);
            (
                audio,
                video,
                rtx.expect("an RTX SSRC: RTX is negotiated"),
                fec.expect("a FEC SSRC: FlexFEC is negotiated"),
            )
        })
        .collect();

    // Audio: one packet of each side is lost.
    world.lose = (0..2)
        .map(|from| Loss::Packet {
            from,
            ssrc: streams[from].0,
            seq: 4,
        })
        .collect();
    for seq in 1..=6u16 {
        for from in 0..2 {
            world.send(from, true, seq, Duration::from_millis(10))?;
        }
    }

    // Video, first: a media packet is lost and so is the whole FEC flow, which leaves the
    // retransmission.
    world.lose = (0..2)
        .flat_map(|from| {
            [
                Loss::Packet {
                    from,
                    ssrc: streams[from].1,
                    seq: 1005,
                },
                Loss::Stream {
                    from,
                    ssrc: streams[from].3,
                },
            ]
        })
        .collect();
    for seq in 1000..1020u16 {
        for from in 0..2 {
            world.send(from, false, seq, Duration::from_millis(16))?;
        }
    }
    world.run_for(Duration::from_secs(1))?;
    let after_first: Vec<Vec<u16>> = (0..2)
        .map(|from| world.read_from(1 - from, streams[from].1).0)
        .collect();

    // Then: a media packet is lost and so is the whole RTX flow, which leaves the FEC.
    world.lose = (0..2)
        .flat_map(|from| {
            [
                Loss::Packet {
                    from,
                    ssrc: streams[from].1,
                    seq: 1032,
                },
                Loss::Stream {
                    from,
                    ssrc: streams[from].2,
                },
            ]
        })
        .collect();
    for seq in 1020..1050u16 {
        for from in 0..2 {
            world.send(from, false, seq, Duration::from_millis(16))?;
        }
    }
    world.run_for(Duration::from_secs(1))?;

    for (from, (own, other)) in [(OFFERER, ANSWERER), (ANSWERER, OFFERER)]
        .into_iter()
        .enumerate()
    {
        let to = 1 - from;
        let (audio, video, rtx, fec) = streams[from];
        assert_ne!(own, other);

        // RFC 3264 sections 5.1 and 6.1: on the wire, the receiving side's numbers.
        assert_eq!(
            world.wire_payload_types(from, audio),
            vec![other.red],
            "peer {from}: Opus goes out as RED under the other side's RED number"
        );
        assert_eq!(
            world.wire_payload_types(from, video),
            vec![other.vp8],
            "peer {from}: VP8 under the other side's VP8 number"
        );
        assert_eq!(
            world.wire_payload_types(from, rtx),
            vec![other.rtx],
            "peer {from}: retransmissions under the other side's RTX number"
        );
        assert_eq!(
            world.wire_payload_types(from, fec),
            vec![other.fec],
            "peer {from}: FEC under the other side's FlexFEC number"
        );

        // What the receiving application reads: everything, under its own numbers.
        let (sequence_numbers, payload_types) = world.read_from(to, audio);
        assert_eq!(
            sequence_numbers,
            (1..=6).collect::<Vec<u16>>(),
            "peer {to}: every Opus packet, the lost one from the next RED packet"
        );
        assert_eq!(
            payload_types,
            vec![other.opus],
            "peer {to}: as its own Opus"
        );
        assert_eq!(
            after_first[from],
            (1000..1020).collect::<Vec<u16>>(),
            "peer {to}: every VP8 packet, the lost one over RTX"
        );
        let (sequence_numbers, payload_types) = world.read_from(to, video);
        assert_eq!(
            sequence_numbers,
            (1000..1050).collect::<Vec<u16>>(),
            "peer {to}: every VP8 packet, the second lost one from FEC"
        );
        assert_eq!(payload_types, vec![other.vp8], "peer {to}: as its own VP8");
    }

    // W3C webrtc-stats: each RTP stream's codec is the one of its direction, with that
    // direction's payload type.
    let now = world.now;
    for (i, (own, other)) in [(OFFERER, ANSWERER), (ANSWERER, OFFERER)]
        .into_iter()
        .enumerate()
    {
        let report = world.peers[i].pc.get_stats(now, StatsSelector::None);
        let codec_payload_type = |codec_id: &str| -> Option<u8> {
            report.iter().find_map(|entry| match entry {
                RTCStatsReportEntry::Codec(codec) if codec.stats.id == codec_id => {
                    Some(codec.payload_type)
                }
                _ => None,
            })
        };
        let (mut outbound, mut inbound) = (vec![], vec![]);
        for entry in report.iter() {
            match entry {
                RTCStatsReportEntry::OutboundRtp(stream) => outbound.push(codec_payload_type(
                    &stream.sent_rtp_stream_stats.rtp_stream_stats.codec_id,
                )),
                RTCStatsReportEntry::InboundRtp(stream) => inbound.push(codec_payload_type(
                    &stream.received_rtp_stream_stats.rtp_stream_stats.codec_id,
                )),
                _ => {}
            }
        }
        outbound.sort_unstable();
        inbound.sort_unstable();
        let mut sent_with = vec![Some(other.opus), Some(other.vp8)];
        sent_with.sort_unstable();
        let mut received_with = vec![Some(own.opus), Some(own.vp8)];
        received_with.sort_unstable();
        assert_eq!(outbound, sent_with, "peer {i}: outbound streams' codecs");
        assert_eq!(inbound, received_with, "peer {i}: inbound streams' codecs");
    }
    Ok(())
}

/// The numbers stay per direction across later exchanges, whoever offers (RFC 3264 section
/// 8.3.2: "the mapping from a particular dynamic payload type number to a particular codec
/// within that media stream MUST NOT change for the duration of a session"): each side's
/// later descriptions keep its own numbers, and so each side goes on sending with the
/// other's.
#[test]
fn later_offers_and_answers_keep_each_sides_numbers() -> Result<()> {
    let (mut world, _, _) = World::negotiated(true)?;
    for (round, offerer) in [0usize, 1, 0].into_iter().enumerate() {
        let (offer, answer) = world.exchange(offerer)?;
        let numbers = [OFFERER, ANSWERER];
        assert_eq!(
            described(&offer).0,
            numbers[offerer],
            "round {round}: the offer of peer {offerer}:\n{offer}"
        );
        assert_eq!(
            described(&answer).0,
            numbers[1 - offerer],
            "round {round}: the answer of peer {}:\n{answer}",
            1 - offerer
        );
        for i in 0..2 {
            assert_eq!(
                world.peers[i].send_numbers(),
                numbers[1 - i],
                "round {round}"
            );
            assert_eq!(
                world.peers[i].receive_numbers(),
                numbers[i],
                "round {round}"
            );
        }
    }
    Ok(())
}

/// A remote offer with other numbers moves what is sent to them when it is applied (RFC 9429
/// section 5.10: "the implementation records the payload type to be used in outgoing RTP
/// packets"), and a rollback brings back the numbers of the last answer (section 5.7: the
/// session returns to its state before the offer); what is received keeps this endpoint's
/// own numbers throughout.
#[test]
fn a_rollback_restores_the_numbers_of_both_directions() -> Result<()> {
    let (mut world, _, _) = World::negotiated(true)?;
    let now = world.now;
    let mut third = Peer::new("10.0.0.3:5000", THIRD, false)?;
    let offer = third.pc.create_offer(None)?;
    assert_eq!(described(&offer.sdp).0, THIRD);

    let offerer = &mut world.peers[0];
    offerer.pc.set_remote_description(now, offer)?;
    assert_eq!(offerer.send_numbers(), THIRD, "the pending offer's numbers");
    assert_eq!(offerer.receive_numbers(), OFFERER);

    offerer
        .pc
        .set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(
        offerer.send_numbers(),
        ANSWERER,
        "after the rollback: the last answer's numbers"
    );
    assert_eq!(offerer.receive_numbers(), OFFERER);
    Ok(())
}

/// With the default setting the answer uses the offer's numbers (RFC 3264 section 6.1: "that
/// same payload type number SHOULD be used for that codec in the answer"), whatever the
/// answerer registered, and both directions have them.
#[test]
fn by_default_an_answer_uses_the_offers_numbers() -> Result<()> {
    let (mut world, _, answer) = World::negotiated(false)?;
    assert_eq!(described(&answer).0, OFFERER, "{answer}");
    for i in 0..2 {
        assert_eq!(world.peers[i].send_numbers(), OFFERER);
        assert_eq!(world.peers[i].receive_numbers(), OFFERER);
    }
    Ok(())
}
