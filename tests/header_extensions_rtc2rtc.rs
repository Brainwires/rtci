//! Header extensions on the wire between two `rtci` peer connections, in virtual time: the
//! one-byte / two-byte form of a stream as `a=extmap-allow-mixed` was negotiated (RFC 8285
//! sections 4.1.2 and 6), and RFC 6904 header extension encryption once an extension is
//! negotiated in its encrypted form.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::{ExtensionForm, Header};
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        media_engine.register_header_extension(
            rtci::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability {
                uri: rtci::rtp::extension::ABS_CAPTURE_TIME_URI.to_owned(),
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
                    rtci::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy::Disable,
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
                rtci::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

/// The forms of the headers on the wire after the first, which carried a 20-byte element.
fn forms_after_a_long_element(
    edit: impl Fn(String) -> String,
) -> Result<Vec<Option<ExtensionForm>>> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, edit)?;
    // A negotiated extension (an element of an id that is not is not sent, RFC 8285 section
    // 4.1.2), the coordination of video orientation.
    let id = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == "urn:3gpp:video-orientation")
        .map(|e| u8::try_from(e.id))
        .expect("video orientation is negotiated")?;
    // An element of 20 bytes fits the two-byte form only (RFC 8285 section 4.2: 1 to 16).
    world.send(sender, 100, &[(id, &[0xAB; 20])])?;
    for seq in 101..106 {
        world.send(sender, seq, &[])?;
    }
    let wire = world.media_wire();
    assert_eq!(6, wire.len(), "every packet went out");
    assert_eq!(Some(ExtensionForm::TwoByte), wire[0].extension_form());
    Ok(wire[1..].iter().map(|h| h.extension_form()).collect())
}

/// RFC 8285 section 4.1.2: "A stream MUST contain only one-byte headers or only two-byte
/// headers unless it is known that all recipients support mixing", by `a=extmap-allow-mixed`
/// in the offer and the answer (section 6: "In the cases where the attribute has been
/// excluded, both clients SHALL NOT use mixed one-byte and two-byte extensions in the same
/// RTP stream"). With it, each packet takes the smallest form; without it, a stream that sent
/// the two-byte form keeps it.
#[test]
fn a_stream_mixes_header_forms_only_when_extmap_allow_mixed_was_negotiated() -> Result<()> {
    let mixed = forms_after_a_long_element(|sdp| sdp)?;
    assert!(
        mixed.iter().all(|f| *f == Some(ExtensionForm::OneByte)),
        "with mixing, later packets are one-byte: {mixed:?}"
    );
    let unmixed = forms_after_a_long_element(|sdp| sdp.replace("a=extmap-allow-mixed\r\n", ""))?;
    assert!(
        unmixed.iter().all(|f| *f == Some(ExtensionForm::TwoByte)),
        "without mixing, the stream stays two-byte: {unmixed:?}"
    );
    Ok(())
}

/// RFC 6904 sections 3 and 4: once the client-to-mixer audio level is negotiated encrypted
/// (both peers offer it best effort and answer the encrypted form), its element is encrypted
/// on the wire and decrypted for the receiving application; the other elements stay in the
/// clear.
#[test]
fn an_extension_negotiated_encrypted_is_encrypted_on_the_wire() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let level = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL)
        .cloned()
        .expect("the audio level is negotiated");
    assert!(
        level.encrypted,
        "negotiated in its encrypted form: {level:?}"
    );
    let id = u8::try_from(level.id)?;

    for seq in 0..8u16 {
        world.send(sender, 200 + seq, &[(id, &[0x2A])])?;
    }
    let wire = world.media_wire();
    assert_eq!(8, wire.len());
    let on_wire: Vec<Option<u8>> = wire
        .iter()
        .map(|h| h.get_extension(id).and_then(|v| v.first().copied()))
        .collect();
    assert!(
        on_wire.iter().all(|v| v.is_some()) && on_wire.iter().any(|v| *v != Some(0x2A)),
        "the element is encrypted on the wire: {on_wire:?}"
    );
    let received: Vec<Option<u8>> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.get_extension(id).and_then(|v| v.first().copied()))
        .collect();
    assert_eq!(
        vec![Some(0x2A); 8],
        received,
        "and decrypted for the receiver"
    );
    Ok(())
}

/// webrtc-extensions 8: a sender stamps a packet's absolute capture time
/// (`write_rtp_with_capture_time`, the `abs-capture-time` extension); the receiver's
/// synchronization source reports it as `captureTimestamp` with the offset as
/// `senderCaptureTimeOffset`, and a later packet without the extension reports a capture time
/// interpolated by its RTP timestamp, with the last offset.
#[test]
fn the_absolute_capture_time_reaches_the_receivers_synchronization_source() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            parameters.rtp_parameters.codecs[0].payload_type,
        )
    };
    let packet = |seq: u16, timestamp: u32| rtci::rtp::Packet {
        header: Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp,
            ssrc,
            marker: true,
            ..Default::default()
        },
        payload: Bytes::from(vec![0x10u8; 100]),
    };
    // 1000 s and a quarter on the capturer's NTP clock; the sender's clock half a second
    // ahead of it.
    let capture_ntp: u64 = (1000u64 << 32) | (1u64 << 30);
    let offset: i64 = 1 << 31;
    let capture_ms = 1_000_250.0;
    let source = |world: &mut World| {
        let receiver = world.peers[1]
            .pc
            .get_receivers()
            .next()
            .expect("a receiver");
        let receiver = world.peers[1].pc.rtp_receiver(receiver).expect("receiver");
        receiver
            .get_synchronization_sources()
            .find(|s| s.source == ssrc)
            .map(|s| (s.capture_timestamp, s.sender_capture_time_offset))
    };

    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_capture_time(now, packet(1, 90_000), capture_ntp, Some(offset))?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(20))?;
    assert_eq!(source(&mut world), Some((Some(capture_ms), Some(500.0))));

    // 100 ms later at 90 kHz, without the extension.
    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(now, packet(2, 99_000))?;
    world.pump()?;
    // (The pacer releases it by its RTP timestamp, 100 ms after the first.)
    world.run_until(now + Duration::from_millis(200))?;
    assert_eq!(
        source(&mut world),
        Some((Some(capture_ms + 100.0), Some(500.0)))
    );
    Ok(())
}

/// The voice activity flags of the receiver's synchronization sources.
fn voice_activity(world: &mut World) -> Vec<Option<bool>> {
    let transceiver = world.peers[1]
        .pc
        .get_transceivers()
        .next()
        .expect("transceiver");
    let receiver = world.peers[1]
        .pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.receiver())
        .expect("receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_synchronization_sources()
        .map(|source| source.voice_activity_flag)
        .collect()
}

/// RFC 6464 sections 3 and 4: the V bit of the client-to-mixer audio level says whether there
/// is voice; it is in use unless the extension was signalled `vad=off` (no attribute is
/// `vad=on`), and then a receiver "MUST" ignore it. The receiver's synchronization source
/// carries it (`voiceActivityFlag`) only then.
#[test]
fn the_v_bit_is_reported_unless_the_audio_level_was_signalled_vad_off() -> Result<()> {
    for (vad_off, expected) in [(false, vec![Some(true)]), (true, vec![None])] {
        let (mut world, sender) = World::connected_edited(
            RtpCodecKind::Audio,
            |offer| {
                if !vad_off {
                    return offer;
                }
                offer
                    .split("\r\n")
                    .map(|l| {
                        if l.starts_with("a=extmap:") && l.ends_with(AUDIO_LEVEL) {
                            format!("{l} vad=off")
                        } else {
                            l.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\r\n")
            },
            |answer| answer,
        )?;
        let level = world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .find(|e| e.uri == AUDIO_LEVEL)
            .cloned()
            .expect("the audio level is negotiated");
        let id = u8::try_from(level.id)?;
        // V set, level 42 -dBov.
        world.send(sender, 300, &[(id, &[0x80 | 0x2A])])?;
        assert_eq!(expected, voice_activity(&mut world), "vad=off: {vad_off}");
    }
    Ok(())
}

/// RFC 8285 section 4.1.2: an element in a stream has a negotiated id. One the application
/// puts in a packet under an id that is not negotiated is taken out; the others go.
#[test]
fn an_element_with_an_id_that_is_not_negotiated_is_not_sent() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let negotiated: Vec<u8> = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .filter_map(|e| u8::try_from(e.id).ok())
        .collect();
    let stray = (1..=14u8)
        .find(|id| !negotiated.contains(id))
        .expect("a free id");
    let kept = negotiated[0];
    world.send(sender, 400, &[(stray, &[0x55]), (kept, &[0x01])])?;
    let wire = world.media_wire();
    let last = wire.last().expect("the packet went out");
    assert_eq!(None, last.get_extension(stray), "{last:?}");
    assert!(last.get_extension(kept).is_some(), "{last:?}");
    Ok(())
}

/// RFC 9335 (Cryptex) end to end: with header encryption negotiated by both peers the header
/// extension block travels encrypted under the Cryptex profile (0xC0DE for the one-byte
/// form), and the receiver reads the elements as they were sent: here the absolute capture
/// time, which its synchronization source reports.
#[test]
fn with_cryptex_the_extensions_are_encrypted_on_the_wire_and_read_in_the_clear() -> Result<()> {
    use rtci::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
    let (mut world, sender) = World::connected_prepared(
        RtpCodecKind::Video,
        |sdp| sdp,
        |pc| {
            pc.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Negotiate)
                .expect("before any description")
        },
    )?;
    assert!(world.peers[0].pc.cryptex_negotiated());
    assert!(world.peers[1].pc.cryptex_negotiated());
    let (ssrc, pt) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            parameters.rtp_parameters.codecs[0].payload_type,
        )
    };
    let capture_ntp: u64 = 0x1122_3344_5566_7788;
    let now = world.now;
    let before = world.wire.len();
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_capture_time(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: pt,
                    sequence_number: 7,
                    timestamp: 90_000,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from(vec![0x10u8; 100]),
            },
            capture_ntp,
            None,
        )?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(20))?;
    let on_wire: Vec<&Header> = world.wire[before..]
        .iter()
        .filter(|h| h.ssrc == ssrc)
        .collect();
    assert_eq!(on_wire.len(), 1);
    assert!(
        matches!(on_wire[0].extension_profile, 0xC0DE | 0xC2DE),
        "the Cryptex profile: {:#x}",
        on_wire[0].extension_profile
    );
    let clear = capture_ntp.to_be_bytes();
    assert!(
        on_wire[0]
            .extensions
            .iter()
            .all(|e| !e.payload.windows(8).any(|w| w == clear)),
        "no element is in the clear on the wire"
    );
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    let capture = world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_synchronization_sources()
        .find(|s| s.source == ssrc)
        .and_then(|s| s.capture_timestamp);
    let expected = capture_ntp as f64 / 4_294_967_296.0 * 1000.0;
    assert_eq!(capture, Some(expected));

    // RFC 9335 section 4: without the peer's support (one side does not offer it), Cryptex is
    // not used: the RFC 8285 profile, the element in the clear.
    let (mut world, sender) = World::connected_prepared(RtpCodecKind::Video, |sdp| sdp, |_| {})?;
    assert!(!world.peers[0].pc.cryptex_negotiated());
    let plain_ssrc = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings[0]
        .rtp_coding_parameters
        .ssrc
        .expect("an SSRC");
    let now = world.now;
    let before = world.wire.len();
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_capture_time(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: pt,
                    sequence_number: 7,
                    timestamp: 90_000,
                    ssrc: plain_ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from(vec![0x10u8; 100]),
            },
            capture_ntp,
            None,
        )?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(20))?;
    let header = world.wire[before..]
        .iter()
        .find(|h| h.payload_type == pt)
        .expect("the packet");
    assert_eq!(header.extension_profile, 0xBEDE);
    assert!(
        header
            .extensions
            .iter()
            .any(|e| e.payload.windows(8).any(|w| w == clear)),
        "in the clear without Cryptex"
    );
    Ok(())
}

const VIDEO_ORIENTATION: &str = "urn:3gpp:video-orientation";

/// The id a description maps `uri` to, if it has an `a=extmap` line for it.
fn extmap_id(sdp: &str, uri: &str) -> Option<u8> {
    sdp.lines().find_map(|l| {
        let rest = l.strip_prefix("a=extmap:")?;
        let (id, rest) = rest.split_once(' ')?;
        (rest.split(' ').next() == Some(uri))
            .then(|| id.split('/').next()?.parse().ok())
            .flatten()
    })
}

/// RFC 7742 section 4: an endpoint that can produce video in other orientations "MUST
/// support generating the R0 and R1 bits of the Coordination of Video Orientation (CVO)
/// mechanism ... and MUST send them for all orientations when the peer indicates support".
/// CVO is among the default header extensions; a frame written with each of the four
/// rotations (and the back camera, flipped, once) reaches the receiving application with its
/// CVO element. A peer that leaves `urn:3gpp:video-orientation` out of its answer gets no
/// element: the sender only sends what was negotiated.
#[test]
fn every_video_orientation_is_sent_when_the_peer_indicates_support() -> Result<()> {
    use rtci::rtp::extension::video_orientation_extension::{
        CameraDirection, VideoOrientationExtension, VideoRotation,
    };
    let orientations: Vec<VideoOrientationExtension> = [
        VideoRotation::Degree0,
        VideoRotation::Degree90,
        VideoRotation::Degree180,
        VideoRotation::Degree270,
    ]
    .into_iter()
    .map(|rotation| VideoOrientationExtension {
        rotation,
        ..Default::default()
    })
    .chain([VideoOrientationExtension {
        direction: CameraDirection::Back,
        flip: true,
        rotation: VideoRotation::Degree90,
    }])
    .collect();
    for supported in [true, false] {
        let (mut world, sender) = World::connected(RtpCodecKind::Video, |answer| {
            if supported {
                return answer;
            }
            answer
                .split("\r\n")
                .filter(|l| !(l.starts_with("a=extmap:") && l.ends_with(VIDEO_ORIENTATION)))
                .collect::<Vec<_>>()
                .join("\r\n")
        })?;
        let offer = world.peers[0]
            .pc
            .local_description()
            .expect("the offer")
            .sdp;
        let id = extmap_id(&offer, VIDEO_ORIENTATION).expect("CVO is offered by default");
        let (ssrc, pt) = {
            let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
            let parameters = sender.get_parameters();
            (
                parameters.encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
                parameters.rtp_parameters.codecs[0].payload_type,
            )
        };
        world.media_ssrc = Some(ssrc);
        for (n, orientation) in orientations.iter().enumerate() {
            let now = world.now;
            let seq = 500 + n as u16;
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp_with_video_orientation(
                    now,
                    rtci::rtp::Packet {
                        header: Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: seq,
                            timestamp: u32::from(seq) * 3000,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 100]),
                    },
                    *orientation,
                )?;
            world.pump()?;
            world.run_until(now + Duration::from_millis(33))?;
        }
        let read: Vec<Option<VideoOrientationExtension>> = world.peers[1]
            .read_rtp
            .iter()
            .filter(|h| h.ssrc == ssrc && h.sequence_number >= 500)
            .map(|h| {
                h.get_extension(id)
                    .map(|mut value| VideoOrientationExtension::unmarshal(&mut value))
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        if supported {
            assert_eq!(
                read,
                orientations.iter().copied().map(Some).collect::<Vec<_>>(),
                "every orientation, as it was written"
            );
        } else {
            assert_eq!(read.len(), orientations.len(), "every frame was read");
            assert!(
                read.iter().all(Option::is_none),
                "no CVO element without the peer's support: {read:?}"
            );
            assert!(
                world
                    .media_wire()
                    .iter()
                    .all(|h| h.get_extension(id).is_none()),
                "none on the wire either"
            );
        }
    }
    Ok(())
}

/// `sdp` without its `a=extmap` lines for the audio level.
fn without_audio_level(sdp: &str) -> String {
    sdp.split("\r\n")
        .filter(|line| !(line.starts_with("a=extmap:") && line.contains(AUDIO_LEVEL)))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// `sdp` with `a=extmap:<id> <audio level>` after the `a=mid` line of its section.
fn with_audio_level(sdp: &str, id: u8) -> String {
    sdp.split("\r\n")
        .flat_map(|line| {
            let mut lines = vec![line.to_owned()];
            if line.starts_with("a=mid:") {
                lines.push(format!("a=extmap:{id} {AUDIO_LEVEL}"));
            }
            lines
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The receiver's synchronization sources: (audio level, voice activity flag).
fn audio_levels(world: &mut World) -> Vec<(Option<f64>, Option<bool>)> {
    let transceiver = world.peers[1]
        .pc
        .get_transceivers()
        .next()
        .expect("transceiver");
    let receiver = world.peers[1]
        .pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.receiver())
        .expect("receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_synchronization_sources()
        .map(|source| (source.audio_level, source.voice_activity_flag))
        .collect()
}

/// RFC 8834 section 10: "The use of any additional RTP header extensions ... MUST be
/// signaled", and "implementations are REQUIRED to ignore unknown RTCP packets and RTP
/// header extensions"; RFC 8285 section 4.1.2 has the element's id be "one that has been
/// negotiated". A sender that puts an audio level element (RFC 6464) under an id the
/// receiver's section does not signal: the packet is delivered and the element is not read
/// as an audio level (`audioLevel` and `voiceActivityFlag` stay unset). Twice: the receiver
/// was never offered the extension (the offer lost its `a=extmap` on the way, the sender
/// believes the answer has it); and the extension was negotiated, then a later offer leaves
/// it out and the receiver's answer with it (the sender again believes it is still on).
#[test]
fn an_audio_level_element_the_section_does_not_signal_is_ignored() -> Result<()> {
    use std::cell::Cell;
    let level: &[u8] = &[0x80 | 0x2A];

    // Never signalled to the receiver.
    let offered = Cell::new(0u8);
    let (mut world, sender) = World::connected_edited(
        RtpCodecKind::Audio,
        |offer| {
            offered.set(extmap_id(&offer, AUDIO_LEVEL).expect("the offer has the audio level"));
            without_audio_level(&offer)
        },
        |answer| with_audio_level(&answer, offered.get()),
    )?;
    let id = offered.get();
    assert!(
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .any(|e| e.uri == AUDIO_LEVEL && e.id == u16::from(id)),
        "the sender sends the audio level"
    );
    world.send(sender, 500, &[(id, level)])?;
    let on_wire = world
        .media_wire()
        .last()
        .map(|h| h.get_extension(id).is_some());
    assert_eq!(Some(true), on_wire, "the element is on the wire");
    assert!(
        world.peers[1]
            .read_rtp
            .iter()
            .any(|h| h.sequence_number == 500),
        "the packet is delivered"
    );
    assert_eq!(
        vec![(None, None)],
        audio_levels(&mut world),
        "never signalled: the element is ignored"
    );

    // Negotiated, then left out of a later offer and answer.
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let id = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL)
        .map(|e| u8::try_from(e.id))
        .expect("the audio level is negotiated")?;
    world.send(sender, 600, &[(id, level)])?;
    let negotiated = audio_levels(&mut world);
    assert_eq!(1, negotiated.len());
    assert!(
        negotiated[0].0.is_some(),
        "negotiated, the level is read: {negotiated:?}"
    );

    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(
        now,
        RTCSessionDescription::offer(without_audio_level(&offer.sdp))?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert_eq!(
        None,
        extmap_id(&answer.sdp, AUDIO_LEVEL),
        "the receiver's answer leaves it out"
    );
    world.peers[0].pc.set_remote_description(
        now,
        RTCSessionDescription::answer(with_audio_level(&answer.sdp, id))?,
    )?;
    world.pump()?;
    world.send(sender, 601, &[(id, level)])?;
    assert!(
        world.peers[1]
            .read_rtp
            .iter()
            .any(|h| h.sequence_number == 601),
        "the packet is delivered"
    );
    assert_eq!(
        vec![(None, None)],
        audio_levels(&mut world),
        "no longer signalled: the element is ignored"
    );
    Ok(())
}
