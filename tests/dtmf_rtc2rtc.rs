//! W3C webrtc-pc section 7, `RTCDTMFSender`, and RFC 4733: tones inserted at an audio sender
//! play out as telephone-event packets in its RTP stream, with `tonechange` events, the
//! spec's bounds, the `,` pause, the final packet three times one update interval apart, and
//! the stream's sequence numbers shared with the application's audio packets.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use bytes::Bytes;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::codec::telephone_event::{
    TelephoneEvent, TelephoneEventReceiver, TelephoneEventReport, dtmf_char_from_event,
};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId};
use rtci::sansio::Protocol;
use rtci::shared::error::Error;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const AUDIO_SSRC: u32 = 4242;

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
    rtp: Vec<(Instant, rtci::rtp::Packet)>,
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

    fn tone_changes(&self) -> Vec<(Instant, String)> {
        self.events
            .iter()
            .filter_map(|(at, e)| match e {
                RTCPeerConnectionEvent::OnDtmfToneChange(change) => {
                    Some((*at, change.tone.clone()))
                }
                _ => None,
            })
            .collect()
    }
}

struct Call {
    caller: Peer,
    callee: Peer,
    now: Instant,
    sender: RTCRtpSenderId,
}

impl Call {
    /// A connected call: the caller sends one Opus stream with SSRC `AUDIO_SSRC`.
    fn connected(port: u16) -> Result<Self> {
        Self::connected_with(port, |sdp| sdp)
    }

    /// As [`Self::connected`], the callee's answer passed through `edit` first.
    fn connected_with(port: u16, edit: impl Fn(String) -> String) -> Result<Self> {
        let now = Instant::now();
        let mut caller = Peer::new(
            format!("127.0.0.1:{port}").parse()?,
            RTCDtlsRole::Client,
            now,
        )?;
        let callee = Peer::new(
            format!("127.0.0.1:{}", port + 1).parse()?,
            RTCDtlsRole::Server,
            now,
        )?;
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "audio".to_owned(),
            "audio".to_owned(),
            RtpCodecKind::Audio,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(AUDIO_SSRC),
                    ..Default::default()
                },
                codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    ..Default::default()
                },
                ..Default::default()
            }],
        );
        let sender = caller.pc.add_track(track)?;
        let mut call = Self {
            caller,
            callee,
            now,
            sender,
        };
        assert!(
            !call.can_insert(),
            "no DTMF before the connection is connected"
        );
        assert!(
            matches!(call.insert("1", None, None), Err(Error::InvalidStateError)),
            "insertDTMF throws InvalidStateError when DTMF cannot be sent"
        );
        let offer = call.caller.pc.create_offer(None)?;
        call.caller.pc.set_local_description(now, offer.clone())?;
        call.callee.pc.set_remote_description(now, offer)?;
        let answer = call.callee.pc.create_answer(None)?;
        call.callee.pc.set_local_description(now, answer.clone())?;
        call.caller
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(edit(answer.sdp))?)?;
        let (a, b) = (call.caller.addr, call.callee.addr);
        call.caller.pc.add_local_candidate(host(a)?)?;
        call.callee.pc.add_local_candidate(host(b)?)?;
        call.caller.pc.add_remote_candidate(host(b)?)?;
        call.callee.pc.add_remote_candidate(host(a)?)?;
        call.run_until(Duration::from_secs(10), |c| {
            c.caller.pc.connection_state() == RTCPeerConnectionState::Connected
                && c.callee.pc.connection_state() == RTCPeerConnectionState::Connected
        })?;
        Ok(call)
    }

    fn can_insert(&mut self) -> bool {
        let mut sender = self.caller.pc.rtp_sender(self.sender).expect("sender");
        sender
            .dtmf()
            .expect("an audio sender's DTMF sender")
            .can_insert_dtmf()
    }

    fn insert(
        &mut self,
        tones: &str,
        duration: Option<Duration>,
        gap: Option<Duration>,
    ) -> rtci::shared::error::Result<()> {
        let now = self.now;
        let mut sender = self.caller.pc.rtp_sender(self.sender).expect("sender");
        sender
            .dtmf()
            .expect("dtmf")
            .insert_dtmf(now, tones, duration, gap)
    }

    fn tone_buffer(&mut self) -> String {
        let mut sender = self.caller.pc.rtp_sender(self.sender).expect("sender");
        sender.dtmf().expect("dtmf").tone_buffer().to_owned()
    }

    fn write_audio(&mut self, seq: u16, timestamp: u32) -> Result<()> {
        let now = self.now;
        let mut sender = self.caller.pc.rtp_sender(self.sender).expect("sender");
        sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header: rtci::rtp::header::Header {
                    version: 2,
                    payload_type: 111,
                    sequence_number: seq,
                    timestamp,
                    ssrc: AUDIO_SSRC,
                    ..Default::default()
                },
                payload: Bytes::from_static(&[0xF8, 0xFF, 0xFE]),
            },
        )?;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        let now = self.now;
        let written = self.caller.turn(now)?;
        self.callee.deliver(self.caller.addr, written, now);
        let written = self.callee.turn(now)?;
        self.caller.deliver(self.callee.addr, written, now);
        Ok(())
    }

    /// Runs until `done` or `span` of virtual time passed, timer by timer.
    fn run_until(&mut self, span: Duration, done: impl Fn(&Call) -> bool) -> Result<()> {
        let until = self.now + span;
        for _ in 0..100_000 {
            self.step()?;
            if done(self) || self.now >= until {
                return Ok(());
            }
            if self.caller.inbox.is_empty() && self.callee.inbox.is_empty() {
                let next = [self.caller.pc.poll_timeout(), self.callee.pc.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min()
                    .map_or(until, |next| next.min(until));
                self.now = self.now.max(next);
                self.caller.pc.handle_timeout(self.now)?;
                self.callee.pc.handle_timeout(self.now)?;
            }
        }
        Ok(())
    }

    /// The telephone-event packets the callee received: (arrival, packet, report).
    fn events_received(&self) -> Vec<(Instant, rtci::rtp::Packet, TelephoneEvent)> {
        self.callee
            .rtp
            .iter()
            .filter(|(_, p)| p.header.payload_type != 111)
            .map(|(at, p)| {
                let mut payload = p.payload.clone();
                let report = TelephoneEvent::unmarshal(&mut payload).expect("an event report");
                (*at, p.clone(), report)
            })
            .collect()
    }
}

/// W3C 7.2 insertDTMF and the playout task: the tones play one after the other, each for
/// [[Duration]] then [[InterToneGap]] (both clamped to their bounds), with a `tonechange` as
/// each begins and an empty one at the end; `toneBuffer` holds what is still to play; `a` is
/// `A`. RFC 4733: the first packet of a tone has M, its final packet has E and goes three
/// times, 50 ms apart, with the same timestamp.
#[test]
fn tones_play_out_as_telephone_events_with_tone_changes() -> Result<()> {
    let mut call = Call::connected(53010)?;
    assert!(
        call.can_insert(),
        "connected, sending, telephone-event negotiated"
    );
    let start = call.now;
    // 10 ms is below the 40 ms minimum tone, 10 ms below the 30 ms minimum gap.
    call.insert(
        "1a",
        Some(Duration::from_millis(10)),
        Some(Duration::from_millis(10)),
    )?;
    assert_eq!(call.tone_buffer(), "1A");
    call.run_until(Duration::from_secs(2), |c| {
        c.caller.tone_changes().iter().any(|(_, t)| t.is_empty())
    })?;
    call.run_until(Duration::from_millis(300), |_| false)?;

    let changes: Vec<(Duration, String)> = call
        .caller
        .tone_changes()
        .into_iter()
        .map(|(at, tone)| (at - start, tone))
        .collect();
    let tones: Vec<&str> = changes.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(tones, ["1", "A", ""]);
    // The second tone begins 40 ms (the clamped duration) + 30 ms (the clamped gap) later.
    assert_eq!(changes[1].0 - changes[0].0, Duration::from_millis(70));
    assert_eq!(call.tone_buffer(), "");

    let received = call.events_received();
    let of = |event: u8| -> Vec<&(Instant, rtci::rtp::Packet, TelephoneEvent)> {
        received
            .iter()
            .filter(|(_, _, r)| r.event == event)
            .collect()
    };
    for event in [1u8, 12] {
        let packets = of(event);
        assert!(packets[0].1.header.marker, "M on the first packet");
        assert_eq!(
            packets.iter().filter(|(_, p, _)| p.header.marker).count(),
            1
        );
        let finals: Vec<_> = packets.iter().filter(|(_, _, r)| r.end).collect();
        assert_eq!(finals.len(), 3, "the final packet three times");
        assert!(finals.iter().all(
            |(_, p, r)| p.header.timestamp == packets[0].1.header.timestamp
                && r.duration == 40 * 48
        ));
        assert_eq!(finals[1].0 - finals[0].0, Duration::from_millis(50));
        assert_eq!(finals[2].0 - finals[1].0, Duration::from_millis(50));
    }
    Ok(())
}

/// W3C 7.2: `,` is a two-second pause, announced like a tone.
#[test]
fn a_comma_pauses_two_seconds() -> Result<()> {
    let mut call = Call::connected(53020)?;
    call.insert(",1", None, None)?;
    call.run_until(Duration::from_secs(4), |c| {
        c.caller.tone_changes().iter().any(|(_, t)| t.is_empty())
    })?;
    let changes = call.caller.tone_changes();
    let tones: Vec<&str> = changes.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(tones, [",", "1", ""]);
    assert_eq!(changes[1].0 - changes[0].0, Duration::from_secs(2));
    Ok(())
}

/// W3C 7.2: a character other than the DTMF tones is an InvalidCharacterError and changes
/// nothing; an empty buffer cancels what is not yet begun; only an audio sender has one.
#[test]
fn insert_dtmf_refuses_unknown_characters_and_an_empty_string_cancels() -> Result<()> {
    let mut call = Call::connected(53030)?;
    assert!(matches!(
        call.insert("12x", None, None),
        Err(Error::ErrDtmfInvalidCharacter('x'))
    ));
    assert_eq!(call.tone_buffer(), "");
    call.insert("123", None, None)?;
    call.run_until(Duration::from_millis(10), |c| {
        !c.caller.tone_changes().is_empty()
    })?;
    assert_eq!(call.tone_buffer(), "23");
    call.insert("", None, None)?;
    call.run_until(Duration::from_secs(1), |_| false)?;
    let tones: Vec<String> = call
        .caller
        .tone_changes()
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    assert_eq!(tones, ["1", ""], "the queued tones were cancelled");

    let video = call
        .caller
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let mut sender = call
        .caller
        .pc
        .rtp_sender(RTCRtpSenderId::from(video))
        .expect("sender");
    assert!(sender.dtmf().is_none(), "a video sender has no DTMF sender");
    Ok(())
}

/// RFC 4733 section 2.5.1.2: event packets share the audio stream's sequence numbers. Those
/// sent between two audio packets take the numbers after the first; the second audio packet
/// comes after them.
#[test]
fn event_packets_share_the_audio_streams_sequence_numbers() -> Result<()> {
    let mut call = Call::connected(53040)?;
    call.write_audio(1000, 96_000)?;
    call.insert("5", Some(Duration::from_millis(40)), None)?;
    call.run_until(Duration::from_secs(1), |c| {
        c.caller.tone_changes().iter().any(|(_, t)| t.is_empty())
    })?;
    call.write_audio(1001, 96_000 + 48_000)?;
    call.run_until(Duration::from_millis(100), |_| false)?;
    // The first audio packet of the stream may be held by the receiver's source validation
    // (RFC 3550 appendix A.1); what matters is what was sent after it: one number space, no
    // gap, the application's packet 1001 among the event packets (it was written between
    // the repeats of the final report) and numbered after those sent before it.
    let after: Vec<(u8, u16)> = call
        .callee
        .rtp
        .iter()
        .map(|(_, p)| (p.header.payload_type, p.header.sequence_number))
        .filter(|(_, seq)| *seq > 1000)
        .collect();
    let numbers: Vec<u16> = after.iter().map(|(_, seq)| *seq).collect();
    let expected: Vec<u16> = (1001..1001 + numbers.len() as u16).collect();
    assert_eq!(numbers, expected, "{after:?}");
    assert_eq!(
        after.iter().filter(|(pt, _)| *pt == 111).count(),
        1,
        "the application's packet 1001, renumbered: {after:?}"
    );
    assert!(after.first().is_some_and(|(pt, _)| *pt != 111), "{after:?}");
    let events = call.events_received();
    assert!(
        events.iter().all(|(_, p, _)| p.header.ssrc == AUDIO_SSRC),
        "in the audio stream"
    );
    assert!(
        events
            .iter()
            .all(|(_, p, _)| p.header.timestamp.wrapping_sub(96_000) < 48_000),
        "timestamps follow the audio packet's"
    );
    Ok(())
}

impl Call {
    /// A new offer from the caller and the callee's answer, applied on both sides.
    fn renegotiate(&mut self) -> Result<()> {
        let now = self.now;
        let offer = self.caller.pc.create_offer(None)?;
        self.caller.pc.set_local_description(now, offer.clone())?;
        self.callee.pc.set_remote_description(now, offer)?;
        let answer = self.callee.pc.create_answer(None)?;
        self.callee.pc.set_local_description(now, answer.clone())?;
        self.caller.pc.set_remote_description(now, answer)?;
        self.run_until(Duration::from_millis(200), |_| false)
    }

    fn set_first_encoding_active(&mut self, active: bool) -> Result<()> {
        let mut sender = self.caller.pc.rtp_sender(self.sender).expect("sender");
        let mut parameters = sender.get_parameters().clone();
        parameters.encodings[0].active = active;
        sender.set_parameters(parameters, None)?;
        Ok(())
    }
}

/// `sdp` without the telephone-event formats.
fn without_telephone_event(sdp: String) -> String {
    let pts: Vec<String> = sdp
        .lines()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .filter(|v| v.to_ascii_lowercase().contains("telephone-event/"))
        .filter_map(|v| v.split_whitespace().next().map(str::to_owned))
        .collect();
    sdp.lines()
        .filter(|l| {
            !pts.iter().any(|pt| {
                l.starts_with(&format!("a=rtpmap:{pt} ")) || l.starts_with(&format!("a=fmtp:{pt} "))
            })
        })
        .map(|l| {
            if l.starts_with("m=audio") {
                l.split(' ')
                    .filter(|f| !pts.iter().any(|pt| pt == f))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

/// W3C 7.3 canInsertDTMF ("determine if DTMF can be sent") is false when telephone-event was
/// not negotiated for sending, and insertDTMF is then an InvalidStateError.
#[test]
fn dtmf_cannot_be_sent_without_a_negotiated_telephone_event() -> Result<()> {
    let mut call = Call::connected_with(53110, without_telephone_event)?;
    assert!(!call.can_insert());
    assert!(matches!(
        call.insert("1", None, None),
        Err(Error::InvalidStateError)
    ));
    Ok(())
}

/// W3C 7.3 canInsertDTMF is false when the sender's first encoding is inactive, and true
/// again once it is active.
#[test]
fn dtmf_cannot_be_sent_while_the_first_encoding_is_inactive() -> Result<()> {
    let mut call = Call::connected(53120)?;
    assert!(call.can_insert());
    call.set_first_encoding_active(false)?;
    assert!(!call.can_insert());
    call.set_first_encoding_active(true)?;
    assert!(call.can_insert());
    Ok(())
}

/// W3C 7.3 canInsertDTMF is false when the sender has no track.
#[test]
fn dtmf_cannot_be_sent_without_a_track() -> Result<()> {
    let mut call = Call::connected(53130)?;
    let sender = call.sender;
    call.caller.pc.remove_track(sender)?;
    assert!(!call.can_insert());
    Ok(())
}

/// W3C 7.3 canInsertDTMF is false unless the transceiver's currentDirection sends: after a
/// renegotiation to recvonly it is false.
#[test]
fn dtmf_cannot_be_sent_unless_the_current_direction_sends() -> Result<()> {
    let mut call = Call::connected(53140)?;
    let transceiver = RTCRtpTransceiverId::from(call.sender);
    call.caller
        .pc
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Recvonly)?;
    assert!(
        call.can_insert(),
        "currentDirection changes with the answer only"
    );
    call.renegotiate()?;
    assert!(!call.can_insert());
    Ok(())
}

/// W3C 7.3 canInsertDTMF is false once the transceiver is stopping.
#[test]
fn dtmf_cannot_be_sent_by_a_stopping_transceiver() -> Result<()> {
    let mut call = Call::connected(53150)?;
    let transceiver = RTCRtpTransceiverId::from(call.sender);
    call.caller
        .pc
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .stop()?;
    let can = call
        .caller
        .pc
        .rtp_sender(call.sender)
        .and_then(|mut s| s.dtmf().map(|mut d| d.can_insert_dtmf()))
        .unwrap_or(false);
    assert!(!can);
    Ok(())
}

/// W3C 7.2 playout task: when DTMF can no longer be sent the task aborts: the tones left are
/// not played.
#[test]
fn the_playout_stops_when_dtmf_can_no_longer_be_sent() -> Result<()> {
    let mut call = Call::connected(53160)?;
    call.insert("123", None, None)?;
    call.run_until(Duration::from_millis(50), |_| false)?;
    assert_eq!(call.caller.tone_changes().len(), 1, "the first tone began");
    call.set_first_encoding_active(false)?;
    call.run_until(Duration::from_secs(2), |_| false)?;
    let tones: Vec<String> = call
        .caller
        .tone_changes()
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    assert!(
        !tones.iter().any(|t| t == "2" || t == "3"),
        "no tone after the sender stopped: {tones:?}"
    );
    Ok(())
}

/// What the callee's application makes of the telephone-event packets it received, consumed
/// with RFC 4733's receiving procedures: each event that ended, as its DTMF character, with
/// its total duration in timestamp units.
fn events_consumed(call: &Call) -> Vec<(char, u32)> {
    let mut receiver = TelephoneEventReceiver::new();
    let mut consumed = Vec::new();
    for (_, packet, _) in call.events_received() {
        let reports = receiver
            .receive(
                packet.header.timestamp,
                packet.header.marker,
                &packet.payload,
            )
            .expect("a well-formed event packet");
        for report in reports {
            if let TelephoneEventReport::Ended {
                event,
                total_duration,
            } = report
            {
                consumed.push((
                    dtmf_char_from_event(event).expect("a DTMF event"),
                    total_duration,
                ));
            }
        }
    }
    consumed
}

/// RFC 7874 section 3: "Generated DTMF events MUST last no more than 8000 ms and no less than
/// 40 ms (default 100 ms)" and the gap "MUST be at least 30 ms (default 70 ms)". A tone asked
/// for 9000 ms is played for 6000 ms (W3C 7.2's bound, within the RFC's), a tone and a gap
/// left to the default last 100 ms and 70 ms; the callee consumes each event with the
/// duration it was played for (48 units a millisecond), the 6000 ms one across segments.
#[test]
fn generated_events_last_at_most_6000_ms_and_default_to_100_ms_with_70_ms_gaps() -> Result<()> {
    let mut call = Call::connected(53170)?;
    let start = call.now;
    call.insert("1", Some(Duration::from_millis(9000)), None)?;
    call.run_until(Duration::from_secs(12), |c| {
        c.caller.tone_changes().iter().any(|(_, t)| t.is_empty())
    })?;
    call.run_until(Duration::from_millis(300), |_| false)?;
    let long: Vec<(Duration, String)> = call
        .caller
        .tone_changes()
        .into_iter()
        .map(|(at, tone)| (at - start, tone))
        .collect();
    assert_eq!(
        long.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>(),
        ["1", ""]
    );
    assert_eq!(
        long[1].0 - long[0].0,
        Duration::from_millis(6000 + 70),
        "the tone for 6000 ms, then the default gap"
    );
    assert_eq!(events_consumed(&call), [('1', 6000 * 48)]);

    let second = call.now;
    call.insert("23", None, None)?;
    call.run_until(Duration::from_secs(2), |c| {
        c.caller
            .tone_changes()
            .iter()
            .filter(|(at, t)| *at >= second && t.is_empty())
            .count()
            == 1
    })?;
    call.run_until(Duration::from_millis(300), |_| false)?;
    let changes: Vec<Instant> = call
        .caller
        .tone_changes()
        .into_iter()
        .filter(|(at, _)| *at >= second)
        .map(|(at, _)| at)
        .collect();
    assert_eq!(changes.len(), 3, "2, 3 and the end of the buffer");
    assert_eq!(changes[1] - changes[0], Duration::from_millis(100 + 70));
    assert_eq!(
        events_consumed(&call),
        [('1', 6000 * 48), ('2', 100 * 48), ('3', 100 * 48)]
    );
    Ok(())
}

/// RFC 7874 section 3: "the endpoint MUST be able to generate and consume events 0 through
/// 15" (the digits, `*`, `#` and A to D). All sixteen go out as telephone events with the
/// codes of RFC 4733 section 3.2, in order, and the callee consumes them as the same sixteen
/// characters.
#[test]
fn all_sixteen_dtmf_events_are_generated_and_consumed() -> Result<()> {
    let mut call = Call::connected(53180)?;
    let tones = "0123456789*#ABCD";
    call.insert(
        tones,
        Some(Duration::from_millis(40)),
        Some(Duration::from_millis(30)),
    )?;
    call.run_until(Duration::from_secs(5), |c| {
        c.caller.tone_changes().iter().any(|(_, t)| t.is_empty())
    })?;
    call.run_until(Duration::from_millis(300), |_| false)?;
    // The first packet of each event has M (the final reports of one event still go out
    // after the next has begun).
    let codes: Vec<u8> = call
        .events_received()
        .into_iter()
        .filter(|(_, packet, _)| packet.header.marker)
        .map(|(_, _, report)| report.event)
        .collect();
    assert_eq!(codes, (0u8..=15).collect::<Vec<_>>(), "the event codes");
    let consumed: String = events_consumed(&call).into_iter().map(|(c, _)| c).collect();
    assert_eq!(consumed, tones);
    Ok(())
}
