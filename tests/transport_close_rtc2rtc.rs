//! A session whose every m= section is rejected has no transport in use: the transport is
//! closed, with its events, and the next description that sets a section up starts a new
//! one (W3C webrtc-pc 4.4.1.4 "set a session description"; RFC 9429 section 5.11).
//!
//! W3C, once an answer made the signaling state stable: "For any transceiver that was removed
//! from the set of transceivers in a previous step, if any of its transports ... are still
//! not closed and they're no longer referenced by a non-stopped transceiver, close the
//! RTCDtlsTransports and their associated RTCIceTransports. This results in events firing on
//! these objects in a queued task." RFC 9429 section 5.11, for a rejected section: "unless a
//! non-rejected "m=" section is bundled with this "m=" section, discard any associated ICE
//! components".
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use bytes::Bytes;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{
    RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTransportEventKind,
};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::{
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState, RTCSignalingState,
};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit, RTCIceTransportState, RTCSctpTransportState, RTCTransportId,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{
    RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(120);
const MAX_TURNS: usize = 50_000;

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
    /// Every event, in order.
    events: Vec<RTCPeerConnectionEvent>,
    /// What the application read: RTP packets and data channel messages.
    rtp: usize,
    messages: Vec<String>,
    /// Datagrams written since it was last reset.
    written: usize,
}

impl Peer {
    fn new(addr: &str, role: RTCDtlsRole, now: Instant) -> Result<Self> {
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
            addr: addr.parse()?,
            inbox: Vec::new(),
            events: Vec::new(),
            rtp: 0,
            messages: Vec::new(),
            written: 0,
        })
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.pc.poll_event() {
            self.events.push(event);
        }
    }

    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        self.drain_events();
        while let Some(read) = self.pc.poll_read() {
            match read.message {
                RTCMessage::RtpPacket(..) => self.rtp += 1,
                RTCMessage::DataChannelMessage(_, message) => self
                    .messages
                    .push(String::from_utf8_lossy(&message.data).into_owned()),
                _ => {}
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        self.written += written.len();
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

    fn connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }

    fn sctp_connected(&self) -> bool {
        self.pc
            .sctp()
            .is_some_and(|s| s.state() == RTCSctpTransportState::Connected)
    }

    /// The ids of the ICE and DTLS transports whose DTLS association connected in the events
    /// from `from` on: the transports that came into use. (An offer may start with a
    /// transport per section, which the answer's BUNDLE group then reduces to one.)
    fn transport_ids(&self, from: usize) -> Vec<(RTCTransportId, RTCTransportId)> {
        let mut ids = vec![];
        for event in &self.events[from..] {
            if let RTCPeerConnectionEvent::OnTransportEvent(event) = event
                && matches!(
                    event.event,
                    RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Connected)
                )
            {
                let pair = (event.ice_transport, event.dtls_transport);
                if !ids.contains(&pair) {
                    ids.push(pair);
                }
            }
        }
        ids
    }

    /// A value of the local description: the text after `prefix` on its first such line.
    fn local(&self, prefix: &str) -> String {
        self.pc
            .local_description()
            .expect("a local description")
            .sdp
            .lines()
            .find_map(|l| l.strip_prefix(prefix))
            .unwrap_or_default()
            .to_owned()
    }
}

/// The events an application orders its work by, as labels.
fn label(event: &RTCPeerConnectionEvent) -> Option<String> {
    Some(match event {
        RTCPeerConnectionEvent::OnSignalingStateChangeEvent(s) => format!("signaling:{s}"),
        RTCPeerConnectionEvent::OnIceTransportStateChange(s) => format!("ice-transport:{s}"),
        RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(s) => format!("ice:{s}"),
        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => format!("connection:{s}"),
        RTCPeerConnectionEvent::OnDtlsTransportStateChange(s) => format!("dtls:{s}"),
        RTCPeerConnectionEvent::OnSctpTransportStateChange(s) => format!("sctp:{s}"),
        RTCPeerConnectionEvent::OnIceGathererStateChange(s) => format!("gatherer:{s}"),
        RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(s) => format!("gathering:{s}"),
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(_)) => {
            "channel:close".to_owned()
        }
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnError(_)) => {
            "channel:error".to_owned()
        }
        _ => return None,
    })
}

fn labels(events: &[RTCPeerConnectionEvent]) -> Vec<String> {
    events.iter().filter_map(label).collect()
}

/// The labels of `all` that start with one of `kinds` (`kind:`).
fn of_kinds(all: &[String], kinds: &[&str]) -> Vec<String> {
    all.iter()
        .filter(|l| kinds.iter().any(|kind| l.starts_with(&format!("{kind}:"))))
        .cloned()
        .collect()
}

fn position(labels: &[String], wanted: &str) -> usize {
    labels
        .iter()
        .position(|l| l == wanted)
        .unwrap_or_else(|| panic!("no {wanted} in {labels:?}"))
}

/// Offer and answer. Returns each side's event count before the answer was applied to it:
/// (offerer, answerer).
fn exchange(offerer: &mut Peer, answerer: &mut Peer, now: Instant) -> Result<(usize, usize)> {
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer.pc.set_remote_description(now, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    offerer.drain_events();
    answerer.drain_events();
    let before = (offerer.events.len(), answerer.events.len());
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;
    Ok(before)
}

/// Runs both peers until `done` holds or the deadline passes. Returns the virtual time.
fn run(
    offerer: &mut Peer,
    answerer: &mut Peer,
    mut now: Instant,
    done: impl Fn(&Peer, &Peer) -> bool,
) -> Result<Instant> {
    let start = now;
    let mut turns = 0;
    while !done(offerer, answerer) && now.duration_since(start) < DEADLINE && turns < MAX_TURNS {
        turns += 1;
        let written = offerer.turn()?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        offerer.deliver(answerer.addr, written, now);
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }
    Ok(now)
}

/// Both peers for `duration` of virtual time, whatever they do.
fn run_for(
    offerer: &mut Peer,
    answerer: &mut Peer,
    mut now: Instant,
    duration: Duration,
) -> Result<Instant> {
    let until = now + duration;
    while now < until {
        let written = offerer.turn()?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        offerer.deliver(answerer.addr, written, now);
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            now += Duration::from_millis(50);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }
    Ok(now)
}

fn sendrecv() -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Sendrecv,
        streams: vec![],
        send_encodings: vec![RTCRtpEncodingParameters {
            active: true,
            ..Default::default()
        }],
    })
}

/// Writes one Opus packet on the transceiver's sender.
fn write_audio(
    peer: &mut Peer,
    transceiver: RTCRtpTransceiverId,
    seq: u16,
    now: Instant,
) -> Result<()> {
    let sender = peer
        .pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .expect("sender");
    let mut sender = peer.pc.rtp_sender(sender).expect("sender");
    let parameters = sender.get_parameters();
    let ssrc = parameters.encodings[0]
        .rtp_coding_parameters
        .ssrc
        .expect("an SSRC");
    let payload_type = parameters
        .rtp_parameters
        .codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("audio/opus"))
        .expect("opus")
        .payload_type;
    sender.write_rtp(
        now,
        rtc::rtp::Packet {
            header: rtc::rtp::header::Header {
                version: 2,
                payload_type,
                sequence_number: seq,
                timestamp: u32::from(seq) * 960,
                ssrc,
                marker: true,
                ..Default::default()
            },
            payload: Bytes::from(vec![0x10u8; 60]),
        },
    )?;
    Ok(())
}

/// Two peers connected with an audio section and a data channel, on one (BUNDLE) transport.
/// Returns them with the offerer's audio transceiver and the virtual time.
fn connected() -> Result<(Peer, Peer, RTCRtpTransceiverId, Instant)> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:52010", RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:52011", RTCDtlsRole::Server, start)?;
    let audio = offerer
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    offerer.pc.create_data_channel("first", None)?;
    exchange(&mut offerer, &mut answerer, start)?;
    let (offerer_addr, answerer_addr) = (offerer.addr, answerer.addr);
    offerer.pc.add_local_candidate(host(offerer_addr)?)?;
    answerer.pc.add_local_candidate(host(answerer_addr)?)?;
    offerer.pc.add_remote_candidate(host(answerer_addr)?)?;
    answerer.pc.add_remote_candidate(host(offerer_addr)?)?;
    let now = run(&mut offerer, &mut answerer, start, |a, b| {
        a.connected() && b.connected() && a.sctp_connected() && b.sctp_connected()
    })?;
    assert!(offerer.connected() && answerer.connected(), "connected");
    Ok((offerer, answerer, audio, now))
}

/// The offerer stops its transceiver and asks for the data section to be rejected; the
/// exchange that follows rejects every m= section. Returns each side's event count before
/// the answer was applied to it.
fn reject_everything(
    offerer: &mut Peer,
    answerer: &mut Peer,
    audio: RTCRtpTransceiverId,
    now: Instant,
) -> Result<(usize, usize)> {
    offerer
        .pc
        .rtp_transceiver(audio)
        .expect("transceiver")
        .stop()?;
    offerer.pc.reject_data_section();
    let before = exchange(offerer, answerer, now)?;
    let answer = answerer.pc.local_description().expect("answer").sdp;
    let ports: Vec<&str> = answer
        .lines()
        .filter(|l| l.starts_with("m="))
        .filter_map(|l| l.split(' ').nth(1))
        .collect();
    assert_eq!(
        ports,
        vec!["0", "0"],
        "every section is rejected:\n{answer}"
    );
    Ok(before)
}

/// W3C 4.4.1.4: the answer that leaves every m= section rejected closes the transport. Each
/// side's DTLS transport and then its ICE transport fire `statechange` to "closed", after the
/// description's `signalingstatechange`; the connection's aggregate states follow them
/// (4.3.3, 4.3.4: with no transport but "new" or "closed" ones the ICE connection state and
/// the connection state are "new"), in the order of W3C 5.6: the transport's event, then
/// `iceconnectionstatechange`, then `connectionstatechange`. The closed transport sends
/// nothing more.
#[test]
fn an_answer_that_rejects_every_section_closes_the_transport_with_its_events() -> Result<()> {
    let (mut offerer, mut answerer, audio, now) = connected()?;
    let old: Vec<_> = [&offerer, &answerer]
        .iter()
        .map(|peer| peer.transport_ids(0))
        .collect();
    for ids in &old {
        assert_eq!(ids.len(), 1, "one transport in use: {ids:?}");
    }

    let before = reject_everything(&mut offerer, &mut answerer, audio, now)?;
    offerer.drain_events();
    answerer.drain_events();

    for (peer, before, old) in [
        (&offerer, before.0, old[0][0]),
        (&answerer, before.1, old[1][0]),
    ] {
        let all = labels(&peer.events[before..]);
        assert_eq!(
            of_kinds(
                &all,
                &["signaling", "dtls", "ice-transport", "ice", "connection"]
            ),
            vec![
                "signaling:stable",
                "dtls:closed",
                "ice-transport:closed",
                "ice:new",
                "connection:new",
            ],
            "the description's event, then the transport's, then the aggregates: {all:?}"
        );
        // The events are fired at the transport that was in use.
        let closed: Vec<_> = peer.events[before..]
            .iter()
            .filter_map(|event| match event {
                RTCPeerConnectionEvent::OnTransportEvent(event) => match event.event {
                    RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Closed) => {
                        Some(("dtls", event.ice_transport, event.dtls_transport))
                    }
                    RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed) => {
                        Some(("ice", event.ice_transport, event.dtls_transport))
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(
            closed,
            vec![("dtls", old.0, old.1), ("ice", old.0, old.1)],
            "closed: the DTLS transport, then its ICE transport"
        );
        assert_eq!(peer.pc.signaling_state(), RTCSignalingState::Stable);
        assert_eq!(peer.pc.ice_connection_state(), RTCIceConnectionState::New);
        assert_eq!(peer.pc.connection_state(), RTCPeerConnectionState::New);
        assert_eq!(peer.pc.ice_gathering_state(), RTCIceGatheringState::New);
    }

    // What the description queued leaves; then the closed transport is silent: no
    // connectivity or consent check, no keepalive, no DTLS, for as long as nothing is
    // negotiated.
    let now = run_for(&mut offerer, &mut answerer, now, Duration::from_millis(200))?;
    offerer.written = 0;
    answerer.written = 0;
    let (events_offerer, events_answerer) = (offerer.events.len(), answerer.events.len());
    run_for(&mut offerer, &mut answerer, now, Duration::from_secs(60))?;
    assert_eq!(
        (offerer.written, answerer.written),
        (0, 0),
        "datagrams from a session without a transport"
    );
    assert_eq!(
        (
            labels(&offerer.events[events_offerer..]),
            labels(&answerer.events[events_answerer..])
        ),
        (vec![], vec![]),
        "no state changes while nothing is negotiated"
    );
    Ok(())
}

/// The next offer finds a new transport: a new ICE agent with credentials of a new
/// generation, a new DTLS association with a new `tls-id`, both with ids of their own. Its
/// states are announced as the first transport's were, the transport's event before the
/// connection's, and it carries media and a data channel. Its DTLS association runs on a new
/// 3-tuple (RFC 8842 section 5.1): the closed transport's candidates are not listed, and the
/// application gathers on new ports.
#[test]
fn the_next_offer_sets_up_a_new_transport_that_carries_media_and_data() -> Result<()> {
    let (mut offerer, mut answerer, audio, now) = connected()?;
    let old: Vec<_> = [&offerer, &answerer]
        .iter()
        .map(|peer| peer.transport_ids(0)[0])
        .collect();
    let old_credentials = (
        offerer.local("a=ice-ufrag:"),
        offerer.local("a=ice-pwd:"),
        offerer.local("a=tls-id:"),
        offerer.local("a=fingerprint:"),
    );
    assert!(!old_credentials.0.is_empty() && !old_credentials.2.is_empty());

    reject_everything(&mut offerer, &mut answerer, audio, now)?;
    let now = run_for(&mut offerer, &mut answerer, now, Duration::from_secs(1))?;
    let since = (offerer.events.len(), answerer.events.len());
    let (rtp_before, messages_before) = (answerer.rtp, answerer.messages.len());

    let audio = offerer
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    let channel = offerer.pc.create_data_channel("second", None)?.id();
    exchange(&mut offerer, &mut answerer, now)?;
    let new_credentials = (
        offerer.local("a=ice-ufrag:"),
        offerer.local("a=ice-pwd:"),
        offerer.local("a=tls-id:"),
        offerer.local("a=fingerprint:"),
    );
    assert_ne!(
        new_credentials.0, old_credentials.0,
        "a new ICE username fragment"
    );
    assert_ne!(new_credentials.1, old_credentials.1, "a new ICE password");
    assert_ne!(new_credentials.2, old_credentials.2, "a new tls-id");
    assert_eq!(new_credentials.3, old_credentials.3, "the same certificate");
    assert!(
        !offerer
            .pc
            .local_description()
            .expect("offer")
            .sdp
            .contains("a=candidate:"),
        "the local description lists none of the candidates gathered before"
    );
    for peer in [&mut offerer, &mut answerer] {
        let port = peer.addr.port();
        peer.addr.set_port(port + 100);
    }
    let (offerer_addr, answerer_addr) = (offerer.addr, answerer.addr);
    offerer.pc.add_local_candidate(host(offerer_addr)?)?;
    answerer.pc.add_local_candidate(host(answerer_addr)?)?;
    offerer.pc.add_remote_candidate(host(answerer_addr)?)?;
    answerer.pc.add_remote_candidate(host(offerer_addr)?)?;

    let opened = |p: &Peer, from: usize| {
        p.events[from..].iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
            )
        })
    };
    let mut now = run(&mut offerer, &mut answerer, now, |a, b| {
        a.connected() && b.connected() && opened(a, since.0) && opened(b, since.1)
    })?;
    assert!(
        offerer.connected() && answerer.connected(),
        "connected again: {:?} / {:?}",
        labels(&offerer.events[since.0..]),
        labels(&answerer.events[since.1..])
    );

    for (peer, since, old) in [(&offerer, since.0, old[0]), (&answerer, since.1, old[1])] {
        let ids = peer.transport_ids(since);
        assert_eq!(ids.len(), 1, "one transport in use: {ids:?}");
        assert_ne!(ids[0].0, old.0, "another ICE transport");
        assert_ne!(ids[0].1, old.1, "another DTLS transport");
        let all = labels(&peer.events[since..]);
        assert!(
            position(&all, "ice-transport:checking") < position(&all, "ice:checking"),
            "{all:?}"
        );
        assert!(
            position(&all, "ice-transport:connected") < position(&all, "ice:connected"),
            "{all:?}"
        );
        assert!(
            position(&all, "dtls:connecting") < position(&all, "dtls:connected"),
            "{all:?}"
        );
        assert!(
            position(&all, "dtls:connected") < position(&all, "connection:connected"),
            "{all:?}"
        );
        assert!(
            !all.iter()
                .any(|l| l.ends_with(":closed") || l.ends_with(":failed")),
            "{all:?}"
        );
    }

    offerer
        .pc
        .data_channel(channel)
        .expect("the channel is open")
        .send_text(now, "over the new transport")?;
    for seq in 1..=5u16 {
        write_audio(&mut offerer, audio, seq, now)?;
        now = run_for(&mut offerer, &mut answerer, now, Duration::from_millis(20))?;
    }
    run_for(&mut offerer, &mut answerer, now, Duration::from_millis(500))?;
    assert_eq!(
        answerer.messages[messages_before..],
        ["over the new transport".to_owned()],
        "the data channel's message"
    );
    assert_eq!(answerer.rtp - rtp_before, 5, "the audio packets");
    Ok(())
}
