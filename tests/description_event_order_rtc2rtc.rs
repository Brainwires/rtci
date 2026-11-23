//! The order of the events a description causes (W3C webrtc-pc 4.4.1.4, "set a session
//! description"), data channels included.
//!
//! The steps, at the end of the algorithm: "If connection.[[SignalingState]] changed above,
//! fire an event named signalingstatechange at connection. For each channel in errorList,
//! fire an event named error using the RTCErrorEvent interface with the errorDetail
//! attribute set to "data-channel-failure" at channel. For each track in muteTracks, set the
//! muted state of track to the value true. For each stream and track pair in removeList,
//! remove the track track from stream. For each stream and track pair in addList, add the
//! track track to stream. For each entry entry in trackEventInits, fire an event named
//! track".
//!
//! errorList holds the channels that got no id: "Give channel a new ID generated according
//! to [RFC8832]. If no available ID could be generated, set channel.[[ReadyState]] to
//! "closed", and add channel to errorList."
//!
//! What a description closes is announced in tasks of its own, after those: an answer that
//! "initiates the closure of an existing SCTP association, as defined in [RFC8841], Sections
//! 10.3 and 10.4" closes the underlying data transport of each channel, and "When an
//! RTCDataChannel object's underlying data transport has been closed, the user agent MUST
//! queue a task to run the following steps: ... If the transport was closed with an error,
//! fire an event named error ... Fire an event named close at channel."
//!
//! The engine queues all of it when the description is applied, in that order; the channels
//! in the order they were created; the SCTP transport's `statechange` after its channels.

use anyhow::Result;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::rtc_error::RTCErrorDetailType;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
    RTCSctpTransportState,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
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
    /// The names the test gives the channels it tells apart.
    names: Vec<(RTCDataChannelId, &'static str)>,
}

impl Peer {
    fn new(addr: &str, role: RTCDtlsRole) -> Result<Self> {
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
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            inbox: Vec::new(),
            events: Vec::new(),
            names: Vec::new(),
        })
    }

    fn channel(&mut self, name: &'static str, init: Option<RTCDataChannelInit>) -> Result<()> {
        let id = self.pc.create_data_channel(name, init)?.id();
        self.names.push((id, name));
        Ok(())
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
        while self.pc.poll_read().is_some() {}
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

    /// The events from `from` on that a description orders, as labels: a channel by the
    /// name the test gave it (`?` for another).
    fn labels(&self, from: usize) -> Vec<String> {
        let name = |id: &RTCDataChannelId| {
            self.names
                .iter()
                .find(|(named, _)| named == id)
                .map_or("?", |(_, name)| name)
        };
        self.events[from..]
            .iter()
            .filter_map(|event| {
                Some(match event {
                    RTCPeerConnectionEvent::OnSignalingStateChangeEvent(s) => {
                        format!("signaling:{s}")
                    }
                    RTCPeerConnectionEvent::OnSctpTransportStateChange(s) => format!("sctp:{s}"),
                    RTCPeerConnectionEvent::OnDataChannel(event) => match event {
                        RTCDataChannelEvent::OnError(id) => format!("error:{}", name(id)),
                        RTCDataChannelEvent::OnClosing(id) => format!("closing:{}", name(id)),
                        RTCDataChannelEvent::OnClose(id) => format!("close:{}", name(id)),
                        _ => return None,
                    },
                    RTCPeerConnectionEvent::OnTrack(event) => match event {
                        RTCTrackEvent::OnMute(_) => "mute".to_owned(),
                        RTCTrackEvent::OnStreamsChanged(_) => "streams".to_owned(),
                        RTCTrackEvent::OnRemoteTrack(_) => "track".to_owned(),
                        _ => return None,
                    },
                    _ => return None,
                })
            })
            .collect()
    }
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

/// Both peers for `duration` of virtual time.
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
            now += Duration::from_millis(5);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }
    Ok(now)
}

/// Writes one Opus packet on the transceiver's sender.
fn write_audio(
    peer: &mut Peer,
    transceiver: rtc::rtp_transceiver::RTCRtpTransceiverId,
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
            payload: bytes::Bytes::from(vec![0x10u8; 60]),
        },
    )?;
    Ok(())
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

/// errorList between the signaling state change and the track event, in the order the
/// channels were created: with every stream id taken by negotiated channels, the two in-band
/// channels that wait for an id when the answer settles the DTLS role get none. Each fires
/// `error` (data-channel-failure) and is closed; then the track the answer makes this side
/// receive is announced.
#[test]
fn channels_without_an_id_fail_after_the_signaling_state_change_and_before_the_track() -> Result<()>
{
    let mut a = Peer::new("127.0.0.1:53010", RTCDtlsRole::Client)?;
    let mut b = Peer::new("127.0.0.1:53011", RTCDtlsRole::Server)?;
    a.pc.add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    b.pc.add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    for id in 0..u16::MAX {
        a.pc.create_data_channel(
            "pinned",
            Some(RTCDataChannelInit {
                negotiated: Some(id),
                ..Default::default()
            }),
        )?;
    }
    a.channel("late one", None)?;
    a.channel("late two", None)?;
    a.drain_events();

    let now = Instant::now();
    let offer = a.pc.create_offer(None)?;
    a.pc.set_local_description(now, offer.clone())?;
    b.pc.set_remote_description(now, offer)?;
    let answer = b.pc.create_answer(None)?;
    b.pc.set_local_description(now, answer.clone())?;
    a.drain_events();
    let before = a.events.len();
    a.pc.set_remote_description(now, answer)?;
    a.drain_events();

    assert_eq!(
        a.labels(before),
        vec![
            "signaling:stable",
            "error:late one",
            "close:late one",
            "error:late two",
            "close:late two",
            "track",
        ]
    );
    for (id, _) in a.names.clone() {
        assert_eq!(
            a.pc.data_channel_error(id).map(|e| e.error_detail),
            Some(RTCErrorDetailType::DataChannelFailure)
        );
    }
    Ok(())
}

/// An answer that rejects the data section, on a connection with two open channels and one
/// being opened, and that also stops the peer's audio: the description's own events first
/// (signaling state, mute), then each channel in the order they were created
/// (`close` for an open one; `error` then `close` for the one that never opened, which did
/// not get what it was created for), then the SCTP transport's `statechange`. They are
/// queued when the description is applied: what the application does next, before it reads
/// its events, comes after them.
#[test]
fn the_channels_of_a_rejected_data_section_close_after_the_descriptions_own_events() -> Result<()> {
    let mut a = Peer::new("127.0.0.1:53020", RTCDtlsRole::Client)?;
    let mut b = Peer::new("127.0.0.1:53021", RTCDtlsRole::Server)?;
    a.pc.add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    let b_audio =
        b.pc.add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    a.channel("one", None)?;
    a.channel("two", None)?;

    let start = Instant::now();
    let offer = a.pc.create_offer(None)?;
    a.pc.set_local_description(start, offer.clone())?;
    b.pc.set_remote_description(start, offer)?;
    let answer = b.pc.create_answer(None)?;
    b.pc.set_local_description(start, answer.clone())?;
    a.pc.set_remote_description(start, answer)?;
    let (a_addr, b_addr) = (a.addr, b.addr);
    a.pc.add_local_candidate(host(a_addr)?)?;
    b.pc.add_local_candidate(host(b_addr)?)?;
    a.pc.add_remote_candidate(host(b_addr)?)?;
    b.pc.add_remote_candidate(host(a_addr)?)?;
    let opened = |p: &Peer| {
        p.events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
                )
            })
            .count()
    };
    let now = run(&mut a, &mut b, start, |a, b| {
        opened(a) == 2
            && opened(b) == 2
            && a.pc.connection_state() == RTCPeerConnectionState::Connected
            && b.pc.connection_state() == RTCPeerConnectionState::Connected
    })?;
    assert_eq!((opened(&a), opened(&b)), (2, 2), "both channels are open");
    // The answerer's audio arrives: the offerer's remote track is live and not muted.
    let mut now = now;
    for seq in 1..=3u16 {
        write_audio(&mut b, b_audio, seq, now)?;
        now = run_for(&mut a, &mut b, now, Duration::from_millis(20))?;
    }
    let unmuted = a.events.iter().any(|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnUnmute(_))
        )
    });
    assert!(unmuted, "the remote track unmuted with its first packet");

    // A third channel is being opened (its DCEP OPEN is not acknowledged: no datagram moves
    // from here on) when the data section is rejected; the answerer stops sending audio.
    a.channel("opening", None)?;
    a.pc.reject_data_section();
    b.pc.rtp_transceiver(b_audio)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Recvonly)?;
    let offer = a.pc.create_offer(None)?;
    a.pc.set_local_description(now, offer.clone())?;
    b.pc.set_remote_description(now, offer)?;
    let answer = b.pc.create_answer(None)?;
    a.drain_events();
    b.drain_events();
    let before = (a.events.len(), b.events.len());
    b.pc.set_local_description(now, answer.clone())?;
    a.pc.set_remote_description(now, answer)?;

    // Before any event is read: another negotiation starts.
    a.pc.restart_ice();
    let offer = a.pc.create_offer(None)?;
    a.pc.set_local_description(now, offer)?;
    a.drain_events();
    b.drain_events();

    assert_eq!(
        a.labels(before.0),
        vec![
            "signaling:stable",
            "mute",
            "close:one",
            "close:two",
            "error:opening",
            "close:opening",
            "sctp:closed",
            "signaling:have-local-offer",
        ],
        "the offerer; the answer:\n{}",
        a.pc.remote_description()
            .map(|d| d.sdp.clone())
            .unwrap_or_default()
    );
    assert_eq!(
        a.pc.sctp().map(|s| s.state()),
        None,
        "the answer made [[SctpTransport]] null"
    );
    // The answerer has the two channels the offerer opened (announced to it: not named
    // here), no track change, and no channel that failed.
    assert_eq!(
        b.labels(before.1),
        vec!["signaling:stable", "close:?", "close:?", "sctp:closed"],
        "the answerer"
    );
    let _ = RTCSctpTransportState::Closed;
    Ok(())
}
