//! W3C webrtc-pc clauses that hold without a transport: the initial slots of a new
//! connection, `setConfiguration` and `addIceCandidate` errors, the ICE credentials and role a
//! description sets, the transports senders and receivers name, the codecs `getParameters`
//! reports after negotiation, `createAnswer` on rid alternatives, negotiation-needed triggers,
//! `createDataChannel` errors, and the attributes of parsed ICE candidates. Signalling only.

mod jsep_common;

use std::time::{Duration, Instant, SystemTime};

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of,
    video_track,
};
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::certificate::RTCCertificate;
use rtc::peer_connection::configuration::RTCBundlePolicy;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::RTCRtcpMuxPolicy;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;
use rtc::peer_connection::transport::{
    RTCIceCandidateInit, RTCIceCandidateType, RTCIceRole, RTCIceTcpCandidateType,
};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;

fn events(pc: &mut RTCPeerConnection) -> Vec<RTCPeerConnectionEvent> {
    let mut events = vec![];
    while let Some(event) = pc.poll_event() {
        events.push(event);
    }
    events
}

fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    events(pc)
        .iter()
        .filter(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent))
        .count()
}

fn attribute<'a>(sdp: &'a str, name: &str) -> Vec<&'a str> {
    let prefix = format!("a={name}:");
    sdp.lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect()
}

/// A peer with one data channel, so that its offer has a section.
fn peer_with_data() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    pc.create_data_channel("d", None)?;
    Ok(pc)
}

/// W3C 4.4.1.1 constructor: [[NegotiationNeeded]] starts false and the four description slots
/// start null; no event is queued by construction.
#[test]
fn a_new_connection_has_no_descriptions_and_needs_no_negotiation() -> TestResult {
    let mut pc = default_peer()?;
    assert!(pc.current_local_description().is_none());
    assert!(pc.pending_local_description().is_none());
    assert!(pc.current_remote_description().is_none());
    assert!(pc.pending_remote_description().is_none());
    assert!(pc.local_description().is_none());
    assert!(pc.remote_description().is_none());
    assert_eq!(pc.signaling_state(), RTCSignalingState::Stable);
    assert!(events(&mut pc).is_empty(), "construction queues no event");
    assert_eq!(pc.get_transceivers().count(), 0);
    assert!(pc.sctp().is_none());
    Ok(())
}

/// W3C 4.2.6 RTCOfferOptions.iceRestart: false, and no restart pending, keeps the current
/// local description's ICE credentials in the next offer.
#[test]
fn an_offer_without_ice_restart_keeps_the_current_credentials() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    let (first, _) = exchange(&mut offerer, &mut answerer)?;
    let second = offerer.create_offer(None)?;
    assert_eq!(
        attribute(&first, "ice-ufrag"),
        attribute(&second.sdp, "ice-ufrag")
    );
    assert_eq!(
        attribute(&first, "ice-pwd"),
        attribute(&second.sdp, "ice-pwd")
    );
    offerer.restart_ice();
    let restarted = offerer.create_offer(None)?;
    assert_ne!(
        attribute(&first, "ice-ufrag"),
        attribute(&restarted.sdp, "ice-ufrag")
    );
    Ok(())
}

/// W3C 4.4.1.1 constructor step 3 and 4.9.2: a configured certificate whose `expires` is in
/// the past makes construction fail (InvalidAccessError), and `setConfiguration` too.
#[test]
fn an_expired_certificate_is_refused() -> TestResult {
    let provider = rtc::crypto::default_provider()?;
    let issued = SystemTime::now() - Duration::from_secs(60 * 24 * 3600);
    let expired = RTCCertificate::generate_certificate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        Some(Duration::from_secs(24 * 3600)),
        issued,
    )?;
    let built = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_certificates(vec![expired])
                .build(),
        )
        .build(Instant::now());
    assert!(
        matches!(built, Err(Error::ErrCertificateExpired)),
        "{:?}",
        built.err()
    );
    let valid = RTCCertificate::generate_certificate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        None,
        SystemTime::now(),
    )?;
    RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_certificates(vec![valid])
                .build(),
        )
        .build(Instant::now())?;
    Ok(())
}

/// W3C 4.4.1.5 set a configuration: a different bundlePolicy or rtcpMuxPolicy is an
/// InvalidModificationError; on a closed connection setConfiguration is an InvalidStateError.
/// iceCandidatePoolSize is stored and returned (4.2.1).
#[test]
fn set_configuration_refuses_policy_changes_and_a_closed_connection() -> TestResult {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(RTCBundlePolicy::MaxBundle)
                .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
                .with_ice_candidate_pool_size(3)
                .build(),
        )
        .build(Instant::now())?;
    assert_eq!(pc.get_configuration().ice_candidate_pool_size(), 3);
    let changed = pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_bundle_policy(RTCBundlePolicy::Balanced)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
            .with_ice_candidate_pool_size(3)
            .build(),
    );
    assert!(
        matches!(changed, Err(Error::ErrModifyingBundlePolicy)),
        "{changed:?}"
    );
    let changed = pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_bundle_policy(RTCBundlePolicy::MaxBundle)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate)
            .with_ice_candidate_pool_size(3)
            .build(),
    );
    assert!(
        matches!(changed, Err(Error::ErrModifyingRTCPMuxPolicy)),
        "{changed:?}"
    );
    assert_eq!(
        pc.get_configuration().bundle_policy(),
        RTCBundlePolicy::MaxBundle
    );
    pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_bundle_policy(RTCBundlePolicy::MaxBundle)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
            .with_ice_candidate_pool_size(3)
            .build(),
    )?;
    pc.close()?;
    let closed = pc.set_configuration(RTCConfigurationBuilder::new().build());
    assert!(
        matches!(closed, Err(Error::ErrConnectionClosed)),
        "{closed:?}"
    );
    Ok(())
}

/// W3C addIceCandidate: without a remote description an InvalidStateError; an
/// sdpMLineIndex beyond the media descriptions an OperationError.
#[test]
fn add_ice_candidate_refuses_without_a_remote_description_or_a_section() -> TestResult {
    let candidate = |index: Option<u16>| RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host".to_owned(),
        sdp_mid: None,
        sdp_mline_index: index,
        username_fragment: None,
        url: None,
        relay_protocol: None,
    };
    let mut answerer = default_peer()?;
    let refused = answerer.add_remote_candidate(candidate(Some(0)));
    assert!(
        matches!(refused, Err(Error::ErrNoRemoteDescription)),
        "{refused:?}"
    );
    let mut offerer = peer_with_data()?;
    let offer = offerer.create_offer(None)?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let refused = answerer.add_remote_candidate(candidate(Some(1)));
    assert!(
        matches!(refused, Err(Error::ErrIceCandidateMediaSectionNotFound)),
        "{refused:?}"
    );
    answerer.add_remote_candidate(candidate(Some(0)))?;
    Ok(())
}

/// W3C 4.4.1.4 (set the description, [[IceRole]]): a remote offer without `a=ice-lite` makes
/// this side controlled, one with it controlling; once set, a later description does not
/// change the role.
#[test]
fn a_remote_offer_sets_the_ice_role_and_it_then_stays() -> TestResult {
    let role = |pc: &mut RTCPeerConnection| -> RTCIceRole {
        pc.sctp()
            .map(|s| s.transport().ice_transport().role())
            .unwrap_or_else(|| {
                let sender = pc.get_senders().next().expect("a sender");
                pc.rtp_sender(sender)
                    .and_then(|s| s.transport().map(|t| t.ice_transport().role()))
                    .expect("a transport")
            })
    };

    // An engine offer has no a=ice-lite: the answerer is controlled, the offerer controlling.
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0303_0303))?;
    exchange(&mut offerer, &mut answerer)?;
    assert_eq!(role(&mut answerer), RTCIceRole::Controlled);
    assert_eq!(role(&mut offerer), RTCIceRole::Controlling);

    // A renegotiation the answerer starts does not swap the roles.
    exchange(&mut answerer, &mut offerer)?;
    assert_eq!(role(&mut answerer), RTCIceRole::Controlled);
    assert_eq!(role(&mut offerer), RTCIceRole::Controlling);

    // A lite offerer: this side, full, is controlling.
    let mut full = default_peer()?;
    let lite_offer = crlf(&format!(
        "{SESSION}a=ice-lite\na=group:BUNDLE 0\nm=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n"
    ));
    full.set_remote_description(Instant::now(), RTCSessionDescription::offer(lite_offer)?)?;
    let answer = full.create_answer(None)?;
    full.set_local_description(Instant::now(), answer)?;
    let transceiver = full.get_transceivers().next().expect("a transceiver");
    let lite_role = full
        .rtp_receiver(transceiver.into())
        .and_then(|r| r.transport().map(|t| t.ice_transport().role()))
        .expect("a transport");
    assert_eq!(lite_role, RTCIceRole::Controlling);
    Ok(())
}

/// W3C 5.2 / 5.3 `transport`: null until the transceiver is associated with a section, then
/// the shared DTLS transport (4.4.1.4: an offer in stable remembers it); a rollback of that
/// offer clears it again, and a stopped transceiver's sender and receiver name none.
#[test]
fn sender_and_receiver_transports_follow_the_descriptions() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("v", 0x0404_0404))?;
    let transceiver = rtc::rtp_transceiver::RTCRtpTransceiverId::from(sender);
    let has_transports = |pc: &mut RTCPeerConnection| {
        let s = pc.rtp_sender(sender).expect("sender").transport().is_some();
        let r = pc
            .rtp_receiver(transceiver.into())
            .expect("receiver")
            .transport()
            .is_some();
        (s, r)
    };
    assert_eq!(has_transports(&mut pc), (false, false));
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    assert_eq!(has_transports(&mut pc), (true, true));
    pc.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert_eq!(has_transports(&mut pc), (false, false));

    let mut answerer = default_peer()?;
    exchange(&mut pc, &mut answerer)?;
    assert_eq!(has_transports(&mut pc), (true, true));
    pc.rtp_transceiver(transceiver)
        .expect("transceiver")
        .stop()?;
    exchange(&mut pc, &mut answerer)?;
    assert!(
        pc.rtp_sender(sender)
            .is_none_or(|s| s.transport().is_none()),
        "a stopped transceiver's sender has no transport"
    );
    Ok(())
}

/// W3C 4.4.1.4: after negotiation [[SendCodecs]] and [[ReceiveCodecs]] are the codecs
/// negotiated for each way, which `getParameters` reports; a sendonly transceiver's receiver
/// has no receive codecs. What the offerer sends, the answerer receives.
#[test]
fn get_parameters_reports_the_codecs_negotiated_for_each_way() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sendonly = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit::with_direction(
            RTCRtpTransceiverDirection::Sendonly,
        )),
    )?;
    exchange(&mut offerer, &mut answerer)?;
    let send_codecs = offerer
        .rtp_sender(sendonly.into())
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    assert!(!send_codecs.is_empty(), "codecs negotiated for sending");
    let receive_codecs = offerer
        .rtp_receiver(sendonly.into())
        .expect("receiver")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    assert!(
        receive_codecs.is_empty(),
        "a sendonly transceiver receives nothing: {receive_codecs:?}"
    );

    let answered = answerer
        .get_transceivers()
        .next()
        .expect("answerer's transceiver");
    let answer_receive = answerer
        .rtp_receiver(answered.into())
        .expect("receiver")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    assert!(!answer_receive.is_empty(), "the answerer receives");
    for codec in &send_codecs {
        assert!(
            answer_receive.iter().any(|c| c
                .rtp_codec
                .mime_type
                .eq_ignore_ascii_case(&codec.rtp_codec.mime_type)),
            "{codec:?} sent but not received"
        );
    }
    Ok(())
}

/// W3C 4.4.2 createAnswer to a simulcast offer: of comma-separated rid alternatives in
/// `a=simulcast` only the first is kept.
#[test]
fn an_answer_to_simulcast_keeps_the_first_rid_of_each_alternative() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0\nm=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendonly\na=rtpmap:96 VP8/90000\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\na=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\na=rid:h send\na=rid:hh send\na=rid:m send\na=rid:l send\na=simulcast:send h,hh;m;l\n"
    ));
    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = answerer.create_answer(None)?;
    let rids: Vec<&str> = attribute(&answer.sdp, "rid")
        .into_iter()
        .map(|r| r.split_whitespace().next().unwrap_or_default())
        .collect();
    assert_eq!(rids, ["h", "m", "l"], "{}", answer.sdp);
    assert_eq!(attribute(&answer.sdp, "simulcast"), ["recv h;m;l"]);
    Ok(())
}

/// W3C 4.4.2 createOffer: the BUNDLE group's first mid, the offerer-tagged section, is that
/// of the first transceiver that is not stopped.
#[test]
fn the_bundle_tag_is_the_first_transceiver_that_is_not_stopped() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let first = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    let group = attribute(&offer, "group");
    let sections = media_sections(&offer);
    assert_eq!(
        group[0].split_whitespace().nth(1),
        mid_of(&sections[0]),
        "{offer}"
    );

    offerer
        .rtp_transceiver(first)
        .expect("transceiver")
        .stop()?;
    exchange(&mut offerer, &mut answerer)?;
    let offer = offerer.create_offer(None)?;
    let second_mid = media_sections(&offer.sdp)[1]
        .iter()
        .find_map(|l| l.strip_prefix("a=mid:").map(str::to_owned))
        .expect("a mid");
    let group = attribute(&offer.sdp, "group");
    assert_eq!(
        group[0].split_whitespace().nth(1),
        Some(second_mid.as_str()),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// W3C 4.7.3 update the negotiation-needed flag: a first data channel when no data section is
/// negotiated raises it; a transceiver added after a negotiation, not associated with a
/// section, raises it; nothing does on a closed connection.
#[test]
fn negotiation_needed_follows_data_channels_and_new_transceivers() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0505_0505))?;
    exchange(&mut offerer, &mut answerer)?;
    events(&mut offerer);

    offerer.create_data_channel("first", None)?;
    assert_eq!(negotiation_needed(&mut offerer), 1, "a first data channel");
    exchange(&mut offerer, &mut answerer)?;
    events(&mut offerer);
    offerer.create_data_channel("second", None)?;
    assert_eq!(
        negotiation_needed(&mut offerer),
        0,
        "the data section is negotiated already"
    );

    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    assert_eq!(
        negotiation_needed(&mut offerer),
        1,
        "an unassociated transceiver"
    );
    exchange(&mut offerer, &mut answerer)?;
    events(&mut offerer);

    offerer.close()?;
    events(&mut offerer);
    let after = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None);
    assert!(after.is_err());
    offerer.restart_ice();
    assert_eq!(negotiation_needed(&mut offerer), 0, "a closed connection");
    Ok(())
}

/// W3C createDataChannel: a closed connection is an InvalidStateError; maxPacketLifeTime and
/// maxRetransmits together a TypeError; a channel announced by the peer (6.2.3) and one
/// created in band report `negotiated` false, a negotiated one true.
#[test]
fn create_data_channel_refuses_what_the_spec_refuses() -> TestResult {
    let mut pc = default_peer()?;
    let both = pc.create_data_channel(
        "both",
        Some(RTCDataChannelInit {
            max_packet_life_time: Some(10),
            max_retransmits: Some(1),
            ..Default::default()
        }),
    );
    assert!(
        matches!(both, Err(Error::ErrRetransmitsOrPacketLifeTime)),
        "{:?}",
        both.err()
    );
    let in_band = pc.create_data_channel("in-band", None)?.id();
    let negotiated = pc
        .create_data_channel(
            "negotiated",
            Some(RTCDataChannelInit {
                negotiated: Some(7),
                max_retransmits: Some(u16::MAX),
                ..Default::default()
            }),
        )?
        .id();
    assert!(!pc.data_channel(in_band).expect("channel").negotiated());
    let channel = pc.data_channel(negotiated).expect("channel");
    assert!(channel.negotiated());
    assert_eq!(channel.max_retransmits(), Some(u16::MAX));
    pc.close()?;
    let closed = pc.create_data_channel("late", None);
    assert!(
        matches!(closed, Err(Error::ErrConnectionClosed)),
        "{:?}",
        closed.err()
    );
    Ok(())
}

/// W3C 4.8.1 RTCIceCandidate attributes, read back from candidates added to the remote
/// description: component, tcpType only for TCP, relatedAddress / relatedPort only for a
/// candidate that has a base, and the candidate types host, srflx, prflx and relay.
#[test]
fn remote_candidates_expose_the_w3c_attributes() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    exchange(&mut offerer, &mut answerer)?;
    for line in [
        "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host",
        "candidate:2 1 udp 1694498815 192.0.2.1 6000 typ srflx raddr 10.0.0.1 rport 5000",
        "candidate:3 1 udp 1862270975 192.0.2.2 6001 typ prflx raddr 10.0.0.1 rport 5000",
        "candidate:4 1 udp 16777215 198.51.100.1 7000 typ relay raddr 192.0.2.1 rport 6000",
        "candidate:6 1 tcp 1518280447 10.0.0.1 5001 typ host tcptype passive",
        "candidate:7 1 tcp 1518280447 10.0.0.1 5002 typ host tcptype so",
    ] {
        answerer.add_remote_candidate(RTCIceCandidateInit {
            candidate: line.to_owned(),
            sdp_mid: Some("0".to_owned()),
            ..Default::default()
        })?;
    }
    let remote = answerer
        .sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_remote_candidates();
    let by_port = |port: u16| {
        remote
            .iter()
            .find(|c| c.port == port)
            .unwrap_or_else(|| panic!("no candidate on {port}: {remote:?}"))
    };
    let host = by_port(5000);
    assert_eq!(host.typ, RTCIceCandidateType::Host);
    assert_eq!(host.component, 1, "component rtp");
    assert_eq!(
        host.tcp_type,
        RTCIceTcpCandidateType::Unspecified,
        "null for UDP"
    );
    assert_eq!((host.related_address.as_str(), host.related_port), ("", 0));
    let srflx = by_port(6000);
    assert_eq!(srflx.typ, RTCIceCandidateType::Srflx);
    assert_eq!(
        (srflx.related_address.as_str(), srflx.related_port),
        ("10.0.0.1", 5000)
    );
    assert_eq!(by_port(6001).typ, RTCIceCandidateType::Prflx);
    let relay = by_port(7000);
    assert_eq!(relay.typ, RTCIceCandidateType::Relay);
    assert_eq!(relay.related_port, 6000);
    assert_eq!(by_port(5001).tcp_type, RTCIceTcpCandidateType::Passive);
    assert_eq!(
        by_port(5002).tcp_type,
        RTCIceTcpCandidateType::SimultaneousOpen
    );
    Ok(())
}

/// W3C addTransceiver sendEncodings: an encoding naming a codec that matches none of the
/// sender's capabilities is an OperationError.
#[test]
fn add_transceiver_refuses_an_encoding_codec_outside_the_capabilities() -> TestResult {
    let mut pc = default_peer()?;
    let refused = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                codec: RTCRtpCodec {
                    mime_type: "video/no-such-codec".to_owned(),
                    clock_rate: 90000,
                    ..Default::default()
                },
                ..Default::default()
            }],
        }),
    );
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(pc.get_transceivers().count(), 0);
    Ok(())
}

/// W3C RTCRtpTransceiverInit.streams are the stream ids signalled for the sender (msid), and
/// "sendonly" / "recvonly" are offered as such.
#[test]
fn init_streams_and_directions_are_what_the_offer_signals() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec!["stream-a".to_owned(), "stream-b".to_owned()],
            send_encodings: vec![],
        }),
    )?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    let offer = pc.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    assert!(sections[0].iter().any(|l| l == "a=sendonly"));
    let msids: Vec<&str> = sections[0]
        .iter()
        .filter_map(|l| l.strip_prefix("a=msid:"))
        .map(|v| v.split_whitespace().next().unwrap_or_default())
        .collect();
    assert_eq!(msids, ["stream-a", "stream-b"], "{}", offer.sdp);
    assert!(sections[1].iter().any(|l| l == "a=recvonly"));
    assert!(
        !sections[1].iter().any(|l| l.starts_with("a=msid:")),
        "a recvonly section describes no sender"
    );
    Ok(())
}

/// W3C 5.2.10 / 5.2.11: the static capabilities list the header extensions by URI.
#[test]
fn capabilities_list_header_extensions_by_uri() -> TestResult {
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability;
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: "urn:ietf:params:rtp-hdrext:sdes:mid".to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let sender = pc.add_track(video_track("v", 0x0606_0606))?;
    let capabilities = pc
        .rtp_sender(sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities");
    assert!(!capabilities.header_extensions.is_empty());
    assert!(
        capabilities
            .header_extensions
            .iter()
            .all(|e| e.uri.starts_with("urn:") || e.uri.starts_with("http")),
        "{:?}",
        capabilities.header_extensions
    );
    assert!(
        capabilities
            .header_extensions
            .iter()
            .any(|e| e.uri == "urn:ietf:params:rtp-hdrext:sdes:mid")
    );
    Ok(())
}

/// W3C 9.3.1: a remote track's getCapabilities is the empty set.
#[test]
fn a_remote_track_has_no_capabilities() -> TestResult {
    use rtc::media_stream::MediaTrackCapabilities;
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0707_0707))?;
    exchange(&mut offerer, &mut answerer)?;
    let receiver = answerer.get_receivers().next().expect("a receiver");
    let receiver = answerer.rtp_receiver(receiver).expect("receiver");
    assert_eq!(
        format!("{:?}", receiver.track().get_capabilities()),
        format!("{:?}", MediaTrackCapabilities::default())
    );
    Ok(())
}

/// W3C 4.4.2 addIceCandidate: a candidate that names neither `sdpMid` nor `sdpMLineIndex` is
/// a TypeError (checked before the remote description is); an end-of-candidates indication
/// without either is for every media description.
#[test]
fn add_ice_candidate_without_a_mid_or_an_index_is_a_type_error() -> TestResult {
    let unnamed = |candidate: &str| RTCIceCandidateInit {
        candidate: candidate.to_owned(),
        ..Default::default()
    };
    let mut answerer = default_peer()?;
    let refused = answerer.add_remote_candidate(unnamed(
        "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host",
    ));
    assert!(matches!(refused, Err(Error::TypeError(_))), "{refused:?}");

    let mut offerer = peer_with_data()?;
    let offer = offerer.create_offer(None)?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let refused = answerer.add_remote_candidate(unnamed(
        "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host",
    ));
    assert!(matches!(refused, Err(Error::TypeError(_))), "{refused:?}");
    let remote = answerer.remote_description().expect("offer").sdp.clone();
    assert!(!remote.contains("a=candidate:"), "{remote}");

    answerer.add_remote_candidate(unnamed(""))?;
    let remote = answerer.remote_description().expect("offer").sdp.clone();
    assert!(remote.contains("a=end-of-candidates"), "{remote}");
    Ok(())
}

/// W3C 4.4.2 addIceCandidate, "add the ICE candidate": a candidate for a media description
/// whose transceiver is stopped resolves without doing anything; the description's other
/// sections still take theirs.
#[test]
fn add_ice_candidate_for_a_stopped_transceivers_section_does_nothing() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("a", 0x0101_0101))?;
    let second = offerer.add_track(video_track("b", 0x0202_0202))?;
    exchange(&mut offerer, &mut answerer)?;
    offerer
        .rtp_transceiver(second.into())
        .expect("transceiver")
        .stop()?;
    // The offer rejects the section: applying it stops the answerer's transceiver, which is
    // removed only once the answer completes the exchange.
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let stopped_mid = answerer
        .get_transceivers()
        .collect::<Vec<_>>()
        .into_iter()
        .find_map(|id| {
            let t = answerer.rtp_transceiver(id)?;
            t.is_stopped().then(|| t.mid().clone()).flatten()
        })
        .expect("the answerer's transceiver of the rejected section is stopped");
    let live_mid = if stopped_mid == "0" { "1" } else { "0" };

    let candidate = |mid: &str, port: u16| RTCIceCandidateInit {
        candidate: format!("candidate:1 1 udp 2130706431 10.0.0.1 {port} typ host"),
        sdp_mid: Some(mid.to_owned()),
        ..Default::default()
    };
    answerer.add_remote_candidate(candidate(&stopped_mid, 5000))?;
    answerer.add_remote_candidate(candidate(live_mid, 5001))?;

    let remote = answerer.remote_description().expect("offer").sdp.clone();
    let sections = media_sections(&remote);
    let section = |mid: &str| {
        sections
            .iter()
            .find(|s| mid_of(s) == Some(mid))
            .unwrap_or_else(|| panic!("no section {mid}: {remote}"))
    };
    assert!(
        !section(&stopped_mid)
            .iter()
            .any(|l| l.starts_with("a=candidate:")),
        "{remote}"
    );
    assert!(
        section(live_mid)
            .iter()
            .any(|l| l.contains("10.0.0.1 5001 typ host")),
        "{remote}"
    );
    Ok(())
}

/// W3C 4.7.3, "check if negotiation is needed": with no current local description and no
/// data channel or transceiver to negotiate, the result is false. A remote offer whose
/// rollback removes the transceivers it created leaves the answerer with nothing to
/// negotiate: no negotiationneeded is fired.
#[test]
fn a_rollback_to_an_empty_stable_state_needs_no_negotiation() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0303_0303))?;
    let offer = offerer.create_offer(None)?;
    answerer.set_remote_description(Instant::now(), offer)?;
    assert_eq!(answerer.get_transceivers().count(), 1);
    events(&mut answerer);

    answerer.set_remote_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert_eq!(answerer.signaling_state(), RTCSignalingState::Stable);
    assert_eq!(
        answerer.get_transceivers().count(),
        0,
        "the rollback removed the transceiver the offer created"
    );
    assert_eq!(negotiation_needed(&mut answerer), 0);

    // A data channel created now is something to negotiate.
    answerer.create_data_channel("d", None)?;
    assert_eq!(negotiation_needed(&mut answerer), 1);
    Ok(())
}

/// W3C 4.4.1.2 and 4.4.2 close: once the connection is closed, every operation that chains
/// (createOffer, createAnswer, setLocalDescription, setRemoteDescription, addIceCandidate)
/// and createDataChannel / setConfiguration are an InvalidStateError; a candidate the
/// application gathered is no longer surfaced; restartIce fires no negotiationneeded.
#[test]
fn every_operation_on_a_closed_connection_is_an_invalid_state_error() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    answerer.close()?;
    events(&mut answerer);

    let candidate = |line: &str| RTCIceCandidateInit {
        candidate: line.to_owned(),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    };
    let closed = |result: Result<(), Error>| matches!(result, Err(Error::ErrConnectionClosed));
    assert!(closed(answerer.add_remote_candidate(candidate(
        "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host"
    ))));
    assert!(closed(answerer.add_remote_candidate(candidate(""))));
    assert!(closed(answerer.add_local_candidate(candidate(
        "candidate:2 1 udp 2130706431 10.0.0.2 5000 typ host"
    ))));
    assert!(closed(answerer.create_offer(None).map(|_| ())));
    assert!(closed(answerer.create_answer(None).map(|_| ())));
    assert!(closed(answerer.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer.clone())?
    )));
    assert!(closed(answerer.set_local_description(
        Instant::now(),
        RTCSessionDescription::offer(offer)?
    )));
    assert!(closed(
        answerer.create_data_channel("late", None).map(|_| ())
    ));
    assert!(closed(
        answerer.set_configuration(RTCConfigurationBuilder::new().build())
    ));
    answerer.restart_ice();
    assert!(events(&mut answerer).is_empty(), "no event after close");
    Ok(())
}

/// W3C 5.6 `[[IceRole]]` and 4.4.1.4 (RFC 8445 rules): the role is "unknown" until the first
/// offer is processed; a local offer makes it controlling (before any answer arrives), a
/// remote offer without `a=ice-lite` controlled.
#[test]
fn the_ice_role_is_unknown_until_the_first_offer() -> TestResult {
    fn role(pc: &mut RTCPeerConnection) -> RTCIceRole {
        let transceiver = pc.get_transceivers().next().expect("a transceiver");
        pc.rtp_sender(transceiver.into())
            .and_then(|s| s.transport().map(|t| t.ice_transport().role()))
            .expect("an associated transceiver names its transport")
    }
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0404_0404))?;
    let offer = offerer.create_offer(None)?;
    assert_eq!(role(&mut offerer), RTCIceRole::Unspecified, "unknown");

    offerer.set_local_description(Instant::now(), offer.clone())?;
    assert_eq!(role(&mut offerer), RTCIceRole::Controlling);

    answerer.set_remote_description(Instant::now(), offer)?;
    assert_eq!(role(&mut answerer), RTCIceRole::Controlled);
    Ok(())
}

/// W3C 4.4.1.5 set a configuration: iceCandidatePoolSize may change until setLocalDescription
/// has been called; after that a different size is an InvalidModificationError, also once a
/// rollback has emptied the local description again.
#[test]
fn the_candidate_pool_size_is_fixed_once_set_local_description_was_called() -> TestResult {
    let pool = |size: u8| {
        RTCConfigurationBuilder::new()
            .with_ice_candidate_pool_size(size)
            .build()
    };
    let mut pc = peer_with_data()?;
    pc.set_configuration(pool(2))?;
    assert_eq!(pc.get_configuration().ice_candidate_pool_size(), 2);
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    pc.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert!(pc.local_description().is_none());
    let refused = pc.set_configuration(pool(4));
    assert!(
        matches!(refused, Err(Error::ErrModifyingICECandidatePoolSize)),
        "{refused:?}"
    );
    pc.set_configuration(pool(2))?;
    Ok(())
}

/// W3C 4.4.2 setLocalDescription and 4.6.2 RTCLocalSessionDescriptionInit: the type is
/// optional ("offer" in stable, "answer" in have-remote-offer) and without an sdp the
/// connection creates the offer or answer itself; [[LastCreatedOffer]] starts empty, so a
/// fresh connection's first call needs no createOffer.
#[test]
fn set_local_description_without_a_type_or_sdp_creates_the_description() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    offerer.set_local_description(Instant::now(), RTCSessionDescription::default())?;
    assert_eq!(offerer.signaling_state(), RTCSignalingState::HaveLocalOffer);
    let offer = offerer.local_description().expect("an offer").clone();
    assert!(offer.sdp.contains("m=application"), "{}", offer.sdp);

    answerer.set_remote_description(Instant::now(), offer)?;
    answerer.set_local_description(Instant::now(), RTCSessionDescription::default())?;
    assert_eq!(answerer.signaling_state(), RTCSignalingState::Stable);
    let answer = answerer.current_local_description().expect("an answer");
    assert_eq!(
        answer.sdp_type,
        rtc::peer_connection::sdp::RTCSdpType::Answer
    );

    offerer.set_remote_description(Instant::now(), answer)?;
    assert_eq!(offerer.signaling_state(), RTCSignalingState::Stable);
    Ok(())
}

/// W3C 4.4.1.4 (set the description, an answer): the sender's [[SendCodecs]] are the codecs
/// negotiated for sending, so a transceiver negotiated recvonly lists none in its sender's
/// getParameters, while its receiver lists the codecs it receives.
#[test]
fn a_recvonly_transceivers_sender_lists_no_send_codecs() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let recvonly = offerer
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    // The answerer sends: its addTrack transceiver takes the offered section.
    let answering = answerer.add_track(video_track("v", 0x0505_0505))?;
    let before = offerer
        .rtp_sender(recvonly.into())
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .len();
    exchange(&mut offerer, &mut answerer)?;
    let send_codecs = offerer
        .rtp_sender(recvonly.into())
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    assert!(
        send_codecs.is_empty(),
        "negotiated recvonly: nothing is sent ({before} before): {send_codecs:?}"
    );
    assert!(
        !offerer
            .rtp_receiver(recvonly.into())
            .expect("receiver")
            .get_parameters()
            .rtp_parameters
            .codecs
            .is_empty()
    );
    assert!(
        !answerer
            .rtp_sender(answering)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs
            .is_empty(),
        "the answerer's sender sends"
    );
    Ok(())
}

/// W3C 4.4.2 currentLocalDescription and currentRemoteDescription: the descriptions of the
/// last completed exchange, with the local candidates gathered since and the remote
/// candidates addIceCandidate added since.
#[test]
fn current_descriptions_carry_the_candidates_added_since() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    exchange(&mut offerer, &mut answerer)?;
    let candidate = |line: &str| RTCIceCandidateInit {
        candidate: line.to_owned(),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    };
    offerer.add_local_candidate(candidate(
        "candidate:1 1 udp 2130706431 192.0.2.10 50000 typ host",
    ))?;
    answerer.add_remote_candidate(candidate(
        "candidate:1 1 udp 2130706431 192.0.2.10 50000 typ host",
    ))?;
    assert!(offerer.pending_local_description().is_none());
    let local = offerer.current_local_description().expect("offer").sdp;
    assert!(local.contains("192.0.2.10 50000 typ host"), "{local}");
    assert!(answerer.pending_remote_description().is_none());
    let remote = answerer
        .current_remote_description()
        .expect("offer")
        .sdp
        .clone();
    assert!(remote.contains("192.0.2.10 50000 typ host"), "{remote}");
    Ok(())
}

/// W3C 4.4.1.1 constructor: `[[DataChannels]]` starts as an empty ordered set; each channel
/// created joins it in order.
#[test]
fn data_channels_start_empty_and_are_kept_in_creation_order() -> TestResult {
    let mut pc = default_peer()?;
    assert!(pc.data_channel_ids().is_empty());
    let first = pc.create_data_channel("first", None)?.id();
    let second = pc.create_data_channel("second", None)?.id();
    assert_eq!(pc.data_channel_ids(), vec![first, second]);
    Ok(())
}

/// The lines of `sdp` with the per-connection random values left out: the origin line (its
/// session id), the ICE credentials and the DTLS `tls-id`.
fn without_random_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|l| {
            !["o=", "a=ice-ufrag:", "a=ice-pwd:", "a=tls-id:"]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .collect()
}

/// W3C 4.2.6: RTCAnswerOptions has no members, so the engine's extra
/// `voice_activity_detection` member changes nothing in the answer.
#[test]
fn answer_options_leave_the_answer_unchanged() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = offerer.create_offer(None)?;
    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let plain = answerer.create_answer(None)?;
    let with_vad = answerer.create_answer(Some(
        rtc::peer_connection::configuration::RTCAnswerOptions {
            voice_activity_detection: true,
        },
    ))?;
    assert_eq!(
        without_random_lines(&plain.sdp),
        without_random_lines(&with_vad.sdp)
    );
    Ok(())
}

/// W3C 4.2.1: no member outside the RTCConfiguration dictionary changes behaviour. The
/// engine's `peer_identity` (webrtc-identity's member, removed from webrtc-pc) leaves the
/// offer as it is.
#[test]
fn the_peer_identity_member_changes_no_offer() -> TestResult {
    let provider = rtc::crypto::default_provider()?;
    let certificate = RTCCertificate::generate_certificate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        None,
        SystemTime::now(),
    )?;
    let peer = |identity: Option<&str>| -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine =
            rtc::peer_connection::configuration::media_engine::MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut configuration =
            RTCConfigurationBuilder::new().with_certificates(vec![certificate.clone()]);
        if let Some(identity) = identity {
            configuration = configuration.with_peer_identitys(identity.to_owned());
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_configuration(configuration.build())
            .build(Instant::now())?;
        pc.create_data_channel("d", None)?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        Ok(pc)
    };
    let plain = peer(None)?.create_offer(None)?;
    let with_identity = peer(Some("alice@example.org"))?.create_offer(None)?;
    assert_eq!(
        without_random_lines(&plain.sdp)
            .into_iter()
            .filter(|l| !l.starts_with("a=ssrc:") && !l.starts_with("a=msid:"))
            .collect::<Vec<_>>(),
        without_random_lines(&with_identity.sdp)
            .into_iter()
            .filter(|l| !l.starts_with("a=ssrc:") && !l.starts_with("a=msid:"))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// The four description slots, as SDP.
fn slots(pc: &RTCPeerConnection) -> [Option<String>; 4] {
    [
        pc.current_local_description().map(|d| d.sdp),
        pc.pending_local_description().map(|d| d.sdp),
        pc.current_remote_description().map(|d| d.sdp.clone()),
        pc.pending_remote_description().map(|d| d.sdp.clone()),
    ]
}

/// W3C 4.4.1: the description slots change only in setLocalDescription,
/// setRemoteDescription, addIceCandidate and when a candidate is surfaced. Creating offers,
/// transceivers and channels, changing directions, the configuration, an ICE restart request
/// and reading statistics leave them as they are.
#[test]
fn only_descriptions_and_candidates_change_the_description_slots() -> TestResult {
    let mut offerer = peer_with_data()?;
    let mut answerer = default_peer()?;
    exchange(&mut offerer, &mut answerer)?;
    let before = slots(&offerer);
    assert!(before[0].is_some() && before[2].is_some());

    offerer.create_offer(None)?;
    let id = offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    offerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Recvonly)?;
    offerer.create_data_channel("another", None)?;
    let configuration = offerer.get_configuration().clone();
    offerer.set_configuration(configuration)?;
    offerer.restart_ice();
    offerer.get_stats(Instant::now(), rtc::statistics::StatsSelector::None);
    offerer.create_offer(None)?;
    assert_eq!(slots(&offerer), before, "no slot changed");

    offerer.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.0.2.10 50000 typ host".to_owned(),
        ..Default::default()
    })?;
    let surfaced = slots(&offerer);
    assert_ne!(
        surfaced[0], before[0],
        "a surfaced candidate joins the local description"
    );
    assert_eq!(surfaced[2], before[2]);
    Ok(())
}

/// W3C 4.4.1: every description-slot change of an operation is complete before any event it
/// raises fires: when the application reads the first event of setRemoteDescription, the
/// pending remote description and the signaling state already are the final ones.
#[test]
fn the_description_slots_are_set_before_the_first_event() -> TestResult {
    let mut offerer = peer_with_data()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = offerer.create_offer(None)?;
    let mut answerer = default_peer()?;
    events(&mut answerer);
    answerer.set_remote_description(Instant::now(), offer.clone())?;
    let mut seen = 0;
    while let Some(_event) = answerer.poll_event() {
        seen += 1;
        assert_eq!(
            answerer.pending_remote_description().map(|d| d.sdp.clone()),
            Some(offer.sdp.clone())
        );
        assert_eq!(
            answerer.signaling_state(),
            RTCSignalingState::HaveRemoteOffer
        );
        assert!(answerer.get_transceivers().count() >= 1);
    }
    assert!(seen > 0, "setRemoteDescription raised events");
    Ok(())
}

/// W3C 5.2.9: a sender's codec `sdpFmtpLine` is the one of the current remote description,
/// a receiver's the one of the local description. The answer adds `stereo=1` to Opus.
#[test]
fn sender_fmtp_follows_the_remote_description_and_receiver_fmtp_the_local() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let id = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    let opus_fmtp = answer
        .sdp
        .lines()
        .find(|l| l.starts_with("a=fmtp:") && l.contains("useinbandfec=1"))
        .expect("an Opus fmtp line")
        .to_owned();
    let munged = answer
        .sdp
        .replace(&opus_fmtp, &format!("{opus_fmtp};stereo=1"));
    offerer.set_remote_description(now, RTCSessionDescription::answer(munged)?)?;

    let opus = |codecs: &[rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters]| {
        codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("audio/opus"))
            .map(|c| c.rtp_codec.sdp_fmtp_line.clone())
            .expect("Opus")
    };
    let sent = opus(
        &offerer
            .rtp_sender(id.into())
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs,
    );
    let received = opus(
        &offerer
            .rtp_receiver(id.into())
            .expect("receiver")
            .get_parameters()
            .rtp_parameters
            .codecs,
    );
    assert!(
        sent.contains("stereo=1"),
        "the remote description's: {sent}"
    );
    assert!(
        !received.contains("stereo=1"),
        "the local description's: {received}"
    );
    Ok(())
}
