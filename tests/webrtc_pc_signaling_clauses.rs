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
