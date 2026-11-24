//! RFC 8866 and RFC 8839 rows about what the engine writes into its own descriptions (sdp
//! branch, jsep-77).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

/// The `<bwtype>` of every `b=` line of `sdp`.
fn bandwidth_types(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("b="))
        .map(|l| l.split(':').next().unwrap_or_default().to_owned())
        .collect()
}

/// RFC 8866 section 5.8: "Use of the "X-" prefix is NOT RECOMMENDED. Instead new (non "X-"
/// prefix) <bwtype> names SHOULD be defined". The receive bandwidth a section states is
/// written with the registered modifiers TIAS (RFC 3890) and AS, in an offer and in an
/// answer, also when the remote offer carried an experimental `b=X-` line.
#[test]
fn bandwidth_lines_use_registered_modifiers_only() -> TestResult {
    let mut pc = default_peer()?;
    let id =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    pc.rtp_transceiver(id)
        .expect("the transceiver")
        .set_receive_bandwidth(Some(500_000));
    let offer = pc.create_offer(None)?;
    assert_eq!(bandwidth_types(&offer.sdp), ["TIAS", "AS"], "{}", offer.sdp);

    // Section 5: b= lines come after c=, at session level before t=.
    let session = SESSION.replace("t=0 0", "b=X-YZ:128\nt=0 0");
    let transport = TRANSPORT.replacen("c=IN IP4 0.0.0.0\n", "c=IN IP4 0.0.0.0\nb=X-YZ:64\n", 1);
    let remote = crlf(&format!(
        "{session}m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:0\na=sendonly\na=msid:s t\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    assert!(remote.contains("b=X-YZ:64\r\na=ice-ufrag"), "{remote}");
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(remote)?)?;
    let id = pc
        .get_transceivers()
        .next()
        .expect("the offered transceiver");
    pc.rtp_transceiver(id)
        .expect("the transceiver")
        .set_receive_bandwidth(Some(500_000));
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 1, "{}", answer.sdp);
    assert_eq!(
        bandwidth_types(&answer.sdp),
        ["TIAS", "AS"],
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("b=X-"), "{}", answer.sdp);
    Ok(())
}

/// RFC 8839 section 4.2.1.6: "If the port value associated with an "m=" section is set to zero
/// ... the agent SHOULD NOT include ICE-related SDP "candidate" attributes in that "m="
/// section". An answerer under `must-bundle` rejects the offered section outside the BUNDLE
/// group (RFC 9429 section 4.1.1), here the first one; after gathering, the candidates are in
/// the accepted (tagged) section, in the answer and in the local description, and the rejected
/// one has none. Likewise for an offer without BUNDLE under balanced, whose second video
/// section is rejected.
#[test]
fn a_section_answered_with_port_zero_has_no_candidates() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
    let video = |mid: &str| {
        format!(
            "m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:{mid}\na=sendrecv\na=rtcp-mux\n\
             a=rtpmap:96 VP8/90000\n"
        )
    };
    let has_candidates = |section: &[String]| {
        section
            .iter()
            .any(|l| l.starts_with("a=candidate:") || l == "a=end-of-candidates")
    };
    for (group, policy, rejected) in [
        (
            "a=group:BUNDLE 1\n",
            Some(RTCBundlePolicy::MustBundle),
            0usize,
        ),
        ("", None, 1usize),
    ] {
        let remote = crlf(&format!("{SESSION}{group}{}{}", video("0"), video("1")));
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut configuration = RTCConfigurationBuilder::new();
        if let Some(policy) = policy {
            configuration = configuration.with_bundle_policy(policy);
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_configuration(configuration.build())
            .build(Instant::now())?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(remote)?)?;
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 10.0.0.2 4000 typ host".to_owned(),
            ..Default::default()
        })?;
        pc.add_local_candidate(RTCIceCandidateInit::default())?;
        let answer = pc.create_answer(None)?;
        pc.set_local_description(Instant::now(), answer.clone())?;
        let local = pc
            .local_description()
            .expect("the local description")
            .sdp
            .clone();
        for sdp in [&answer.sdp, &local] {
            let sections = media_sections(sdp);
            assert_eq!(sections.len(), 2, "{sdp}");
            let accepted = 1 - rejected;
            assert_ne!(port_of(&sections[accepted]), 0, "{sdp}");
            assert!(has_candidates(&sections[accepted]), "{sdp}");
            assert_eq!(port_of(&sections[rejected]), 0, "{sdp}");
            assert!(!has_candidates(&sections[rejected]), "{sdp}");
        }
    }
    Ok(())
}

/// RFC 3264 section 6.1: "The answerer MAY include a non-zero ptime attribute for any media
/// stream". An answerer whose application set a packet time (`set_audio_packet_time`) states
/// it in the answer's audio section, and one that set none states none.
#[test]
fn an_answer_states_the_packet_time_the_application_set() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::{MediaEngine, RTCPacketTime};
    let remote = crlf(&format!(
        "{SESSION}m=audio 9 UDP/TLS/RTP/SAVPF 111\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:111 opus/48000/2\n"
    ));
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.set_audio_packet_time(RTCPacketTime {
        ptime: Some(40),
        maxptime: Some(60),
    });
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(remote.clone())?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(answer.sdp.contains("\r\na=ptime:40\r\n"), "{}", answer.sdp);
    assert!(
        answer.sdp.contains("\r\na=maxptime:60\r\n"),
        "{}",
        answer.sdp
    );

    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(remote)?)?;
    let answer = pc.create_answer(None)?;
    assert!(!answer.sdp.contains("a=ptime"), "{}", answer.sdp);
    Ok(())
}
