//! RFC 9429 rows of the sweep (jsep12): candidates and `a=end-of-candidates` in the tagged
//! section only (sections 5.2.2, 5.3.2), and the mandatory-to-use values every section must
//! have, at media or session level (section 5.8.3).

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, video_track,
};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceCandidateInit;

fn gather(pc: &mut RTCPeerConnection, address: &str) -> TestResult {
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: format!("candidate:1 1 udp 2130706431 {address} 4000 typ host"),
        ..Default::default()
    })?;
    // The end of gathering.
    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    Ok(())
}

fn has(section: &[String], prefix: &str) -> bool {
    section.iter().any(|l| l.starts_with(prefix))
}

/// Sections 5.2.2 and 5.3.2: "If the 'm=' section is not bundled into another 'm=' section,
/// ... an 'a=end-of-candidates' attribute MUST be added" once gathering for it is complete,
/// and "if the 'm=' section is bundled into another 'm=' section, both 'a=candidate' and
/// 'a=end-of-candidates' MUST be omitted". Before gathering completes no section says so;
/// afterwards the later offer and the later answer carry both in the tagged section only.
#[test]
fn candidates_and_end_of_candidates_are_in_the_tagged_section_only() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("a", 0x5e10_0101))?;
    offerer.add_track(video_track("b", 0x5e10_0102))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for sdp in [&offer, &answer] {
        assert!(!sdp.contains("a=end-of-candidates"), "{sdp}");
    }

    gather(&mut offerer, "10.0.0.1")?;
    gather(&mut answerer, "10.0.0.2")?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for sdp in [&offer, &answer] {
        assert!(sdp.contains("a=group:BUNDLE 0 1"), "{sdp}");
        let sections = media_sections(sdp);
        assert_eq!(sections.len(), 2, "{sdp}");
        assert!(has(&sections[0], "a=candidate:"), "{sdp}");
        assert!(has(&sections[0], "a=end-of-candidates"), "{sdp}");
        assert!(!has(&sections[1], "a=candidate:"), "{sdp}");
        assert!(!has(&sections[1], "a=end-of-candidates"), "{sdp}");
    }
    Ok(())
}

/// A remote offer of one video section with `transport` (ICE and DTLS lines) at session
/// level and `media` lines in the section.
fn offer(session: &str, media: &str) -> Result<RTCSessionDescription, rtc::shared::error::Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}{session}a=group:BUNDLE 0\nm=video 9 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 0.0.0.0\n\
         {media}a=mid:0\na=sendrecv\na=rtcp-mux\na=rtpmap:96 VP8/90000\n"
    )))
}

/// The ICE and DTLS attributes of [`TRANSPORT`], one per line.
fn transport_attributes() -> String {
    TRANSPORT
        .lines()
        .filter(|l| {
            l.starts_with("a=ice-") || l.starts_with("a=fingerprint") || l.starts_with("a=setup")
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Section 5.8.3: "For each 'm=' section, valid values for each of the mandatory-to-use
/// features enumerated in Section 5.1.1 MUST be present. These values MAY be either present
/// at the media level or inherited from the session level": ICE credentials and a DTLS
/// fingerprint at session level serve the section; without the ICE password, or without any
/// fingerprint, at either level, the description is refused. (`a=tls-id` may be absent: RFC
/// 8842 section 5 provides for a peer that does not write it, as browsers do not.)
#[test]
fn mandatory_values_may_be_inherited_from_the_session_and_must_be_somewhere() -> TestResult {
    let transport = transport_attributes();
    let without = |prefix: &str| -> String {
        transport
            .lines()
            .filter(|l| !l.starts_with(prefix))
            .map(|l| format!("{l}\n"))
            .collect()
    };
    // At session level: taken.
    default_peer()?.set_remote_description(Instant::now(), offer(&transport, "")?)?;
    // At media level: taken.
    default_peer()?.set_remote_description(Instant::now(), offer("", &transport)?)?;
    for missing in ["a=ice-pwd", "a=ice-ufrag", "a=fingerprint"] {
        let mut pc = default_peer()?;
        let refused = pc.set_remote_description(Instant::now(), offer(&without(missing), "")?);
        assert!(refused.is_err(), "without {missing}: {refused:?}");
        assert!(pc.remote_description().is_none(), "without {missing}");
    }
    Ok(())
}

/// Section 3.5.3: candidates the policy disallows "MUST NOT be ... exposed to the application
/// ... nor ... leaked through other fields such as the raddr/rport". Under the "relay" policy
/// a host candidate is not taken (no `a=candidate` for it), and a relayed one is described
/// with its related address suppressed (`raddr 0.0.0.0 rport 9`, RFC 8827 section 6.4), so
/// the host address behind it shows nowhere in the description.
#[test]
fn the_relay_policy_exposes_no_local_address_not_even_as_a_related_address() -> TestResult {
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build(),
        )
        .build(Instant::now())?;
    pc.add_track(video_track("v", 0x5e12_0101))?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    let _ = pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.168.1.20 4000 typ host".to_owned(),
        ..Default::default()
    });
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:2 1 udp 16777215 203.0.113.9 50000 typ relay raddr 192.168.1.20 \
                    rport 4000"
            .to_owned(),
        ..Default::default()
    })?;
    let local = pc
        .pending_local_description()
        .expect("the offer")
        .sdp
        .clone();
    assert!(local.contains("203.0.113.9 50000 typ relay"), "{local}");
    assert!(!local.contains("192.168.1.20"), "{local}");
    assert!(local.contains("raddr 0.0.0.0 rport 9"), "{local}");
    Ok(())
}

/// Section 5.8.2: "Any 'a=rtcp' attribute MUST be parsed as specified in [RFC3605], Section
/// 2.1, but its value is ignored": a well-formed line is taken (and changes nothing), one
/// that is not `port [nettype addrtype address]` refuses the description.
#[test]
fn an_rtcp_attribute_is_parsed_and_its_value_ignored() -> TestResult {
    let transport = transport_attributes();
    for (line, taken) in [
        ("a=rtcp:9 IN IP4 0.0.0.0\n", true),
        ("a=rtcp:53020\n", true),
        ("a=rtcp:port\n", false),
        ("a=rtcp:9 IN IP4\n", false),
    ] {
        let mut pc = default_peer()?;
        let applied =
            pc.set_remote_description(Instant::now(), offer("", &format!("{transport}{line}"))?);
        assert_eq!(applied.is_ok(), taken, "{line}: {applied:?}");
    }
    Ok(())
}
