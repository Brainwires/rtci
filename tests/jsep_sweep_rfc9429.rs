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

/// Section 5.8: "If any line is not well formed or cannot be parsed as described, the parser
/// MUST stop with an error and reject the session description, even if the value is to be
/// discarded." Malformed values of attributes the engine reads, and of ones it then ignores,
/// refuse the description at either level; an unknown attribute is ignored (RFC 8866 section
/// 5.13), and so are the malformed lines other specifications have the receiver ignore:
/// `a=msid` (RFC 8830 section 2) and `a=rid` (RFC 8851 section 6.2.2 step 1).
#[test]
fn a_malformed_attribute_refuses_the_description_unless_its_specification_ignores_it() -> TestResult
{
    let transport = transport_attributes();
    for (session, media, taken) in [
        ("", "", true),
        ("", "a=x-unknown:anything at all\n", true),
        ("", "a=msid:one two three\n", true),
        ("", "a=rid:\n", true),
        ("", "a=rid:1 sideways\n", true),
        ("", "a=ssrc:1234 msid:one two three\n", true),
        ("", "a=ssrc:1234 x-unknown:anything\n", true),
        ("", "a=ssrc:1234 previous-ssrc:none\n", false),
        ("", "a=ssrc:1234 cname\n", false),
        ("", "a=ssrc-group:FID 1234  5678\n", false),
        ("", "a=rtpmap:97 H264\n", false),
        ("", "a=fmtp:\n", false),
        ("", "a=rtcp-fb:96\n", false),
        ("", "a=ptime:soon\n", false),
        ("", "a=framerate:fast\n", false),
        ("", "a=ssrc:not-a-number cname:x\n", false),
        ("", "a=ssrc-group:FID one two\n", false),
        (
            "",
            "a=extmap:x urn:ietf:params:rtp-hdrext:sdes:mid\n",
            false,
        ),
        ("", "a=rtcp-mux:yes\n", false),
        // RFC 8839 section 5.1: the candidate grammar.
        (
            "",
            "a=candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host\n",
            true,
        ),
        (
            "",
            "a=candidate:1 1 udp 1694498815 203.0.113.9 4000 typ srflx raddr 10.0.0.1 rport \
             4000 generation 0\n",
            true,
        ),
        (
            "",
            "a=candidate:1 1 udp 2130706431 10.0.0.1 4000 type host\n",
            false,
        ),
        (
            "",
            "a=candidate:1 1 udp 2130706431 10.0.0.1 4000 typ\n",
            false,
        ),
        (
            "",
            "a=candidate:a!b 1 udp 2130706431 10.0.0.1 4000 typ host\n",
            false,
        ),
        (
            "",
            "a=candidate:123456789012345678901234567890123 1 udp 1 10.0.0.1 4000 typ host\n",
            false,
        ),
        (
            "",
            "a=candidate:1 1 udp 12345678901 10.0.0.1 4000 typ host\n",
            false,
        ),
        (
            "",
            "a=candidate:1 1 udp 1 203.0.113.9 4000 typ srflx raddr 10.0.0.1 rport\n",
            false,
        ),
        ("a=ice-options:\n", "", false),
        ("a=msid-semantic\n", "", false),
    ] {
        let mut pc = default_peer()?;
        let applied = pc.set_remote_description(
            Instant::now(),
            offer(session, &format!("{transport}{media}"))?,
        );
        assert_eq!(applied.is_ok(), taken, "{session}{media}: {applied:?}");
        if !taken {
            assert!(pc.remote_description().is_none(), "{session}{media}");
        }
    }
    Ok(())
}

/// Section 5.2.1: the offer's formats include the codecs every WebRTC endpoint must support:
/// RFC 7874 section 3, Opus, PCMA and PCMU, comfort noise for G.711 and telephone events
/// (RFC 4733) on the clock of each audio codec; RFC 7742 section 5, VP8 and H.264 Constrained
/// Baseline (`profile-level-id` 42e0xx).
#[test]
fn an_offer_has_the_mandatory_audio_and_video_formats() -> TestResult {
    use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?.sdp;
    let encodings: Vec<String> = offer
        .lines()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .filter_map(|l| l.split_once(' ').map(|(_, e)| e.to_ascii_lowercase()))
        .collect();
    for mandatory in [
        "opus/48000/2",
        "pcmu/8000",
        "pcma/8000",
        "cn/8000",
        "telephone-event/48000",
        "telephone-event/8000",
        "vp8/90000",
        "h264/90000",
    ] {
        assert!(
            encodings.iter().any(|e| e == mandatory),
            "{mandatory} is not offered:\n{offer}"
        );
    }
    assert!(
        offer
            .lines()
            .any(|l| l.starts_with("a=fmtp:") && l.contains("profile-level-id=42e0")),
        "no H.264 Constrained Baseline:\n{offer}"
    );
    Ok(())
}

/// Section 5.8 with the deployed stacks: webrtc-rs 0.17 and Pion write a feedback without
/// parameters as `a=rtcp-fb:96 goog-remb ` (a trailing space). By default white space at the
/// end of a value is not held against it, so their offers are answered;
/// `with_strict_sdp_attribute_grammar(true)` is the strict RFC reading, which refuses it. A
/// value that is malformed otherwise is refused either way.
#[test]
fn trailing_white_space_in_a_value_is_refused_only_when_asked() -> TestResult {
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    let peer = |strict: bool| -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_strict_sdp_attribute_grammar(strict)
                    .build(),
            )
            .build(Instant::now())?)
    };
    let transport = transport_attributes();
    for (media, default_takes, strict_takes) in [
        ("a=rtcp-fb:96 goog-remb \n", true, false),
        ("a=rtcp-fb:96 goog-remb\n", true, true),
        ("a=rtcp-fb:96 \n", false, false),
    ] {
        for (strict, takes) in [(false, default_takes), (true, strict_takes)] {
            let applied = peer(strict)?
                .set_remote_description(Instant::now(), offer("", &format!("{transport}{media}"))?);
            assert_eq!(
                applied.is_ok(),
                takes,
                "strict {strict}, {media:?}: {applied:?}"
            );
        }
    }
    Ok(())
}
