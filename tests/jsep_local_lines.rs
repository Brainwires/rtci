//! Lines a local description must not carry: candidates of an RTCP component that does not
//! exist (RFC 8858 section 5.3, RFC 5761 section 5.1.3) and source attributes that are not
//! registered (RFC 5576 section 4.1).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtc::peer_connection::transport::RTCIceCandidateInit;

#[test]
fn local_candidates_are_written_for_the_rtp_component_only() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0101_0101))?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.0.2.7 50000 typ host".to_owned(),
        ..Default::default()
    })?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer.clone())?;

    for sdp in [
        offer.sdp,
        pc.local_description().expect("local description").sdp,
    ] {
        let candidates: Vec<&str> = sdp
            .lines()
            .filter(|l| l.starts_with("a=candidate:"))
            .collect();
        assert_eq!(candidates.len(), 1, "{sdp}");
        assert_eq!(
            candidates[0].split(' ').nth(1),
            Some("1"),
            "component 1 (RTP): {sdp}"
        );
    }
    Ok(())
}

#[test]
fn source_attributes_are_cname_and_msid() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0202_0202))?;
    let offer = pc.create_offer(None)?;
    let sources: Vec<&str> = offer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=ssrc:"))
        .collect();
    assert!(!sources.is_empty(), "{}", offer.sdp);
    for line in &sources {
        let attribute = line.split(' ').nth(1).unwrap_or_default();
        assert!(
            attribute.starts_with("cname:") || attribute.starts_with("msid:"),
            "{line}"
        );
    }
    // Each SSRC (media and RTX) has both.
    let ssrc = 0x0202_0202u32;
    let cname = pc.rtcp_cname().to_owned();
    assert!(sources.contains(&format!("a=ssrc:{ssrc} cname:{cname}").as_str()));
    assert!(sources.contains(&format!("a=ssrc:{ssrc} msid:local-stream local").as_str()));
    Ok(())
}

/// RFC 5576 section 6.1: the `cname` source attribute is "the same as the CNAME that the
/// source uses in RTCP"; RFC 8834 section 4.9 and RFC 7022: one CNAME for the connection. So
/// every `a=ssrc ... cname:` line, of whatever track and stream, and the RTCP parameters of
/// every sender and receiver, carry `RTCPeerConnection::rtcp_cname()`.
#[test]
fn one_cname_is_in_every_source_attribute_and_in_the_rtcp_parameters() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("first", 0x0303_0303))?;
    pc.add_track(video_track("second", 0x0404_0404))?;
    let cname = pc.rtcp_cname().to_owned();
    // RFC 7022 section 4.2: 96 random bits, Base64: 16 characters.
    assert_eq!(cname.len(), 16, "{cname}");

    let offer = pc.create_offer(None)?;
    let cnames: Vec<&str> = offer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=ssrc:"))
        .filter_map(|l| l.split_once(" cname:").map(|(_, cname)| cname))
        .collect();
    // Two tracks, each with a media and an RTX SSRC.
    assert_eq!(cnames.len(), 4, "{}", offer.sdp);
    assert!(cnames.iter().all(|c| *c == cname), "{}", offer.sdp);

    let ids: Vec<_> = pc.get_transceivers().collect();
    for id in ids {
        let (sender, receiver) = {
            let transceiver = pc.rtp_transceiver(id).expect("transceiver");
            (transceiver.sender(), transceiver.receiver())
        };
        let sender = sender.expect("a sender");
        assert_eq!(
            pc.rtp_sender(sender)
                .expect("sender")
                .get_parameters()
                .rtp_parameters
                .rtcp
                .cname,
            cname
        );
        let receiver = receiver.expect("a receiver");
        assert_eq!(
            pc.rtp_receiver(receiver)
                .expect("receiver")
                .get_parameters()
                .rtp_parameters
                .rtcp
                .cname,
            cname
        );
    }

    // Another connection has another.
    assert_ne!(default_peer()?.rtcp_cname(), cname);
    Ok(())
}

/// RFC 8839 sections 4.2.1.2, 4.3.1 and 4.3.2: "each candidate for a data stream" is a
/// `candidate` attribute in that stream's m= section, in offers and answers. With a transport
/// per section (`max-compat`, no BUNDLE: RFC 9429 section 4.1.1) each section lists its own
/// transport's candidates, and only those; under BUNDLE the candidates are TRANSPORT attributes
/// (RFC 8859 section 5.13, RFC 9143 section 7.1.3), written once for the group in the tagged
/// section, as the browsers write them (`tests/fixtures/browser-sdp/`).
#[test]
fn each_section_with_a_transport_lists_that_transports_candidates() -> TestResult {
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
    use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

    let candidates_of = |section: &[String]| -> Vec<String> {
        section
            .iter()
            .filter_map(|l| l.strip_prefix("a=candidate:"))
            .map(|c| c.split(' ').nth(4).unwrap_or_default().to_owned())
            .collect()
    };
    let add = |pc: &mut rtc::peer_connection::RTCPeerConnection, mid: &str, address: &str| {
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: format!("candidate:1 1 udp 2130706431 {address} 50000 typ host"),
            sdp_mid: Some(mid.to_owned()),
            ..Default::default()
        })
    };

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(RTCBundlePolicy::MaxCompat)
                .build(),
        )
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    add(&mut pc, "0", "192.0.2.10")?;
    add(&mut pc, "1", "192.0.2.11")?;
    let sdp = pc.local_description().expect("local description").sdp;
    let sections = jsep_common::media_sections(&sdp);
    assert_eq!(sections.len(), 2, "{sdp}");
    assert_eq!(candidates_of(&sections[0]), vec!["192.0.2.10"], "{sdp}");
    assert_eq!(candidates_of(&sections[1]), vec!["192.0.2.11"], "{sdp}");

    // Bundled: the default policy puts both sections on the first transport; its candidates
    // are written in the tagged section, the first.
    let mut pc = default_peer()?;
    pc.add_track(video_track("first", 0x0303_0101))?;
    pc.add_track(video_track("second", 0x0303_0102))?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.0.2.12 50000 typ host".to_owned(),
        ..Default::default()
    })?;
    let offer = pc.create_offer(None)?;
    let sections = jsep_common::media_sections(&offer.sdp);
    assert!(offer.sdp.contains("a=group:BUNDLE 0 1"), "{}", offer.sdp);
    assert_eq!(
        candidates_of(&sections[0]),
        vec!["192.0.2.12"],
        "{}",
        offer.sdp
    );
    Ok(())
}
