//! Where the BUNDLE attributes go (RFC 9143 section 7.1.3; RFC 8859 categories IDENTICAL and
//! TRANSPORT). From the remote side both forms are taken: repeated in every bundled section,
//! or in the tagged section only, whose attributes then apply to every bundled section. What
//! this endpoint writes in answers and subsequent offers is the tagged-only form the RFC
//! requires, and the repeated form (as browsers write) with
//! `SettingEngineBuilder::with_bundle_attributes_repeated`.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections, port_of, video_track};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

const BUNDLE_ATTRIBUTES: [&str; 5] = [
    "a=ice-ufrag:",
    "a=ice-pwd:",
    "a=setup:",
    "a=rtcp-mux",
    "a=rtcp-rsize",
];

fn repeating_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_bundle_attributes_repeated(true)
                .build(),
        )
        .build(Instant::now())?)
}

/// Audio, video and video.
fn add_media(pc: &mut RTCPeerConnection) -> TestResult {
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_track(video_track("first", 0x0101_0101))?;
    pc.add_track(video_track("second", 0x0202_0202))?;
    Ok(())
}

/// For each section, which of the BUNDLE attributes it carries.
fn carried(sdp: &str) -> Vec<Vec<&'static str>> {
    media_sections(sdp)
        .iter()
        .map(|section| {
            assert_ne!(port_of(section), 0, "{sdp}");
            BUNDLE_ATTRIBUTES
                .into_iter()
                .filter(|attribute| section.iter().any(|l| l.starts_with(attribute)))
                .collect()
        })
        .collect()
}

fn every_transceiver_uses_reduced_size_rtcp(pc: &mut RTCPeerConnection) -> bool {
    let ids: Vec<usize> = pc.get_transceivers().collect();
    assert_eq!(ids.len(), 3);
    ids.into_iter().all(|id| {
        pc.rtp_transceiver(id)
            .expect("transceiver")
            .rtcp_reduced_size()
    })
}

#[test]
fn when_asked_answers_and_later_offers_repeat_the_bundle_attributes() -> TestResult {
    let mut a = repeating_peer()?;
    let mut b = repeating_peer()?;
    add_media(&mut a)?;
    let (_, answer) = jsep_common::exchange(&mut a, &mut b)?;
    for section in carried(&answer) {
        assert_eq!(section, BUNDLE_ATTRIBUTES.to_vec(), "{answer}");
    }
    let offer = a.create_offer(None)?;
    for section in carried(&offer.sdp) {
        assert_eq!(section, BUNDLE_ATTRIBUTES.to_vec(), "{}", offer.sdp);
    }
    Ok(())
}

/// The initial offer is the one description whose bundled sections each carry the BUNDLE
/// attributes (RFC 9143 section 7.1.3, first exception), bundle-only sections excepted.
#[test]
fn an_initial_offer_has_them_in_every_section_that_is_not_bundle_only() -> TestResult {
    let mut a = default_peer()?;
    add_media(&mut a)?;
    let offer = a.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    assert_eq!(sections.len(), 3);
    for section in &sections {
        let bundle_only = section.iter().any(|l| l == "a=bundle-only");
        for attribute in BUNDLE_ATTRIBUTES {
            assert_eq!(
                section.iter().any(|l| l.starts_with(attribute)),
                !bundle_only,
                "{attribute}\n{}",
                offer.sdp
            );
        }
    }
    Ok(())
}

#[test]
fn by_default_they_are_in_the_tagged_section_only_and_apply_to_all() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    add_media(&mut a)?;

    // The answer.
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    b.set_remote_description(Instant::now(), offer)?;
    let answer = b.create_answer(None)?;
    let shape = carried(&answer.sdp);
    assert_eq!(shape[0], BUNDLE_ATTRIBUTES.to_vec(), "{}", answer.sdp);
    assert!(shape[1].is_empty() && shape[2].is_empty(), "{}", answer.sdp);
    assert!(
        answer.sdp.contains("a=group:BUNDLE 0 1 2"),
        "{}",
        answer.sdp
    );
    b.set_local_description(Instant::now(), answer.clone())?;

    // The other side takes it: the tagged section's attributes are every bundled section's.
    a.set_remote_description(Instant::now(), answer)?;
    assert!(every_transceiver_uses_reduced_size_rtcp(&mut a));
    assert!(every_transceiver_uses_reduced_size_rtcp(&mut b));

    // A subsequent offer, from either side, has the same form, and is answered.
    for answerer_offers in [true, false] {
        let (x, y) = if answerer_offers {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let offer = x.create_offer(None)?;
        let shape = carried(&offer.sdp);
        assert_eq!(shape[0], BUNDLE_ATTRIBUTES.to_vec(), "{}", offer.sdp);
        assert!(shape[1].is_empty() && shape[2].is_empty(), "{}", offer.sdp);
        x.set_local_description(Instant::now(), offer.clone())?;
        y.set_remote_description(Instant::now(), offer)?;
        let answer = y.create_answer(None)?;
        let shape = carried(&answer.sdp);
        assert_eq!(shape[0], BUNDLE_ATTRIBUTES.to_vec(), "{}", answer.sdp);
        assert!(shape[1].is_empty() && shape[2].is_empty(), "{}", answer.sdp);
        y.set_local_description(Instant::now(), answer.clone())?;
        x.set_remote_description(Instant::now(), answer)?;
        assert!(every_transceiver_uses_reduced_size_rtcp(x));
        assert!(every_transceiver_uses_reduced_size_rtcp(y));
    }
    Ok(())
}

/// The same from a peer that is not this engine: an answer written by hand in the form of
/// RFC 9143 section 7.1.3, the BUNDLE attributes (and the fingerprint) in the answerer-tagged
/// section only.
#[test]
fn an_answer_with_the_bundle_attributes_in_the_tagged_section_only_is_applied() -> TestResult {
    let mut a = default_peer()?;
    add_media(&mut a)?;
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    let formats: Vec<String> = media_sections(&offer.sdp)
        .iter()
        .map(|section| {
            let pt = section[0].split(' ').nth(3).expect("a format").to_owned();
            let rtpmap = section
                .iter()
                .find(|l| l.starts_with(&format!("a=rtpmap:{pt} ")))
                .expect("its rtpmap")
                .clone();
            format!("{pt}\n{rtpmap}")
        })
        .collect();
    let section = |media: &str, mid: usize, transport: &str| {
        let (pt, rtpmap) = formats[mid].split_once('\n').expect("format");
        // The audio transceiver only receives, the video ones send and receive.
        let direction = if mid == 0 { "sendonly" } else { "recvonly" };
        format!(
            "m={media} 9 UDP/TLS/RTP/SAVPF {pt}\r\nc=IN IP4 0.0.0.0\r\n{transport}a=mid:{mid}\r\na={direction}\r\n{rtpmap}\r\n"
        )
    };
    let transport = "a=ice-ufrag:4ZcD\r\na=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz\r\na=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16\r\na=setup:active\r\na=rtcp-mux\r\na=rtcp-rsize\r\n";
    let answer = format!(
        "v=0\r\no=- 4215775240449105457 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1 2\r\n{}{}{}",
        section("audio", 0, transport),
        section("video", 1, ""),
        section("video", 2, ""),
    );
    a.set_remote_description(Instant::now(), RTCSessionDescription::answer(answer)?)?;
    assert!(a.current_remote_description().is_some());
    assert!(every_transceiver_uses_reduced_size_rtcp(&mut a));
    Ok(())
}

/// RFC 9143 section 7.1.3, the note, and section 9.3.1.2: the tagged section carries
/// `a=rtcp-mux` for the group "even if the tagged 'm=' section does not describe RTP-based
/// media". A connection that began with a data channel has the data section tagged; the
/// subsequent offer that adds video, and its answer, say `a=rtcp-mux` (and `a=rtcp-rsize`)
/// there, and both sides take it for the video section.
#[test]
fn a_tagged_data_section_carries_rtcp_mux_for_the_rtp_sections() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.create_data_channel("data", None)?;
    jsep_common::exchange(&mut a, &mut b)?;

    a.add_track(video_track("later", 0x0303_0303))?;
    let (offer, answer) = jsep_common::exchange(&mut a, &mut b)?;
    for sdp in [&offer, &answer] {
        let sections = media_sections(sdp);
        assert_eq!(sections.len(), 2, "{sdp}");
        assert!(sections[0][0].starts_with("m=application"), "{sdp}");
        for attribute in ["a=rtcp-mux", "a=rtcp-rsize", "a=ice-ufrag:"] {
            assert!(
                sections[0].iter().any(|l| l.starts_with(attribute)),
                "{attribute} in the tagged section:\n{sdp}"
            );
            assert!(
                !sections[1].iter().any(|l| l.starts_with(attribute)),
                "{attribute} not in the video section:\n{sdp}"
            );
        }
        assert_ne!(port_of(&sections[1]), 0, "{sdp}");
    }
    for pc in [&mut a, &mut b] {
        let id = pc.get_transceivers().next().expect("the video transceiver");
        assert!(
            pc.rtp_transceiver(id)
                .expect("transceiver")
                .rtcp_reduced_size()
        );
    }
    Ok(())
}
