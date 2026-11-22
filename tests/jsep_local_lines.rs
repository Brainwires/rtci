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
    assert!(sources.contains(&format!("a=ssrc:{ssrc} cname:local-stream").as_str()));
    assert!(sources.contains(&format!("a=ssrc:{ssrc} msid:local-stream local").as_str()));
    Ok(())
}
