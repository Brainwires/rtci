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
