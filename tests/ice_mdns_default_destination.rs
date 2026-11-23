//! draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.4: an mDNS name never appears in the
//! `c=` line (or as the `m=` port's address); with only mDNS host candidates the default
//! destination is `0.0.0.0` (`::`) and port 9.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Instant;

#[test]
fn an_mdns_host_candidate_is_never_the_default_destination()
-> Result<(), Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::QueryAndGather)
                .build(),
        )
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.create_data_channel("data", None)?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host".to_owned(),
        ..Default::default()
    })?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    let sdp = pc.pending_local_description().expect("the offer").sdp;
    let candidate = sdp
        .lines()
        .find(|l| l.starts_with("a=candidate:"))
        .unwrap_or_else(|| panic!("the candidate is listed: {sdp}"));
    assert!(
        candidate.contains(".local "),
        "the host address is hidden: {candidate}"
    );
    assert!(!sdp.contains("10.0.0.1"), "{sdp}");
    let mut sections = 0;
    for line in sdp.lines() {
        if let Some(m) = line.strip_prefix("m=") {
            sections += 1;
            assert_eq!(m.split_whitespace().nth(1), Some("9"), "{sdp}");
        }
        if let Some(c) = line.strip_prefix("c=") {
            assert!(!c.contains(".local"), "{sdp}");
            assert!(c == "IN IP4 0.0.0.0" || c == "IN IP6 ::", "{sdp}");
        }
        if let Some(rtcp) = line.strip_prefix("a=rtcp:") {
            assert!(!rtcp.contains(".local"), "{sdp}");
        }
    }
    assert_eq!(sections, 2);
    Ok(())
}
