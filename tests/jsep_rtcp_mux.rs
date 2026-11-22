//! RTP/RTCP multiplexing and reduced-size RTCP in descriptions (RFC 5761 section 5.1.1,
//! RFC 8858, RFC 5506 section 5, RFC 9429 sections 5.2.1, 5.3.1, 5.8.3 and 5.11, RFC 9143
//! section 9.3.1): the attributes are read, not only written. This endpoint has no RTCP
//! component, so it says `a=rtcp-mux-only`, refuses (or, under the "negotiate" policy,
//! rejects) what does not multiplex, and uses reduced-size RTCP only when both sides say so.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TestResult, crlf, default_peer, exchange, media_sections, port_of, video_track,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtcpMuxPolicy};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpTransceiverId;
use rtc::shared::error::Error;

/// The transport lines of a remote section, without `a=rtcp-mux`.
const TRANSPORT_NO_MUX: &str = "c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16
a=setup:actpass
";

fn section(media: &str, mid: &str, payload: &str, rtcp: &str) -> String {
    format!(
        "m={media} 9 UDP/TLS/RTP/SAVPF {}
{TRANSPORT_NO_MUX}a=mid:{mid}
a=sendrecv
{rtcp}a=rtpmap:{payload}
",
        payload.split(' ').next().unwrap_or_default()
    )
}

fn audio(mid: &str, rtcp: &str) -> String {
    section("audio", mid, "111 opus/48000/2", rtcp)
}

fn video(mid: &str, rtcp: &str) -> String {
    section("video", mid, "96 VP8/90000", rtcp)
}

fn offer(group: &str, sections: &[String]) -> Result<RTCSessionDescription, Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE {group}\n{}",
        sections.concat()
    )))
}

fn peer_with(policy: RTCRtcpMuxPolicy) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_rtcp_mux_policy(policy)
                .build(),
        )
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn has(section: &[String], line: &str) -> bool {
    section.iter().any(|l| l == line)
}

#[test]
fn an_offer_says_it_only_multiplexes() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0101_0101))?;
    pc.create_data_channel("data", None)?;
    let offer = pc.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    assert!(sections[0][0].starts_with("m=video"), "{}", offer.sdp);
    for line in ["a=rtcp-mux", "a=rtcp-mux-only", "a=rtcp-rsize"] {
        assert!(has(&sections[0], line), "{line}:\n{}", offer.sdp);
    }
    assert!(!has(&sections[1], "a=rtcp-mux-only"), "{}", offer.sdp);
    Ok(())
}

#[test]
fn an_offer_without_rtcp_mux_is_refused_under_the_require_policy() -> TestResult {
    // The default policy is "require" (W3C RTCConfiguration.rtcpMuxPolicy).
    for mut pc in [default_peer()?, peer_with(RTCRtcpMuxPolicy::Require)?] {
        // The video section is in no BUNDLE group, so no tagged section's attribute is its.
        let refused = pc.set_remote_description(
            Instant::now(),
            offer("0", &[audio("0", "a=rtcp-mux\n"), video("1", "")])?,
        );
        assert!(
            matches!(&refused, Err(Error::SdpInvalidValue(why)) if why.contains("a=rtcp-mux")),
            "{refused:?}"
        );
        assert!(pc.remote_description().is_none());
        assert_eq!(pc.get_transceivers().count(), 0);
    }
    Ok(())
}

#[test]
fn a_section_without_rtcp_mux_is_rejected_under_the_negotiate_policy() -> TestResult {
    let mut pc = peer_with(RTCRtcpMuxPolicy::Negotiate)?;
    pc.set_remote_description(
        Instant::now(),
        offer("0", &[audio("0", "a=rtcp-mux\n"), video("1", "")])?,
    )?;
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_ne!(port_of(&sections[0]), 0, "{}", answer.sdp);
    assert!(has(&sections[0], "a=rtcp-mux"), "{}", answer.sdp);
    // No RTCP component to answer the video section with: rejected.
    assert_eq!(port_of(&sections[1]), 0, "{}", answer.sdp);
    assert!(
        answer.sdp.contains("a=group:BUNDLE 0\r\n"),
        "{}",
        answer.sdp
    );
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

#[test]
fn rtcp_mux_only_needs_rtcp_mux() -> TestResult {
    let mut pc = peer_with(RTCRtcpMuxPolicy::Negotiate)?;
    let refused = pc.set_remote_description(
        Instant::now(),
        offer("0", &[audio("0", "a=rtcp-mux-only\n")])?,
    );
    assert!(
        matches!(&refused, Err(Error::SdpInvalidValue(why)) if why.contains("rtcp-mux-only")),
        "{refused:?}"
    );
    assert!(pc.remote_description().is_none());
    Ok(())
}

#[test]
fn an_answer_without_rtcp_mux_is_refused_and_the_offer_stays_pending() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("local", 0x0202_0202))?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert!(answer.sdp.contains("a=rtcp-mux\r\n"), "{}", answer.sdp);

    let without = answer
        .sdp
        .replace("a=rtcp-mux\r\n", "")
        .replace("a=rtcp-mux-only\r\n", "");
    let refused =
        offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(without)?);
    assert!(
        matches!(&refused, Err(Error::SdpInvalidValue(why)) if why.contains("a=rtcp-mux")),
        "{refused:?}"
    );
    assert!(offerer.remote_description().is_none());

    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(())
}

/// RFC 9143 section 9.3.1.2: when the offerer-tagged section had `a=rtcp-mux-only`, the
/// answerer-tagged section says so too; no other answered section does (RFC 8858 section 4.3).
#[test]
fn the_answerer_tagged_section_repeats_rtcp_mux_only() -> TestResult {
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        offer(
            "0 1",
            &[
                audio("0", "a=rtcp-mux\na=rtcp-mux-only\n"),
                video("1", "a=rtcp-mux\na=rtcp-mux-only\n"),
            ],
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert!(has(&sections[0], "a=rtcp-mux"), "{}", answer.sdp);
    assert!(has(&sections[0], "a=rtcp-mux-only"), "{}", answer.sdp);
    assert!(has(&sections[1], "a=rtcp-mux"), "{}", answer.sdp);
    assert!(!has(&sections[1], "a=rtcp-mux-only"), "{}", answer.sdp);

    // Not offered: not answered.
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), offer("0", &[audio("0", "a=rtcp-mux\n")])?)?;
    let answer = pc.create_answer(None)?;
    assert!(!answer.sdp.contains("a=rtcp-mux-only"), "{}", answer.sdp);
    Ok(())
}

fn receiver_reduced_size(pc: &mut RTCPeerConnection) -> bool {
    let id = pc.get_transceivers().next().expect("transceiver");
    let receiver = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .receiver()
        .expect("receiver");
    pc.rtp_receiver(receiver)
        .expect("receiver")
        .get_parameters()
        .rtp_parameters
        .rtcp
        .reduced_size
}

/// RFC 5506 section 5, RFC 9429 section 5.11: reduced-size RTCP only when the offer and the
/// answer both carry `a=rtcp-rsize`.
#[test]
fn reduced_size_rtcp_is_used_only_when_both_sides_signal_it() -> TestResult {
    // Offered without it: the answer does not say it, and it is not used.
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), offer("0", &[video("0", "a=rtcp-mux\n")])?)?;
    let answer = pc.create_answer(None)?;
    assert!(!answer.sdp.contains("a=rtcp-rsize"), "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    assert!(!receiver_reduced_size(&mut pc));

    // Offered with it: answered with it, and used.
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        offer("0", &[video("0", "a=rtcp-mux\na=rtcp-rsize\n")])?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(answer.sdp.contains("a=rtcp-rsize"), "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    assert!(receiver_reduced_size(&mut pc));

    // The offerer: used after an answer with it, not after one without.
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("local", 0x0303_0303))?;
    let sender_reduced_size = |pc: &mut RTCPeerConnection| {
        let id = pc
            .rtp_transceiver(RTCRtpTransceiverId::from(sender))
            .expect("transceiver")
            .sender()
            .expect("sender");
        pc.rtp_sender(id)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .rtcp
            .reduced_size
    };
    assert!(!sender_reduced_size(&mut offerer), "nothing negotiated yet");
    exchange(&mut offerer, &mut answerer)?;
    assert!(sender_reduced_size(&mut offerer));

    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    let without = answer.sdp.replace("a=rtcp-rsize\r\n", "");
    assert_ne!(without, answer.sdp);
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(without)?)?;
    assert!(!sender_reduced_size(&mut offerer));
    Ok(())
}

/// RFC 9429 section 5.10: a media-level `b=TIAS` (else `b=AS`) is the most this endpoint may
/// send; a session-level `b=` line and `b=CT` are ignored. `b=RS` / `b=RR` are RFC 3556's
/// RTCP bandwidths. RFC 3611 section 5.1: `a=rtcp-xr` at media level replaces the session's.
#[test]
fn bandwidth_lines_and_rtcp_xr_of_a_remote_section_are_read() -> TestResult {
    let section = |mid: &str, lines: &str, attributes: &str| {
        format!(
            "m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
{lines}a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16
a=setup:actpass
a=mid:{mid}
a=sendrecv
a=rtcp-mux
{attributes}a=rtpmap:96 VP8/90000
"
        )
    };
    let offer = crlf(&format!(
        "v=0
o=- 4215775240449105457 2 IN IP4 127.0.0.1
s=-
b=AS:9999
t=0 0
a=group:BUNDLE 0 1 2
a=rtcp-xr:rcvr-rtt=all
{}{}{}",
        section("0", "b=AS:500\nb=TIAS:400000\nb=RS:2000\nb=RR:0\n", ""),
        section(
            "1",
            "b=CT:7000\nb=AS:300\n",
            "a=rtcp-xr:pkt-loss-rle stat-summary=loss,dup\n"
        ),
        section("2", "", "a=rtcp-xr\n"),
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let ids: Vec<usize> = pc.get_transceivers().collect();
    assert_eq!(ids.len(), 3);

    let first = pc.rtp_transceiver(ids[0]).expect("transceiver");
    let bandwidth = first.remote_bandwidth();
    assert_eq!(bandwidth.max_bitrate, Some(400_000), "TIAS wins over AS");
    assert_eq!(bandwidth.rtcp_senders_bitrate, Some(2000));
    assert_eq!(bandwidth.rtcp_receivers_bitrate, Some(0));
    assert_eq!(
        first.remote_rtcp_xr().map(<[String]>::to_vec),
        Some(vec!["rcvr-rtt=all".to_owned()]),
        "the session's attribute"
    );

    let second = pc.rtp_transceiver(ids[1]).expect("transceiver");
    let bandwidth = second.remote_bandwidth();
    assert_eq!(bandwidth.max_bitrate, Some(300_000), "AS is in kilobits");
    assert_eq!(bandwidth.rtcp_senders_bitrate, None);
    assert_eq!(
        second.remote_rtcp_xr().map(<[String]>::to_vec),
        Some(vec![
            "pkt-loss-rle".to_owned(),
            "stat-summary=loss,dup".to_owned()
        ])
    );

    let third = pc.rtp_transceiver(ids[2]).expect("transceiver");
    assert_eq!(
        third.remote_bandwidth().max_bitrate,
        None,
        "the session-level b=AS is not a section's"
    );
    assert_eq!(
        third.remote_rtcp_xr().map(<[String]>::to_vec),
        Some(vec![]),
        "an empty media-level attribute replaces the session's"
    );
    Ok(())
}

/// RFC 9429 section 4.1.1: `a=rtcp-mux-only` goes into new m= sections under the "require"
/// policy; section 5.2.2: a section negotiated before does not get it again, and keeps
/// `a=rtcp-rsize` only if the most recent answer had it.
#[test]
fn a_subsequent_offer_follows_the_most_recent_answer() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("first", 0x0404_0404))?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    // The answer the offerer sees has no a=rtcp-rsize.
    let without = answer.sdp.replace("a=rtcp-rsize\r\n", "");
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(without)?)?;

    offerer.add_track(video_track("second", 0x0505_0505))?;
    let offer = offerer.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    assert_eq!(sections.len(), 2, "{}", offer.sdp);
    // The negotiated section.
    assert!(has(&sections[0], "a=rtcp-mux"), "{}", offer.sdp);
    assert!(!has(&sections[0], "a=rtcp-mux-only"), "{}", offer.sdp);
    assert!(!has(&sections[0], "a=rtcp-rsize"), "{}", offer.sdp);
    // The new one.
    for line in ["a=rtcp-mux", "a=rtcp-mux-only", "a=rtcp-rsize"] {
        assert!(has(&sections[1], line), "{line}:\n{}", offer.sdp);
    }

    // Under "negotiate" no section says it only multiplexes.
    let mut pc = peer_with(RTCRtcpMuxPolicy::Negotiate)?;
    pc.add_track(video_track("local", 0x0606_0606))?;
    let offer = pc.create_offer(None)?;
    assert!(offer.sdp.contains("a=rtcp-mux\r\n"), "{}", offer.sdp);
    assert!(!offer.sdp.contains("a=rtcp-mux-only"), "{}", offer.sdp);
    Ok(())
}
