//! The `a=fmtp` parameters of a generated description are this endpoint's own, not the ones
//! the peer stated (RFC 3264 section 6.1), by each codec's offer/answer rules: Opus (RFC 7587
//! section 7.1, declarative), H.264 (RFC 6184 section 8.2.2: profile and packetization mode
//! symmetric, level per `level-asymmetry-allowed`), AV1 (AV1 RTP section 7.2.3) and VP9
//! (RFC 9628 section 6). A format whose configuration this endpoint does not have is removed,
//! not negotiated by its name alone.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::sdp::RTCSessionDescription;

fn offer(media: &str, formats: &str, lines: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m={media} 9 UDP/TLS/RTP/SAVPF {formats}
{TRANSPORT}a=mid:0
a=sendrecv
{lines}"
    ))
}

fn answer(pc: &mut RTCPeerConnection, offer: String) -> Result<String, Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

/// The fmtp parameters of payload type `pt` in `sdp`, sorted.
fn fmtp(sdp: &str, pt: &str) -> Vec<String> {
    let mut parameters: Vec<String> = sdp
        .lines()
        .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
        .map(|line| line.split(';').map(|p| p.trim().to_owned()).collect())
        .unwrap_or_default();
    parameters.sort();
    parameters
}

#[test]
fn an_opus_answer_states_this_endpoints_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "audio",
            "111",
            "a=rtpmap:111 opus/48000/2\na=fmtp:111 minptime=20;useinbandfec=0;stereo=1;maxaveragebitrate=64000\n",
        ),
    )?;
    assert_eq!(
        fmtp(&sdp, "111"),
        vec!["minptime=10", "useinbandfec=1"],
        "{sdp}"
    );

    // And so does its next offer: the peer's parameters are not this endpoint's.
    let offer = pc.create_offer(None)?;
    assert_eq!(
        fmtp(&offer.sdp, "111"),
        vec!["minptime=10", "useinbandfec=1"],
        "{}",
        offer.sdp
    );
    Ok(())
}

#[test]
fn an_h264_answer_keeps_the_profile_and_states_the_level_the_rfc_allows() -> TestResult {
    // Both sides allow level asymmetry: this endpoint's own level (3.1), not the offered 5.2.
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "video",
            "100",
            "a=rtpmap:100 H264/90000\na=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e034;max-fs=9999\n",
        ),
    )?;
    assert_eq!(
        fmtp(&sdp, "100"),
        vec![
            "level-asymmetry-allowed=1",
            "packetization-mode=1",
            "profile-level-id=42e01f"
        ],
        "{sdp}"
    );

    // The offer does not allow it: the answered level is not above the offered one (1.3).
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "video",
            "100",
            "a=rtpmap:100 H264/90000\na=fmtp:100 packetization-mode=1;profile-level-id=42e00d\n",
        ),
    )?;
    assert!(
        fmtp(&sdp, "100").contains(&"profile-level-id=42e00d".to_owned()),
        "{sdp}"
    );

    // Nor is a lower level of this endpoint raised to the offered one.
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "video",
            "100",
            "a=rtpmap:100 H264/90000\na=fmtp:100 packetization-mode=1;profile-level-id=42e034\n",
        ),
    )?;
    assert!(
        fmtp(&sdp, "100").contains(&"profile-level-id=42e01f".to_owned()),
        "{sdp}"
    );
    Ok(())
}

/// RFC 6184 section 8.2.2: "the answerer MUST either maintain all configuration parameters or
/// remove the media format (payload type) completely". A profile this endpoint did not
/// register (Extended, 58) is not negotiated because its name is H264.
#[test]
fn a_format_whose_configuration_is_not_supported_is_removed() -> TestResult {
    let h264 = "a=rtpmap:100 H264/90000\na=fmtp:100 packetization-mode=1;profile-level-id=58001f\na=rtpmap:101 rtx/90000\na=fmtp:101 apt=100\n";

    // The only format: the section is rejected.
    let mut pc = default_peer()?;
    let sdp = answer(&mut pc, offer("video", "100 101", h264))?;
    assert_eq!(port_of(&media_sections(&sdp)[0]), 0, "{sdp}");

    // With VP8 beside it: VP8 is answered, the H.264 format and its RTX are not.
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "video",
            "100 101 96",
            &format!("{h264}a=rtpmap:96 VP8/90000\n"),
        ),
    )?;
    let section = &media_sections(&sdp)[0];
    assert_eq!(section[0], "m=video 9 UDP/TLS/RTP/SAVPF 96", "{sdp}");
    Ok(())
}

#[test]
fn av1_and_vp9_answers_state_this_endpoints_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "video",
            "45 98",
            "a=rtpmap:45 AV1/90000\na=fmtp:45 level-idx=8;profile=0;tier=1\na=rtpmap:98 VP9/90000\na=fmtp:98 profile-id=0;max-fs=3600\n",
        ),
    )?;
    assert_eq!(fmtp(&sdp, "45"), vec!["profile=0"], "{sdp}");
    assert_eq!(fmtp(&sdp, "98"), vec!["profile-id=0"], "{sdp}");
    Ok(())
}
