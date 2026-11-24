//! The `a=fmtp` parameters of a generated description are this endpoint's own, not the ones
//! the peer stated (RFC 3264 section 6.1), by each codec's offer/answer rules: Opus (RFC 7587
//! section 7.1, declarative), H.264 (RFC 6184 section 8.2.2: profile and packetization mode
//! symmetric, level per `level-asymmetry-allowed`), AV1 (AV1 RTP section 7.2.3) and VP9
//! (RFC 9628 section 6). A format whose configuration this endpoint does not have is removed,
//! not negotiated by its name alone.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;

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
    // VP8 first; the formats the offer lacked may follow (RFC 9429 section 5.3.1), but not
    // the offered H.264 format with its unsupported profile, nor its RTX.
    assert!(
        section[0].starts_with("m=video 9 UDP/TLS/RTP/SAVPF 96"),
        "{sdp}"
    );
    assert!(
        !section.iter().any(|l| l.starts_with("a=rtpmap:100 ")
            || l.starts_with("a=rtpmap:101 ")
            || l.contains("profile-level-id=58")),
        "{sdp}"
    );
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
    // The offer's `max-fs` is the offerer's receiver limit, not this endpoint's; the
    // default VP9 formats state none of their own (`set_vp9_receiver_limits`).
    assert_eq!(fmtp(&sdp, "98"), vec!["profile-id=0"], "{sdp}");
    Ok(())
}

/// A peer whose only video format is the H.264 format `fmtp` registers.
fn h264_peer(fmtp: &str) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_H264, MediaEngine};
    use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_H264.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 102,
        },
        RtpCodecKind::Video,
    )?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    Ok(pc)
}

/// RFC 7742 section 6.2: "Implementations MUST include this parameter [profile-level-id]
/// within SDP". An H.264 format the application registers without fmtp parameters is the
/// RFC 6184 section 8.1 default (Baseline, Level 1), and the offer states it explicitly.
#[test]
fn an_h264_format_registered_without_profile_level_id_is_offered_with_its_default() -> TestResult {
    let mut pc = h264_peer("")?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        fmtp(&offer.sdp, "102"),
        vec!["profile-level-id=42000a"],
        "{}",
        offer.sdp
    );
    Ok(())
}

/// RFC 7742 section 6.2: parameter sets travel in-band, "WebRTC implementations MUST NOT
/// include this parameter [sprop-parameter-sets] in the SDP they generate": not from a format
/// the application registered with it, nor in an answer to an offer that has it.
#[test]
fn sprop_parameter_sets_is_never_written() -> TestResult {
    let mut pc = h264_peer(
        "packetization-mode=1;profile-level-id=42e01f;sprop-parameter-sets=Z0IACpZTBYmI,aMljiA==",
    )?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        fmtp(&offer.sdp, "102"),
        vec!["packetization-mode=1", "profile-level-id=42e01f"],
        "{}",
        offer.sdp
    );

    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer_with_h264(
            "packetization-mode=1;profile-level-id=42e01f;sprop-parameter-sets=Z0IACpZTBYmI,aMljiA==",
        ),
    )?;
    let parameters = fmtp(&sdp, "100");
    assert!(
        parameters.contains(&"profile-level-id=42e01f".to_owned()),
        "{sdp}"
    );
    assert!(!sdp.contains("sprop-parameter-sets"), "{sdp}");
    Ok(())
}

fn offer_with_h264(fmtp: &str) -> String {
    let fmtp = if fmtp.is_empty() {
        String::new()
    } else {
        format!("a=fmtp:100 {fmtp}\n")
    };
    offer("video", "100", &format!("a=rtpmap:100 H264/90000\n{fmtp}"))
}

/// RFC 7742 section 6.2: `profile-level-id` is interpreted when received. An offer without
/// it is RFC 6184 section 8.1's Baseline at Level 1 in single NAL mode; the answer keeps the
/// profile and answers no higher level than that (this endpoint's own is 3.1), stating it.
#[test]
fn an_h264_offer_without_profile_level_id_is_answered_at_level_1() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(&mut pc, offer_with_h264(""))?;
    let parameters = fmtp(&sdp, "100");
    assert!(
        parameters.contains(&"profile-level-id=42000a".to_owned()),
        "{sdp}"
    );
    assert!(
        parameters.contains(&"packetization-mode=0".to_owned()),
        "{sdp}"
    );
    Ok(())
}

/// RFC 7798 section 7.2.2: with decoding order numbers in play (`sprop-max-don-diff` above
/// 0) "both parties are RECOMMENDED to include depack-buf-cap". An answer to an H.265 offer
/// that announces reordering states this endpoint's de-packetization buffer in bytes
/// (`MAX_DEPACKETIZATION_BYTES`, 32 MiB: absent, the offerer would take 4294967295); an
/// answer to one without it, and this endpoint's default offer, carry none.
#[test]
fn an_h265_answer_to_a_reordering_stream_states_the_depacketization_buffer() -> TestResult {
    let cap = format!(
        "depack-buf-cap={}",
        rtci::rtp::codec::h265::MAX_DEPACKETIZATION_BYTES
    );
    let h265 = |extra: &str| {
        offer(
            "video",
            "110",
            &format!(
                "a=rtpmap:110 H265/90000\n\
                 a=fmtp:110 level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST{extra}\n"
            ),
        )
    };
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        h265(";sprop-max-don-diff=2;sprop-depack-buf-nalus=4;sprop-depack-buf-bytes=40000"),
    )?;
    assert!(fmtp(&sdp, "110").contains(&cap), "{sdp}");

    let mut pc = default_peer()?;
    let sdp = answer(&mut pc, h265(""))?;
    assert!(!fmtp(&sdp, "110").is_empty(), "H.265 answered: {sdp}");
    assert!(!sdp.contains("depack-buf-cap"), "{sdp}");

    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    assert!(!offer.sdp.contains("depack-buf-cap"), "{}", offer.sdp);
    Ok(())
}
