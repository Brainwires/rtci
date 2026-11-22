//! Codec parameters in offers and answers: the audio formats a WebRTC endpoint offers (RFC
//! 7874 section 3), Opus (RFC 7587 section 7), H.264 (RFC 6184 section 8) and AV1 (AV1 RTP
//! payload format section 7.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::media_engine::MIME_TYPE_PCMU;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

/// The `a=rtpmap` and `a=fmtp` values of the first media section of `sdp`, as
/// `(payload type, rtpmap, fmtp)` in `m=` line order.
fn formats(sdp: &str) -> Vec<(String, String, String)> {
    let section: Vec<&str> = sdp
        .lines()
        .skip_while(|l| !l.starts_with("m="))
        .enumerate()
        .take_while(|(i, l)| *i == 0 || !l.starts_with("m="))
        .map(|(_, l)| l)
        .collect();
    let pts: Vec<String> = section[0]
        .split_whitespace()
        .skip(3)
        .map(str::to_owned)
        .collect();
    let value = |prefix: &str, pt: &str| {
        section
            .iter()
            .find_map(|l| l.strip_prefix(&format!("a={prefix}:{pt} ")))
            .unwrap_or("")
            .to_owned()
    };
    pts.iter()
        .map(|pt| (pt.clone(), value("rtpmap", pt), value("fmtp", pt)))
        .collect()
}

/// The answer a default peer gives to a remote offer with one `media` section whose formats
/// are `lines` (`a=rtpmap` / `a=fmtp`) on the payload types `pts`.
fn answer_to(media: &str, pts: &str, lines: &str) -> Result<String, Box<dyn std::error::Error>> {
    let offer = crlf(&format!(
        "{SESSION}m={media} 9 UDP/TLS/RTP/SAVPF {pts}\n{TRANSPORT}a=mid:0\na=sendrecv\n{lines}"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    Ok(pc.create_answer(None)?.sdp)
}

fn offer_with_audio(pc: &mut RTCPeerConnection) -> Result<String, Box<dyn std::error::Error>> {
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    Ok(pc.create_offer(None)?.sdp)
}

/// RFC 7874 section 3: Opus, PCMA and PCMU, RFC 3389 comfort noise "for streams encoded with
/// G.711", and `audio/telephone-event` are required, Opus is offered first; RFC 3389 section
/// 4: CN at 8000 Hz is the static payload type 13.
#[test]
fn the_default_audio_offer_has_the_rfc_7874_formats_with_opus_first() -> TestResult {
    let mut pc = default_peer()?;
    let offered = formats(&offer_with_audio(&mut pc)?);
    let rtpmaps: Vec<&str> = offered.iter().map(|(_, r, _)| r.as_str()).collect();
    assert_eq!(Some(&"opus/48000/2"), rtpmaps.first(), "{rtpmaps:?}");
    for format in [
        "PCMU/8000",
        "PCMA/8000",
        "telephone-event/8000",
        "telephone-event/48000",
    ] {
        assert!(rtpmaps.contains(&format), "{format} in {rtpmaps:?}");
    }
    assert!(
        offered
            .iter()
            .any(|(pt, rtpmap, _)| pt == "13" && rtpmap == "CN/8000"),
        "{offered:?}"
    );
    assert!(
        !rtpmaps.iter().any(|r| r.starts_with("CN/48000")),
        "no RFC 3389 CN for Opus (RFC 7874 section 3)"
    );
    Ok(())
}

/// RFC 4733 section 2.1 and RFC 3389 section 5: telephone events and comfort noise run in the
/// stream of the audio codec on its clock. A track that names its codec keeps the ones on that
/// codec's clock in the offer.
#[test]
fn a_track_that_names_its_codec_keeps_telephone_events_and_comfort_noise() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(MediaStreamTrack::new(
        "voice-stream".to_owned(),
        "voice".to_owned(),
        "voice".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(0x0A0D_1001),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_PCMU.to_owned(),
                clock_rate: 8000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    ))?;
    let offered = formats(&pc.create_offer(None)?.sdp);
    let rtpmaps: Vec<&str> = offered.iter().map(|(_, r, _)| r.as_str()).collect();
    assert_eq!(
        rtpmaps,
        vec!["PCMU/8000", "CN/8000", "telephone-event/8000"],
        "{offered:?}"
    );
    Ok(())
}

/// RFC 7587 section 7.1: "offer and answer parameters are independent": an answer states this
/// endpoint's own receive parameters, and an unknown parameter of the offer is not repeated.
/// Section 7: Opus is `opus/48000/2`; an offer of another channel count is another format,
/// which this endpoint does not have.
#[test]
fn an_opus_answer_states_its_own_parameters_and_only_opus_48000_2_matches() -> TestResult {
    let answer = answer_to(
        "audio",
        "111",
        "a=rtpmap:111 opus/48000/2\na=fmtp:111 stereo=1;usedtx=1;x-unknown=7\n",
    )?;
    assert_eq!(
        formats(&answer),
        vec![(
            "111".to_owned(),
            "opus/48000/2".to_owned(),
            "minptime=10;useinbandfec=1".to_owned()
        )]
    );
    let answer = answer_to(
        "audio",
        "111 0",
        "a=rtpmap:111 opus/48000/1\na=rtpmap:0 PCMU/8000\n",
    )?;
    let answered: Vec<String> = formats(&answer).into_iter().map(|(pt, _, _)| pt).collect();
    assert_eq!(answered, vec!["0".to_owned()]);
    Ok(())
}

/// RFC 6184 section 8.1: a format without `packetization-mode` is single NAL unit mode and
/// one without `profile-level-id` is Baseline at level 1; Table 5: combinations of
/// `profile_idc` and `profile-iop` that stand for one profile are that profile, so
/// Constrained Baseline offered as a Main profile id (`4d801f`) matches this endpoint's
/// Constrained Baseline (`42e01f`).
#[test]
fn h264_formats_match_by_their_rfc_6184_defaults_and_table_5_profiles() -> TestResult {
    let answer = answer_to(
        "video",
        "102 103",
        "a=rtpmap:102 H264/90000\na=rtpmap:103 H264/90000\na=fmtp:103 packetization-mode=1;profile-level-id=4d801f\n",
    )?;
    let answered = formats(&answer);
    let pts: Vec<&str> = answered.iter().map(|(pt, _, _)| pt.as_str()).collect();
    assert!(
        pts.contains(&"103"),
        "Constrained Baseline as Main: {answered:?}"
    );
    assert!(
        pts.contains(&"102"),
        "no fmtp is Baseline, mode 0: {answered:?}"
    );
    let fmtp_103 = &answered
        .iter()
        .find(|(pt, _, _)| pt == "103")
        .expect("103")
        .2;
    assert!(fmtp_103.contains("packetization-mode=1"), "{fmtp_103}");
    Ok(())
}

/// AV1 RTP section 7.2: an absent `profile` is 0, and the profile is the format (section
/// 7.2.3): an offer of profile 1 does not match this endpoint's profile 0; one without a
/// profile does, and is answered with this endpoint's own parameters ("the answerer MAY
/// declare its own" level and tier).
#[test]
fn av1_formats_match_by_profile_and_the_answer_declares_its_own_parameters() -> TestResult {
    let answer = answer_to(
        "video",
        "45 46",
        "a=rtpmap:45 AV1/90000\na=fmtp:45 profile=1\na=rtpmap:46 AV1/90000\na=fmtp:46 level-idx=8;tier=1\n",
    )?;
    let answered = formats(&answer);
    let av1: Vec<&(String, String, String)> = answered
        .iter()
        .filter(|(_, r, _)| r.starts_with("AV1/"))
        .collect();
    assert_eq!(1, av1.len(), "{answered:?}");
    assert_eq!("46", av1[0].0);
    assert_eq!("AV1/90000", av1[0].1);
    assert!(!av1[0].2.contains("level-idx=8"), "{:?}", av1[0]);
    Ok(())
}
