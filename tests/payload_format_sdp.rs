//! The SDP side of the video and Opus payload formats with the default codecs: media types and
//! clock rates (RFC 6184 5.1, RFC 7798 4.1, 7.2.1, AV1 RTP 7.2.1, RFC 7587 4.1), the form of
//! `a=fmtp` (RFC 6184 8.2.1, RFC 7798 7.2.1, RFC 7741 6.2.1, RFC 9628 6.1.1, RFC 7587 7), the
//! receiver capabilities VP9 states (RFC 9628 6), and what an answer keeps of an offer
//! (RFC 6184 8.2.2, RFC 7798 7.2, 7.2.2, RFC 9628 6.1.2, RFC 7741 6.2.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fn offer(formats: &str, lines: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF {formats}
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

/// The default offer with an audio and a video section.
fn default_offer() -> Result<String, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    Ok(pc.create_offer(None)?.sdp)
}

/// The formats of the answer's video m= line that the offer listed (`offered`), in order. An
/// answer lists the offered formats it takes first, then the registered ones the offer lacked
/// (RFC 9429 section 5.3.1), which never reuse an offered number.
fn answered_offered_formats<'a>(section: &'a str, offered: &str) -> Vec<&'a str> {
    let offered: Vec<&str> = offered.split_whitespace().collect();
    let formats: Vec<&str> = section.split_whitespace().skip(3).collect();
    let answered: Vec<&str> = formats
        .iter()
        .copied()
        .filter(|f| offered.contains(f))
        .collect();
    assert_eq!(
        &formats[..answered.len()],
        answered.as_slice(),
        "the offered formats come first: {section}"
    );
    answered
}

/// `(media, payload type, encoding)` of every rtpmap, with the media of its section.
fn rtpmaps(sdp: &str) -> Vec<(String, String, String)> {
    let mut media = String::new();
    let mut out = vec![];
    for line in sdp.lines() {
        if let Some(m) = line.strip_prefix("m=") {
            media = m.split_whitespace().next().unwrap_or_default().to_owned();
        }
        if let Some((pt, encoding)) = line
            .strip_prefix("a=rtpmap:")
            .and_then(|r| r.split_once(' '))
        {
            out.push((media.clone(), pt.to_owned(), encoding.to_owned()));
        }
    }
    out
}

/// The fmtp parameters of payload type `pt` in `sdp`, as `name=value` strings.
fn fmtp(sdp: &str, pt: &str) -> Vec<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
        .map(|line| line.split(';').map(|p| p.trim().to_owned()).collect())
        .unwrap_or_default()
}

fn payload_type_of(sdp: &str, encoding_prefix: &str) -> Option<String> {
    rtpmaps(sdp)
        .into_iter()
        .find(|(_, _, e)| e.to_ascii_lowercase().starts_with(encoding_prefix))
        .map(|(_, pt, _)| pt)
}

/// RFC 6184 5.1 and 8.2.1, RFC 7798 4.1 and 7.2.1, AV1 RTP 7.2.1: H.264, H.265, AV1, VP8 and
/// VP9 are offered in a `video` section at 90 kHz.
#[test]
fn the_default_video_formats_are_video_at_90_khz() -> TestResult {
    let maps = rtpmaps(&default_offer()?);
    for name in ["h264", "h265", "av1", "vp8", "vp9"] {
        let found: Vec<_> = maps
            .iter()
            .filter(|(_, _, e)| e.to_ascii_lowercase().starts_with(&format!("{name}/")))
            .collect();
        assert!(!found.is_empty(), "{name} in {maps:?}");
        for (media, _, encoding) in found {
            assert_eq!("video", media, "{encoding}");
            assert!(encoding.ends_with("/90000"), "{encoding}");
        }
    }
    Ok(())
}

/// RFC 6184 8.2.1, RFC 7798 7.2.1, RFC 7741 6.2.1, RFC 9628 6.1.1, RFC 7587 7: optional
/// parameters go in `a=fmtp` as a semicolon-separated list of `name=value`. (The
/// telephone-event list of RFC 4733 and the RTX `apt` are their own forms.)
#[test]
fn every_default_fmtp_line_is_a_list_of_name_value_pairs() -> TestResult {
    let sdp = default_offer()?;
    let maps = rtpmaps(&sdp);
    let mut checked = 0;
    for (_, pt, encoding) in &maps {
        let lower = encoding.to_ascii_lowercase();
        if lower.starts_with("telephone-event/") || lower.starts_with("red/") {
            continue;
        }
        for parameter in fmtp(&sdp, pt) {
            let (name, value) = parameter
                .split_once('=')
                .unwrap_or_else(|| panic!("{encoding}: {parameter:?} is not name=value"));
            assert!(
                !name.is_empty() && !value.is_empty(),
                "{encoding}: {parameter}"
            );
            assert!(!name.contains(' ') && !value.contains(' '), "{parameter}");
            checked += 1;
        }
    }
    assert!(checked > 5, "{sdp}");
    Ok(())
}

/// RFC 7587 4.1 and 7: Opus has a dynamic payload type, and no receive parameter is put in a
/// source-level `a=ssrc:<ssrc> fmtp:` attribute.
#[test]
fn opus_has_a_dynamic_payload_type_and_no_source_level_fmtp() -> TestResult {
    let sdp = default_offer()?;
    let opus: u8 = payload_type_of(&sdp, "opus/")
        .expect("Opus is offered")
        .parse()?;
    assert!((96..=127).contains(&opus), "{opus}");
    assert!(
        !sdp.lines()
            .any(|l| l.starts_with("a=ssrc:") && l.contains(" fmtp:")),
        "{sdp}"
    );
    Ok(())
}

/// The VP9 formats of `sdp`, each with its fmtp parameters.
fn vp9_parameters(sdp: &str) -> Vec<(String, Vec<String>)> {
    rtpmaps(sdp)
        .into_iter()
        .filter(|(_, _, e)| e.to_ascii_lowercase().starts_with("vp9/"))
        .map(|(_, pt, _)| {
            let parameters = fmtp(sdp, &pt);
            (pt, parameters)
        })
        .collect()
}

/// The default VP9 formats leave out `max-fr` and `max-fs`: a WebKit sender answered with
/// them sends no VP9 (browser matrix, "reflect video VP9"). The RFC 9628 section 6 form is
/// `MediaEngine::set_vp9_receiver_limits(true)`.
#[test]
fn the_default_vp9_formats_leave_out_the_receiver_limits() -> TestResult {
    let vp9 = vp9_parameters(&default_offer()?);
    assert!(!vp9.is_empty());
    for (pt, parameters) in vp9 {
        assert!(
            parameters
                .iter()
                .all(|p| !p.starts_with("max-fr=") && !p.starts_with("max-fs=")),
            "{pt}: {parameters:?}"
        );
    }
    Ok(())
}

/// RFC 9628 section 6: "If the implementation is willing to receive media, both parameters
/// [max-fr and max-fs] MUST be provided." With the receiver limits setting every VP9 format
/// of the default offer states both.
#[test]
fn the_vp9_receiver_limits_setting_states_max_fr_and_max_fs() -> TestResult {
    let mut media_engine =
        rtci::peer_connection::configuration::media_engine::MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.set_vp9_receiver_limits(true);
    let mut pc = rtci::peer_connection::RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let sdp = pc.create_offer(None)?.sdp;
    let vp9: Vec<String> = rtpmaps(&sdp)
        .into_iter()
        .filter(|(_, _, e)| e.to_ascii_lowercase().starts_with("vp9/"))
        .map(|(_, pt, _)| pt)
        .collect();
    assert!(!vp9.is_empty());
    for pt in vp9 {
        let parameters = fmtp(&sdp, &pt);
        for name in ["max-fr", "max-fs"] {
            let value = parameters
                .iter()
                .find_map(|p| p.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("{name} for {pt}: {parameters:?}"));
            assert!(value.parse::<u32>()? > 0, "{name}={value}");
        }
    }
    Ok(())
}

/// RFC 6184 8.2.2: the answerer keeps `packetization-mode` and the profile, or removes the
/// payload type; an offered payload type number comes back only with the same configuration.
/// An offer of a mode this endpoint does not have (2, interleaved) is not answered with H.264.
#[test]
fn an_h264_mode_this_endpoint_does_not_have_is_not_answered() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "100 96",
            "a=rtpmap:100 H264/90000\na=fmtp:100 packetization-mode=2;profile-level-id=42001f\na=rtpmap:96 VP8/90000\n",
        ),
    )?;
    let section = sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    assert_eq!(
        answered_offered_formats(section, "100 96"),
        vec!["96"],
        "{sdp}"
    );
    Ok(())
}

/// RFC 6184 8.2.2: "If the answerer ... [does not use] level-asymmetry-allowed, the default
/// level in the answer MUST NOT be higher than the default level in the offer": an offer of
/// Constrained Baseline at level 3.0 without level asymmetry is answered at level 3.0 or
/// below, in the offered mode.
#[test]
fn an_h264_answer_is_not_above_the_offered_level() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "100",
            "a=rtpmap:100 H264/90000\na=fmtp:100 packetization-mode=1;profile-level-id=42e01e\n",
        ),
    )?;
    let parameters = fmtp(&sdp, "100");
    assert!(
        parameters.iter().any(|p| p == "packetization-mode=1"),
        "{parameters:?}"
    );
    let level = parameters
        .iter()
        .find_map(|p| p.strip_prefix("profile-level-id="))
        .map(|id| u8::from_str_radix(&id[4..6], 16))
        .transpose()?
        .unwrap_or(0x1e);
    assert!(level <= 0x1e, "level {level:#x} above the offer's: {sdp}");
    Ok(())
}

/// RFC 7798 7.2: "the receiver MUST ignore any parameter unspecified in this memo"; 7.2.2:
/// an answer to an H.265 offer keeps the payload type when the configuration matches.
#[test]
fn an_h265_offer_with_an_unknown_parameter_is_answered() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "110",
            "a=rtpmap:110 H265/90000\na=fmtp:110 level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST;x-unknown=7\n",
        ),
    )?;
    let section = sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    assert_eq!(
        answered_offered_formats(section, "110"),
        vec!["110"],
        "{sdp}"
    );
    let parameters = fmtp(&sdp, "110");
    for configuration in ["profile-id=1", "tier-flag=0", "tx-mode=SRST"] {
        assert!(
            parameters.iter().any(|p| p == configuration),
            "{configuration} echoed: {parameters:?}"
        );
    }
    Ok(())
}

/// RFC 9628 6.1.2: "profile-id ... MUST be the same" in offer and answer, or the payload type
/// is dropped; a payload type is used again only with the same profile. A VP9 profile this
/// endpoint does not have (3) is not answered.
#[test]
fn a_vp9_profile_this_endpoint_does_not_have_is_not_answered() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "98 96",
            "a=rtpmap:98 VP9/90000\na=fmtp:98 profile-id=3\na=rtpmap:96 VP8/90000\n",
        ),
    )?;
    let section = sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    assert_eq!(
        answered_offered_formats(section, "98 96"),
        vec!["96"],
        "{sdp}"
    );
    Ok(())
}

/// RFC 7741 6.2.2: max-fs and max-fr are receiver capabilities, declarative and not to be
/// matched: an offer whose VP8 states them is answered with VP8.
#[test]
fn a_vp8_offer_with_receiver_limits_is_answered() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            "96",
            "a=rtpmap:96 VP8/90000\na=fmtp:96 max-fr=30;max-fs=3600\n",
        ),
    )?;
    let section = sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    assert_eq!(answered_offered_formats(section, "96"), vec!["96"], "{sdp}");
    Ok(())
}

/// RFC 4733 sections 2.4 and 2.5.2.1: telephone events are offered at the rtpmap clock rate of
/// the audio they go with (8000 and 48000), and a receiver that signals with SDP lists the
/// events it can process in the fmtp, as the list itself (`0-15`), with no `events=`.
#[test]
fn telephone_events_list_the_events_received_at_each_clock_rate() -> TestResult {
    let sdp = default_offer()?;
    let events: Vec<(String, String)> = rtpmaps(&sdp)
        .into_iter()
        .filter(|(_, _, e)| e.to_ascii_lowercase().starts_with("telephone-event/"))
        .map(|(_, pt, e)| (pt, e))
        .collect();
    let rates: Vec<&str> = events
        .iter()
        .map(|(_, e)| e.rsplit('/').next().unwrap_or_default())
        .collect();
    assert!(
        rates.contains(&"8000") && rates.contains(&"48000"),
        "{events:?}"
    );
    for (pt, _) in &events {
        let line = sdp
            .lines()
            .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
            .unwrap_or_else(|| panic!("an event list for {pt}: {sdp}"));
        assert_eq!("0-15", line.trim(), "{sdp}");
    }
    Ok(())
}

/// RFC 7741 section 6.1: VP8's `max-fr` and `max-fs` go together, both or neither, when a
/// receiver states its capability. The default VP8 format states neither.
#[test]
fn the_default_vp8_format_states_both_receiver_limits_or_neither() -> TestResult {
    let sdp = default_offer()?;
    let vp8 = payload_type_of(&sdp, "vp8/").expect("VP8 is offered");
    let parameters = fmtp(&sdp, &vp8);
    let has = |name: &str| {
        parameters
            .iter()
            .any(|p| p.starts_with(&format!("{name}=")))
    };
    assert_eq!(has("max-fr"), has("max-fs"), "{parameters:?}");
    Ok(())
}
