//! RFC 9429 section 5.2.2, a later offer: the `m=` line "MUST only include media formats that
//! have not been excluded by the codec preferences of the associated transceiver and also
//! MUST include all currently available formats", the formats of the most recent answer first
//! in its order, the others after them; payload types, once negotiated, stay the same. A
//! format the first answer left out comes back in the next offer, and an answer that accepts
//! it again negotiates it.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, exchange, media_sections};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};

/// The `a=rtpmap` lines of the video section, as `(payload type, encoding name)`.
fn video_formats(sdp: &str) -> Vec<(u8, String)> {
    let video = media_sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=video"))
        .expect("a video section");
    video
        .iter()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .map(|l| {
            let (pt, rest) = l.split_once(' ').expect("pt and name");
            let name = rest.split('/').next().unwrap_or_default().to_owned();
            (pt.parse().expect("a payload type"), name)
        })
        .collect()
}

fn names(formats: &[(u8, String)]) -> Vec<&str> {
    formats.iter().map(|(_, n)| n.as_str()).collect()
}

#[test]
fn a_later_offer_brings_back_the_formats_the_answer_left_out() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    // A transceiver without a track: its offers list every registered video format.
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let (first_offer, _) = {
        // The answerer prefers VP8 alone: its answer leaves every other video format out.
        let now = Instant::now();
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(now, offer.clone())?;
        answerer.set_remote_description(now, offer.clone())?;
        let id = answerer.get_transceivers().next().expect("a transceiver");
        let sender = answerer.get_senders().next().expect("a sender");
        let vp8: Vec<RTCRtpCodecParameters> = answerer
            .rtp_sender(sender)
            .expect("the sender")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video capabilities")
            .codecs
            .into_iter()
            .filter(|c| c.mime_type.eq_ignore_ascii_case("video/VP8"))
            .map(|rtp_codec| RTCRtpCodecParameters {
                rtp_codec,
                payload_type: 0,
            })
            .collect();
        assert!(!vp8.is_empty(), "VP8 is a capability");
        answerer
            .rtp_transceiver(id)
            .expect("the transceiver")
            .set_codec_preferences(vp8)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        offerer.set_remote_description(now, answer.clone())?;
        assert_eq!(
            names(&video_formats(&answer.sdp)),
            ["VP8"],
            "{}",
            answer.sdp
        );
        (offer.sdp, answer.sdp)
    };
    let offered = video_formats(&first_offer);

    let reoffer = offerer.create_offer(None)?.sdp;
    let formats = video_formats(&reoffer);
    // The answered format first, with its payload type...
    assert_eq!(
        formats.first(),
        offered.iter().find(|(_, n)| n == "VP8"),
        "{reoffer}"
    );
    // ...and every format of the first offer again, each with the number it had.
    for format in &offered {
        assert!(
            formats.contains(format),
            "{format:?} is not offered again:\n{reoffer}"
        );
    }
    assert_eq!(formats.len(), offered.len(), "{reoffer}");

    // An answer that accepts the formats again (no preferences now) negotiates them.
    let id = answerer.get_transceivers().next().expect("a transceiver");
    answerer
        .rtp_transceiver(id)
        .expect("the transceiver")
        .set_codec_preferences(vec![])?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    let answered = video_formats(&answer);
    assert!(names(&answered).contains(&"VP9"), "{answer}");
    let sender = offerer.get_senders().next().expect("the sender");
    let codecs: Vec<String> = offerer
        .rtp_sender(sender)
        .expect("the sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .map(|c| c.rtp_codec.mime_type.to_ascii_lowercase())
        .collect();
    assert!(codecs.contains(&"video/vp9".to_owned()), "{codecs:?}");
    Ok(())
}

/// What limits the first offer locally (here the codec of the track the sender was made for)
/// limits the later ones too: "only media formats that have not been excluded by the codec
/// preferences". The answer's list is not such a limit.
#[test]
fn a_later_offer_keeps_the_local_limits_of_the_first() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(jsep_common::video_track("cam", 1111))?;
    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    let reoffer = offerer.create_offer(None)?.sdp;
    assert_eq!(video_formats(&reoffer), video_formats(&offer), "{reoffer}");
    Ok(())
}
