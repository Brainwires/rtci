//! RFC 9429 sections 5.2.3.2 and 5.3.3.1, `VoiceActivityDetection`: silence suppression is
//! asked for in an offer with comfort noise formats and Opus `usedtx=1`, refused with neither
//! and `usedtx=0`, and an answer has it only where the offer did.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::{RTCAnswerOptions, RTCOfferOptions};
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

fn audio_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    Ok(pc)
}

/// (whether the audio section has a CN format, the `usedtx` value of Opus, if any).
fn silence_suppression(sdp: &str) -> (bool, Option<String>) {
    let section = media_sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=audio"))
        .expect("an audio section");
    let cn = section
        .iter()
        .any(|l| l.starts_with("a=rtpmap:") && l.contains(" CN/"));
    let opus = section
        .iter()
        .find_map(|l| {
            let rest = l.strip_prefix("a=rtpmap:")?;
            let (pt, codec) = rest.split_once(' ')?;
            codec.starts_with("opus/").then(|| pt.to_owned())
        })
        .expect("an opus format");
    let usedtx = section.iter().find_map(|l| {
        let params = l.strip_prefix(&format!("a=fmtp:{opus} "))?;
        params
            .split(';')
            .find_map(|p| p.strip_prefix("usedtx=").map(str::to_owned))
    });
    (cn, usedtx)
}

fn offer_with(vad: Option<bool>) -> Result<String, Box<dyn std::error::Error>> {
    let mut pc = audio_peer()?;
    Ok(pc
        .create_offer(Some(RTCOfferOptions {
            voice_activity_detection: vad,
            ..Default::default()
        }))?
        .sdp)
}

#[test]
fn an_offer_asks_for_silence_suppression_or_refuses_it_when_specified() -> TestResult {
    let unspecified = offer_with(None)?;
    assert_eq!(
        silence_suppression(&unspecified),
        (true, None),
        "unspecified: the media engine's offer (CN is a default format): {unspecified}"
    );
    let on = offer_with(Some(true))?;
    assert_eq!(
        silence_suppression(&on),
        (true, Some("1".to_owned())),
        "{on}"
    );
    let off = offer_with(Some(false))?;
    assert_eq!(
        silence_suppression(&off),
        (false, Some("0".to_owned())),
        "{off}"
    );
    Ok(())
}

#[test]
fn an_answer_has_silence_suppression_only_where_the_offer_had_it() -> TestResult {
    let answer_to =
        |offer_vad: bool, answer_vad: bool| -> Result<String, Box<dyn std::error::Error>> {
            let mut offerer = audio_peer()?;
            let offer = offerer.create_offer(Some(RTCOfferOptions {
                voice_activity_detection: Some(offer_vad),
                ..Default::default()
            }))?;
            let mut answerer = default_peer()?;
            answerer.set_remote_description(Instant::now(), offer)?;
            Ok(answerer
                .create_answer(Some(RTCAnswerOptions {
                    voice_activity_detection: answer_vad,
                }))?
                .sdp)
        };
    let both = answer_to(true, true)?;
    assert_eq!(
        silence_suppression(&both),
        (true, Some("1".to_owned())),
        "{both}"
    );
    let not_offered = answer_to(false, true)?;
    assert_eq!(
        silence_suppression(&not_offered),
        (false, Some("0".to_owned())),
        "as if false: {not_offered}"
    );
    let refused = answer_to(true, false)?;
    assert_eq!(
        silence_suppression(&refused),
        (false, Some("0".to_owned())),
        "{refused}"
    );
    Ok(())
}
