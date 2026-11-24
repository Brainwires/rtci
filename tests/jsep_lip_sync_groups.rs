//! Lip synchronization groups (`a=group:LS`, RFC 5888 section 7) in offers and answers (RFC
//! 9429 sections 4.1.2, 5.2.1, 5.2.2 and 5.3.1).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, exchange};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

/// A track of `kind` in the stream `stream`.
fn track(stream: &str, id: &str, kind: RtpCodecKind, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        stream.to_owned(),
        id.to_owned(),
        id.to_owned(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            ..Default::default()
        }],
    )
}

/// The `a=group:LS` values of `sdp`.
fn ls(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=group:LS "))
        .map(str::to_owned)
        .collect()
}

/// A peer that sends an audio and a video track, in one stream or in two.
fn sender(one_stream: bool) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    pc.add_track(track("ms1", "a1", RtpCodecKind::Audio, 0x4C53_0001))?;
    let video_stream = if one_stream { "ms1" } else { "ms2" };
    pc.add_track(track(video_stream, "v1", RtpCodecKind::Video, 0x4C53_0002))?;
    Ok(pc)
}

/// RFC 9429 section 5.2.1: "For each MediaStream referenced by more than one RtpTransceiver
/// ..., a group of type "LS" MUST be added that contains the MID values for each
/// RtpTransceiver"; tracks in different streams are not grouped.
#[test]
fn an_offer_groups_the_transceivers_of_one_stream() -> TestResult {
    let mut pc = sender(true)?;
    assert_eq!(vec!["0 1".to_owned()], ls(&pc.create_offer(None)?.sdp));

    let mut pc = sender(false)?;
    assert!(ls(&pc.create_offer(None)?.sdp).is_empty());
    Ok(())
}

/// RFC 9429 section 5.3.1 and its three examples: an offered LS group is answered with the
/// transceivers that "either reference a common local MediaStream ... or have no MediaStream
/// to reference", when there are two; otherwise it is ignored.
#[test]
fn an_answer_keeps_an_offered_group_whose_transceivers_share_a_stream_or_have_none() -> TestResult {
    // The answerer adds no tracks: the offerer's preference is kept.
    let mut offerer = sender(true)?;
    let mut answerer = default_peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(vec!["0 1".to_owned()], ls(&answer));
    assert_eq!(
        vec![vec!["0".to_owned(), "1".to_owned()]],
        answerer.remote_lip_sync_groups(),
        "the offered group is exposed"
    );

    // The answerer sends both tracks in one stream of its own.
    let mut offerer = sender(true)?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    answerer.add_track(track("ms2", "a2", RtpCodecKind::Audio, 0x4C53_0011))?;
    answerer.add_track(track("ms2", "v2", RtpCodecKind::Video, 0x4C53_0012))?;
    assert_eq!(
        vec!["0 1".to_owned()],
        ls(&answerer.create_answer(None)?.sdp)
    );

    // In two streams: no group.
    let mut offerer = sender(true)?;
    let mut answerer = default_peer()?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    answerer.add_track(track("ms2a", "a2", RtpCodecKind::Audio, 0x4C53_0021))?;
    answerer.add_track(track("ms2b", "v2", RtpCodecKind::Video, 0x4C53_0022))?;
    assert!(ls(&answerer.create_answer(None)?.sdp).is_empty());

    // No group offered: none answered, whatever the streams.
    let mut offerer = sender(false)?;
    let mut answerer = default_peer()?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    answerer.add_track(track("ms3", "a3", RtpCodecKind::Audio, 0x4C53_0031))?;
    answerer.add_track(track("ms3", "v3", RtpCodecKind::Video, 0x4C53_0032))?;
    assert!(ls(&answerer.create_answer(None)?.sdp).is_empty());
    Ok(())
}

/// RFC 9429 section 5.2.2: "any lip sync groups that were present in the most recent answer
/// MUST continue to exist and MUST contain any previously existing MID identifiers": the
/// answerer's later offer keeps the answered group although its transceivers have no stream.
#[test]
fn a_later_offer_keeps_the_groups_of_the_last_answer() -> TestResult {
    let mut first = sender(true)?;
    let mut second = default_peer()?;
    let (_, answer) = exchange(&mut first, &mut second)?;
    assert_eq!(vec!["0 1".to_owned()], ls(&answer));

    let reoffer = second.create_offer(None)?;
    assert_eq!(vec!["0 1".to_owned()], ls(&reoffer.sdp));
    // And it is answered again.
    let now = Instant::now();
    second.set_local_description(now, reoffer.clone())?;
    first.set_remote_description(now, RTCSessionDescription::offer(reoffer.sdp)?)?;
    assert_eq!(vec!["0 1".to_owned()], ls(&first.create_answer(None)?.sdp));
    Ok(())
}
