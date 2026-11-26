use std::collections::HashSet;
/// Regression test for duplicate mid bug in generate_matched_sdp().
///
/// When create_offer() is called for a renegotiation (i.e. current_remote_description
/// exists), the function iterates remote media sections to build matched entries, then
/// iterates all local transceivers for unmatched ones. Without the fix, transceivers
/// already matched from the remote description would be added again, producing duplicate
/// m-sections with the same mid in the generated SDP.
use std::time::Instant;

use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use sansio::Protocol;

fn new_video_track(stream_id: &str, track_id: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        stream_id.to_owned(),
        track_id.to_owned(),
        format!("track-{}", track_id),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

/// Collect all mid values from a parsed SDP's media descriptions.
fn collect_mids(sdp: &RTCSessionDescription) -> Vec<String> {
    let parsed = sdp.unmarshal().expect("failed to parse SDP");
    parsed
        .media_descriptions
        .iter()
        .filter_map(|m| m.attribute("mid").and_then(|v| v.map(|s| s.to_owned())))
        .collect()
}

/// After a full offer/answer exchange, a renegotiation offer must not contain
/// duplicate mids for transceivers that were already matched from the remote
/// description.
#[test]
fn test_renegotiation_no_duplicate_mids() -> Result<(), Box<dyn std::error::Error>> {
    let mut me = MediaEngine::default();
    me.register_default_codecs()?;
    let me2 = me.clone();

    // --- Offerer ---
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())?;

    // Add an initial video track.
    let track1 = new_video_track("stream-1", "video-1", 11111);
    offerer.add_track(track1)?;

    // --- Answerer ---
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me2)
        .build(Instant::now())?;

    // ---- First offer/answer exchange ----
    let offer1 = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer1.clone())?;

    answerer.set_remote_description(Instant::now(), offer1)?;
    let answer1 = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer1.clone())?;

    offerer.set_remote_description(Instant::now(), answer1)?;

    // Sanity: first offer has unique mids.
    let offer1_for_check = offerer.create_offer(None)?;
    let mids = collect_mids(&offer1_for_check);
    let unique: HashSet<_> = mids.iter().collect();
    assert_eq!(
        mids.len(),
        unique.len(),
        "first renegotiation offer already has duplicate mids: {:?}",
        mids,
    );

    // ---- Add a second video track and renegotiate ----
    let track2 = new_video_track("stream-2", "video-2", 22222);
    offerer.add_track(track2)?;

    let offer2 = offerer.create_offer(None)?;
    let mids = collect_mids(&offer2);
    let unique: HashSet<_> = mids.iter().collect();
    assert_eq!(
        mids.len(),
        unique.len(),
        "renegotiation offer has duplicate mids: {:?}",
        mids,
    );

    // Verify we have the expected number of media sections (1 video + 1 new video = 2).
    assert_eq!(
        mids.len(),
        2,
        "expected 2 media sections, got {}: {:?}",
        mids.len(),
        mids,
    );

    offerer.close()?;
    answerer.close()?;
    Ok(())
}

/// RFC 3264 section 8.1: "New media streams are created by new additional media descriptions
/// below the existing ones". After an offer/answer with two video sections, the offerer adds a
/// third track and the answerer adds one of its own: each one's next offer lists the
/// negotiated sections first, in their negotiated order, and the new section last.
#[test]
fn a_new_media_description_goes_below_the_existing_ones() -> Result<(), Box<dyn std::error::Error>>
{
    let mut me = MediaEngine::default();
    me.register_default_codecs()?;
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me.clone())
        .build(Instant::now())?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())?;
    offerer.add_track(new_video_track("stream-1", "video-1", 11111))?;
    offerer.add_track(new_video_track("stream-1", "video-2", 22222))?;

    let offer = offerer.create_offer(None)?;
    let negotiated = collect_mids(&offer);
    assert_eq!(negotiated.len(), 2);
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert_eq!(
        collect_mids(&answer),
        negotiated,
        "the answer keeps the order"
    );
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    offerer.add_track(new_video_track("stream-2", "video-3", 33333))?;
    let again = collect_mids(&offerer.create_offer(None)?);
    assert_eq!(again.len(), 3, "{again:?}");
    assert_eq!(again[..2], negotiated[..], "the offerer: {again:?}");
    assert!(!negotiated.contains(&again[2]), "{again:?}");

    // Audio: a video track would take one of the answerer's two video transceivers, which
    // have no sender yet (RFC 9429 section 5.2.2), and need no new section.
    answerer.add_track(MediaStreamTrack::new(
        "stream-3".to_owned(),
        "audio-1".to_owned(),
        "track-audio-1".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(44444),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: rtci::peer_connection::configuration::media_engine::MIME_TYPE_OPUS
                    .to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    ))?;
    let from_answerer = collect_mids(&answerer.create_offer(None)?);
    assert_eq!(from_answerer.len(), 3, "{from_answerer:?}");
    assert_eq!(
        from_answerer[..2],
        negotiated[..],
        "the answerer, offering in turn: {from_answerer:?}"
    );
    assert!(!negotiated.contains(&from_answerer[2]));

    offerer.close()?;
    answerer.close()?;
    Ok(())
}
