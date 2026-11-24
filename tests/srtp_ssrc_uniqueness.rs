//! RFC 3711 sections 8 and 9.1, RFC 5764 section 3: every local stream of a peer connection is
//! protected under the one SRTP master key its DTLS association exports, so two local streams
//! with the same SSRC would encrypt with the same keystream (a two-time pad). An SSRC the
//! application names that another local stream already has, or that it names twice, is
//! refused; the SSRCs the connection draws itself are always new.

mod jsep_common;

use jsep_common::{TestResult, default_peer, video_track};
use rtci::media_stream::MediaStreamTrack;
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtci::shared::error::Error;
use std::collections::HashSet;

const SSRC: u32 = 0x5151_0001;

fn track_with(name: &str, encodings: Vec<RTCRtpEncodingParameters>) -> MediaStreamTrack {
    MediaStreamTrack::new(
        format!("{name}-stream"),
        name.to_owned(),
        name.to_owned(),
        RtpCodecKind::Video,
        encodings,
    )
}

fn encoding(ssrc: u32, rtx: Option<u32>, rid: &str) -> RTCRtpEncodingParameters {
    let template = video_track("template", ssrc).codings()[0].clone();
    RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ssrc: Some(ssrc),
            rtx: rtx.map(|ssrc| RTCRtpRtxParameters { ssrc }),
            ..Default::default()
        },
        codec: template.codec.clone(),
        ..Default::default()
    }
}

#[test]
fn a_second_local_stream_cannot_take_an_ssrc_in_use() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("first", SSRC))?;

    // add_track, add_transceiver_from_track and add_transceiver_from_kind with encodings.
    assert_eq!(
        pc.add_track(video_track("second", SSRC)).err(),
        Some(Error::ErrRTPSenderSsrcTaken(SSRC))
    );
    assert_eq!(
        pc.add_transceiver_from_track(video_track("third", SSRC), None)
            .err(),
        Some(Error::ErrRTPSenderSsrcTaken(SSRC))
    );
    let init = RTCRtpTransceiverInit {
        send_encodings: vec![encoding(SSRC, None, "")],
        ..Default::default()
    };
    assert_eq!(
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(init))
            .err(),
        Some(Error::ErrRTPSenderSsrcTaken(SSRC))
    );
    // The first stream's RTX SSRC is taken too.
    let rtx = pc.get_senders().next().expect("the first sender");
    let rtx = pc
        .rtp_sender(rtx)
        .expect("the sender")
        .get_parameters()
        .encodings[0]
        .rtp_coding_parameters
        .rtx
        .as_ref()
        .map(|rtx| rtx.ssrc);
    if let Some(rtx) = rtx {
        assert_eq!(
            pc.add_track(video_track("fourth", rtx)).err(),
            Some(Error::ErrRTPSenderSsrcTaken(rtx))
        );
    }
    // Another SSRC is fine.
    pc.add_track(video_track("fifth", SSRC + 1))?;
    Ok(())
}

#[test]
fn one_stream_cannot_name_an_ssrc_twice() -> TestResult {
    let mut pc = default_peer()?;
    // Two simulcast encodings with one SSRC, and an encoding whose RTX is its own SSRC.
    let twice = track_with(
        "twice",
        vec![encoding(SSRC, None, "low"), encoding(SSRC, None, "high")],
    );
    assert_eq!(
        pc.add_track(twice).err(),
        Some(Error::ErrRTPSenderSsrcTaken(SSRC))
    );
    let own_rtx = track_with("own-rtx", vec![encoding(SSRC, Some(SSRC), "")]);
    assert_eq!(
        pc.add_track(own_rtx).err(),
        Some(Error::ErrRTPSenderSsrcTaken(SSRC))
    );
    Ok(())
}

#[test]
fn the_ssrcs_the_connection_draws_are_all_distinct() -> TestResult {
    let mut pc = default_peer()?;
    for _ in 0..16 {
        pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    }
    let mut seen = HashSet::new();
    let senders: Vec<_> = pc.get_senders().collect();
    for sender in senders {
        for encoding in &pc
            .rtp_sender(sender)
            .expect("a sender")
            .get_parameters()
            .encodings
        {
            let coding = &encoding.rtp_coding_parameters;
            for ssrc in [coding.ssrc, coding.rtx.as_ref().map(|rtx| rtx.ssrc)]
                .into_iter()
                .flatten()
            {
                assert!(seen.insert(ssrc), "SSRC {ssrc} twice");
            }
        }
    }
    assert!(seen.len() >= 32);
    Ok(())
}
