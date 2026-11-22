//! Codec parameters in offers and answers: the audio formats a WebRTC endpoint offers (RFC
//! 7874 section 3), Opus (RFC 7587 section 7), H.264 (RFC 6184 section 8) and AV1 (AV1 RTP
//! payload format section 7.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_PCMU, MediaEngine, RTCPacketTime,
};
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

/// RFC 7798 section 7.2.2: the H.265 configuration parameters but `level-id` are symmetric,
/// each with its section 7.1 default when absent: an offer of Main 10 or of MRST is not
/// answered by this endpoint's Main / SRST format, and an answer's `level-id` is not higher
/// than the offer's.
#[test]
fn h265_formats_match_by_configuration_and_the_answer_level_is_not_above_the_offer() -> TestResult {
    // The H.265 formats of the answer to an offer of `lines`, as (payload type, fmtp).
    let answered =
        |pts: &str, lines: &str| -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
            Ok(formats(&answer_to("video", pts, lines)?)
                .into_iter()
                .filter(|(_, r, _)| r.starts_with("H265/"))
                .map(|(pt, _, fmtp)| (pt, fmtp))
                .collect())
        };
    assert_eq!(
        vec![(
            "102".to_owned(),
            "level-id=60;profile-id=1;tier-flag=0;tx-mode=SRST".to_owned()
        )],
        answered(
            "100 101 102",
            "a=rtpmap:100 H265/90000\na=fmtp:100 profile-id=2\n\
             a=rtpmap:101 H265/90000\na=fmtp:101 tx-mode=MRST\n\
             a=rtpmap:102 H265/90000\na=fmtp:102 level-id=60;profile-id=1\n",
        )?,
        "Main 10 and MRST are not answered; the level is lowered to the offer's"
    );
    assert_eq!(
        vec![(
            "103".to_owned(),
            "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST".to_owned()
        )],
        answered(
            "103",
            "a=rtpmap:103 H265/90000\na=fmtp:103 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\n",
        )?,
        "this endpoint's own level, below the offer's"
    );
    Ok(())
}

/// RFC 6184 section 8.1: "packetization-mode ... MUST be equal to 0, 1, or 2": an offered
/// format with another mode is not answered.
#[test]
fn an_h264_format_with_a_packetization_mode_above_2_is_not_answered() -> TestResult {
    let answer = answer_to(
        "video",
        "102 103",
        "a=rtpmap:102 H264/90000\na=fmtp:102 packetization-mode=3;profile-level-id=42e01f\n\
         a=rtpmap:103 H264/90000\na=fmtp:103 packetization-mode=1;profile-level-id=42e01f\n",
    )?;
    let pts: Vec<String> = formats(&answer)
        .into_iter()
        .filter(|(_, r, _)| r.starts_with("H264/"))
        .map(|(pt, _, _)| pt)
        .collect();
    assert_eq!(vec!["103".to_owned()], pts);
    Ok(())
}

/// RFC 7587 section 7: Opus's `ptime` and `maxptime` are `a=ptime` and `a=maxptime`, and
/// section 7.1 handles `maxptime` like `ptime` (RFC 3264 section 5: what the side that
/// states it wants to receive). This endpoint's are written in its audio sections when set,
/// and the remote side's are read for each transceiver (RFC 8866 sections 6.4, 6.5).
#[test]
fn packet_times_are_written_when_set_and_the_remote_ones_are_read() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = offer_with_audio(&mut pc)?;
    assert!(
        !sdp.contains("a=ptime") && !sdp.contains("a=maxptime"),
        "{sdp}"
    );

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.set_audio_packet_time(RTCPacketTime {
        ptime: Some(20),
        maxptime: Some(120),
    });
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let sdp = offer_with_audio(&mut pc)?;
    assert!(sdp.contains("a=ptime:20\r\n"), "{sdp}");
    assert!(sdp.contains("a=maxptime:120\r\n"), "{sdp}");

    let offer = crlf(&format!(
        "{SESSION}m=audio 9 UDP/TLS/RTP/SAVPF 111\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:111 opus/48000/2\na=ptime:40\na=maxptime:60\n"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let ids: Vec<usize> = pc.get_transceivers().collect();
    let transceiver = pc.rtp_transceiver(ids[0]).expect("transceiver");
    assert_eq!(
        RTCPacketTime {
            ptime: Some(40),
            maxptime: Some(60)
        },
        transceiver.remote_packet_time()
    );
    let answer = pc.create_answer(None)?.sdp;
    assert!(
        !answer.contains("a=ptime"),
        "not stated unless set: {answer}"
    );
    Ok(())
}

/// The `a=rtcp-fb` values of payload type `pt` in `sdp`.
fn feedback_of(sdp: &str, pt: &str) -> Vec<String> {
    let prefix = format!("a=rtcp-fb:{pt} ");
    sdp.lines()
        .filter_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .collect()
}

/// RFC 5104 section 7.2: "The answerer MUST remove all CCM parameters corresponding to the
/// CCMs that it does not wish to support ... MUST NOT add new ccm parameters"; the TMMBR
/// session maximum packet rate is declarative, "the highest value from offer and answer SHALL
/// be used. If [it] is not present in an offer, it SHALL NOT be included by the answerer".
/// With the default interceptors this endpoint takes FIR and TMMBR, not TSTR, VBCM or LRR.
#[test]
fn an_answer_keeps_the_codec_control_messages_it_supports_and_the_offered_smaxpr() -> TestResult {
    let answer = |feedback: &str| -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let offer = crlf(&format!(
            "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
             a=rtpmap:96 VP8/90000\n{feedback}"
        ));
        let mut pc = interceptor_peer()?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
        let mut ccm: Vec<String> = feedback_of(&pc.create_answer(None)?.sdp, "96")
            .into_iter()
            .filter(|f| f.starts_with("ccm"))
            .collect();
        ccm.sort();
        Ok(ccm)
    };
    assert_eq!(
        vec!["ccm fir".to_owned(), "ccm tmmbr smaxpr=120".to_owned()],
        answer(
            "a=rtcp-fb:96 ccm fir\na=rtcp-fb:96 ccm tmmbr smaxpr=120\na=rtcp-fb:96 ccm tstr\n\
             a=rtcp-fb:96 ccm vbcm 1 2\na=rtcp-fb:96 ccm lrr\n"
        )?
    );
    assert_eq!(
        vec!["ccm tmmbr".to_owned()],
        answer("a=rtcp-fb:96 ccm tmmbr\n")?,
        "no smaxpr when the offer has none"
    );
    assert!(answer("a=rtcp-fb:96 nack\n")?.is_empty(), "none added");
    Ok(())
}

/// A peer with the default codecs and the default interceptors.
fn interceptor_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

/// RFC 3611 section 5: XR use is signalled with `a=rtcp-xr`. With the default interceptors
/// (receiver reference times for video) an offer asks for `rcvr-rtt=all`; an answer states
/// the offered mode when it takes it, an empty attribute when it takes nothing the offer lists
/// (section 5.2), and none when the offer has none (section 5.1); a media-level attribute
/// replaces the session's (section 5.1).
#[test]
fn rtcp_xr_is_offered_and_answered() -> TestResult {
    let mut pc = interceptor_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?.sdp;
    assert!(offer.contains("a=rtcp-xr:rcvr-rtt=all\r\n"), "{offer}");

    let answer = |session: &str, media: &str| -> Result<String, Box<dyn std::error::Error>> {
        let session = SESSION.replace("t=0 0\n", &format!("t=0 0\n{session}"));
        let offer = crlf(&format!(
            "{session}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
             a=rtpmap:96 VP8/90000\n{media}"
        ));
        let mut pc = interceptor_peer()?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
        Ok(pc.create_answer(None)?.sdp)
    };
    let rtcp_xr = |sdp: &str| -> Vec<String> {
        sdp.lines()
            .filter_map(|l| l.strip_prefix("a=rtcp-xr"))
            .map(str::to_owned)
            .collect()
    };

    let sdp = answer("", "a=rtcp-xr:rcvr-rtt=sender\n")?;
    assert_eq!(vec![":rcvr-rtt=sender".to_owned()], rtcp_xr(&sdp));
    assert!(
        feedback_of(&sdp, "96").iter().all(|f| f != "rrtr"),
        "not added: {sdp}"
    );

    let sdp = answer(
        "a=rtcp-xr:rcvr-rtt=all\n",
        "a=rtcp-xr:pkt-loss-rle\na=rtcp-fb:96 rrtr\n",
    )?;
    assert_eq!(
        vec![":".to_owned()],
        rtcp_xr(&sdp),
        "the media level wins: {sdp}"
    );
    assert!(feedback_of(&sdp, "96").iter().all(|f| f != "rrtr"), "{sdp}");

    let sdp = answer("a=rtcp-xr:rcvr-rtt=all\n", "")?;
    assert_eq!(
        vec![":rcvr-rtt=all".to_owned()],
        rtcp_xr(&sdp),
        "the session's: {sdp}"
    );

    let sdp = answer("", "a=rtcp-fb:96 rrtr\n")?;
    assert!(rtcp_xr(&sdp).is_empty(), "{sdp}");
    assert!(feedback_of(&sdp, "96").iter().any(|f| f == "rrtr"), "{sdp}");
    Ok(())
}
