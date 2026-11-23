//! Tests for [`MediaEngine`], after Pion's `mediaengine_test.go`: codec registration, codec
//! negotiation from a remote description, and header extension registration and negotiation.
//! Only behaviour this crate's engine has is covered.

use std::time::Instant;

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;

const HEAD: &str = "v=0\r\no=- 4596489990601351948 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";

fn parse(sdp: &str) -> SessionDescription {
    let mut reader = std::io::Cursor::new(sdp.as_bytes());
    SessionDescription::unmarshal(&mut reader).expect("test SDP parses")
}

fn remote(media: &str) -> SessionDescription {
    parse(&format!("{HEAD}{media}"))
}

fn codec(mime_type: &str, clock_rate: u32, channels: u16, fmtp: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    }
}

fn opus() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: codec(MIME_TYPE_OPUS, 48000, 2, "minptime=10;useinbandfec=1"),
        payload_type: 111,
    }
}

fn extension(uri: &str) -> RTCRtpHeaderExtensionCapability {
    RTCRtpHeaderExtensionCapability {
        uri: uri.to_owned(),
    }
}

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

/// The default codecs appear in an offer with the expected rtpmap.
#[test]
fn test_opus_and_video_case() -> Result<()> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;

    let offer = pc.create_offer(None)?;
    assert!(
        offer.sdp.contains("a=rtpmap:111 opus/48000/2"),
        "{}",
        offer.sdp
    );
    assert!(offer.sdp.contains("a=rtpmap:96 VP8/90000"), "{}", offer.sdp);
    assert!(offer.sdp.contains(" H264/90000"), "{}", offer.sdp);
    assert!(offer.sdp.contains(" VP9/90000"), "{}", offer.sdp);
    Ok(())
}

#[test]
fn test_media_engine_remote_description() -> Result<()> {
    // "No Media"
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&parse(HEAD))?;

        assert!(!m.negotiated_video);
        assert!(!m.negotiated_audio);
    }

    // "Enable Opus"
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=fmtp:111 minptime=10; useinbandfec=1\r\n",
        ))?;

        assert!(!m.negotiated_video);
        assert!(m.negotiated_audio);

        let (opus_codec, kind) = m.get_codec_by_payload(111)?;
        assert_eq!(kind, RtpCodecKind::Audio);
        assert_eq!(opus_codec.rtp_codec.mime_type, MIME_TYPE_OPUS);
    }

    // "Change Payload Type": the remote's payload type is the one used afterwards.
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 112\r\n\
             a=rtpmap:112 opus/48000/2\r\n\
             a=fmtp:112 minptime=10; useinbandfec=1\r\n",
        ))?;

        assert!(!m.negotiated_video);
        assert!(m.negotiated_audio);

        assert!(m.get_codec_by_payload(111).is_err());
        let (opus_codec, _) = m.get_codec_by_payload(112)?;
        assert_eq!(opus_codec.rtp_codec.mime_type, MIME_TYPE_OPUS);
    }

    // "Case Insensitive"
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=rtpmap:111 OPUS/48000/2\r\n\
             a=fmtp:111 minptime=10; useinbandfec=1\r\n",
        ))?;

        assert!(!m.negotiated_video);
        assert!(m.negotiated_audio);

        let (opus_codec, _) = m.get_codec_by_payload(111)?;
        assert!(
            opus_codec
                .rtp_codec
                .mime_type
                .eq_ignore_ascii_case(MIME_TYPE_OPUS)
        );
    }

    // "Handle different fmtp": a codec whose parameters differ still matches on its MIME type.
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=rtpmap:111 opus/48000/2\r\n",
        ))?;

        assert!(!m.negotiated_video);
        assert!(m.negotiated_audio);

        let (opus_codec, _) = m.get_codec_by_payload(111)?;
        assert_eq!(opus_codec.rtp_codec.mime_type, MIME_TYPE_OPUS);
    }

    // "Header Extensions": only registered extensions are negotiated, at the remote's id.
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        for uri in [MID_URI, AUDIO_LEVEL_URI] {
            m.register_header_extension(extension(uri), RtpCodecKind::Audio, None)?;
        }

        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=extmap:7 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
             a=extmap:5 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
             a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n\
             a=rtpmap:111 opus/48000/2\r\n",
        ))?;

        assert!(!m.negotiated_video);
        assert!(m.negotiated_audio);

        assert_eq!(
            m.get_header_extension_id(extension(MID_URI)),
            (7, true, false)
        );
        assert_eq!(
            m.get_header_extension_id(extension(AUDIO_LEVEL_URI)),
            (5, true, false)
        );
        assert_eq!(
            m.get_header_extension_id(extension(ABS_SEND_TIME_URI)),
            (0, false, false),
            "an extension that was not registered is not negotiated"
        );
    }

    // "Prefers exact codec matches": of two H264 profiles, the one registered is taken.
    {
        let mut m = MediaEngine::default();
        m.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(
                    MIME_TYPE_H264,
                    90000,
                    0,
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
                ),
                payload_type: 127,
            },
            RtpCodecKind::Video,
        )?;

        m.update_from_remote_description(&remote(
            "m=video 60323 UDP/TLS/RTP/SAVPF 96 98\r\n\
             a=rtpmap:96 H264/90000\r\n\
             a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\r\n\
             a=rtpmap:98 H264/90000\r\n\
             a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n",
        ))?;

        assert!(m.negotiated_video);
        assert!(!m.negotiated_audio);

        let (h264, _) = m.get_codec_by_payload(98)?;
        assert_eq!(h264.rtp_codec.mime_type, MIME_TYPE_H264);
        assert!(
            m.get_codec_by_payload(96).is_err(),
            "the partial match is dropped when an exact one exists"
        );
    }

    // No fallback to the name for H.264: a profile this endpoint did not register (High,
    // against Constrained Baseline) is removed (RFC 6184 section 8.2.2), not negotiated.
    {
        let mut m = MediaEngine::default();
        m.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(
                    MIME_TYPE_H264,
                    90000,
                    0,
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
                ),
                payload_type: 127,
            },
            RtpCodecKind::Video,
        )?;

        m.update_from_remote_description(&remote(
            "m=video 60323 UDP/TLS/RTP/SAVPF 96\r\n\
             a=rtpmap:96 H264/90000\r\n\
             a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\r\n",
        ))?;

        assert!(m.negotiated_video);
        assert!(m.get_codec_by_payload(96).is_err());
    }

    // "Matches RTX": an RTX codec is negotiated with the remote's `apt`, as is its primary.
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;

        m.update_from_remote_description(&remote(
            "m=video 60323 UDP/TLS/RTP/SAVPF 100 101\r\n\
             a=rtpmap:100 VP8/90000\r\n\
             a=rtpmap:101 rtx/90000\r\n\
             a=fmtp:101 apt=100\r\n",
        ))?;

        assert!(m.negotiated_video);
        let (vp8, _) = m.get_codec_by_payload(100)?;
        assert_eq!(vp8.rtp_codec.mime_type, MIME_TYPE_VP8);
        let (rtx, _) = m.get_codec_by_payload(101)?;
        assert!(rtx.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX));
        assert_eq!(rtx.rtp_codec.sdp_fmtp_line, "apt=100");
        assert!(m.is_rtx_enabled(RtpCodecKind::Video, RTCRtpTransceiverDirection::Sendrecv));
    }

    // "Unsupported codec": nothing matches, so the kind is attempted but nothing is negotiated.
    {
        let mut m = MediaEngine::default();
        m.register_codec(opus(), RtpCodecKind::Audio)?;

        m.update_from_remote_description(&remote(
            "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
        ))?;

        assert!(m.negotiated_audio);
        assert!(m.get_codec_by_payload(0).is_err());
        assert!(m.get_codecs_by_kind(RtpCodecKind::Audio).is_empty());
    }

    Ok(())
}

#[test]
fn test_media_engine_header_extension_direction() -> Result<()> {
    let registered = |m: &MediaEngine, direction| {
        m.get_rtp_parameters_by_kind(RtpCodecKind::Audio, direction)
            .header_extensions
            .iter()
            .any(|h| h.uri == MID_URI)
    };

    // "No direction": every direction matches.
    {
        let mut m = MediaEngine::default();
        m.register_codec(opus(), RtpCodecKind::Audio)?;
        m.register_header_extension(extension(MID_URI), RtpCodecKind::Audio, None)?;

        assert!(registered(&m, RTCRtpTransceiverDirection::Recvonly));
        assert!(registered(&m, RTCRtpTransceiverDirection::Sendonly));
    }

    // "Same direction"
    {
        let mut m = MediaEngine::default();
        m.register_codec(opus(), RtpCodecKind::Audio)?;
        m.register_header_extension(
            extension(MID_URI),
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverDirection::Recvonly),
        )?;

        assert!(registered(&m, RTCRtpTransceiverDirection::Recvonly));
    }

    // "Different direction"
    {
        let mut m = MediaEngine::default();
        m.register_codec(opus(), RtpCodecKind::Audio)?;
        m.register_header_extension(
            extension(MID_URI),
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverDirection::Sendonly),
        )?;

        assert!(!registered(&m, RTCRtpTransceiverDirection::Recvonly));
    }

    // "Invalid direction"
    for direction in [
        RTCRtpTransceiverDirection::Inactive,
        RTCRtpTransceiverDirection::Unspecified,
    ] {
        let mut m = MediaEngine::default();
        m.register_codec(opus(), RtpCodecKind::Audio)?;
        assert_eq!(
            m.register_header_extension(extension(MID_URI), RtpCodecKind::Audio, Some(direction))
                .unwrap_err(),
            Error::ErrRegisterHeaderExtensionInvalidDirection
        );
    }

    Ok(())
}

/// Registering the same codec twice keeps one; registering an unknown kind is an error.
#[test]
fn test_media_engine_double_register() -> Result<()> {
    let mut m = MediaEngine::default();
    m.register_codec(opus(), RtpCodecKind::Audio)?;
    m.register_codec(opus(), RtpCodecKind::Audio)?;
    assert_eq!(m.audio_codecs.len(), 1);

    assert_eq!(
        m.register_codec(opus(), RtpCodecKind::Unspecified)
            .unwrap_err(),
        Error::ErrUnknownType
    );

    // Registering an extension twice keeps one entry, now covering both kinds.
    m.register_header_extension(extension(MID_URI), RtpCodecKind::Audio, None)?;
    m.register_header_extension(extension(MID_URI), RtpCodecKind::Video, None)?;
    assert_eq!(m.header_extensions.len(), 1);
    assert!(m.header_extensions[0].is_audio);
    assert!(m.header_extensions[0].is_video);
    Ok(())
}

/// An id the remote has taken for one extension is not handed to another one this side
/// offers for a kind that is not negotiated yet.
#[test]
fn test_media_engine_extension_id_collision() -> Result<()> {
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    m.register_header_extension(extension(MID_URI), RtpCodecKind::Video, None)?;
    m.register_header_extension(extension(AUDIO_LEVEL_URI), RtpCodecKind::Audio, None)?;

    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
         a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
         a=rtpmap:111 opus/48000/2\r\n",
    ))?;

    assert_eq!(
        m.get_header_extension_id(extension(AUDIO_LEVEL_URI)),
        (1, true, false)
    );

    let video =
        m.get_rtp_parameters_by_kind(RtpCodecKind::Video, RTCRtpTransceiverDirection::Sendrecv);
    let mid = video
        .header_extensions
        .iter()
        .find(|h| h.uri == MID_URI)
        .expect("mid is offered for video");
    assert_ne!(mid.id, 1, "id 1 is the remote's audio level");
    Ok(())
}

/// A copy for a new connection keeps what the application registered and drops what a
/// previous negotiation decided.
#[test]
fn test_media_engine_clone_to() -> Result<()> {
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    m.register_header_extension(extension(MID_URI), RtpCodecKind::Audio, None)?;
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 112\r\n\
         a=extmap:7 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
         a=rtpmap:112 opus/48000/2\r\n",
    ))?;
    assert!(m.negotiated_audio);

    let copy = m.clone_to();
    assert!(!copy.negotiated_audio);
    assert!(copy.negotiated_audio_codecs.is_empty());
    assert!(copy.negotiated_header_extensions.is_empty());
    assert_eq!(copy.audio_codecs, m.audio_codecs);
    assert_eq!(copy.video_codecs, m.video_codecs);
    assert_eq!(copy.header_extensions.len(), 1);
    let (opus_codec, _) = copy.get_codec_by_payload(111)?;
    assert_eq!(opus_codec.rtp_codec.mime_type, MIME_TYPE_OPUS);
    Ok(())
}

fn vp8_rtx_and(fec_mime_type: &str, fec_fmtp: &str) -> MediaEngine {
    let mut m = MediaEngine::default();
    for (payload_type, mime_type, fmtp) in [
        (96, MIME_TYPE_VP8, ""),
        (97, MIME_TYPE_RTX, "apt=96"),
        (118, fec_mime_type, fec_fmtp),
    ] {
        m.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(mime_type, 90000, 0, fmtp),
                payload_type,
            },
            RtpCodecKind::Video,
        )
        .expect("register");
    }
    m
}

fn offer_with_rtx_and(fec_name: &str, fec_fmtp: &str) -> SessionDescription {
    remote(&format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97 118\r\n\
         a=rtpmap:96 VP8/90000\r\n\
         a=rtpmap:97 rtx/90000\r\n\
         a=fmtp:97 apt=96\r\n\
         a=rtpmap:118 {fec_name}/90000\r\n\
         a=fmtp:118 {fec_fmtp}\r\n"
    ))
}

fn negotiated_video_names(m: &MediaEngine) -> Vec<String> {
    m.negotiated_video_codecs
        .iter()
        .map(|codec| codec.rtp_codec.mime_type.to_lowercase())
        .collect()
}

/// RFC 8627 section 1.1.7: an offer with both FlexFEC and RTP retransmission (RFC 4588) is
/// answered with FlexFEC only.
#[test]
fn flexfec_offered_with_rtx_is_negotiated_without_rtx() -> Result<()> {
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC, "repair-window=200000");
    m.update_from_remote_description(&offer_with_rtx_and("flexfec", "repair-window=200000"))?;

    assert_eq!(
        vec!["video/vp8".to_owned(), "video/flexfec".to_owned()],
        negotiated_video_names(&m),
        "no retransmission format beside FlexFEC"
    );
    Ok(())
}

/// The rule belongs to the RFC's `flexfec`. `flexfec-03`, the draft format browsers offer, has
/// none: it is answered together with RTX, as libwebrtc does.
#[test]
fn flexfec03_offered_with_rtx_keeps_rtx() -> Result<()> {
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC03, "repair-window=10000000");
    m.update_from_remote_description(&offer_with_rtx_and("flexfec-03", "repair-window=10000000"))?;

    assert_eq!(
        vec![
            "video/vp8".to_owned(),
            "video/rtx".to_owned(),
            "video/flexfec-03".to_owned()
        ],
        negotiated_video_names(&m)
    );
    Ok(())
}

/// The lenient setting answers the RFC format with RTX too.
#[test]
fn the_lenient_setting_keeps_rtx_beside_flexfec() -> Result<()> {
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC, "repair-window=200000");
    m.set_flexfec_with_retransmission(true);
    m.update_from_remote_description(&offer_with_rtx_and("flexfec", "repair-window=200000"))?;

    assert!(negotiated_video_names(&m).contains(&"video/rtx".to_owned()));
    Ok(())
}

/// Without FlexFEC in the offer, RTX is negotiated as before.
#[test]
fn rtx_is_negotiated_when_flexfec_is_registered_but_not_offered() -> Result<()> {
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC, "repair-window=200000");
    m.update_from_remote_description(&remote(
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
         a=rtpmap:96 VP8/90000\r\n\
         a=rtpmap:97 rtx/90000\r\n\
         a=fmtp:97 apt=96\r\n",
    ))?;

    assert_eq!(
        vec!["video/vp8".to_owned(), "video/rtx".to_owned()],
        negotiated_video_names(&m)
    );
    Ok(())
}

/// RFC 8627 section 5.1 and draft-03 section 5.1: `repair-window` is a required parameter. An
/// offered FlexFEC format without one is not negotiated (RTX stays, as without FlexFEC).
#[test]
fn flexfec_offered_without_a_repair_window_is_not_negotiated() -> Result<()> {
    for (mime_type, name) in [
        (MIME_TYPE_FLEX_FEC, "flexfec"),
        (MIME_TYPE_FLEX_FEC03, "flexfec-03"),
    ] {
        let mut m = vp8_rtx_and(mime_type, "repair-window=200000");
        m.update_from_remote_description(&offer_with_rtx_and(name, "L=5"))?;
        assert_eq!(
            vec!["video/vp8".to_owned(), "video/rtx".to_owned()],
            negotiated_video_names(&m),
            "{name}"
        );
    }
    Ok(())
}

/// RFC 8627 section 5.2.1: "the receiver ... MUST reject the offer" whose repair window it
/// cannot support. A window longer than the one this endpoint registered is not negotiated; a
/// shorter one is.
#[test]
fn a_repair_window_longer_than_the_registered_one_is_not_negotiated() -> Result<()> {
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC, "repair-window=200000");
    m.update_from_remote_description(&offer_with_rtx_and("flexfec", "repair-window=400000"))?;
    assert_eq!(
        vec!["video/vp8".to_owned(), "video/rtx".to_owned()],
        negotiated_video_names(&m)
    );
    let mut m = vp8_rtx_and(MIME_TYPE_FLEX_FEC, "repair-window=200000");
    m.update_from_remote_description(&offer_with_rtx_and("flexfec", "repair-window=100000"))?;
    assert_eq!(
        vec!["video/vp8".to_owned(), "video/flexfec".to_owned()],
        negotiated_video_names(&m)
    );
    Ok(())
}

/// RFC 8627 section 5.1: a FlexFEC format the application registers without `repair-window`
/// is described with the window its receiver uses for a line without one (10 s), so the
/// required parameter is always signalled.
#[test]
fn a_flexfec_format_registered_without_a_repair_window_gets_the_default_one() {
    for mime_type in [MIME_TYPE_FLEX_FEC, MIME_TYPE_FLEX_FEC03] {
        let m = vp8_rtx_and(mime_type, "");
        let fec = m
            .video_codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type == mime_type)
            .expect("registered");
        assert_eq!(fec.rtp_codec.sdp_fmtp_line, "repair-window=10000000");
    }
}

/// Opus and RED (`red/48000/2`, `a=fmtp:63 111/111`, as browsers register it).
fn opus_and_red() -> MediaEngine {
    let mut m = MediaEngine::default();
    for (payload_type, mime_type, fmtp) in [
        (111, MIME_TYPE_OPUS, "minptime=10;useinbandfec=1"),
        (63, "audio/red", "111/111"),
    ] {
        m.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(mime_type, 48000, 2, fmtp),
                payload_type,
            },
            RtpCodecKind::Audio,
        )
        .expect("register");
    }
    m
}

fn negotiated_audio_names(m: &MediaEngine) -> Vec<String> {
    m.negotiated_audio_codecs
        .iter()
        .map(|codec| codec.rtp_codec.mime_type.to_lowercase())
        .collect()
}

/// RFC 2198 section 5: the encodings a RED format names in its fmtp are formats of the m=
/// line; a RED format whose blocks are of the section's Opus is negotiated.
#[test]
fn red_naming_a_format_of_the_section_is_negotiated() -> Result<()> {
    let mut m = opus_and_red();
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
         a=fmtp:111 minptime=10;useinbandfec=1\r\n\
         a=rtpmap:63 red/48000/2\r\n\
         a=fmtp:63 111/111\r\n",
    ))?;
    assert_eq!(
        vec!["audio/opus".to_owned(), "audio/red".to_owned()],
        negotiated_audio_names(&m)
    );
    Ok(())
}

/// RFC 2198 section 5: "a=fmtp:<pt> <pt1>/<pt2>..." names the encodings by the payload types
/// of the description that carries it. A remote offer numbering Opus 109 and RED 110 with
/// `109/109` negotiates RED under the offer's numbers, its slash list naming the offer's Opus.
#[test]
fn red_is_negotiated_under_the_offers_payload_type_numbers() -> Result<()> {
    let mut m = opus_and_red();
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 109 110\r\n\
         a=rtpmap:109 opus/48000/2\r\n\
         a=fmtp:109 minptime=10;useinbandfec=1\r\n\
         a=rtpmap:110 red/48000/2\r\n\
         a=fmtp:110 109/109\r\n",
    ))?;
    let red = m
        .negotiated_audio_codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("audio/red"))
        .expect("RED negotiated");
    assert_eq!(red.payload_type, 110);
    assert_eq!(red.rtp_codec.sdp_fmtp_line.trim(), "109/109");
    Ok(())
}

/// RFC 2198 section 5: the RED fmtp is a slash-separated list of payload types. A line that is
/// not one (`109/x`) names no encoding the receiver could decode: RED is not negotiated.
#[test]
fn red_with_a_malformed_slash_list_is_not_negotiated() -> Result<()> {
    let mut m = opus_and_red();
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 109 110\r\n\
         a=rtpmap:109 opus/48000/2\r\n\
         a=fmtp:109 minptime=10;useinbandfec=1\r\n\
         a=rtpmap:110 red/48000/2\r\n\
         a=fmtp:110 109/x\r\n",
    ))?;
    assert_eq!(vec!["audio/opus".to_owned()], negotiated_audio_names(&m));
    Ok(())
}

/// A RED format naming a payload type that is not a format of the m= line (RFC 2198 section
/// 5: "MUST" be listed) is not negotiated: its blocks could not be decoded.
#[test]
fn red_naming_a_payload_type_missing_from_the_m_line_is_not_negotiated() -> Result<()> {
    let mut m = opus_and_red();
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 63\r\n\
         a=rtpmap:63 red/48000/2\r\n\
         a=fmtp:63 111/111\r\n",
    ))?;
    assert!(negotiated_audio_names(&m).is_empty());
    Ok(())
}

/// RFC 2198 section 3: a redundant encoding uses the primary's clock rate. RED at 48 kHz
/// naming PCMU (8 kHz) is not negotiated.
#[test]
fn red_naming_a_format_of_another_clock_rate_is_not_negotiated() -> Result<()> {
    let mut m = MediaEngine::default();
    for (payload_type, mime_type, clock_rate, channels, fmtp) in [
        (0, MIME_TYPE_PCMU, 8000, 0, ""),
        (63, "audio/red", 48000, 2, "0/0"),
    ] {
        m.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(mime_type, clock_rate, channels, fmtp),
                payload_type,
            },
            RtpCodecKind::Audio,
        )?;
    }
    m.update_from_remote_description(&remote(
        "m=audio 9 UDP/TLS/RTP/SAVPF 0 63\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:63 red/48000/2\r\n\
         a=fmtp:63 0/0\r\n",
    ))?;
    assert_eq!(vec!["audio/pcmu".to_owned()], negotiated_audio_names(&m));
    Ok(())
}
