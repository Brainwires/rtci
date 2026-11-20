//! Several media sections of one kind each negotiate their own codecs (RFC 9429, Section
//! 5.10), and the negotiated list keeps one entry per format and one format per payload type.
//!
//! `test_multi_codec_negotiation` is upstream `webrtc` v0.17.1's test of the same name
//! (`api/media_engine/media_engine_test.rs`), made synchronous.

use std::time::Instant;

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;

/// Upstream's offer: a data channel, a VP9 section (simulcast send) and a VP8 section.
const MULTI_CODEC_OFFER: &str = "v=0
o=- 781500112831855234 6 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1 2 3
a=extmap-allow-mixed
a=msid-semantic: WMS be0216be-f3d8-40ca-a624-379edf70f1c9
m=application 53555 UDP/DTLS/SCTP webrtc-datachannel
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
m=video 9 UDP/TLS/RTP/SAVPF 98
a=mid:1
a=sendonly
a=msid:be0216be-f3d8-40ca-a624-379edf70f1c9 3d032b3b-ffe5-48ec-b783-21375668d1c3
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:98 VP9/90000
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 transport-cc
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=fmtp:98 profile-id=0
a=rid:q send
a=rid:h send
a=simulcast:send q;h
m=video 9 UDP/TLS/RTP/SAVPF 96
a=mid:2
a=sendonly
a=msid:6ff05509-be96-4ef1-a74f-425e14720983 16d5d7fe-d076-4718-9ca9-ec62b4543727
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=ssrc:4281768245 cname:JDM9GNMEg+9To6K7
a=ssrc:4281768245 msid:6ff05509-be96-4ef1-a74f-425e14720983 16d5d7fe-d076-4718-9ca9-ec62b4543727
";

const HEAD: &str = "v=0\r\no=- 4596489990601351948 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";

fn parse(sdp: &str) -> SessionDescription {
    let crlf = sdp.replace("\r\n", "\n").replace('\n', "\r\n");
    let mut reader = std::io::Cursor::new(crlf.as_bytes());
    SessionDescription::unmarshal(&mut reader).expect("test SDP parses")
}

fn video(mime_type: &str, payload_type: PayloadType, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// An engine with VP8, VP9 (each with RTX) and FlexFEC, multi-codec negotiation on.
fn engine() -> MediaEngine {
    let mut m = MediaEngine::default();
    for codec in [
        video(MIME_TYPE_VP8, 96, ""),
        video(MIME_TYPE_RTX, 97, "apt=96"),
        video(MIME_TYPE_VP9, 98, "profile-id=0"),
        video(MIME_TYPE_RTX, 99, "apt=98"),
        video(MIME_TYPE_FLEX_FEC03, 45, "repair-window=10000000"),
    ] {
        m.register_codec(codec, RtpCodecKind::Video)
            .expect("register codec");
    }
    m.set_multi_codec_negotiation(true);
    m
}

/// One video section offering `formats` (`(pt, rtpmap encoding, fmtp)`).
fn video_section(mid: &str, formats: &[(u8, &str, &str)]) -> String {
    let numbers: Vec<String> = formats.iter().map(|(pt, _, _)| pt.to_string()).collect();
    let mut section = format!(
        "m=video 9 UDP/TLS/RTP/SAVPF {}\r\na=mid:{mid}\r\na=sendrecv\r\na=rtcp-mux\r\n",
        numbers.join(" ")
    );
    for (pt, encoding, fmtp) in formats {
        section.push_str(&format!("a=rtpmap:{pt} {encoding}\r\n"));
        if !fmtp.is_empty() {
            section.push_str(&format!("a=fmtp:{pt} {fmtp}\r\n"));
        }
    }
    section
}

fn remote(sections: &[String]) -> SessionDescription {
    parse(&format!("{HEAD}{}", sections.concat()))
}

fn negotiated(m: &MediaEngine) -> Vec<(PayloadType, String, String)> {
    m.negotiated_video_codecs
        .iter()
        .map(|c| {
            (
                c.payload_type,
                c.rtp_codec.mime_type.to_lowercase(),
                c.rtp_codec.sdp_fmtp_line.clone(),
            )
        })
        .collect()
}

#[test]
fn test_multi_codec_negotiation() -> Result<()> {
    // Multi codec negotiation disabled
    {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        m.update_from_remote_description(&parse(MULTI_CODEC_OFFER))?;
        assert_eq!(m.negotiated_video_codecs.len(), 1);
    }

    // Multi codec negotiation enabled
    {
        let mut m = MediaEngine::default();
        m.set_multi_codec_negotiation(true);
        assert!(m.multi_codec_negotiation());
        m.register_default_codecs()?;
        m.update_from_remote_description(&parse(MULTI_CODEC_OFFER))?;
        assert_eq!(m.negotiated_video_codecs.len(), 2);
    }

    Ok(())
}

#[test]
fn a_peer_connection_negotiates_each_section_unless_told_not_to() -> Result<()> {
    let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    assert!(
        pc.media_engine.multi_codec_negotiation(),
        "with_disable_media_engine_multiple_codecs documents `false` as the default"
    );

    let pc = RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_disable_media_engine_multiple_codecs(true)
                .build(),
        )
        .build(Instant::now())?;
    assert!(!pc.media_engine.multi_codec_negotiation());
    Ok(())
}

#[test]
fn a_second_section_adds_only_the_formats_the_first_did_not_have() -> Result<()> {
    let mut m = engine();
    m.update_from_remote_description(&remote(&[
        video_section("0", &[(96, "VP8/90000", ""), (97, "rtx/90000", "apt=96")]),
        video_section(
            "1",
            &[
                (96, "VP8/90000", ""),
                (97, "rtx/90000", "apt=96"),
                (98, "VP9/90000", "profile-id=0"),
                (99, "rtx/90000", "apt=98"),
            ],
        ),
    ]))?;

    assert_eq!(
        negotiated(&m),
        vec![
            (96, "video/vp8".to_owned(), "".to_owned()),
            (97, "video/rtx".to_owned(), "apt=96".to_owned()),
            (98, "video/vp9".to_owned(), "profile-id=0".to_owned()),
            (99, "video/rtx".to_owned(), "apt=98".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn a_renumbered_format_is_kept_once_under_its_first_number() -> Result<()> {
    let mut m = engine();
    let first = [
        (100, "VP8/90000", ""),
        (101, "rtx/90000", "apt=100"),
        (35, "flexfec-03/90000", "repair-window=10000000"),
    ];
    // RFC 3264 section 8.3.2 forbids this, so the stale mapping is kept and nothing doubles.
    let renumbered = [
        (102, "VP8/90000", ""),
        (104, "rtx/90000", "apt=102"),
        (115, "flexfec-03/90000", "repair-window=10000000"),
    ];

    m.update_from_remote_description(&remote(&[video_section("0", &first)]))?;
    let after_first = negotiated(&m);
    assert_eq!(
        after_first,
        vec![
            (100, "video/vp8".to_owned(), "".to_owned()),
            (101, "video/rtx".to_owned(), "apt=100".to_owned()),
            (
                35,
                "video/flexfec-03".to_owned(),
                "repair-window=10000000".to_owned()
            ),
        ]
    );

    m.update_from_remote_description(&remote(&[video_section("0", &renumbered)]))?;
    assert_eq!(negotiated(&m), after_first, "a renumbering adds nothing");

    // The same in one description, across two sections.
    let mut m = engine();
    m.update_from_remote_description(&remote(&[
        video_section("0", &first),
        video_section("1", &renumbered),
    ]))?;
    assert_eq!(negotiated(&m), after_first);
    Ok(())
}

#[test]
fn a_payload_type_keeps_the_format_it_first_named() -> Result<()> {
    let mut m = engine();
    m.update_from_remote_description(&remote(&[
        video_section("0", &[(96, "VP8/90000", "")]),
        // 96 again, for another format: RFC 8843 section 7.5 allows one format per number.
        video_section("1", &[(96, "VP9/90000", "profile-id=0")]),
    ]))?;
    assert_eq!(
        negotiated(&m),
        vec![(96, "video/vp8".to_owned(), "".to_owned())]
    );
    Ok(())
}

#[test]
fn rtx_follows_its_primary() -> Result<()> {
    let mut m = engine();
    m.update_from_remote_description(&remote(&[
        video_section("0", &[(96, "VP8/90000", "")]),
        // RTX listed ahead of its primary: still bound to the VP9 this section adds. (The
        // matching's second pass, which picks such an RTX up, puts it after its primary.)
        video_section(
            "1",
            &[
                (99, "rtx/90000", "apt=98"),
                (98, "VP9/90000", "profile-id=0"),
            ],
        ),
    ]))?;
    assert_eq!(
        negotiated(&m),
        vec![
            (96, "video/vp8".to_owned(), "".to_owned()),
            (98, "video/vp9".to_owned(), "profile-id=0".to_owned()),
            (99, "video/rtx".to_owned(), "apt=98".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn fmtp_parameter_order_and_case_do_not_make_a_new_format() {
    assert!(same_format(
        &video(MIME_TYPE_VP9, 98, "profile-id=0;x-google-start-bitrate=800").rtp_codec,
        &video("video/vp9", 120, "X-Google-Start-Bitrate=800; profile-id=0").rtp_codec,
    ));
    assert!(!same_format(
        &video(MIME_TYPE_VP9, 98, "profile-id=0").rtp_codec,
        &video(MIME_TYPE_VP9, 98, "profile-id=2").rtp_codec,
    ));
    assert!(!same_format(
        &video(MIME_TYPE_VP9, 98, "profile-id=0").rtp_codec,
        &video(MIME_TYPE_VP8, 98, "profile-id=0").rtp_codec,
    ));
}
