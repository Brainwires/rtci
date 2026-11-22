//! RFC 5761 section 4: "RTP payload types in the range 64-95 MUST NOT be used" when RTP and
//! RTCP share a port. With the marker bit set, such a packet's second octet is an RTCP packet
//! type (192 to 223), so the demultiplexer would take it for RTCP. This endpoint always
//! multiplexes: it registers no codec with such a payload type and uses none a remote
//! description numbers so.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of, vp8,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use rtc::shared::error::Error;

#[test]
fn a_codec_is_not_registered_with_a_payload_type_of_64_to_95() {
    for payload_type in [0u8, 35, 63, 96, 127] {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: vp8(),
                    payload_type,
                },
                RtpCodecKind::Video,
            )
            .unwrap_or_else(|err| panic!("payload type {payload_type}: {err}"));
    }
    for payload_type in [64u8, 72, 95] {
        let mut media_engine = MediaEngine::default();
        let refused = media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: vp8(),
                payload_type,
            },
            RtpCodecKind::Video,
        );
        assert!(
            matches!(&refused, Err(Error::SdpInvalidValue(why)) if why.contains("RFC 5761")),
            "payload type {payload_type}: {refused:?}"
        );
    }
}

/// The default codecs keep out of the range.
#[test]
fn the_default_codecs_register() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(())
}

/// A remote offer that numbers a format 72: the format is one this endpoint cannot use, so
/// the answer leaves it out and takes the offer's other format.
#[test]
fn a_remote_format_numbered_64_to_95_is_not_answered() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 72 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:72 VP8/90000
a=rtpmap:96 VP9/90000
a=fmtp:96 profile-id=0
"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_ne!(port_of(&sections[0]), 0, "{}", answer.sdp);
    let formats: Vec<&str> = sections[0][0].split(' ').skip(3).collect();
    assert_eq!(formats, vec!["96"], "{}", answer.sdp);
    assert!(!answer.sdp.contains("a=rtpmap:72 "), "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

/// RFC 7874 section 3 and RFC 4733 section 2.4.1: the default codecs offer
/// `telephone-event` for each audio clock rate, with the DTMF events 0 to 15, and it is
/// answered.
#[test]
fn telephone_event_is_offered_with_the_dtmf_events_and_answered() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_transceiver_from_kind(rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Audio, None)?;
    let (offer, answer) = jsep_common::exchange(&mut a, &mut b)?;
    for sdp in [&offer, &answer] {
        let audio = &media_sections(sdp)[0];
        for rate in [48000, 8000] {
            let rtpmap = audio
                .iter()
                .find(|l| l.ends_with(&format!(" telephone-event/{rate}")))
                .unwrap_or_else(|| panic!("telephone-event/{rate} in:\n{sdp}"));
            let payload_type = rtpmap
                .strip_prefix("a=rtpmap:")
                .and_then(|l| l.split(' ').next())
                .expect("a payload type");
            assert!(
                audio.contains(&format!("a=fmtp:{payload_type} 0-15")),
                "{sdp}"
            );
            assert!(
                audio[0]
                    .split(' ')
                    .skip(3)
                    .any(|format| format == payload_type),
                "{sdp}"
            );
        }
        // After the audio codecs: it is not the format media is sent with.
        assert!(audio[0].contains(" 111 "), "{sdp}");
        let formats: Vec<&str> = audio[0].split(' ').skip(3).collect();
        assert_eq!(formats[0], "111", "{sdp}");
    }
    Ok(())
}
