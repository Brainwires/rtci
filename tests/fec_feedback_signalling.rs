//! What descriptions say about FEC and congestion control feedback: a FlexFEC answer states
//! this endpoint's own parameters and drops what the offer had that it does not know (RFC 8627
//! 5.2.1, draft-ietf-payload-flexible-fec-scheme-03 5.2.1), and RFC 8888 feedback is signalled
//! the same in every bundled section (RFC 8888 6, RFC 8859 IDENTICAL-PER-PT).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC, MIME_TYPE_FLEX_FEC03, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};

fn codec(mime_type: &str, fmtp: &str, payload_type: u8) -> RTCRtpCodecParameters {
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

/// VP8 on 96 and the FEC format `fec` on 49 with `fmtp`.
fn peer(fec: &str, fmtp: &str) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(codec(MIME_TYPE_VP8, "", 96), RtpCodecKind::Video)?;
    media_engine.register_codec(codec(fec, fmtp, 49), RtpCodecKind::Video)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn fmtp_of(sdp: &str, pt: &str) -> Vec<String> {
    let mut parameters: Vec<String> = sdp
        .lines()
        .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
        .map(|line| line.split(';').map(|p| p.trim().to_owned()).collect())
        .unwrap_or_default();
    parameters.sort();
    parameters
}

fn answer_to(
    pc: &mut RTCPeerConnection,
    encoding: &str,
    fmtp: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 49
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtpmap:49 {encoding}/90000
a=fmtp:49 {fmtp}
"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

/// RFC 8627 section 5.2.1: "Any unknown option in the offer must be ignored and deleted from
/// the answer"; the answer states this endpoint's parameters.
#[test]
fn a_flexfec_answer_drops_unknown_options() -> TestResult {
    let mut pc = peer(MIME_TYPE_FLEX_FEC, "repair-window=200000")?;
    let sdp = answer_to(&mut pc, "flexfec", "repair-window=200000;x-unknown=1")?;
    assert!(sdp.contains("a=rtpmap:49 flexfec/90000"), "{sdp}");
    assert_eq!(vec!["repair-window=200000"], fmtp_of(&sdp, "49"), "{sdp}");
    Ok(())
}

/// draft-ietf-payload-flexible-fec-scheme-03 section 5.2.1: the same for `flexfec-03`.
#[test]
fn a_flexfec_03_answer_drops_unknown_options() -> TestResult {
    let mut pc = peer(MIME_TYPE_FLEX_FEC03, "repair-window=10000000")?;
    let sdp = answer_to(&mut pc, "flexfec-03", "repair-window=10000000;x-unknown=1")?;
    assert!(sdp.contains("a=rtpmap:49 flexfec-03/90000"), "{sdp}");
    assert_eq!(vec!["repair-window=10000000"], fmtp_of(&sdp, "49"), "{sdp}");
    Ok(())
}

/// RFC 8888 section 6 with RFC 8859: `a=rtcp-fb` is IDENTICAL-PER-PT under BUNDLE. RFC 8888
/// feedback is written with the wildcard payload type, the same line in every bundled
/// section of the default offer.
#[test]
fn rfc_8888_feedback_is_signalled_alike_in_every_bundled_section() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?.sdp;
    let sections: Vec<&str> = offer.split("\r\nm=").skip(1).collect();
    assert_eq!(2, sections.len(), "{offer}");
    for section in sections {
        let ccfb: Vec<&str> = section
            .lines()
            .filter(|l| l.starts_with("a=rtcp-fb:") && l.ends_with("ack ccfb"))
            .collect();
        assert_eq!(vec!["a=rtcp-fb:* ack ccfb"], ccfb, "{offer}");
    }
    Ok(())
}

/// RFC 2198 sections 3 and 5: the redundancy format takes a dynamic payload type, bound with
/// `a=rtpmap:<pt> red/<rate>/<channels>`, and its fmtp names the primary and redundant
/// encodings by payload type, which the `m=` line lists too.
#[test]
fn audio_red_is_offered_with_a_dynamic_payload_type_and_its_encodings() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: "audio/opus".to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: "audio/red".to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "111/111".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 121,
        },
        RtpCodecKind::Audio,
    )?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?.sdp;
    assert!(offer.contains("a=rtpmap:121 red/48000/2"), "{offer}");
    assert!(offer.contains("a=fmtp:121 111/111"), "{offer}");
    let m_line = offer
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("an audio section");
    let formats: Vec<&str> = m_line.split_whitespace().skip(3).collect();
    assert!(
        formats.contains(&"121") && formats.contains(&"111"),
        "{m_line}"
    );
    Ok(())
}
