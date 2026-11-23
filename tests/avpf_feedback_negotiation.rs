//! RFC 4585 (RTP/AVPF) sections 3.7.2, 4.1 and 4.2 as descriptions carry them: feedback is
//! signalled under the AVPF profile only, at media level only, and an answer keeps only the
//! feedback both sides understand.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};

fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    }
}

/// A peer whose only codec is VP8 (payload type 96) with NACK and PLI.
fn peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![feedback("nack", ""), feedback("nack", "pli")],
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// A peer with the default codecs and interceptors, and their feedback.
fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

fn feedback_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=rtcp-fb:"))
        .collect()
}

fn offer(feedback: &str) -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
    Ok(RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
{feedback}"
    )))?)
}

/// RFC 4585 sections 3.7.2, 4.2: an endpoint that uses feedback signals the AVPF profile
/// (here its secure form, `UDP/TLS/RTP/SAVPF`) in every section that carries `a=rtcp-fb`,
/// and writes `a=rtcp-fb` only at media level.
#[test]
fn feedback_is_offered_under_the_avpf_profile_and_at_media_level_only() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    let mut in_media = false;
    let mut profile = String::new();
    let mut with_feedback = 0;
    for line in offer.sdp.lines() {
        if let Some(m) = line.strip_prefix("m=") {
            in_media = true;
            profile = m.split_whitespace().nth(2).unwrap_or_default().to_owned();
        }
        if line.starts_with("a=rtcp-fb:") {
            assert!(in_media, "a session-level a=rtcp-fb: {}", offer.sdp);
            assert!(
                profile.ends_with("AVPF"),
                "a=rtcp-fb under {profile}: {}",
                offer.sdp
            );
            with_feedback += 1;
        }
    }
    assert!(with_feedback > 0, "{}", offer.sdp);
    Ok(())
}

/// RFC 4585 section 4.2: "Feedback types that are not understood ... MUST be ignored"; and
/// the answerer "MUST remove" the feedback it does not understand or want: an unknown type
/// and an unknown parameter of a known one are not answered, the rest is.
#[test]
fn feedback_this_endpoint_does_not_understand_is_left_out_of_the_answer() -> TestResult {
    let mut pc = peer()?;
    pc.set_remote_description(
        Instant::now(),
        offer("a=rtcp-fb:96 nack\na=rtcp-fb:96 x-unknown\na=rtcp-fb:96 nack x-unknown\na=rtcp-fb:96 nack pli\n")?,
    )?;
    let answer = pc.create_answer(None)?;
    let mut lines = feedback_lines(&answer.sdp);
    lines.sort_unstable();
    assert_eq!(vec!["96 nack", "96 nack pli"], lines, "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

/// RFC 3611 section 5.1: "The indicators 'TTL' and 'HL' MUST NOT be signaled together". The
/// endpoint signals only the round-trip pair (`rcvr-rtt`): an answer to an offer whose
/// `a=rtcp-xr` lists a statistics summary with both keeps neither, and states the `rcvr-rtt`
/// it takes.
#[test]
fn ttl_and_hl_are_never_signalled_together() -> TestResult {
    let mut pc = default_peer()?;
    let remote = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtcp-xr:rcvr-rtt=all stat-summary=loss,TTL,HL
"
    )))?;
    pc.set_remote_description(Instant::now(), remote)?;
    let answer = pc.create_answer(None)?;
    for line in answer.sdp.lines().filter(|l| l.starts_with("a=rtcp-xr")) {
        assert!(
            !(line.contains("TTL") && line.contains("HL")),
            "{}",
            answer.sdp
        );
    }
    let offer = default_peer()
        .and_then(|mut pc| {
            pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
            Ok(pc.create_offer(None)?)
        })?
        .sdp;
    for line in offer.lines().filter(|l| l.starts_with("a=rtcp-xr")) {
        assert!(!(line.contains("TTL") && line.contains("HL")), "{offer}");
    }
    Ok(())
}

/// RFC 4585 section 4.1 ("feedback ... MUST NOT be used" outside an AVPF-based profile) and
/// RFC 5506 sections 4, 4.1 (reduced-size RTCP only with AVPF early feedback, never with
/// RTP/SAVP): a section offered as `UDP/TLS/RTP/SAVP` with `a=rtcp-fb` and `a=rtcp-rsize`
/// negotiates neither; the same section under `SAVPF` negotiates both.
#[test]
fn a_section_without_the_avpf_profile_negotiates_no_feedback_and_no_reduced_size() -> TestResult {
    for (profile, expect_feedback) in [("UDP/TLS/RTP/SAVP", false), ("UDP/TLS/RTP/SAVPF", true)] {
        let mut pc = peer()?;
        let remote = RTCSessionDescription::offer(crlf(&format!(
            "{SESSION}a=group:BUNDLE 0
m=video 9 {profile} 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
"
        )))?;
        pc.set_remote_description(Instant::now(), remote)?;
        let answer = pc.create_answer(None)?;
        assert_eq!(
            expect_feedback,
            !feedback_lines(&answer.sdp).is_empty(),
            "{profile}: {}",
            answer.sdp
        );
        pc.set_local_description(Instant::now(), answer)?;
        let id = pc.get_transceivers().next().expect("a transceiver");
        let reduced_size = pc
            .rtp_transceiver(id)
            .expect("transceiver")
            .rtcp_reduced_size();
        assert_eq!(expect_feedback, reduced_size, "{profile}: reduced-size");
    }
    Ok(())
}

/// RFC 4585 section 4.2 ("no feedback messages other than those listed in the 'a=rtcp-fb'
/// lines MUST be used") and RFC 5104 section 7.2 ("MUST NOT use other CCM messages than those
/// indicated"): the application's own RTCP feedback is held to what the section negotiated.
/// A PLI goes; a FIR, not negotiated, is refused, unless the departure is configured.
#[test]
fn application_feedback_the_section_did_not_negotiate_is_refused() -> TestResult {
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtc::rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
    use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;

    let answered = |pc: &mut RTCPeerConnection| -> TestResult {
        pc.set_remote_description(
            Instant::now(),
            offer("a=rtcp-fb:96 nack\na=rtcp-fb:96 nack pli\na=rtcp-fb:96 ccm fir\n")?,
        )?;
        let answer = pc.create_answer(None)?;
        pc.set_local_description(Instant::now(), answer)?;
        Ok(())
    };
    let pli = || -> Vec<Box<dyn rtc::rtcp::Packet>> {
        vec![Box::new(PictureLossIndication {
            sender_ssrc: 0,
            media_ssrc: 1234,
        })]
    };
    let fir = || -> Vec<Box<dyn rtc::rtcp::Packet>> {
        vec![Box::new(FullIntraRequest {
            sender_ssrc: 0,
            media_ssrc: 1234,
            fir: vec![FirEntry {
                ssrc: 1234,
                sequence_number: 1,
            }],
        })]
    };

    // This endpoint registered VP8 with NACK and PLI only: `ccm fir` is not negotiated.
    let mut pc = peer()?;
    answered(&mut pc)?;
    let receiver = pc.get_receivers().next().expect("a receiver");
    let mut receiver = pc.rtp_receiver(receiver).expect("receiver");
    receiver.write_rtcp(Instant::now(), pli())?;
    match receiver.write_rtcp(Instant::now(), fir()) {
        Err(shared::error::Error::ErrRTCPFeedbackNotNegotiated(typ, parameter)) => {
            assert_eq!(("ccm", "fir"), (typ.as_str(), parameter.as_str()));
        }
        other => panic!("a FIR that was not negotiated: {other:?}"),
    }

    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![feedback("nack", ""), feedback("nack", "pli")],
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    let mut lenient = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_unnegotiated_rtcp_feedback(true)
                .build(),
        )
        .build(Instant::now())?;
    answered(&mut lenient)?;
    let receiver = lenient.get_receivers().next().expect("a receiver");
    lenient
        .rtp_receiver(receiver)
        .expect("receiver")
        .write_rtcp(Instant::now(), fir())?;
    Ok(())
}

/// RFC 4588 section 4: "the retransmission payload type ... MUST use the same clock rate as
/// the original payload type". An offered `rtx` of another clock rate than the format it
/// names in `apt` is not negotiated; one of the same rate is.
#[test]
fn an_rtx_format_of_another_clock_rate_than_its_original_is_not_negotiated() -> TestResult {
    for (rtx_rate, answered) in [(48000u32, false), (90000, true)] {
        let mut media_engine = MediaEngine::default();
        for (mime_type, payload_type, fmtp) in
            [(MIME_TYPE_VP8, 96u8, ""), ("video/rtx", 97, "apt=96")]
        {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: RTCRtpCodec {
                        mime_type: mime_type.to_owned(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: fmtp.to_owned(),
                        rtcp_feedback: vec![feedback("nack", "")],
                    },
                    payload_type,
                },
                RtpCodecKind::Video,
            )?;
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        let remote = RTCSessionDescription::offer(crlf(&format!(
            "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 97
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtpmap:97 rtx/{rtx_rate}
a=fmtp:97 apt=96
"
        )))?;
        pc.set_remote_description(Instant::now(), remote)?;
        let answer = pc.create_answer(None)?;
        assert_eq!(
            answered,
            answer.sdp.contains("a=rtpmap:97 rtx/"),
            "rtx/{rtx_rate}: {}",
            answer.sdp
        );
    }
    Ok(())
}

/// RFC 2198 section 5, send side: "the payload types of the primary and redundant encodings
/// ... MUST also be listed" as formats of the m= line. A RED format whose fmtp names an
/// encoding this endpoint does not offer in the section is left out of its offer; one naming
/// offered Opus is offered.
#[test]
fn an_offer_leaves_out_a_red_format_naming_an_encoding_it_does_not_offer() -> TestResult {
    for (red_fmtp, offered) in [("120/120", false), ("111/111", true)] {
        let mut media_engine = MediaEngine::default();
        for (mime_type, payload_type, fmtp) in [
            ("audio/opus", 111u8, "minptime=10;useinbandfec=1"),
            ("audio/red", 63, red_fmtp),
        ] {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: RTCRtpCodec {
                        mime_type: mime_type.to_owned(),
                        clock_rate: 48000,
                        channels: 2,
                        sdp_fmtp_line: fmtp.to_owned(),
                        rtcp_feedback: vec![],
                    },
                    payload_type,
                },
                RtpCodecKind::Audio,
            )?;
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let offer = pc.create_offer(None)?;
        assert!(
            offer.sdp.contains("a=rtpmap:111 opus/48000/2"),
            "{}",
            offer.sdp
        );
        assert_eq!(
            offered,
            offer.sdp.contains("a=rtpmap:63 red/48000"),
            "red {red_fmtp}: {}",
            offer.sdp
        );
    }
    Ok(())
}
