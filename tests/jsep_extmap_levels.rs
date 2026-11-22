//! `a=extmap` at session level and with a direction (RFC 8285 sections 5 and 7, RFC 9429
//! section 5.8.1): a session-level mapping is every RTP section's unless the section has its
//! own, and an extension offered for one direction is answered for the other.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};

const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const RID: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
const RRID: &str = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
const ABS: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

fn peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for uri in [MID, RID, RRID, ABS] {
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            media_engine.register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: uri.to_owned(),
                },
                kind,
                None,
            )?;
        }
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// The `a=extmap` values of each section of the answer `pc` gives to the offer, sorted.
fn answered_extmaps(
    session: &str,
    sections: &[&str],
) -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let mut offer = format!("{SESSION}a=group:BUNDLE 0 1\n{session}");
    for (mid, lines) in sections.iter().enumerate() {
        let (media, format) = if mid == 0 {
            ("audio", "111 opus/48000/2")
        } else {
            ("video", "96 VP8/90000")
        };
        offer.push_str(&format!(
            "m={media} 9 UDP/TLS/RTP/SAVPF {}
{TRANSPORT}a=mid:{mid}
a=sendrecv
{lines}a=rtpmap:{format}
",
            format.split(' ').next().unwrap_or_default()
        ));
    }
    let mut pc = peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(&offer))?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    let mut out: Vec<Vec<String>> = vec![];
    for line in answer.sdp.lines() {
        if line.starts_with("m=") {
            out.push(vec![]);
        } else if let (Some(value), Some(section)) =
            (line.strip_prefix("a=extmap:"), out.last_mut())
        {
            section.push(value.to_owned());
        }
    }
    for section in &mut out {
        section.sort();
    }
    Ok(out)
}

#[test]
fn a_session_level_extmap_is_every_rtp_sections() -> TestResult {
    let answered = answered_extmaps(
        &format!("a=extmap:3 {MID}\na=extmap:5 {ABS}\n"),
        // The video section has its own mapping of the MID extension.
        &["", &format!("a=extmap:7 {MID}\n")],
    )?;
    assert_eq!(
        answered,
        vec![
            vec![format!("3 {MID}"), format!("5 {ABS}")],
            vec![format!("5 {ABS}"), format!("7 {MID}")],
        ]
    );
    Ok(())
}

/// RFC 8285 section 7: sendonly is answered recvonly, recvonly sendonly, inactive inactive,
/// and an extension offered without a direction is answered without one.
#[test]
fn an_extension_offered_for_one_direction_is_answered_for_the_other() -> TestResult {
    let answered = answered_extmaps(
        "",
        &[
            &format!("a=extmap:3 {MID}\n"),
            &format!(
                "a=extmap:3 {MID}\na=extmap:9/sendonly {RID}\na=extmap:10/recvonly {RRID}\na=extmap:5/inactive {ABS}\n"
            ),
        ],
    )?;
    assert_eq!(
        answered,
        vec![
            vec![format!("3 {MID}")],
            vec![
                format!("10/sendonly {RRID}"),
                format!("3 {MID}"),
                format!("5/inactive {ABS}"),
                format!("9/recvonly {RID}"),
            ],
        ]
    );
    Ok(())
}
