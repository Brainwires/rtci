//! RFC 8834 (media transport and use of RTP in WebRTC) as the default set offers it: the
//! payload types of the default codecs (section 4.3), the header extensions a WebRTC endpoint
//! implements (sections 5.2.4, 5.2.5) and the FEC it indicates (section 6.2, RFC 8854
//! sections 4.2 and 7).

use std::collections::HashMap;
use std::time::Instant;

use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const VIDEO_ORIENTATION: &str = "urn:3gpp:video-orientation";

/// A peer with the default codecs and the default interceptors (and their extensions).
fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

/// The default offer with one audio and one video section, as its media sections' lines.
fn default_offer_sections() -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    let mut sections: Vec<Vec<String>> = vec![];
    for line in offer.sdp.lines() {
        if line.starts_with("m=") {
            sections.push(vec![]);
        }
        if let Some(section) = sections.last_mut() {
            section.push(line.to_owned());
        }
    }
    Ok(sections)
}

fn extmap_uris(section: &[String]) -> Vec<String> {
    section
        .iter()
        .filter_map(|l| l.strip_prefix("a=extmap:"))
        .filter_map(|v| v.split_whitespace().nth(1).map(str::to_owned))
        .collect()
}

/// RFC 8834 section 4.3: "a given payload type ... MUST NOT be assigned to two different
/// formats or configurations within one RTP session". With BUNDLE the audio and video
/// sections are one RTP session, so a payload type of the default offer names one format with
/// one `a=fmtp`, whichever section it is in.
#[test]
fn no_payload_type_of_the_default_offer_names_two_formats() -> TestResult {
    let sections = default_offer_sections()?;
    assert_eq!(2, sections.len());
    let mut formats: HashMap<String, String> = HashMap::new();
    for section in &sections {
        for line in section {
            let Some(rest) = line.strip_prefix("a=rtpmap:") else {
                continue;
            };
            let (pt, encoding) = rest.split_once(' ').expect("an rtpmap");
            let fmtp = section
                .iter()
                .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")))
                .unwrap_or("");
            let format = format!("{encoding} {fmtp}");
            if let Some(previous) = formats.insert(pt.to_owned(), format.clone()) {
                assert_eq!(previous, format, "payload type {pt} names two formats");
            }
        }
    }
    assert!(formats.len() > 10, "{formats:?}");
    Ok(())
}

/// RFC 8834 section 5.2.4: an endpoint implements the RTP MID header extension (RFC 8843),
/// for every kind of media it sends.
#[test]
fn the_default_offer_carries_the_mid_extension_for_audio_and_video() -> TestResult {
    for section in default_offer_sections()? {
        assert!(
            extmap_uris(&section).iter().any(|uri| uri == MID),
            "{section:?}"
        );
    }
    Ok(())
}

/// RFC 8834 section 5.2.5: video endpoints implement the coordination of video orientation
/// (3GPP TS 26.114, `urn:3gpp:video-orientation`). The default video section offers it; audio
/// does not.
#[test]
fn the_default_video_offer_offers_the_coordination_of_video_orientation() -> TestResult {
    let sections = default_offer_sections()?;
    let audio = &sections[0];
    let video = &sections[1];
    assert!(audio[0].starts_with("m=audio"), "{audio:?}");
    assert!(video[0].starts_with("m=video"), "{video:?}");
    assert!(
        extmap_uris(video)
            .iter()
            .any(|uri| uri == VIDEO_ORIENTATION),
        "{video:?}"
    );
    assert!(
        !extmap_uris(audio)
            .iter()
            .any(|uri| uri == VIDEO_ORIENTATION),
        "{audio:?}"
    );
    Ok(())
}

/// RFC 8834 section 6.2 by way of RFC 8854 sections 4.2 and 7: an endpoint indicates that it
/// can receive the FEC of its audio codecs; for Opus that is `useinbandfec=1` (RFC 7587).
#[test]
fn the_default_opus_offer_indicates_in_band_fec() -> TestResult {
    let sections = default_offer_sections()?;
    let audio = &sections[0];
    let opus = audio
        .iter()
        .find_map(|l| {
            let rest = l.strip_prefix("a=rtpmap:")?;
            let (pt, encoding) = rest.split_once(' ')?;
            encoding
                .to_ascii_lowercase()
                .starts_with("opus/")
                .then(|| pt.to_owned())
        })
        .expect("Opus is offered");
    let fmtp = audio
        .iter()
        .find_map(|l| l.strip_prefix(&format!("a=fmtp:{opus} ")))
        .expect("Opus has an fmtp line");
    assert!(
        fmtp.split(';').any(|p| p.trim() == "useinbandfec=1"),
        "{fmtp}"
    );
    Ok(())
}

/// RFC 8834 section 4.3 with RFC 7874 section 3 and RFC 7742 section 5: the payload formats
/// of the mandatory codecs are offered by default: Opus, PCMA, PCMU, comfort noise and
/// telephone events for audio, VP8 and H.264 for video.
#[test]
fn the_default_offer_has_the_mandatory_payload_formats() -> TestResult {
    let sections = default_offer_sections()?;
    let encodings = |section: &[String]| -> Vec<String> {
        section
            .iter()
            .filter_map(|l| l.strip_prefix("a=rtpmap:"))
            .filter_map(|r| r.split_once(' ').map(|(_, e)| e.to_ascii_lowercase()))
            .collect()
    };
    let audio = encodings(&sections[0]);
    for expected in ["opus/48000/2", "pcmu/8000", "pcma/8000", "cn/8000"] {
        assert!(
            audio.iter().any(|e| e == expected),
            "{expected} in {audio:?}"
        );
    }
    assert!(
        audio.iter().any(|e| e.starts_with("telephone-event/")),
        "{audio:?}"
    );
    let video = encodings(&sections[1]);
    for expected in ["vp8/90000", "h264/90000"] {
        assert!(
            video.iter().any(|e| e == expected),
            "{expected} in {video:?}"
        );
    }
    Ok(())
}

/// RFC 3550 section 5.1: the SSRC identifier "SHOULD be chosen randomly"; section 8.1: by a
/// routine that keeps two sources (or one source after a restart) from picking the same
/// value. Peer connections made one after another (each a restart of the application, as far
/// as the identifiers go) give their senders SSRCs that do not repeat and vary in every bit.
#[test]
fn sender_ssrcs_are_random_across_peer_connections() -> TestResult {
    let mut ssrcs = vec![];
    for _ in 0..64 {
        let mut pc = default_peer()?;
        let transceiver = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let sender = pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .ok_or("a sender")?;
        let ssrc = pc
            .rtp_sender(sender)
            .ok_or("sender")?
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .ok_or("an SSRC")?;
        ssrcs.push(ssrc);
    }
    let distinct: std::collections::HashSet<u32> = ssrcs.iter().copied().collect();
    assert_eq!(distinct.len(), ssrcs.len(), "no repeats: {ssrcs:?}");
    let (any, all) = ssrcs
        .iter()
        .fold((0u32, u32::MAX), |(any, all), s| (any | s, all & s));
    assert_eq!((any, all), (u32::MAX, 0), "every bit varies");
    Ok(())
}
