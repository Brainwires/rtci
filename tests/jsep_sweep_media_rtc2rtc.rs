//! Rows of the sweep (jsep12) that need media between two connected `rtc` peers in virtual
//! time: what the sender puts on the wire follows the negotiated formats of its own section
//! (RFC 3264 sections 8.3.2, 8.3.4; RFC 9143 section 9.1).

mod dtls_sdp_common;

use anyhow::Result;
use bytes::Bytes;
use dtls_sdp_common::{Peer, World};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use std::time::Duration;

const SSRC: u32 = 0x5e20_0101;

fn video_track() -> MediaStreamTrack {
    MediaStreamTrack::new(
        "s".to_owned(),
        "v".to_owned(),
        "v".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SSRC),
                ..Default::default()
            },
            // No codec of its own: the sender sends with what negotiation picks.
            ..Default::default()
        }],
    )
}

/// The payload type of the first `a=rtpmap` of `encoding` (e.g. `VP8/90000`) in `sdp`.
fn payload_type(sdp: &str, encoding: &str) -> u8 {
    sdp.lines()
        .find_map(|l| {
            let rest = l.strip_prefix("a=rtpmap:")?;
            let (pt, name) = rest.split_once(' ')?;
            name.eq_ignore_ascii_case(encoding)
                .then(|| pt.parse().ok())?
        })
        .unwrap_or_else(|| panic!("no {encoding} in {sdp}"))
}

/// `sdp` without the format `pt` and the RTX formats that repair it: the m= line, rtpmap,
/// fmtp and rtcp-fb lines.
fn without_format(sdp: &str, pt: u8) -> String {
    let mut gone = vec![pt.to_string()];
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("a=fmtp:")
            && let Some((rtx, params)) = rest.split_once(' ')
            && params.split(';').any(|p| p.trim() == format!("apt={pt}"))
        {
            gone.push(rtx.to_owned());
        }
    }
    let mut out = String::new();
    for line in sdp.split("\r\n").filter(|l| !l.is_empty()) {
        if line.starts_with("m=video") {
            let kept: Vec<&str> = line
                .split(' ')
                .enumerate()
                .filter(|(i, f)| *i < 3 || !gone.iter().any(|g| g == f))
                .map(|(_, f)| f)
                .collect();
            out += &kept.join(" ");
        } else if ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"].iter().any(|prefix| {
            line.strip_prefix(prefix)
                .is_some_and(|rest| gone.iter().any(|g| rest.starts_with(&format!("{g} "))))
        }) {
            continue;
        } else {
            out += line;
        }
        out += "\r\n";
    }
    out
}

/// Writes `packets` RTP packets with sequence numbers from `first` (SRTP's replay window
/// drops a number it has seen).
fn write(
    world: &mut World,
    sender: RTCRtpSenderId,
    payload_type: u8,
    first: u16,
    packets: u16,
) -> Result<()> {
    for n in 0..packets {
        let now = world.now;
        let mut s = world.peers[0].pc.rtp_sender(sender).expect("the sender");
        s.write_rtp(
            now,
            rtc::rtp::Packet {
                header: rtc::rtp::header::Header {
                    version: 2,
                    payload_type,
                    sequence_number: first + n,
                    timestamp: u32::from(first + n) * 3000,
                    ssrc: SSRC,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from(vec![0x10u8; 100]),
            },
        )?;
        world.run_for(Duration::from_millis(20), |_| false);
    }
    world.run_for(Duration::from_millis(200), |_| false);
    Ok(())
}

/// RFC 9143 section 9.1: an SSRC "MUST NOT" be used with payload types of another bundled
/// section: a packet the application writes on the video sender with the audio section's
/// payload type goes out with the video one. RFC 3264 sections 8.3.2 and 8.3.4: once a later
/// answer no longer lists the format the sender used, the sender switches to one the new
/// answer lists, as soon as that answer is applied; the old one is not sent.
#[test]
fn the_sender_uses_its_sections_formats_and_follows_a_new_answer() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let sender = world.peers[0].pc.add_track(video_track())?;
    let (offer, _) = world.connect()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let opus = payload_type(&offer, "opus/48000/2");

    write(&mut world, sender, vp8, 100, 5)?;
    write(&mut world, sender, opus, 200, 5)?;
    let received: Vec<u8> = world.peers[1]
        .rtp
        .iter()
        .filter(|(_, ssrc)| *ssrc == SSRC)
        .map(|(pt, _)| *pt)
        .collect();
    assert!(received.len() >= 8, "{received:?}");
    assert!(received.iter().all(|pt| *pt == vp8), "{received:?}");

    // A later answer without VP8.
    let (_, answer) = world.exchange_with(
        0,
        |offer| offer.to_owned(),
        |answer| without_format(answer, vp8),
    )?;
    assert!(
        answer.contains(&format!("a=rtpmap:{vp8} VP8")),
        "the answerer's own still has it"
    );
    world.peers[1].rtp.clear();
    let _ = write(&mut world, sender, vp8, 300, 5);
    let received: Vec<u8> = world.peers[1]
        .rtp
        .iter()
        .filter(|(_, ssrc)| *ssrc == SSRC)
        .map(|(pt, _)| *pt)
        .collect();
    let listed = without_format(&answer, vp8);
    assert!(
        received.len() >= 4,
        "sent after the new answer: {received:?}"
    );
    for pt in &received {
        assert_ne!(*pt, vp8, "{received:?}");
        assert!(
            listed.contains(&format!("a=rtpmap:{pt} ")),
            "{pt} is not in {listed}"
        );
    }
    Ok(())
}
