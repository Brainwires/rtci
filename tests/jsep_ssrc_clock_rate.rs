//! RFC 9429 section 5.11: "If media is already being transmitted, the same SSRC SHOULD be used
//! unless the clock rate of the new codec is different, in which case a new SSRC MUST be
//! chosen, as specified in [RFC7160], Section 4.1."

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::SSRC;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

const FIRST_SSRC: SSRC = 0x1234_5678;

/// A remote offer of one sendrecv audio section with these formats.
fn audio_offer(version: u32, formats: &str, rtpmaps: &str) -> String {
    crlf(&format!(
        "{}m=audio 9 UDP/TLS/RTP/SAVPF {formats}\n{TRANSPORT}a=mid:0\na=sendrecv\n{rtpmaps}",
        SESSION.replace(" 2 IN IP4", &format!(" {version} IN IP4"))
    ))
}

fn answer_offer(
    pc: &mut RTCPeerConnection,
    offer: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    Ok(answer.sdp)
}

fn sender_ssrc(pc: &mut RTCPeerConnection) -> SSRC {
    let ids: Vec<_> = pc.get_senders().collect();
    let mut sender = pc.rtp_sender(ids[0]).expect("sender");
    sender.get_parameters().encodings[0]
        .rtp_coding_parameters
        .ssrc
        .expect("an SSRC")
}

/// An audio stream sent with Opus (48 kHz) keeps its SSRC through a renegotiation that keeps
/// a 48 kHz codec, and gets a new one when the remote side leaves only PCMU (8 kHz); the
/// answer after that describes the new SSRC with `previous-ssrc`.
#[test]
fn a_new_codec_with_another_clock_rate_gets_a_new_ssrc() -> TestResult {
    let mut pc = default_peer()?;
    let track = MediaStreamTrack::new(
        "stream".to_owned(),
        "audio".to_owned(),
        "audio".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(FIRST_SSRC),
                ..Default::default()
            },
            ..Default::default()
        }],
    );
    pc.add_track(track)?;
    let opus_and_pcmu = "a=rtpmap:111 opus/48000/2\na=rtpmap:0 PCMU/8000\n";
    let answer = answer_offer(&mut pc, audio_offer(2, "111 0", opus_and_pcmu))?;
    assert!(
        answer.contains(&format!("a=ssrc:{FIRST_SSRC} ")),
        "{answer}"
    );
    assert_eq!(FIRST_SSRC, sender_ssrc(&mut pc));

    // Same codec again: the SSRC stays.
    answer_offer(&mut pc, audio_offer(3, "111 0", opus_and_pcmu))?;
    assert_eq!(
        FIRST_SSRC,
        sender_ssrc(&mut pc),
        "same clock rate, same SSRC"
    );

    // Only PCMU: 8000 Hz instead of 48000 Hz.
    answer_offer(&mut pc, audio_offer(4, "0", "a=rtpmap:0 PCMU/8000\n"))?;
    let moved = sender_ssrc(&mut pc);
    assert_ne!(FIRST_SSRC, moved, "a new clock rate needs a new SSRC");

    let answer = answer_offer(&mut pc, audio_offer(5, "0", "a=rtpmap:0 PCMU/8000\n"))?;
    assert!(
        answer.contains(&format!("a=ssrc:{moved} previous-ssrc:{FIRST_SSRC}\r\n")),
        "{answer}"
    );
    assert!(
        !answer.contains(&format!("a=ssrc:{FIRST_SSRC} ")),
        "{answer}"
    );
    Ok(())
}
