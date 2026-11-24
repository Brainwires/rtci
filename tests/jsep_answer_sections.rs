//! What an answer says about each offered m= section (RFC 9429 section 5.3.1, RFC 3264
//! section 6, RFC 9143 section 7.3): the BUNDLE group is the offered BUNDLE group whatever
//! other groups the offer lists, an offer without one is answered without one, the offered
//! profile is repeated, a section with no direction attribute is sendrecv, and
//! `a=bundle-only` means something only inside the group.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, mid_of, port_of,
    video_track,
};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::RTCRtpTransceiverDirection;

fn audio(mid: &str, proto: &str, extra: &str) -> String {
    format!(
        "m=audio 9 {proto} 111
{TRANSPORT}a=mid:{mid}
a=rtpmap:111 opus/48000/2
{extra}"
    )
}

fn video(mid: &str, port: u16, extra: &str) -> String {
    format!(
        "m=video {port} UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:{mid}
a=rtpmap:96 VP8/90000
{extra}"
    )
}

/// The answer `pc` gives to `offer` (session lines and media sections, LF line endings).
fn answer_to(
    pc: &mut RTCPeerConnection,
    offer: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(offer))?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

fn groups(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|l| l.starts_with("a=group:")).collect()
}

fn direction_of(section: &[String]) -> &str {
    section
        .iter()
        .map(String::as_str)
        .find(|l| {
            matches!(
                *l,
                "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive"
            )
        })
        .unwrap_or_else(|| panic!("a direction in {section:?}"))
}

#[test]
fn a_group_of_other_semantics_before_the_bundle_group_rejects_nothing() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:LS 0 1
a=group:BUNDLE 0 1 2
{}{}{}",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n"),
        video("1", 9, "a=sendrecv\n"),
        video("2", 9, "a=sendrecv\n"),
    );
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    assert_eq!(sections.len(), 3, "{answer}");
    for section in &sections {
        assert_ne!(port_of(section), 0, "{answer}");
    }
    // RFC 9429 section 5.3.1: the LS group is answered too, the answerer's transceivers
    // having no stream to reference.
    assert_eq!(
        groups(&answer),
        vec!["a=group:BUNDLE 0 1 2", "a=group:LS 0 1"],
        "{answer}"
    );
    Ok(())
}

#[test]
fn an_offer_without_a_bundle_group_is_answered_without_one_and_accepted() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}{}",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n")
    );
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    assert_ne!(port_of(&sections[0]), 0, "{answer}");
    assert!(groups(&answer).is_empty(), "{answer}");
    Ok(())
}

#[test]
fn the_answers_group_keeps_the_offers_tag_order() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:BUNDLE 1 0
{}{}",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n"),
        video("1", 9, "a=sendrecv\n"),
    );
    let answer = answer_to(&mut pc, &offer)?;
    // RFC 9143 section 7.3.1: the offerer-tagged section, accepted, is the answerer-tagged one.
    assert_eq!(groups(&answer), vec!["a=group:BUNDLE 1 0"], "{answer}");
    Ok(())
}

#[test]
fn a_bundle_only_section_of_the_group_is_answered_with_a_port() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0 1
{}{}",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n"),
        video("1", 0, "a=sendrecv\na=bundle-only\n"),
    );
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    assert_ne!(port_of(&sections[1]), 0, "{answer}");
    assert!(!answer.contains("a=bundle-only"), "{answer}");
    assert_eq!(groups(&answer), vec!["a=group:BUNDLE 0 1"], "{answer}");
    Ok(())
}

/// RFC 9143 section 6: `a=bundle-only` in a section that is in no BUNDLE group is discarded,
/// which leaves a section with port zero: rejected (RFC 3264 section 6).
#[test]
fn a_bundle_only_attribute_outside_the_group_is_discarded() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0
{}{}",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n"),
        video("1", 0, "a=sendrecv\na=bundle-only\n"),
    );
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(&offer))?)?;
    let ids: Vec<usize> = pc.get_transceivers().collect();
    let video_transceiver = ids
        .into_iter()
        .find(|&id| pc_mid(&mut pc, id).as_deref() == Some("1"))
        .expect("the rejected section has a transceiver");
    assert!(
        pc.rtp_transceiver(video_transceiver)
            .expect("transceiver")
            .stopped(),
        "a rejected section's transceiver is stopped"
    );
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(port_of(&sections[1]), 0, "{}", answer.sdp);
    assert_eq!(
        groups(&answer.sdp),
        vec!["a=group:BUNDLE 0"],
        "{}",
        answer.sdp
    );
    Ok(())
}

fn pc_mid(pc: &mut RTCPeerConnection, id: usize) -> Option<String> {
    pc.rtp_transceiver(id).and_then(|t| t.mid().clone())
}

/// RFC 9429 section 5.1.2: each of the eight profiles is accepted, and "the profile in any
/// 'm=' line in any generated answer MUST exactly match the profile provided in the offer".
#[test]
fn an_answer_repeats_the_offered_profile() -> TestResult {
    for proto in [
        "RTP/AVP",
        "RTP/AVPF",
        "RTP/SAVP",
        "RTP/SAVPF",
        "TCP/DTLS/RTP/SAVP",
        "TCP/DTLS/RTP/SAVPF",
        "UDP/TLS/RTP/SAVP",
        "UDP/TLS/RTP/SAVPF",
    ] {
        let mut pc = default_peer()?;
        let offer = format!(
            "{SESSION}a=group:BUNDLE 0 1 2
{}m=video 0 {proto} 96
c=IN IP4 0.0.0.0
a=mid:1
m=application 9 TCP/DTLS/SCTP webrtc-datachannel
{TRANSPORT}a=mid:2
a=sctp-port:5000
",
            audio("0", proto, "a=sendrecv\n"),
        );
        let answer = answer_to(&mut pc, &offer)?;
        let sections = media_sections(&answer);
        // The offered format first; formats the offer lacked may follow (RFC 9429 5.3.1).
        assert!(
            sections[0][0].starts_with(&format!("m=audio 9 {proto} 111")),
            "{answer}"
        );
        // A rejected section keeps the profile too.
        assert!(
            sections[1][0].starts_with(&format!("m=video 0 {proto} ")),
            "{answer}"
        );
        assert_eq!(
            sections[2][0], "m=application 9 TCP/DTLS/SCTP webrtc-datachannel",
            "{answer}"
        );

        // A later offer of this endpoint states its own profiles again.
        let offer = pc.create_offer(None)?;
        let sections = media_sections(&offer.sdp);
        assert!(
            sections[0][0].starts_with("m=audio 9 UDP/TLS/RTP/SAVPF "),
            "{}",
            offer.sdp
        );
        assert!(
            sections[2][0].starts_with("m=application 9 UDP/DTLS/SCTP "),
            "{}",
            offer.sdp
        );
    }
    Ok(())
}

#[test]
fn an_audio_section_of_another_profile_is_rejected_as_offered() -> TestResult {
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0 1
{}m=audio 9 udptl 0
{TRANSPORT}a=mid:1
",
        audio("0", "UDP/TLS/RTP/SAVPF", "a=sendrecv\n"),
    );
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    assert_ne!(port_of(&sections[0]), 0, "{answer}");
    assert_eq!(sections[1][0], "m=audio 0 udptl 0", "{answer}");
    assert_eq!(groups(&answer), vec!["a=group:BUNDLE 0"], "{answer}");
    Ok(())
}

/// RFC 8866 section 6.7 / RFC 3264 section 6.1: no direction attribute is sendrecv.
#[test]
fn a_section_without_a_direction_attribute_is_sendrecv() -> TestResult {
    // With a track to send, the answer is sendrecv.
    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0101_0101))?;
    let offer = format!("{SESSION}a=group:BUNDLE 0\n{}", video("0", 9, ""));
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    assert_eq!(mid_of(&sections[0]), Some("0"));
    assert_ne!(port_of(&sections[0]), 0, "{answer}");
    assert_eq!(direction_of(&sections[0]), "a=sendrecv", "{answer}");

    // With none, it is recvonly: the offerer sends.
    let mut pc = default_peer()?;
    let answer = answer_to(&mut pc, &offer)?;
    assert_eq!(
        direction_of(&media_sections(&answer)[0]),
        "a=recvonly",
        "{answer}"
    );
    Ok(())
}

/// A direction at session level is every section's that has none of its own (RFC 8866
/// section 6.7; Firefox writes `a=sendrecv` there).
#[test]
fn a_session_level_direction_is_the_sections_that_have_none() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0202_0202))?;
    let offer = format!(
        "{SESSION}a=recvonly
a=group:BUNDLE 0 1
{}{}",
        video("0", 9, ""),
        video("1", 9, "a=sendonly\n"),
    );
    let answer = answer_to(&mut pc, &offer)?;
    let sections = media_sections(&answer);
    // Offered recvonly (the session's): this endpoint may only send.
    assert_eq!(direction_of(&sections[0]), "a=sendonly", "{answer}");
    // Offered sendonly (its own): this endpoint may only receive.
    assert_eq!(direction_of(&sections[1]), "a=recvonly", "{answer}");
    Ok(())
}

/// W3C webrtc-pc "set a session description": the transceiver made for a remote m= section
/// has direction recvonly, whatever was offered. A section offered recvonly is then answered
/// inactive until the application gives the transceiver a track.
#[test]
fn the_transceiver_created_for_a_remote_section_is_recvonly() -> TestResult {
    for offered in ["sendrecv", "sendonly", "recvonly", "inactive"] {
        let mut pc = default_peer()?;
        let offer = format!(
            "{SESSION}a=group:BUNDLE 0\n{}",
            video("0", 9, &format!("a={offered}\n"))
        );
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(&offer))?)?;
        let id = pc.get_transceivers().next().expect("transceiver");
        assert_eq!(
            pc.rtp_transceiver(id).expect("transceiver").direction(),
            RTCRtpTransceiverDirection::Recvonly,
            "offered {offered}"
        );
        let answer = pc.create_answer(None)?;
        let expected = match offered {
            "sendrecv" | "sendonly" => "a=recvonly",
            _ => "a=inactive",
        };
        assert_eq!(
            direction_of(&media_sections(&answer.sdp)[0]),
            expected,
            "offered {offered}:\n{}",
            answer.sdp
        );
    }

    // With a track added after the offer, a section offered recvonly is answered sendonly.
    let mut pc = default_peer()?;
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0\n{}",
        video("0", 9, "a=recvonly\n")
    );
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(&offer))?)?;
    pc.add_track(video_track("later", 0x0303_0303))?;
    assert_eq!(pc.get_transceivers().count(), 1, "addTrack reuses it");
    let answer = pc.create_answer(None)?;
    assert_eq!(
        direction_of(&media_sections(&answer.sdp)[0]),
        "a=sendonly",
        "{}",
        answer.sdp
    );
    Ok(())
}

/// RFC 4585 section 4.2: "The answerer MUST NOT add feedback parameters to the media
/// description": a renegotiation whose offer no longer has a feedback type is answered
/// without it, though the first exchange negotiated it.
#[test]
fn a_feedback_type_a_later_offer_drops_is_not_answered() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(jsep_common::video_track("camera", 0x0b0b_0b0b))?;
    let (_, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert!(answer.contains(" nack pli\r\n"), "{answer}");

    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let without_pli: String = offer
        .sdp
        .split_inclusive("\r\n")
        .filter(|line| !line.ends_with(" nack pli\r\n"))
        .collect();
    answerer.set_remote_description(now, RTCSessionDescription::offer(without_pli)?)?;
    let answer = answerer.create_answer(None)?;
    assert!(!answer.sdp.contains(" nack pli\r\n"), "{}", answer.sdp);
    assert!(
        answer.sdp.contains(" nack\r\n"),
        "the rest stays: {}",
        answer.sdp
    );
    Ok(())
}

/// RFC 5124 section 3.3.1: an offerer "SHOULD NOT" offer a secure and an insecure profile as
/// alternatives for the same media, and section 5: security is not left to such a mix. Every
/// audio and video section of this endpoint's offers (the first, and a later one with one more
/// section) is `UDP/TLS/RTP/SAVPF`: no `RTP/AVP` or `RTP/AVPF` alternative is ever written.
#[test]
fn offers_never_carry_an_insecure_profile_beside_the_secure_one() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("v", 4242))?;
    pc.add_transceiver_from_kind(rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Audio, None)?;
    pc.create_data_channel("d", None)?;
    let first = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), first.clone())?;
    pc.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    pc.add_transceiver_from_kind(rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Video, None)?;
    let later = pc.create_offer(None)?;
    for offer in [&first.sdp, &later.sdp] {
        let mut rtp = 0;
        for section in media_sections(offer) {
            let m = &section[0];
            if m.starts_with("m=audio") || m.starts_with("m=video") {
                rtp += 1;
                assert_eq!(m.split(' ').nth(2), Some("UDP/TLS/RTP/SAVPF"), "{offer}");
            }
        }
        assert!(rtp >= 2, "{offer}");
        for insecure in [" RTP/AVP ", " RTP/AVPF "] {
            assert!(!offer.contains(insecure), "{insecure} in {offer}");
        }
    }
    Ok(())
}
