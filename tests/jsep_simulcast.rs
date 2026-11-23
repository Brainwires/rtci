//! Simulcast (RFC 8853) and RTP stream identifiers (RFC 8851) in offers and answers: what is
//! written, what an answer may say, and what an applied answer leaves of a sender's
//! encodings (W3C webrtc-pc "set a session description").

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, vp8};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRidRestrictions, RtpCodecKind,
};
use rtc::shared::error::Error;

/// A track with one VP8 encoding per `(rid, max-width)`.
fn simulcast_track(layers: &[(&str, Option<u64>)]) -> MediaStreamTrack {
    let encodings = layers
        .iter()
        .enumerate()
        .map(|(i, (rid, max_width))| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ssrc: Some(0x0515_0000 + i as u32),
                rid_restrictions: RTCRtpRidRestrictions {
                    max_width: *max_width,
                    ..Default::default()
                },
                ..Default::default()
            },
            codec: vp8(),
            active: true,
            ..Default::default()
        })
        .collect();
    MediaStreamTrack::new(
        "simulcast-stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    )
}

/// A default peer sending `layers` as simulcast.
fn simulcast_sender(
    layers: &[(&str, Option<u64>)],
) -> Result<(RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    let sender = pc.add_track(simulcast_track(layers))?;
    Ok((pc, sender))
}

/// The rids of the sender's encodings, with their max-width, as `getParameters` gives them.
fn sent_layers(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> Vec<(String, Option<u64>)> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings
        .iter()
        .map(|e| {
            (
                e.rtp_coding_parameters.rid.clone(),
                e.rtp_coding_parameters.rid_restrictions.max_width,
            )
        })
        .collect()
}

fn layers(expected: &[(&str, Option<u64>)]) -> Vec<(String, Option<u64>)> {
    expected
        .iter()
        .map(|(rid, width)| ((*rid).to_owned(), *width))
        .collect()
}

/// A remote offer of one VP8 video section, `direction`, with `extra` lines (rids, simulcast).
fn remote_offer(direction: &str, extra: &str) -> Result<RTCSessionDescription, Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=msid:remote-stream remote-track
a={direction}
a=rtpmap:96 VP8/90000
{extra}"
    )))
}

/// The lines of `sdp` that start with `prefix`.
fn lines_with<'a>(sdp: &'a str, prefix: &str) -> Vec<&'a str> {
    sdp.lines().filter(|l| l.starts_with(prefix)).collect()
}

/// `sdp` with `from` replaced by `to`, which must occur in it.
fn edited(sdp: &str, from: &str, to: &str) -> String {
    assert!(sdp.contains(from), "`{from}` is not in\n{sdp}");
    sdp.replace(from, to)
}

/// RFC 8851 section 5 / 6.3: the restrictions an application gives its encodings are written
/// on the offer's `a=rid ... send` lines, the answerer echoes them on its `recv` lines, and the
/// answerer's receiver exposes them.
#[test]
fn rid_restrictions_are_offered_echoed_and_exposed_on_the_receiver() -> TestResult {
    let (mut offerer, _) = simulcast_sender(&[("f", Some(1280)), ("h", Some(640))])?;
    let mut answerer = default_peer()?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;

    assert_eq!(
        lines_with(&offer, "a=rid:"),
        vec!["a=rid:f send max-width=1280", "a=rid:h send max-width=640"],
        "{offer}"
    );
    assert_eq!(
        lines_with(&answer, "a=rid:"),
        vec!["a=rid:f recv max-width=1280", "a=rid:h recv max-width=640"],
        "{answer}"
    );
    assert_eq!(
        lines_with(&answer, "a=simulcast:"),
        vec!["a=simulcast:recv f;h"]
    );

    let receiver = answerer.get_receivers().next().expect("a receiver");
    let receiver = answerer.rtp_receiver(receiver).expect("receiver");
    let exposed: Vec<(String, Option<u64>)> = receiver
        .track()
        .codings()
        .iter()
        .map(|c| {
            (
                c.rtp_coding_parameters.rid.clone(),
                c.rtp_coding_parameters.rid_restrictions.max_width,
            )
        })
        .collect();
    assert_eq!(exposed, layers(&[("f", Some(1280)), ("h", Some(640))]));
    Ok(())
}

/// RFC 8853 section 5.3.2: "The answerer MUST NOT add any simulcast streams": an answer to
/// `a=simulcast:recv f;x` from a sender of f, h, q lists f only, and W3C webrtc-pc leaves the
/// sender the encodings the answer kept.
#[test]
fn an_answer_sends_only_the_offered_rids_the_sender_has() -> TestResult {
    let (mut pc, sender) = simulcast_sender(&[("f", None), ("h", None), ("q", None)])?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:x recv\na=simulcast:recv f;x\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:f send"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send f"]
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", None)]));
    Ok(())
}

/// RFC 8853 section 5.3.2: an offer that asks for no simulcast gets an answer without
/// `a=simulcast` or `a=rid`, and the sender keeps its first encoding only (W3C webrtc-pc:
/// "If description indicates that simulcast is not supported or desired ... remove all
/// dictionaries ... except the first one").
#[test]
fn an_offer_without_simulcast_is_answered_with_the_first_encoding_only() -> TestResult {
    let (mut pc, sender) = simulcast_sender(&[("f", None), ("h", None)])?;
    let now = Instant::now();
    pc.set_remote_description(now, remote_offer("recvonly", "")?)?;
    let answer = pc.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=rid:").is_empty(),
        "{}",
        answer.sdp
    );
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", None)]));
    Ok(())
}

/// An offerer whose simulcast offer of f, h, q was answered by a default peer, with the answer
/// left unapplied for the test to edit.
fn offered_three_layers()
-> Result<(RTCPeerConnection, RTCRtpSenderId, String), Box<dyn std::error::Error>> {
    let (mut offerer, sender) =
        simulcast_sender(&[("f", Some(1280)), ("h", Some(640)), ("q", Some(320))])?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    Ok((offerer, sender, answer.sdp.replace("\r\n", "\n")))
}

/// RFC 8853 section 5.3.3 and W3C webrtc-pc "set a session description": a remote answer that
/// accepts two of three offered streams leaves the sender those two, and the next offer lists
/// only them.
#[test]
fn a_remote_answer_that_accepts_two_of_three_streams_removes_the_third() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(&answer, "a=rid:q recv max-width=320\n", "");
    let answer = edited(&answer, "a=simulcast:recv f;h;q", "a=simulcast:recv f;h");
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;

    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", Some(1280)), ("h", Some(640))])
    );
    let next = pc.create_offer(None)?;
    assert_eq!(
        lines_with(&next.sdp, "a=simulcast:"),
        vec!["a=simulcast:send f;h"],
        "{}",
        next.sdp
    );
    Ok(())
}

/// W3C webrtc-pc "set a session description": an answer without simulcast leaves the first
/// encoding.
#[test]
fn a_remote_answer_without_simulcast_leaves_the_first_encoding() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer: String = answer
        .lines()
        .filter(|l| !l.starts_with("a=rid:") && !l.starts_with("a=simulcast:"))
        .map(|l| format!("{l}\n"))
        .collect();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", Some(1280))]));
    Ok(())
}

/// RFC 8851 section 6.4: an answered `a=rid` line may tighten a restriction (the encoding
/// takes the tighter one) but one that loosens it, or adds a `pt=` the offer did not have, is
/// discarded and its stream goes.
#[test]
fn an_answered_rid_may_tighten_but_not_loosen_the_offer() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(
        &answer,
        "a=rid:f recv max-width=1280",
        "a=rid:f recv max-width=960",
    );
    let answer = edited(
        &answer,
        "a=rid:h recv max-width=640",
        "a=rid:h recv max-width=1920",
    );
    let answer = edited(
        &answer,
        "a=rid:q recv max-width=320",
        "a=rid:q recv pt=96;max-width=320",
    );
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", Some(960))]));
    Ok(())
}

/// RFC 8851 section 8: the rid restrictions "impose additional restrictions beyond those
/// communicated in other techniques": an encoding is sent under the smaller of its answered
/// rid limits and the answer's VP8 `max-fr` / `max-fs` and `b=TIAS`.
#[test]
fn an_encoding_is_sent_under_the_tighter_of_its_rid_format_and_bandwidth_limits() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(
        &answer,
        "a=rtpmap:96 VP8/90000\n",
        "a=rtpmap:96 VP8/90000\na=fmtp:96 max-fr=15;max-fs=3600\n",
    );
    let at = answer.find("m=video").expect("a video section");
    let c_line = at + answer[at..].find("c=IN IP4 0.0.0.0\n").expect("a c= line");
    let answer = format!(
        "{}c=IN IP4 0.0.0.0\nb=TIAS:800000\n{}",
        &answer[..c_line],
        &answer[c_line + "c=IN IP4 0.0.0.0\n".len()..]
    );
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    let mut rtp_sender = pc.rtp_sender(sender).expect("sender");
    let f = rtp_sender.send_restrictions("f").expect("encoding f");
    assert_eq!(f.max_width, Some(1280), "the rid's width is the tighter");
    assert_eq!(f.max_height, Some(2704), "int(sqrt(3600 * 8)) macroblocks");
    assert_eq!(f.max_fps, Some(15), "VP8 max-fr");
    assert_eq!(f.max_fs, Some(3600 * 256), "VP8 max-fs in pixels");
    assert_eq!(f.max_br, Some(800_000), "b=TIAS");
    let q = rtp_sender.send_restrictions("q").expect("encoding q");
    assert_eq!(q.max_width, Some(320));
    assert!(rtp_sender.send_restrictions("x").is_none());
    Ok(())
}

/// RFC 8853 section 5.2 / 5.3.2: the pause mark `~` needs RFC 7728, which the engine does not
/// negotiate: by default it is not repeated in an answer, with `with_rid_pause_marks(true)` it
/// is.
#[test]
fn an_offered_pause_mark_is_answered_only_when_pause_marks_are_written() -> TestResult {
    for rid_pause_marks in [false, true] {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_rid_pause_marks(rid_pause_marks)
                    .build(),
            )
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        pc.add_track(simulcast_track(&[("f", None), ("h", None)]))?;
        pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "recvonly",
                "a=rid:f recv\na=rid:h recv\na=simulcast:recv f;~h\n",
            )?,
        )?;
        let answer = pc.create_answer(None)?;
        let expected = if rid_pause_marks {
            "a=simulcast:send f;~h"
        } else {
            "a=simulcast:send f;h"
        };
        assert_eq!(
            lines_with(&answer.sdp, "a=simulcast:"),
            vec![expected],
            "pause marks {rid_pause_marks}:\n{}",
            answer.sdp
        );
    }
    Ok(())
}

/// RFC 8851 section 6.2.2 step 2: a rid-id on two `a=rid` lines discards both, so the answer
/// sends only the other stream.
#[test]
fn a_rid_id_offered_twice_is_not_answered() -> TestResult {
    let (mut pc, _) = simulcast_sender(&[("f", None), ("h", None)])?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:f recv max-width=640\na=rid:h recv\na=simulcast:recv f;h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(lines_with(&answer.sdp, "a=rid:"), vec!["a=rid:h send"]);
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send h"]
    );
    Ok(())
}

/// RFC 8853 section 5.3.2: an offer with more than one `a=simulcast` line in a section is
/// answered without simulcast.
#[test]
fn several_simulcast_lines_are_answered_without_simulcast() -> TestResult {
    let (mut pc, _) = simulcast_sender(&[("f", None), ("h", None)])?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:h recv\na=simulcast:recv f\na=simulcast:recv h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "{}",
        answer.sdp
    );
    Ok(())
}

/// RFC 9429 section 5.8.3: "All rid-ids referenced in an 'a=simulcast' line MUST exist as
/// 'a=rid' lines": a description that names one without its line is refused.
#[test]
fn a_simulcast_rid_without_its_rid_line_refuses_the_description() -> TestResult {
    let mut pc = default_peer()?;
    let result = pc.set_remote_description(
        Instant::now(),
        remote_offer("sendonly", "a=rid:f send\na=simulcast:send f;z\n")?,
    );
    assert!(
        matches!(result, Err(Error::SdpInvalidValue(ref reason)) if reason.contains("rid z")),
        "{result:?}"
    );
    Ok(())
}

/// RFC 8853 section 5.2: "a single rid-id MUST NOT occur more than once per 'a=simulcast'
/// line", and "each direction MUST NOT occur more than once"; RFC 9429 section 5.8: a line that
/// is not well formed rejects the whole description (the line used to be ignored).
#[test]
fn a_simulcast_line_that_repeats_a_rid_or_a_direction_refuses_the_description() -> TestResult {
    for line in [
        "a=simulcast:send f;f",
        "a=simulcast:send f,h;h",
        "a=simulcast:send f send h",
    ] {
        let mut pc = default_peer()?;
        let result = pc.set_remote_description(
            Instant::now(),
            remote_offer("sendonly", &format!("a=rid:f send\na=rid:h send\n{line}\n"))?,
        );
        assert!(
            matches!(result, Err(Error::SdpInvalidValue(ref reason)) if reason.contains("a=simulcast")),
            "{line}: {result:?}"
        );
    }
    Ok(())
}

/// W3C webrtc-pc addTransceiver: a rid outside the grammar is refused. The rid is sent as the
/// RtpStreamId of RFC 8852, which section 3.1 limits to 1 to 255 alphanumeric characters.
#[test]
fn a_rid_that_is_not_alphanumeric_is_refused() -> TestResult {
    for rid in ["a-b", "a_b", "é", &"a".repeat(256)] {
        let mut pc = default_peer()?;
        let result = pc.add_track(simulcast_track(&[("f", None), (rid, None)]));
        assert!(
            matches!(result, Err(Error::ErrRTPSenderRidInvalid)),
            "rid {rid:?}: {result:?}"
        );
    }
    let mut pc = default_peer()?;
    pc.add_track(simulcast_track(&[("f", None), (&"a".repeat(255), None)]))?;
    Ok(())
}

/// RFC 8851 section 6.1: "any payload type listed in 'pt=' MUST be one of the formats of the
/// m= line": an encoding's `payload_types` keeps in the offer only the ones the section has,
/// and the offerer's answer to an offer `~` it does not support is not applied as a pause
/// (RFC 8853 section 5.3.3: no initial pause without RFC 7728).
#[test]
fn a_pt_restriction_keeps_the_formats_of_the_section_and_an_answered_pause_mark_is_ignored()
-> TestResult {
    let mut track = simulcast_track(&[("f", None), ("h", None)]);
    let mut encodings = track.codings().to_vec();
    encodings[0]
        .rtp_coding_parameters
        .rid_restrictions
        .payload_types = vec![96, 0];
    track = MediaStreamTrack::new(
        "simulcast-stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    );
    let mut offerer = default_peer()?;
    let sender = offerer.add_track(track)?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    assert_eq!(
        lines_with(&offer.sdp, "a=rid:"),
        vec!["a=rid:f send pt=96", "a=rid:h send"],
        "{}",
        offer.sdp
    );
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    let answer = edited(
        &answer.sdp.replace("\r\n", "\n"),
        "a=simulcast:recv f;h",
        "a=simulcast:recv f;~h",
    );
    offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&answer))?)?;
    let s = offerer.rtp_sender(sender);
    let mut s = s.expect("sender");
    let encodings = &s.get_parameters().encodings;
    assert_eq!(encodings.len(), 2);
    assert!(encodings.iter().all(|e| e.active), "no encoding is paused");
    Ok(())
}

fn w3c_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_w3c_simulcast_answer(true)
                .build(),
        )
        .build(Instant::now())?)
}

/// W3C webrtc-pc row 4.4.2-39, the W3C form as a setting: with `with_w3c_simulcast_answer` a
/// remote `a=simulcast` line that names a rid twice is taken with the rid at its first place
/// (by default it refuses the description: RFC 8853 section 5.2), and the answer's `a=rid`
/// lines carry no restrictions (by default they keep the offered ones: RFC 8851 section 6.3).
#[test]
fn the_w3c_answer_form_reduces_a_repeated_rid_and_sets_no_restrictions() -> TestResult {
    let mut pc = w3c_peer()?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "sendonly",
            "a=rid:f send max-width=1280\na=rid:h send max-width=640\na=simulcast:send f;h;f\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:recv f;h"]
    );

    // The default, for contrast: the same offer is refused, and restrictions are echoed.
    let mut pc = default_peer()?;
    assert!(
        pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "sendonly",
                "a=rid:f send\na=rid:h send\na=simulcast:send f;h;f\n"
            )?,
        )
        .is_err()
    );
    let (mut offerer, _) = simulcast_sender(&[("f", Some(1280)), ("h", Some(640))])?;
    let mut answerer = w3c_peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        lines_with(&answer, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv"],
        "{answer}"
    );
    Ok(())
}

/// RFC 8853 section 5.3.1: an offerer may ask to receive simulcast; it is then "prepared to
/// receive" each stream. `set_receive_simulcast` writes the `recv` rids and `a=simulcast:recv`;
/// a simulcast sender answers with the streams it has, and the offerer's receiver takes them
/// as its layers.
#[test]
fn an_offer_can_ask_to_receive_simulcast() -> TestResult {
    let mut offerer = default_peer()?;
    let id = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let mut transceiver = offerer.rtp_transceiver(id).expect("the transceiver");
    assert!(
        transceiver
            .set_receive_simulcast(vec!["f".to_owned()])
            .is_err()
    );
    assert!(
        transceiver
            .set_receive_simulcast(vec!["f".to_owned(), "f".to_owned()])
            .is_err()
    );
    transceiver.set_receive_simulcast(vec!["f".to_owned(), "h".to_owned(), "q".to_owned()])?;

    let (mut answerer, _) = simulcast_sender(&[("f", None), ("h", None), ("q", None)])?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        lines_with(&offer, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv", "a=rid:q recv"],
        "{offer}"
    );
    assert_eq!(
        lines_with(&offer, "a=simulcast:"),
        vec!["a=simulcast:recv f;h;q"]
    );
    assert_eq!(
        lines_with(&answer, "a=simulcast:"),
        vec!["a=simulcast:send f;h;q"],
        "{answer}"
    );

    let receiver = offerer.get_receivers().next().expect("a receiver");
    let receiver = offerer.rtp_receiver(receiver).expect("receiver");
    let layers: Vec<String> = receiver
        .track()
        .codings()
        .iter()
        .map(|c| c.rtp_coding_parameters.rid.clone())
        .collect();
    assert_eq!(layers, vec!["f", "h", "q"]);
    Ok(())
}

/// RFC 9429 section 5.2.1: for a sender with several encodings, "an 'a=rid' line for each
/// encoding ... If the application has not set an rid ..., an rid-id value MUST be generated".
/// Encodings stated to be simulcast layers (`with_simulcast_layers`) are offered as layers
/// with generated rids (no user data, one byte each), rids the application set are kept;
/// encodings without rids and without that statement stay codec alternatives of one stream
/// (`codec_negotiation.rs::test_add_track_negotiates_non_first_codec`).
#[test]
fn simulcast_layers_without_rids_get_generated_rids() -> TestResult {
    use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
    use rtc::rtp_transceiver::RTCRtpTransceiverInit;
    for (given, expected) in [
        (["", "", ""], ["0", "1", "2"]),
        (["", "1", ""], ["0", "1", "2"]),
        (["0", "", "hi"], ["0", "1", "hi"]),
    ] {
        let mut pc = default_peer()?;
        let encodings = given
            .iter()
            .map(|rid| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: (*rid).to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect();
        pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(
                RTCRtpTransceiverInit::with_direction(RTCRtpTransceiverDirection::Sendonly)
                    .with_simulcast_layers(encodings),
            ),
        )?;
        let offer = pc.create_offer(None)?.sdp;
        let rid_lines: Vec<String> = expected.iter().map(|r| format!("a=rid:{r} send")).collect();
        assert_eq!(
            lines_with(&offer, "a=rid:"),
            rid_lines,
            "{given:?}\n{offer}"
        );
        assert_eq!(
            lines_with(&offer, "a=simulcast:"),
            [format!("a=simulcast:send {}", expected.join(";"))],
            "{given:?}"
        );
    }
    Ok(())
}

/// The scale factors of the sender's encodings, in order.
fn sent_scales(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> Vec<Option<f64>> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings
        .iter()
        .map(|e| e.scale_resolution_down_by)
        .collect()
}

/// W3C webrtc-pc "set the RTCSessionDescription" (`proposedSendEncodings`): a remote offer to
/// receive simulcast promotes a sender with one rid-less encoding to the offered layers, in the
/// offer's order, scaled down by 2^(n - index - 1); the answer sends them; at most
/// `MAX_SEND_ENCODINGS` are taken; a rollback restores the rid-less encoding
/// (`[[LastStableRidlessSendEncodings]]`).
#[test]
fn a_remote_offer_to_receive_simulcast_promotes_a_unicast_sender() -> TestResult {
    let (mut pc, sender) = {
        let mut pc = default_peer()?;
        let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0001))?;
        (pc, sender)
    };
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("", None)]));
    let now = Instant::now();
    let offer = || {
        remote_offer(
            "recvonly",
            "a=rid:q recv\na=rid:h recv\na=rid:f recv\na=simulcast:recv q;h;f\n",
        )
    };
    pc.set_remote_description(now, offer()?)?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("q", None), ("h", None), ("f", None)])
    );
    assert_eq!(
        sent_scales(&mut pc, sender),
        [Some(4.0), Some(2.0), Some(1.0)]
    );

    // Rolled back: the rid-less encoding again.
    pc.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("", None)]));

    // Answered: the layers are sent.
    pc.set_remote_description(now, offer()?)?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:q send", "a=rid:h send", "a=rid:f send"],
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender).len(), 3);

    // Truncated to the supported number of encodings.
    let mut pc = default_peer()?;
    let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0002))?;
    let ids: Vec<String> = (0..20).map(|i| format!("r{i}")).collect();
    let mut extra: String = ids.iter().map(|id| format!("a=rid:{id} recv\n")).collect();
    extra.push_str(&format!("a=simulcast:recv {}\n", ids.join(";")));
    pc.set_remote_description(now, remote_offer("recvonly", &extra)?)?;
    assert_eq!(
        sent_layers(&mut pc, sender).len(),
        rtc::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS
    );
    Ok(())
}

/// W3C `proposedSendEncodings`: "Remove any RTCRtpEncodingParameters dictionaries in
/// proposedSendEncodings if their rid member is the same as a rid member of an earlier one",
/// in the W3C answer form, which takes an `a=simulcast` line that repeats a rid.
#[test]
fn proposed_send_encodings_drop_a_repeated_rid() -> TestResult {
    let mut pc = w3c_peer()?;
    let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0003))?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:h recv\na=rid:f recv\na=simulcast:recv h;f;h\n",
        )?,
    )?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("h", None), ("f", None)])
    );
    Ok(())
}
