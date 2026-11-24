//! Header extension signalling (RFC 8285 sections 5 to 7, RFC 6904 section 4, RFC 6464
//! section 4, RFC 6465 section 5): the ids an offer uses, what a received description may map,
//! the extended range an answer remaps, directions, encrypted forms and extension attributes.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::shared::error::Error;

const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const RID: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
const ABS: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const CSRC_AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:csrc-audio-level";
const ENCRYPT: &str = "urn:ietf:params:rtp-hdrext:encrypt";

fn capability(uri: &str) -> RTCRtpHeaderExtensionCapability {
    RTCRtpHeaderExtensionCapability {
        uri: uri.to_owned(),
    }
}

/// A peer with the default codecs and `uris` registered for audio and video.
fn peer_with(uris: &[&str]) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for uri in uris {
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            media_engine.register_header_extension(capability(uri), kind, None)?;
        }
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// A peer with the default codecs and the default interceptors (and their extensions).
fn default_interceptor_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

/// A remote offer with an audio section (mid 0) and a video section (mid 1) in one BUNDLE
/// group, each with its own `a=extmap` (and other) lines.
fn offer(audio: &str, video: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:0
a=sendrecv
{audio}a=rtpmap:111 opus/48000/2
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:1
a=sendrecv
{video}a=rtpmap:96 VP8/90000
"
    ))
}

/// The `a=extmap` values of each section of `sdp`, sorted.
fn extmaps(sdp: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = vec![];
    for line in sdp.lines() {
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
    out
}

/// The answer `pc` gives to `offer`, applied.
fn answer(pc: &mut RTCPeerConnection, offer: String) -> Result<String, Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

/// RFC 8285 section 4.1.2: the one-byte ids first ("the one-byte header form is preferred"),
/// then ids above 14, which need the two-byte form (section 4.3); 15 is never used (section
/// 5: reserved). Up to 254 extensions can be registered.
#[test]
fn an_offer_takes_ids_above_14_once_the_one_byte_ids_are_taken() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for n in 0..17 {
        media_engine.register_header_extension(
            capability(&format!("urn:example:ext-{n}")),
            RtpCodecKind::Video,
            None,
        )?;
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    let mut ids: Vec<u16> = offer
        .sdp
        .lines()
        .filter_map(|l| l.strip_prefix("a=extmap:"))
        .filter_map(|v| v.split([' ', '/']).next()?.parse().ok())
        .collect();
    ids.sort();
    let expected: Vec<u16> = (1..=14).chain(16..=18).collect();
    assert_eq!(ids, expected);
    Ok(())
}

#[test]
fn registering_more_than_254_header_extensions_is_refused() -> TestResult {
    let mut media_engine = MediaEngine::default();
    for n in 0..254 {
        media_engine.register_header_extension(
            capability(&format!("urn:example:ext-{n}")),
            RtpCodecKind::Video,
            None,
        )?;
    }
    assert!(matches!(
        media_engine.register_header_extension(
            capability("urn:example:one-too-many"),
            RtpCodecKind::Video,
            None
        ),
        Err(Error::ErrRegisterHeaderExtensionNoFreeID)
    ));
    Ok(())
}

/// RFC 8285 section 5: "A usable mapping MUST use IDs in the valid range"; 15 is reserved in
/// the one-byte form and is not one. Such a mapping is not used, and does not fail the offer.
#[test]
fn a_mapping_to_the_reserved_id_15_is_not_used() -> TestResult {
    let mut pc = peer_with(&[MID, ABS])?;
    let sdp = answer(
        &mut pc,
        offer(
            &format!("a=extmap:15 {MID}\na=extmap:5 {ABS}\n"),
            &format!("a=extmap:5 {ABS}\n"),
        ),
    )?;
    assert_eq!(
        extmaps(&sdp),
        vec![vec![format!("5 {ABS}")], vec![format!("5 {ABS}")]]
    );
    Ok(())
}

/// RFC 8285 sections 5 and 7: an id maps one extension in a section and in a BUNDLE group,
/// whose sections share one id space, and an extension has one id there.
#[test]
fn a_description_whose_mappings_contradict_each_other_is_refused() -> TestResult {
    for (audio, video) in [
        // One id, two extensions, in one section.
        (
            format!("a=extmap:3 {MID}\na=extmap:3 {ABS}\n"),
            String::new(),
        ),
        // One extension, two ids, in one section.
        (
            format!("a=extmap:3 {MID}\na=extmap:4 {MID}\n"),
            String::new(),
        ),
        // One id, two extensions, in two bundled sections.
        (format!("a=extmap:3 {MID}\n"), format!("a=extmap:3 {ABS}\n")),
        // One extension, two ids, in two bundled sections.
        (format!("a=extmap:3 {MID}\n"), format!("a=extmap:4 {MID}\n")),
    ] {
        let mut pc = peer_with(&[MID, ABS])?;
        let result = pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(offer(&audio, &video))?,
        );
        assert!(
            matches!(result, Err(Error::SdpInvalidValue(_))),
            "{audio:?} / {video:?}: {result:?}"
        );
    }
    // The same mapping in both sections is what BUNDLE wants.
    let mut pc = peer_with(&[MID, ABS])?;
    answer(
        &mut pc,
        offer(
            &format!("a=extmap:3 {MID}\n"),
            &format!("a=extmap:3 {MID}\n"),
        ),
    )?;
    Ok(())
}

/// RFC 8285 section 7: of offered alternatives sharing an id of the extended range (4096 to
/// 4351), the answerer "SHOULD select, at most, one ... and remap it to a free identifier in
/// the valid range"; likewise for extensions offered there because the valid range was full.
/// The remapped id is negotiated: it is the one the answer states, and a later offer keeps it.
#[test]
fn an_extension_offered_in_the_extended_range_is_remapped_to_a_free_id() -> TestResult {
    let mut pc = peer_with(&[MID, RID, ABS])?;
    let sdp = answer(
        &mut pc,
        offer(
            &format!(
                "a=extmap:1 {ABS}\na=extmap:4096 urn:example:not-registered\na=extmap:4096 {MID}\na=extmap:4097 {RID}\n"
            ),
            &format!("a=extmap:1 {ABS}\na=extmap:4096 {MID}\n"),
        ),
    )?;
    assert_eq!(
        extmaps(&sdp),
        vec![
            vec![format!("1 {ABS}"), format!("2 {MID}"), format!("3 {RID}")],
            vec![format!("1 {ABS}"), format!("2 {MID}")],
        ]
    );
    let reoffer = pc.create_offer(None)?;
    assert!(
        extmaps(&reoffer.sdp)[0].contains(&format!("2 {MID}")),
        "{:?}",
        extmaps(&reoffer.sdp)
    );
    Ok(())
}

/// RFC 6465 section 5: a client that does not mix states the mixer-to-client audio level
/// `recvonly`; RFC 8285 section 7: an extension may carry a direction. RFC 8834 sections
/// 5.2.2 and 5.2.3: the audio level extensions are offered encrypted too (RFC 6904 section
/// 4.1, best effort), under their own ids.
#[test]
fn the_default_audio_offer_has_both_audio_levels_clear_and_encrypted() -> TestResult {
    let mut pc = default_interceptor_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?;
    let audio = &extmaps(&offer.sdp)[0];
    let lines: Vec<String> = audio
        .iter()
        .filter_map(|v| {
            let (entry, rest) = v.split_once(' ')?;
            let dir = entry.split_once('/').map(|(_, d)| d).unwrap_or("");
            Some(format!("{dir}|{rest}"))
        })
        .collect();
    for expected in [
        format!("|{AUDIO_LEVEL}"),
        format!("|{ENCRYPT} {AUDIO_LEVEL}"),
        format!("recvonly|{CSRC_AUDIO_LEVEL}"),
        format!("recvonly|{ENCRYPT} {CSRC_AUDIO_LEVEL}"),
    ] {
        assert!(lines.contains(&expected), "{expected} in {audio:?}");
    }

    // A section that only sends has no use for the receive-only extension.
    let mut pc = default_interceptor_peer()?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let offer = pc.create_offer(None)?;
    assert!(
        !offer.sdp.contains(CSRC_AUDIO_LEVEL),
        "{:?}",
        extmaps(&offer.sdp)
    );
    Ok(())
}

/// RFC 6465 section 5: the audio level extensions "MUST NOT be advertised with other media
/// types"; RFC 6904 section 4: the `encrypt` URI is not an extension of its own.
#[test]
fn audio_levels_for_video_and_the_encrypt_uri_cannot_be_registered() {
    let mut media_engine = MediaEngine::default();
    for uri in [AUDIO_LEVEL, CSRC_AUDIO_LEVEL] {
        assert!(matches!(
            media_engine.register_header_extension(capability(uri), RtpCodecKind::Video, None),
            Err(Error::TypeError(_))
        ));
    }
    assert!(matches!(
        media_engine.register_header_extension(capability(ENCRYPT), RtpCodecKind::Audio, None),
        Err(Error::TypeError(_))
    ));
}

/// RFC 6904 section 4.1: an answerer that understands header extension encryption "SHOULD
/// choose the encrypted form of the offered header extension element and mark the
/// unencrypted form 'inactive'"; it never negotiates both. The negotiated parameters say the
/// extension is encrypted.
#[test]
fn an_extension_offered_in_both_forms_is_answered_encrypted() -> TestResult {
    let mut pc = default_interceptor_peer()?;
    let sdp = answer(
        &mut pc,
        offer(
            &format!("a=extmap:3 {AUDIO_LEVEL}\na=extmap:4 {ENCRYPT} {AUDIO_LEVEL}\n"),
            "",
        ),
    )?;
    assert_eq!(
        extmaps(&sdp)[0],
        vec![
            format!("3/inactive {AUDIO_LEVEL}"),
            format!("4 {ENCRYPT} {AUDIO_LEVEL}"),
        ]
    );
    let receiver = pc.get_receivers().next().expect("a receiver");
    let parameters = pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_parameters()
        .clone();
    let level = parameters
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL)
        .expect("the audio level is negotiated");
    assert_eq!((4, true), (level.id, level.encrypted));

    // Offered in the clear only, it is answered in the clear.
    let mut pc = default_interceptor_peer()?;
    let sdp = answer(&mut pc, offer(&format!("a=extmap:3 {AUDIO_LEVEL}\n"), ""))?;
    assert_eq!(extmaps(&sdp)[0], vec![format!("3 {AUDIO_LEVEL}")]);
    Ok(())
}

/// RFC 8285 section 7, with an extension registered receive-only (RFC 6465 section 5): offered
/// sendonly it is answered recvonly; offered recvonly (the peer wants it sent), it is left out
/// ("An answerer that has no desire to, or is unable to, send the extension SHOULD remove it").
#[test]
fn a_receive_only_extension_is_answered_only_when_the_peer_sends_it() -> TestResult {
    let mut pc = default_interceptor_peer()?;
    let sdp = answer(
        &mut pc,
        offer(&format!("a=extmap:7/sendonly {CSRC_AUDIO_LEVEL}\n"), ""),
    )?;
    assert_eq!(
        extmaps(&sdp)[0],
        vec![format!("7/recvonly {CSRC_AUDIO_LEVEL}")]
    );

    let mut pc = default_interceptor_peer()?;
    let sdp = answer(
        &mut pc,
        offer(&format!("a=extmap:7/recvonly {CSRC_AUDIO_LEVEL}\n"), ""),
    )?;
    assert!(extmaps(&sdp)[0].is_empty(), "{:?}", extmaps(&sdp));

    // Offered for both directions, it is answered for the one it was registered for.
    let mut pc = default_interceptor_peer()?;
    let sdp = answer(
        &mut pc,
        offer(&format!("a=extmap:7 {CSRC_AUDIO_LEVEL}\n"), ""),
    )?;
    assert_eq!(
        extmaps(&sdp)[0],
        vec![format!("7/recvonly {CSRC_AUDIO_LEVEL}")]
    );
    Ok(())
}

/// RFC 6464 section 4: the `vad` extension attribute says whether the V bit is in use. The
/// value the peer signalled is in the negotiated parameters, for the application to read the
/// V bit by (`vad=off`: ignore it).
#[test]
fn the_peers_vad_attribute_is_in_the_negotiated_parameters() -> TestResult {
    let mut pc = default_interceptor_peer()?;
    answer(
        &mut pc,
        offer(&format!("a=extmap:3 {AUDIO_LEVEL} vad=off\n"), ""),
    )?;
    let receiver = pc.get_receivers().next().expect("a receiver");
    let parameters = pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_parameters()
        .clone();
    let level = parameters
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL)
        .expect("the audio level is negotiated");
    assert_eq!(Some("vad=off"), level.attributes.as_deref());
    Ok(())
}

/// RFC 6464 section 4: "the semantics chosen for a header extension element (including its vad
/// setting) for a particular extension identifier value MUST NOT be changed within an RTP
/// session". A peer offers the audio level as id 3 with `vad=off`: the answer maps id 3 with
/// `vad=off` too, and so does the engine's own later offer (without the attribute it would mean
/// `vad=on`, the default), in the clear and encrypted forms alike; an id offered without one
/// stays without one.
#[test]
fn the_vad_of_an_audio_level_id_is_kept_through_the_session() -> TestResult {
    for encrypted in [false, true] {
        let mut pc = default_interceptor_peer()?;
        let line = if encrypted {
            format!("3 {ENCRYPT} {AUDIO_LEVEL} vad=off")
        } else {
            format!("3 {AUDIO_LEVEL} vad=off")
        };
        let sdp = answer(
            &mut pc,
            offer(
                &format!("a=extmap:{line}\na=extmap:4 {CSRC_AUDIO_LEVEL}\n"),
                "",
            ),
        )?;
        assert!(extmaps(&sdp)[0].contains(&line), "the answer: {sdp}");
        let reoffer = pc.create_offer(None)?;
        let audio = &extmaps(&reoffer.sdp)[0];
        assert!(audio.contains(&line), "the later offer: {audio:?}");
        assert!(
            audio
                .iter()
                .filter(|l| l.starts_with("4 ") || l.starts_with("4/"))
                .all(|l| !l.contains("vad")),
            "{audio:?}"
        );
    }
    Ok(())
}

/// RFC 6464 section 4, the offerer's side: the engine offers the audio level (no `vad`, which
/// is `vad=on`), the answer maps that id with `vad=off`; the engine's next offer keeps
/// `vad=off` for the id, the semantics the negotiation gave it.
#[test]
fn an_answered_vad_is_kept_in_the_next_offer() -> TestResult {
    let mut offerer = default_interceptor_peer()?;
    let mut answerer = default_interceptor_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    let id = extmaps(&offer.sdp)[0]
        .iter()
        .find_map(|l| {
            l.strip_suffix(&format!(" {AUDIO_LEVEL}"))
                .map(str::to_owned)
        })
        .expect("the audio level is offered in the clear");
    // The answerer is given the clear form only (a peer without RFC 6904).
    let clear_only: String = offer
        .sdp
        .split_inclusive("\r\n")
        .filter(|l| !(l.contains(ENCRYPT) && l.contains(AUDIO_LEVEL)))
        .collect();
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(clear_only)?)?;
    let answer = answerer.create_answer(None)?;
    let edited = answer.sdp.replace(
        &format!("a=extmap:{id} {AUDIO_LEVEL}\r\n"),
        &format!("a=extmap:{id} {AUDIO_LEVEL} vad=off\r\n"),
    );
    assert_ne!(edited, answer.sdp, "the answer maps the clear form at {id}");
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(edited)?)?;
    let reoffer = offerer.create_offer(None)?;
    let line = format!("{id} {AUDIO_LEVEL} vad=off");
    assert!(
        extmaps(&reoffer.sdp)[0].contains(&line),
        "{:?}",
        extmaps(&reoffer.sdp)[0]
    );
    Ok(())
}

/// RFC 8285 section 6: the attribute may be at media level; offered there, it is answered.
#[test]
fn extmap_allow_mixed_at_media_level_is_answered() -> TestResult {
    let mut pc = peer_with(&[MID])?;
    let sdp = answer(
        &mut pc,
        offer(
            &format!("a=extmap-allow-mixed\na=extmap:3 {MID}\n"),
            &format!("a=extmap:3 {MID}\n"),
        ),
    )?;
    assert!(sdp.contains("a=extmap-allow-mixed"), "{sdp}");
    Ok(())
}

/// W3C webrtc-pc 5.2 / 5.3 `getParameters`: the header extensions are those this media
/// section negotiated, for sending (the sender) and for receiving (the receiver), not every
/// extension of the kind; none before an answer. Two video sections, abs-send-time offered in
/// the first only.
#[test]
fn parameters_list_the_header_extensions_of_their_own_section() -> TestResult {
    let mut pc = peer_with(&[MID, ABS])?;
    let first = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    {
        let sender = pc
            .rtp_transceiver(first)
            .and_then(|t| t.sender())
            .expect("a sender");
        let before = pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .clone();
        assert!(before.is_empty(), "none negotiated yet: {before:?}");
    }
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=extmap:1 {MID}
a=extmap:2 {ABS}
a=rtpmap:96 VP8/90000
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:1
a=sendrecv
a=extmap:1 {MID}
a=rtpmap:96 VP8/90000
"
    ));
    answer(&mut pc, offer)?;
    let mut uris = |index: usize| -> (Vec<String>, Vec<String>) {
        let ids: Vec<_> = pc.get_transceivers().collect();
        let t = pc.rtp_transceiver(ids[index]).expect("t");
        let (sender, receiver) = (t.sender().expect("s"), t.receiver().expect("r"));
        let mut send: Vec<String> = pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .map(|e| e.uri.clone())
            .collect();
        let mut recv: Vec<String> = pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .map(|e| e.uri.clone())
            .collect();
        send.sort();
        recv.sort();
        (send, recv)
    };
    let mut both = vec![ABS.to_owned(), MID.to_owned()];
    both.sort();
    assert_eq!(uris(0), (both.clone(), both));
    assert_eq!(uris(1), (vec![MID.to_owned()], vec![MID.to_owned()]));
    Ok(())
}
