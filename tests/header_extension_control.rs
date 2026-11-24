//! webrtc-extensions section 4, RTP header extension control: a transceiver's
//! `[[HeaderExtensionsToNegotiate]]` with a direction per extension, the four
//! InvalidModificationErrors of `setHeaderExtensionsToNegotiate`, offers and answers that carry
//! the directions, and `[[NegotiatedHeaderExtensions]]` once an answer is applied. Signalling
//! only.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, exchange, media_sections};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpHeaderExtensionCapability, RTCRtpHeaderExtensionToNegotiate, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverId};
use rtci::shared::error::Error;

use RTCRtpTransceiverDirection::{Inactive, Recvonly, Sendonly, Sendrecv, Stopped};

const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const ABS: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
const ORIENTATION: &str = "urn:3gpp:video-orientation";
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

/// A peer with the default codecs and the mid, abs-send-time and video orientation
/// extensions for video, the audio level for audio.
fn peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for uri in [MID, ABS, ORIENTATION] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }
    for uri in [MID, AUDIO_LEVEL] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Audio,
            None,
        )?;
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn ext(uri: &str, direction: RTCRtpTransceiverDirection) -> RTCRtpHeaderExtensionToNegotiate {
    RTCRtpHeaderExtensionToNegotiate {
        uri: uri.to_owned(),
        direction,
    }
}

fn to_negotiate(
    pc: &mut RTCPeerConnection,
    id: RTCRtpTransceiverId,
) -> Vec<(String, RTCRtpTransceiverDirection)> {
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .get_header_extensions_to_negotiate()
        .into_iter()
        .map(|e| (e.uri, e.direction))
        .collect()
}

fn negotiated(
    pc: &mut RTCPeerConnection,
    id: RTCRtpTransceiverId,
) -> Vec<(String, RTCRtpTransceiverDirection)> {
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .get_negotiated_header_extensions()
        .into_iter()
        .map(|e| (e.uri, e.direction))
        .collect()
}

fn set(
    pc: &mut RTCPeerConnection,
    id: RTCRtpTransceiverId,
    list: &[(&str, RTCRtpTransceiverDirection)],
) -> Result<(), Error> {
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_header_extensions_to_negotiate(list.iter().map(|(u, d)| ext(u, *d)).collect())
}

/// The `a=extmap` values (`uri[/direction]`) of the first media section, sorted (the order
/// of the lines is not the point).
fn extmaps(sdp: &str) -> Vec<String> {
    let mut lines: Vec<String> = media_sections(sdp)[0]
        .iter()
        .filter_map(|l| l.strip_prefix("a=extmap:"))
        .map(|v| {
            let (id, uri) = v.split_once(' ').expect("id uri");
            match id.split_once('/') {
                Some((_, direction)) => format!("{uri}/{direction}"),
                None => uri.to_owned(),
            }
        })
        .collect();
    lines.sort();
    lines
}

fn sorted(mut lines: Vec<String>) -> Vec<String> {
    lines.sort();
    lines
}

fn owned(list: &[(&str, RTCRtpTransceiverDirection)]) -> Vec<(String, RTCRtpTransceiverDirection)> {
    list.iter().map(|(u, d)| ((*u).to_owned(), *d)).collect()
}

fn video(pc: &mut RTCPeerConnection) -> Result<RTCRtpTransceiverId, Error> {
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)
}

/// webrtc-extensions 4.1 / 4.2: a new transceiver's list is the media engine's extensions for
/// its kind, "sendrecv"; [[NegotiatedHeaderExtensions]] starts empty.
#[test]
fn a_new_transceiver_negotiates_every_registered_extension() -> TestResult {
    let mut pc = peer()?;
    let v = video(&mut pc)?;
    assert_eq!(
        to_negotiate(&mut pc, v),
        owned(&[(MID, Sendrecv), (ABS, Sendrecv), (ORIENTATION, Sendrecv)])
    );
    assert!(negotiated(&mut pc, v).is_empty());
    let a = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    assert_eq!(
        to_negotiate(&mut pc, a),
        owned(&[(MID, Sendrecv), (AUDIO_LEVEL, Sendrecv)])
    );
    Ok(())
}

/// webrtc-extensions 4.2 setHeaderExtensionsToNegotiate: another size, another URI at an
/// index, the mandatory-to-use mid anything but "sendrecv", and a mandatory-to-implement
/// extension "stopped" are InvalidModificationErrors, and leave the list as it was.
#[test]
fn set_header_extensions_to_negotiate_refuses_the_four_modifications() -> TestResult {
    let mut pc = peer()?;
    let v = video(&mut pc)?;
    let a = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let before = to_negotiate(&mut pc, v);
    for list in [
        &[(MID, Sendrecv), (ABS, Sendrecv)][..],
        &[
            (MID, Sendrecv),
            (ABS, Sendrecv),
            (ORIENTATION, Sendrecv),
            (AUDIO_LEVEL, Sendrecv),
        ][..],
        &[(MID, Sendrecv), (ORIENTATION, Sendrecv), (ABS, Sendrecv)][..],
        &[(MID, Recvonly), (ABS, Sendrecv), (ORIENTATION, Sendrecv)][..],
        &[(MID, Stopped), (ABS, Sendrecv), (ORIENTATION, Sendrecv)][..],
    ] {
        let refused = set(&mut pc, v, list);
        assert!(
            matches!(refused, Err(Error::InvalidModificationError)),
            "{list:?}: {refused:?}"
        );
    }
    assert_eq!(to_negotiate(&mut pc, v), before);
    let refused = set(&mut pc, a, &[(MID, Sendrecv), (AUDIO_LEVEL, Stopped)]);
    assert!(
        matches!(refused, Err(Error::InvalidModificationError)),
        "the audio level is mandatory to implement: {refused:?}"
    );
    set(&mut pc, a, &[(MID, Sendrecv), (AUDIO_LEVEL, Recvonly)])?;
    set(
        &mut pc,
        v,
        &[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Recvonly)],
    )?;
    assert_eq!(
        to_negotiate(&mut pc, v),
        owned(&[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Recvonly)])
    );
    Ok(())
}

/// webrtc-extensions 4.1: an offer has an `a=extmap` for each extension that is not
/// "stopped", with its direction; an answer only for an offered one it does not stop, in a
/// direction within the offer's. After the answer, each side's [[NegotiatedHeaderExtensions]]
/// and [[HeaderExtensionsToNegotiate]] are what it negotiated, from its own point of view,
/// "stopped" for what the answer left out.
#[test]
fn offers_and_answers_carry_the_directions_and_the_answer_sets_them() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = video(&mut offerer)?;
    set(
        &mut offerer,
        v,
        &[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Sendonly)],
    )?;
    let offer = offerer.create_offer(None)?;
    assert_eq!(
        extmaps(&offer.sdp),
        sorted(vec![MID.to_owned(), format!("{ORIENTATION}/sendonly")]),
        "{}",
        offer.sdp
    );
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let w = answerer.get_transceivers().next().expect("a transceiver");
    let answer = answerer.create_answer(None)?;
    // The offerer sends the orientation only: the answer receives it.
    assert_eq!(
        extmaps(&answer.sdp),
        sorted(vec![MID.to_owned(), format!("{ORIENTATION}/recvonly")]),
        "{}",
        answer.sdp
    );
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    let expected_offerer = owned(&[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Sendonly)]);
    assert_eq!(negotiated(&mut offerer, v), expected_offerer);
    assert_eq!(to_negotiate(&mut offerer, v), expected_offerer);
    let expected_answerer = owned(&[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Recvonly)]);
    assert_eq!(negotiated(&mut answerer, w), expected_answerer);
    assert_eq!(to_negotiate(&mut answerer, w), expected_answerer);
    Ok(())
}

/// webrtc-extensions 4.1: an answerer that stops an offered extension leaves it out of the
/// answer, the offerer then has it "stopped"; a later offer carries it again once the
/// offerer's application lists it again (a subsequent offer reads
/// [[HeaderExtensionsToNegotiate]]), and an inactive extension is offered inactive.
#[test]
fn a_stopped_extension_is_left_out_and_can_be_offered_again() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = video(&mut offerer)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let w = answerer.get_transceivers().next().expect("a transceiver");
    set(
        &mut answerer,
        w,
        &[(MID, Sendrecv), (ABS, Sendrecv), (ORIENTATION, Stopped)],
    )?;
    let answer = answerer.create_answer(None)?;
    assert_eq!(
        extmaps(&answer.sdp),
        sorted(vec![MID.to_owned(), ABS.to_owned()]),
        "{}",
        answer.sdp
    );
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    assert_eq!(
        negotiated(&mut offerer, v),
        owned(&[(MID, Sendrecv), (ABS, Sendrecv), (ORIENTATION, Stopped)])
    );
    let offer = offerer.create_offer(None)?;
    assert_eq!(
        extmaps(&offer.sdp),
        sorted(vec![MID.to_owned(), ABS.to_owned()]),
        "{}",
        offer.sdp
    );

    set(
        &mut offerer,
        v,
        &[(MID, Sendrecv), (ABS, Inactive), (ORIENTATION, Sendrecv)],
    )?;
    let offer = offerer.create_offer(None)?;
    let lines = extmaps(&offer.sdp);
    assert!(lines.contains(&ORIENTATION.to_owned()), "{}", offer.sdp);
    assert!(lines.contains(&format!("{ABS}/inactive")), "{}", offer.sdp);
    Ok(())
}

/// webrtc-extensions 4.1: a new transceiver takes the list of the first transceiver of its
/// kind that is not stopping.
#[test]
fn a_new_transceiver_copies_the_list_of_the_first_of_its_kind() -> TestResult {
    let mut pc = peer()?;
    let first = video(&mut pc)?;
    set(
        &mut pc,
        first,
        &[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Recvonly)],
    )?;
    let second = video(&mut pc)?;
    assert_eq!(to_negotiate(&mut pc, second), to_negotiate(&mut pc, first));
    let audio = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    assert_eq!(
        to_negotiate(&mut pc, audio),
        owned(&[(MID, Sendrecv), (AUDIO_LEVEL, Sendrecv)]),
        "another kind keeps the defaults"
    );
    pc.rtp_transceiver(first).expect("transceiver").stop()?;
    let third = video(&mut pc)?;
    assert_eq!(to_negotiate(&mut pc, third), to_negotiate(&mut pc, second));
    Ok(())
}

/// A default exchange (no list set) is unchanged by the control: the answer keeps every
/// extension both registered, and both sides then report them "sendrecv".
#[test]
fn without_a_list_every_common_extension_is_negotiated_sendrecv() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = video(&mut offerer)?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        extmaps(&answer),
        sorted(vec![MID.to_owned(), ABS.to_owned(), ORIENTATION.to_owned()])
    );
    assert_eq!(
        negotiated(&mut offerer, v),
        owned(&[(MID, Sendrecv), (ABS, Sendrecv), (ORIENTATION, Sendrecv)])
    );
    Ok(())
}

/// webrtc-extensions 4.1: an extension the answer negotiates but that the negotiated
/// direction of its media section leaves no use for (a send-only extension on a section
/// this side only receives) is "stopped"; one the section can use keeps its direction, and
/// a held (inactive) section stops nothing.
#[test]
fn an_extension_the_section_direction_cannot_use_is_stopped() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtci::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    set(
        &mut offerer,
        v,
        &[(MID, Sendrecv), (ABS, Recvonly), (ORIENTATION, Sendonly)],
    )?;
    // The answerer sends, so the section is negotiated recvonly here (not inactive).
    answerer.add_track(jsep_common::video_track("v", 0x0b0b_0b0b))?;
    exchange(&mut offerer, &mut answerer)?;
    let listed = negotiated(&mut offerer, v);
    let direction_of = |uri: &str| {
        listed
            .iter()
            .find(|(u, _)| u == uri)
            .map(|(_, d)| *d)
            .expect("listed")
    };
    assert_eq!(direction_of(MID), Sendrecv);
    assert_eq!(
        direction_of(ABS),
        Recvonly,
        "received on a receiving section"
    );
    assert_eq!(
        direction_of(ORIENTATION),
        Stopped,
        "sent, on a section that only receives: {listed:?}"
    );

    // A held section keeps its extensions for when it resumes.
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = video(&mut offerer)?;
    exchange(&mut offerer, &mut answerer)?;
    offerer
        .rtp_transceiver(v)
        .expect("transceiver")
        .set_direction(Inactive)?;
    exchange(&mut offerer, &mut answerer)?;
    assert!(
        negotiated(&mut offerer, v)
            .iter()
            .all(|(_, d)| *d != Stopped),
        "{:?}",
        negotiated(&mut offerer, v)
    );
    Ok(())
}

/// The URIs of the header extensions a sender's or a receiver's `getParameters` reports,
/// sorted.
fn parameter_uris(
    pc: &mut RTCPeerConnection,
    id: RTCRtpTransceiverId,
    sender: bool,
) -> Vec<String> {
    let mut uris: Vec<String> = if sender {
        pc.rtp_sender(id.into())
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .map(|e| e.uri.clone())
            .collect()
    } else {
        pc.rtp_receiver(id.into())
            .expect("receiver")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .map(|e| e.uri.clone())
            .collect()
    };
    uris.sort();
    uris
}

/// W3C webrtc-pc 5.2.7 (an extension's direction is seen as its presence in the sender's
/// and the receiver's `getParameters`), 5.2 and 5.3 getParameters (`headerExtensions` are
/// those this m= section negotiated for sending, resp. receiving; none before the answer):
/// the offerer sends the orientation only, so it is in the offerer's sender parameters and
/// the answerer's receiver parameters, and in neither of the others; the mid is in all four,
/// the stopped abs-send-time in none.
#[test]
fn a_header_extensions_direction_shows_in_sender_and_receiver_parameters() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let v = video(&mut offerer)?;
    set(
        &mut offerer,
        v,
        &[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Sendonly)],
    )?;
    assert!(
        parameter_uris(&mut offerer, v, true).is_empty(),
        "nothing negotiated yet"
    );
    assert!(
        parameter_uris(&mut offerer, v, false).is_empty(),
        "nothing negotiated yet"
    );
    exchange(&mut offerer, &mut answerer)?;
    let w = answerer.get_transceivers().next().expect("a transceiver");

    let both = vec![MID.to_owned()];
    let with_orientation = sorted(vec![MID.to_owned(), ORIENTATION.to_owned()]);
    assert_eq!(parameter_uris(&mut offerer, v, true), with_orientation);
    assert_eq!(parameter_uris(&mut offerer, v, false), both);
    assert_eq!(parameter_uris(&mut answerer, w, true), both);
    assert_eq!(parameter_uris(&mut answerer, w, false), with_orientation);
    Ok(())
}

/// webrtc-extensions 4.2 setHeaderExtensionsToNegotiate: "If necessary, restrict
/// extension.direction as to not exceed the user agent's capabilities for this extension."
/// An extension the media engine registered receive-only (or send-only) keeps only that half
/// of what the application asks; "stopped" and an allowed direction are kept as given.
#[test]
fn set_header_extensions_to_negotiate_restricts_directions_to_the_capability() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for (uri, direction) in [
        (MID, None),
        (ABS, Some(Recvonly)),
        (ORIENTATION, Some(Sendonly)),
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Video,
            direction,
        )?;
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let v = video(&mut pc)?;
    set(
        &mut pc,
        v,
        &[(MID, Sendrecv), (ABS, Sendrecv), (ORIENTATION, Recvonly)],
    )?;
    assert_eq!(
        to_negotiate(&mut pc, v),
        owned(&[(MID, Sendrecv), (ABS, Recvonly), (ORIENTATION, Inactive)])
    );
    set(
        &mut pc,
        v,
        &[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Sendonly)],
    )?;
    assert_eq!(
        to_negotiate(&mut pc, v),
        owned(&[(MID, Sendrecv), (ABS, Stopped), (ORIENTATION, Sendonly)])
    );
    Ok(())
}
