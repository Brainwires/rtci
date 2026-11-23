//! W3C webrtc-pc 4.7.3 "check if negotiation is needed", step 5.3.1: a sending transceiver
//! whose sender is in no MediaStream is described with `a=msid:- <id>` (RFC 8830 section 2,
//! RFC 9429 section 5.2.1). Its `[[AssociatedMediaStreamIds]]` are empty, and the description
//! says `-`: both mean "no stream", so once the transceiver is negotiated nothing is left to
//! negotiate. Comparing the empty set with `-` kept negotiation-needed raised after every
//! exchange, and an application that honours the event re-offered forever.

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpEncodingParameters};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use sansio::Protocol;
use std::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// One offer/answer exchange; returns the offer's SDP.
fn negotiate(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> Result<String, Box<dyn std::error::Error>> {
    let offer = offerer.create_offer(None)?;
    let sdp = offer.sdp.clone();
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(sdp)
}

fn msid_stream_ids(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix("a=msid:"))
        .filter_map(|value| value.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// `addTransceiver(kind)` without `streams`: the default direction sends, the sender has no
/// track and no stream. After the exchange that negotiates it, neither side asks again, as
/// offerer or as answerer, however often the application renegotiates.
#[test]
fn a_kind_sender_in_no_stream_settles_after_one_exchange() -> TestResult {
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        let mut offerer = peer()?;
        let mut answerer = peer()?;
        offerer.add_transceiver_from_kind(kind, None)?;
        assert_eq!(
            negotiation_needed(&mut offerer),
            1,
            "{kind}: a new transceiver"
        );

        let sdp = negotiate(&mut offerer, &mut answerer)?;
        assert_eq!(
            msid_stream_ids(&sdp),
            vec!["-".to_owned()],
            "{kind}: a sender in no stream is described as `a=msid:- <id>`"
        );
        assert_eq!(
            negotiation_needed(&mut offerer),
            0,
            "{kind}: the offerer has negotiated everything it has"
        );
        let _ = negotiation_needed(&mut answerer);

        for round in 1..=3 {
            negotiate(&mut answerer, &mut offerer)?;
            assert_eq!(
                negotiation_needed(&mut offerer),
                0,
                "{kind}: the kind sender's side, as answerer, round {round}"
            );
            assert_eq!(
                negotiation_needed(&mut answerer),
                0,
                "{kind}: the other side, as offerer, round {round}"
            );
            negotiate(&mut offerer, &mut answerer)?;
            assert_eq!(
                negotiation_needed(&mut offerer),
                0,
                "{kind}: the kind sender's side, as offerer, round {round}"
            );
            assert_eq!(
                negotiation_needed(&mut answerer),
                0,
                "{kind}: round {round}"
            );
        }
    }
    Ok(())
}

/// The same with other shapes of a kind sender in no stream: sendonly, simulcast encodings
/// (rids), and a direction changed after the first exchange.
#[test]
fn other_kind_senders_in_no_stream_settle_too() -> TestResult {
    let encoding = |rid: &str| RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    };
    let inits = [
        RTCRtpTransceiverInit::with_direction(RTCRtpTransceiverDirection::Sendonly),
        RTCRtpTransceiverInit {
            send_encodings: vec![encoding("h"), encoding("l")],
            ..Default::default()
        },
    ];
    for (i, init) in inits.into_iter().enumerate() {
        let mut offerer = peer()?;
        let mut answerer = peer()?;
        let transceiver = offerer.add_transceiver_from_kind(RtpCodecKind::Video, Some(init))?;
        negotiate(&mut offerer, &mut answerer)?;
        let _ = negotiation_needed(&mut offerer);
        let _ = negotiation_needed(&mut answerer);
        for round in 1..=2 {
            negotiate(&mut offerer, &mut answerer)?;
            negotiate(&mut answerer, &mut offerer)?;
            assert_eq!(
                negotiation_needed(&mut offerer),
                0,
                "shape {i}, round {round}"
            );
            assert_eq!(
                negotiation_needed(&mut answerer),
                0,
                "shape {i}, round {round}"
            );
        }
        offerer
            .rtp_transceiver(transceiver)
            .expect("the transceiver")
            .set_direction(RTCRtpTransceiverDirection::Sendrecv)?;
        negotiate(&mut offerer, &mut answerer)?;
        let _ = negotiation_needed(&mut offerer);
        negotiate(&mut answerer, &mut offerer)?;
        assert_eq!(
            negotiation_needed(&mut offerer),
            0,
            "shape {i}, after set_direction"
        );
    }
    Ok(())
}

/// `setStreams()` with no argument on a sender that was in a stream: one exchange describes
/// `a=msid:- <id>`, and then the flag stays down; `setStreams` with a stream again raises it.
#[test]
fn set_streams_to_none_settles_after_one_exchange() -> TestResult {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let transceiver = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            streams: vec!["s".to_owned()],
            ..Default::default()
        }),
    )?;
    negotiate(&mut offerer, &mut answerer)?;
    let _ = negotiation_needed(&mut offerer);
    let _ = negotiation_needed(&mut answerer);

    offerer
        .rtp_sender(transceiver.into())
        .expect("a sender")
        .set_streams(vec![])?;
    assert_eq!(negotiation_needed(&mut offerer), 1, "the streams changed");
    let sdp = negotiate(&mut offerer, &mut answerer)?;
    assert_eq!(msid_stream_ids(&sdp), vec!["-".to_owned()]);
    assert_eq!(negotiation_needed(&mut offerer), 0, "settled");
    negotiate(&mut answerer, &mut offerer)?;
    assert_eq!(
        negotiation_needed(&mut offerer),
        0,
        "settled as answerer too"
    );

    offerer
        .rtp_sender(transceiver.into())
        .expect("a sender")
        .set_streams(vec!["t".to_owned()])?;
    assert_eq!(negotiation_needed(&mut offerer), 1, "a stream again");
    Ok(())
}
