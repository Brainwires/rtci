//! W3C webrtc-pc 4.4.1.6, the SCTP parts of "set an RTCSessionDescription": an offer that
//! describes an SCTP association creates `[[SctpTransport]]` ("connecting") when there is
//! none, an answer that closes the association makes it null, a rollback brings back
//! `[[LastStableStateSctpTransport]]`; a data channel that can be given no id is closed and
//! gets an `error` event with `data-channel-failure` (the errorList).

use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::rtc_error::RTCErrorDetailType;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCSctpTransportState;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
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

fn rollback() -> RTCSessionDescription {
    RTCSessionDescription::rollback(None).expect("a rollback description")
}

fn sctp_state(pc: &RTCPeerConnection) -> Option<RTCSctpTransportState> {
    pc.sctp().map(|sctp| sctp.state())
}

/// 4.4.1.6: a local or a remote offer with a data section creates the transport in
/// "connecting"; a rollback of the first such offer makes it null again; the completed
/// exchange keeps it on both sides.
#[test]
fn an_offer_that_describes_sctp_creates_a_connecting_transport() -> TestResult {
    let mut a = peer()?;
    let mut b = peer()?;
    a.create_data_channel("data", None)?;
    assert_eq!(sctp_state(&a), None, "nothing applied yet");
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    assert_eq!(sctp_state(&a), Some(RTCSctpTransportState::Connecting));
    a.set_local_description(Instant::now(), rollback())?;
    assert_eq!(
        sctp_state(&a),
        None,
        "[[LastStableStateSctpTransport]] was null"
    );

    a.set_local_description(Instant::now(), offer.clone())?;
    b.set_remote_description(Instant::now(), offer.clone())?;
    assert_eq!(sctp_state(&b), Some(RTCSctpTransportState::Connecting));
    b.set_remote_description(Instant::now(), rollback())?;
    assert_eq!(sctp_state(&b), None);

    b.set_remote_description(Instant::now(), offer)?;
    let answer = b.create_answer(None)?;
    b.set_local_description(Instant::now(), answer.clone())?;
    a.set_remote_description(Instant::now(), answer)?;
    assert!(a.sctp().is_some() && b.sctp().is_some(), "negotiated");
    Ok(())
}

/// 4.4.1.6: an answer that closes the SCTP association (RFC 8841 10.4: `a=sctp-port:0`)
/// makes `[[SctpTransport]]` null, which the offer had created, and the transport goes to
/// "closed" (6.1.2).
#[test]
fn an_answer_that_closes_the_association_makes_the_transport_null() -> TestResult {
    let mut a = peer()?;
    let mut b = peer()?;
    a.create_data_channel("data", None)?;
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    b.set_remote_description(Instant::now(), offer)?;
    let answer = b.create_answer(None)?;
    let port = answer
        .sdp
        .lines()
        .find(|l| l.starts_with("a=sctp-port:"))
        .expect("an sctp-port")
        .to_owned();
    let closing = answer.sdp.replace(&port, "a=sctp-port:0");
    assert!(a.sctp().is_some());
    while a.poll_event().is_some() {}
    a.set_remote_description(Instant::now(), RTCSessionDescription::answer(closing)?)?;
    assert!(a.sctp().is_none());
    // W3C 6.1.2 "closed": the association is closed intentionally by a remote description
    // that rejects data or changes the SCTP port; the transport fires statechange.
    let closed = std::iter::from_fn(|| a.poll_event())
        .filter(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnSctpTransportStateChange(RTCSctpTransportState::Closed)
            )
        })
        .count();
    assert_eq!(closed, 1, "one statechange to closed");
    Ok(())
}

/// 4.4.1.6 errorList: with every stream id taken by negotiated channels, the in-band channel
/// that waits for an id when the answer settles the DTLS role gets none; it is closed, with
/// an `error` event (`data-channel-failure`) and then a `close` event.
#[test]
fn a_channel_that_gets_no_id_is_closed_with_a_data_channel_failure() -> TestResult {
    let mut a = peer()?;
    let mut b = peer()?;
    for id in 0..u16::MAX {
        a.create_data_channel(
            "pinned",
            Some(RTCDataChannelInit {
                negotiated: Some(id),
                ..Default::default()
            }),
        )?;
    }
    let late = a.create_data_channel("late", None)?.id();
    while a.poll_event().is_some() {}

    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    b.set_remote_description(Instant::now(), offer)?;
    let answer = b.create_answer(None)?;
    b.set_local_description(Instant::now(), answer.clone())?;
    a.set_remote_description(Instant::now(), answer)?;

    let mut events = Vec::new();
    while let Some(event) = a.poll_event() {
        if let RTCPeerConnectionEvent::OnDataChannel(event) = event {
            match event {
                RTCDataChannelEvent::OnError(id) if id == late => events.push("error"),
                RTCDataChannelEvent::OnClose(id) if id == late => events.push("close"),
                _ => {}
            }
        }
    }
    assert_eq!(events, vec!["error", "close"]);
    assert_eq!(
        a.data_channel_error(late).map(|e| e.error_detail),
        Some(RTCErrorDetailType::DataChannelFailure)
    );
    assert!(a.data_channel(late).is_none(), "the channel is closed");
    Ok(())
}
