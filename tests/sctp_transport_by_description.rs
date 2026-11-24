//! W3C webrtc-pc 4.4.1.6, the SCTP parts of "set an RTCSessionDescription": an offer that
//! describes an SCTP association creates `[[SctpTransport]]` ("connecting") when there is
//! none, an answer that closes the association makes it null, a rollback brings back
//! `[[LastStableStateSctpTransport]]`; a data channel that can be given no id is closed and
//! gets an `error` event with `data-channel-failure` (the errorList).

use rtci::data_channel::RTCDataChannelInit;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::rtc_error::RTCErrorDetailType;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::RTCSctpTransportState;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
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

/// W3C createDataChannel: once the DTLS role is negotiated a new in-band channel is given its
/// id at once; with every id of its parity taken there is none, which is an OperationError,
/// and no channel is left in `[[DataChannels]]`.
#[test]
fn create_data_channel_without_an_available_id_is_refused_and_leaves_nothing() -> TestResult {
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
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer.clone())?;
    b.set_remote_description(Instant::now(), offer)?;
    let answer = b.create_answer(None)?;
    b.set_local_description(Instant::now(), answer.clone())?;
    a.set_remote_description(Instant::now(), answer)?;
    let before = a.data_channel_ids().len();

    let refused = a.create_data_channel("late", None).map(|dc| dc.id());
    assert!(
        matches!(
            refused,
            Err(rtci::shared::error::Error::ErrMaxDataChannelID)
        ),
        "{refused:?}"
    );
    assert_eq!(a.data_channel_ids().len(), before, "nothing was added");
    Ok(())
}

/// `sdp` with its `a=max-message-size` set to `size`.
fn with_max_message_size(sdp: &str, size: u32) -> String {
    sdp.lines()
        .map(|l| {
            if l.starts_with("a=max-message-size:") {
                format!("a=max-message-size:{size}\r\n")
            } else {
                format!("{l}\r\n")
            }
        })
        .collect()
}

fn max_message_size(pc: &RTCPeerConnection) -> Option<u32> {
    pc.sctp().and_then(|sctp| sctp.max_message_size())
}

/// 4.4.1.4, for an answer or a provisional answer: "If description initiates the
/// establishment of a new SCTP association ... or an SCTP association already exists, update
/// the data max message size of connection.[[SctpTransport]]". A provisional answer sets it
/// (null before), the final answer sets it again from its own value, and a later exchange
/// that keeps the association follows the value the peer states then, down and up.
#[test]
fn the_max_message_size_follows_every_answer_and_provisional_answer() -> TestResult {
    let now = Instant::now();
    let mut a = peer()?;
    let mut b = peer()?;
    a.create_data_channel("d", None)?;

    let offer = a.create_offer(None)?;
    a.set_local_description(now, offer.clone())?;
    assert_eq!(max_message_size(&a), None, "null until an answer");
    b.set_remote_description(now, offer)?;
    let answer = b.create_answer(None)?;
    b.set_local_description(now, answer.clone())?;
    assert!(
        answer.sdp.contains("a=max-message-size:"),
        "the answer states a size:\n{}",
        answer.sdp
    );

    a.set_remote_description(
        now,
        RTCSessionDescription::pranswer(with_max_message_size(&answer.sdp, 5000))?,
    )?;
    assert_eq!(max_message_size(&a), Some(5000), "the provisional answer's");
    a.set_remote_description(
        now,
        RTCSessionDescription::answer(with_max_message_size(&answer.sdp, 7000))?,
    )?;
    assert_eq!(max_message_size(&a), Some(7000), "the final answer's");

    // Later exchanges on the same association (the same `a=sctp-port` on both sides).
    for size in [1200u32, 30_000] {
        let offer = a.create_offer(None)?;
        a.set_local_description(now, offer.clone())?;
        b.set_remote_description(now, offer)?;
        let answer = b.create_answer(None)?;
        b.set_local_description(now, answer.clone())?;
        a.set_remote_description(
            now,
            RTCSessionDescription::answer(with_max_message_size(&answer.sdp, size))?,
        )?;
        assert_eq!(
            max_message_size(&a),
            Some(size),
            "the size a later answer states"
        );
    }
    Ok(())
}
