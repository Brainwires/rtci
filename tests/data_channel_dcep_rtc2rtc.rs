//! RFC 8832 section 6 and RFC 8831 section 6.7 between two engines, in memory on a virtual
//! clock: data sent before the DATA_CHANNEL_ACK, and a stream used again after its reset.

mod dc_common;

use anyhow::Result;
use bytes::BytesMut;
use dc_common::Pair;
use rtc::data_channel::{RTCDataChannelInit, RTCDataChannelState};
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::transport::RTCDtlsRole;

/// RFC 8832 section 6: "the peer that sent the DATA_CHANNEL_OPEN message MAY start sending
/// messages containing user data without waiting for the reception of the corresponding
/// DATA_CHANNEL_ACK message." On an unordered channel that data used to leave unordered and
/// could overtake the OPEN; sent ordered, it arrives behind it, complete and in order.
#[test]
fn data_sent_before_the_ack_arrives_on_an_unordered_channel() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let (mut pair, _first) = Pair::connected(answerer_role, "first")?;

        // The association is up, so the channel is dialed at once and `send` is allowed
        // although no ACK can have arrived.
        let mut early = pair.offerer.pc.create_data_channel(
            "early",
            Some(RTCDataChannelInit {
                ordered: false,
                max_retransmits: Some(0),
                ..Default::default()
            }),
        )?;
        assert_eq!(early.ready_state(), RTCDataChannelState::Connecting);
        let now = pair.now;
        for i in 0..8u8 {
            early.send(now, BytesMut::from(&[i; 2000][..]))?;
        }
        let early = early.id();

        assert!(
            pair.run_until(|p| p.answerer.received.len() == 8)?,
            "{answerer_role}: {} of 8 early messages arrived",
            pair.answerer.received.len()
        );
        let accepted = *pair.answerer.opened().last().expect("the early channel");
        let dc = pair.answerer.pc.data_channel(accepted).expect("accepted");
        assert_eq!(dc.label(), "early");
        assert!(!dc.ordered());
        for (i, (id, is_string, data)) in pair.answerer.received.iter().enumerate() {
            assert_eq!(*id, accepted);
            assert!(!is_string);
            assert_eq!(data, &vec![i as u8; 2000], "{answerer_role}: message {i}");
        }
        assert!(pair.run_until(|p| p.offerer.opened().contains(&early))?);
    }
    Ok(())
}

/// RFC 8831 section 6.7: "Streams are available for reuse after a reset has been performed",
/// and RFC 8832 section 6: after the reset "a new DATA_CHANNEL_OPEN message can be sent on
/// the stream". A channel is closed, and the next one this side opens takes the same stream
/// and carries data both ways.
#[test]
fn a_stream_is_used_again_after_its_channel_closed() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let (mut pair, first) = Pair::connected(answerer_role, "first")?;
        let first_remote = pair.answerer.opened()[0];
        let stream_id = pair
            .offerer
            .pc
            .data_channel(first)
            .expect("first")
            .stream_id()
            .expect("an open channel has a stream");

        pair.offerer
            .pc
            .data_channel(first)
            .expect("first")
            .close()?;
        assert!(
            pair.run_until(|p| p.offerer.closed(first) && p.answerer.closed(first_remote))?,
            "{answerer_role}: the close never completed"
        );
        assert_eq!(
            pair.answerer.events_of(first_remote),
            vec![
                RTCDataChannelEvent::OnOpen(first_remote),
                RTCDataChannelEvent::OnClosing(first_remote),
                RTCDataChannelEvent::OnClose(first_remote),
            ]
        );

        let second = pair.offerer.pc.create_data_channel("second", None)?.id();
        assert_eq!(
            pair.offerer
                .pc
                .data_channel(second)
                .expect("second")
                .stream_id(),
            Some(stream_id),
            "{answerer_role}: the freed stream is the first unused one of this side's parity"
        );
        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&second) && p.answerer.opened().len() == 2
            )?,
            "{answerer_role}: the channel on the reused stream never opened"
        );
        let second_remote = pair.answerer.opened()[1];
        assert_ne!(second_remote, first_remote, "a new channel, a new handle");
        let remote = pair
            .answerer
            .pc
            .data_channel(second_remote)
            .expect("second");
        assert_eq!(remote.label(), "second");
        assert_eq!(remote.stream_id(), Some(stream_id));

        let now = pair.now;
        pair.offerer
            .pc
            .data_channel(second)
            .expect("second")
            .send_text(now, "ping")?;
        pair.answerer
            .pc
            .data_channel(second_remote)
            .expect("second")
            .send_text(now, "pong")?;
        assert!(
            pair.run_until(|p| !p.offerer.received.is_empty() && !p.answerer.received.is_empty())?
        );
        assert_eq!(
            pair.answerer.received,
            vec![(second_remote, true, b"ping".to_vec())]
        );
        assert_eq!(
            pair.offerer.received,
            vec![(second, true, b"pong".to_vec())]
        );
    }
    Ok(())
}
