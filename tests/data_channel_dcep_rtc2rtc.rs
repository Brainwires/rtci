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

/// RFC 8832 section 6: the DATA_CHANNEL_OPEN and the DATA_CHANNEL_ACK travel on a reliable
/// stream, so a channel opens for as long as the association lives, however long the
/// retransmissions take. Under heavy loss (`tests/lossy_link_rtc2rtc.rs`, 30 % each way) the
/// ACK can take longer than 30 seconds: the peer's half of the SCTP handshake may still be in
/// progress (its COOKIE ACK lost, it discards the OPEN until its COOKIE ECHO is answered,
/// retransmitted at a doubling interval), or the OPEN or the ACK is retransmitted at RTO
/// 1, 2, 4, 8, 16 seconds. A DCEP handshake timeout of 30 seconds, the default once, closed the
/// channel there although the path and the association were up, and with no error.
///
/// Here every DTLS datagram the answerer writes is lost for 35 seconds from the moment the
/// offerer's association is up (STUN still passes, so ICE stays connected): the ACK arrives
/// with the OPEN's retransmission after that. The channel opens, and carries data both ways.
#[test]
fn a_channel_whose_ack_takes_longer_than_thirty_seconds_still_opens() -> Result<()> {
    use rtc::peer_connection::transport::RTCSctpTransportState;
    use rtc::sansio::Protocol;
    use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
    use std::time::Duration;

    const BLACKOUT: Duration = Duration::from_secs(35);

    let mut pair = Pair::new(RTCDtlsRole::Client)?;
    let channel = pair.offerer.pc.create_data_channel("slow", None)?.id();
    pair.negotiate()?;
    let mut now = pair.now;
    let deadline = now + Duration::from_secs(180);
    let offerer = &mut pair.offerer.pc;
    let answerer = &mut pair.answerer.pc;
    let arriving = |datagram: TaggedBytesMut, now| TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: datagram.transport.peer_addr,
            peer_addr: datagram.transport.local_addr,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: datagram.message,
    };

    let mut blackout_until = None;
    let mut offerer_events = Vec::new();
    let mut answerer_open = None;
    let mut received = (Vec::new(), Vec::new());
    let mut sent = false;
    loop {
        anyhow::ensure!(
            now < deadline,
            "the channel never opened and carried data: offerer events {offerer_events:?}"
        );
        let to_answerer: Vec<_> = std::iter::from_fn(|| offerer.poll_write()).collect();
        let mut to_offerer: Vec<_> = std::iter::from_fn(|| answerer.poll_write()).collect();
        let quiet = to_answerer.is_empty() && to_offerer.is_empty();
        if blackout_until.is_some_and(|until| now < until) {
            // RFC 7983 section 7: 20..=63 is DTLS; STUN (0..=3) passes.
            to_offerer.retain(|d| !(20..=63).contains(&d.message.first().copied().unwrap_or(0)));
        }
        for datagram in to_answerer {
            answerer.handle_read(arriving(datagram, now))?;
        }
        for datagram in to_offerer {
            offerer.handle_read(arriving(datagram, now))?;
        }
        while let Some(event) = offerer.poll_event() {
            if let rtc::peer_connection::event::RTCPeerConnectionEvent::OnDataChannel(event) = event
                && !matches!(event, RTCDataChannelEvent::OnBufferedAmountLow(_))
            {
                offerer_events.push(event);
            }
        }
        while let Some(event) = answerer.poll_event() {
            if let rtc::peer_connection::event::RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnOpen(id),
            ) = event
            {
                answerer_open = Some(id);
            }
        }
        while let Some(read) = offerer.poll_read() {
            if let rtc::peer_connection::message::RTCMessage::DataChannelMessage(_, m) =
                read.message
            {
                received.0.push(m.data.to_vec());
            }
        }
        while let Some(read) = answerer.poll_read() {
            if let rtc::peer_connection::message::RTCMessage::DataChannelMessage(_, m) =
                read.message
            {
                received.1.push(m.data.to_vec());
            }
        }
        // The blackout starts once the offerer's association is up: it has sent its OPEN.
        if blackout_until.is_none()
            && offerer
                .sctp()
                .is_some_and(|sctp| sctp.state() == RTCSctpTransportState::Connected)
        {
            blackout_until = Some(now + BLACKOUT);
        }
        let open = offerer_events.contains(&RTCDataChannelEvent::OnOpen(channel));
        if open && !sent {
            let remote = answerer_open.expect("the answerer has the channel");
            offerer
                .data_channel(channel)
                .expect("open")
                .send(now, BytesMut::from(&b"from the offerer"[..]))?;
            answerer
                .data_channel(remote)
                .expect("open")
                .send(now, BytesMut::from(&b"from the answerer"[..]))?;
            sent = true;
        }
        if sent && !received.0.is_empty() && !received.1.is_empty() {
            break;
        }
        if quiet {
            let next = [offerer.poll_timeout(), answerer.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + Duration::from_secs(1));
            now = now.max(next);
            offerer.handle_timeout(now)?;
            answerer.handle_timeout(now)?;
        }
    }
    let opened_at = now;
    assert!(
        opened_at >= blackout_until.expect("the association came up"),
        "the ACK cannot have arrived during the blackout"
    );
    assert_eq!(
        offerer_events,
        vec![RTCDataChannelEvent::OnOpen(channel)],
        "the channel opens, and is neither failed nor closed on the way"
    );
    assert_eq!(received.0, vec![b"from the answerer".to_vec()]);
    assert_eq!(received.1, vec![b"from the offerer".to_vec()]);
    Ok(())
}
