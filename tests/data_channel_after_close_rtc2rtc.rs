//! W3C webrtc-pc 6.2.2 "announce the data channel as open" and 6.2.3 "announce the data
//! channel instance" both begin "if connection.[[IsClosed]] is true, abort these steps": a
//! DCEP message that reaches a connection after `close()` announces nothing.

mod dc_common;

use anyhow::Result;
use dc_common::{Pair, Peer};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::Instant;

/// What `from` writes now (after a timer turn at `now`), without delivering it.
fn written(from: &mut Peer, now: Instant) -> Result<Vec<TaggedBytesMut>> {
    from.pc.handle_timeout(now)?;
    let mut out = vec![];
    while let Some(datagram) = from.pc.poll_write() {
        out.push(datagram);
    }
    Ok(out)
}

/// Hands `to` the datagrams another peer wrote to it, as its socket would.
fn hand(to: &mut Peer, datagrams: Vec<TaggedBytesMut>, now: Instant) {
    for datagram in datagrams {
        // The engine refuses input once closed, or drops it: either way nothing is announced.
        let _ = to.pc.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: datagram.transport.peer_addr,
                peer_addr: datagram.transport.local_addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: datagram.message,
        });
    }
}

/// Every data channel event `peer` raises from now on.
fn channel_events(peer: &mut Peer) -> Vec<RTCDataChannelEvent> {
    std::iter::from_fn(|| peer.pc.poll_event())
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnDataChannel(event) => Some(event),
            _ => None,
        })
        .collect()
}

/// 6.2.3: the peer's DATA_CHANNEL_OPEN for a new channel arrives after this side closed its
/// connection: no channel is announced (`ondatachannel`) or opened.
#[test]
fn a_dcep_open_after_close_announces_no_channel() -> Result<()> {
    let (mut pair, _) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    pair.offerer.pc.create_data_channel("late", None)?;
    let open = written(&mut pair.offerer, now)?;
    assert!(!open.is_empty(), "the DCEP OPEN is written");

    channel_events(&mut pair.answerer);
    let known = pair.answerer.pc.data_channel_ids();
    pair.answerer.pc.close()?;
    channel_events(&mut pair.answerer);
    hand(&mut pair.answerer, open, now);
    while pair.answerer.pc.poll_read().is_some() {}
    let events = channel_events(&mut pair.answerer);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, RTCDataChannelEvent::OnOpen(_))),
        "{events:?}"
    );
    assert!(
        pair.answerer
            .pc
            .data_channel_ids()
            .iter()
            .all(|id| known.contains(id)),
        "no channel joined [[DataChannels]]"
    );
    Ok(())
}

/// 6.2.2: the peer's DATA_CHANNEL_ACK arrives after this side closed its connection: the
/// channel is not announced open.
#[test]
fn a_dcep_ack_after_close_announces_nothing_open() -> Result<()> {
    let (mut pair, _) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let late = pair.offerer.pc.create_data_channel("late", None)?.id();
    let open = written(&mut pair.offerer, now)?;
    hand(&mut pair.answerer, open, now);
    while pair.answerer.pc.poll_read().is_some() {}
    let ack = written(&mut pair.answerer, now)?;
    assert!(!ack.is_empty(), "the DCEP ACK is written");

    channel_events(&mut pair.offerer);
    pair.offerer.pc.close()?;
    channel_events(&mut pair.offerer);
    hand(&mut pair.offerer, ack, now);
    while pair.offerer.pc.poll_read().is_some() {}
    let events = channel_events(&mut pair.offerer);
    assert!(
        !events.contains(&RTCDataChannelEvent::OnOpen(late)),
        "{events:?}"
    );
    Ok(())
}
