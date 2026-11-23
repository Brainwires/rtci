//! Loss recovery over a lossy link, deterministic in virtual time (RFC 3758 3.5, RFC 9260 6.3).

use super::link_test::{Link, first_chunk_type};
use super::*;
use crate::AssociationError;
use crate::association::Event;
use crate::association::stream::ReliabilityType;
use crate::association::timer::TimerConfig;
use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;
use crate::chunk::chunk_type::{CT_FORWARD_TSN, CT_PAYLOAD_DATA};
use shared::error::Result;
use std::collections::HashSet;
use std::time::Duration;

fn message(i: u32, len: usize) -> Bytes {
    let mut m = vec![0u8; len];
    m[..4].copy_from_slice(&i.to_be_bytes());
    Bytes::from(m)
}

fn message_ids(received: &[(u16, Bytes)]) -> HashSet<u32> {
    received
        .iter()
        .map(|(_, m)| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
        .collect()
}

/// An unordered channel with `maxRetransmits = 0` over a link that loses 10% of the datagrams
/// in each direction delivers about 90% of what it sends and drains its queue: each loss is
/// abandoned (RFC 3758 3.5 A3) and skipped with FORWARD TSN (C1-C5), whether it happens in or
/// out of Fast Recovery, and whether or not the FORWARD TSN itself is lost (C3, A5).
///
/// The bounds are the environment test's (`unreliable_channel_loses_without_retransmitting`):
/// with no retransmission at most 1000 arrive, and losing more than 20% means recovery stalled.
#[test]
fn unreliable_channel_delivers_about_ninety_percent_at_ten_percent_loss() -> Result<()> {
    for seed in [1u64, 7, 42, 1000, 31337] {
        let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), seed);
        link.latency = Duration::from_millis(20);
        link.connect();
        link.loss_percent = 10;

        let start = link.now;
        let ppi = PayloadProtocolIdentifier::Binary;
        {
            let mut stream = link.client.conn().open_stream(1, ppi)?;
            stream.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
            for i in 0..1000u32 {
                stream.write_sctp(start, &message(i, 100), ppi)?;
            }
        }

        let drained = link.run_until(start + Duration::from_secs(30), |l| {
            l.client.conn().buffered_amount() == 0
        });
        assert!(
            drained,
            "seed {seed}: {} bytes still queued after 30 virtual seconds",
            link.client.conn().buffered_amount()
        );
        // What is still on the wire lands within one more second.
        link.run_for(Duration::from_secs(1));

        let delivered = message_ids(&link.server.received).len();
        assert!(
            (800..=1000).contains(&delivered),
            "seed {seed}: {delivered} of 1000 delivered (dropped {} datagrams)",
            link.dropped
        );
        assert_eq!(
            delivered,
            link.server.received.len(),
            "seed {seed}: a message delivered twice"
        );
    }
    Ok(())
}

/// The FORWARD TSN that skips an abandoned message is lost, and nothing else is sent after it:
/// T3-rtx must send it again (RFC 3758 3.5 A5, C5), so the peer's cumulative TSN moves past
/// the gap and the sender's queue empties.
#[test]
fn a_lost_forward_tsn_is_sent_again() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 3);
    link.connect();

    let mut data_seen = 0;
    let mut forward_tsn_seen = 0;
    link.filter = Some(Box::new(
        move |from_client: bool, datagram: &Bytes| -> bool {
            if !from_client {
                return false;
            }
            match first_chunk_type(datagram) {
                Some(t) if t == CT_PAYLOAD_DATA.0 => {
                    data_seen += 1;
                    data_seen == 1 // the first message
                }
                Some(t) if t == CT_FORWARD_TSN.0 => {
                    forward_tsn_seen += 1;
                    forward_tsn_seen == 1 // the FORWARD TSN that skips it
                }
                _ => false,
            }
        },
    ));

    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    link.client
        .conn()
        .open_stream(1, ppi)?
        .set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
    for i in 0..3u32 {
        link.client
            .conn()
            .stream(1)?
            .write_sctp(start, &message(i, 100), ppi)?;
        // One message per packet, so the filter can pick the first.
        link.run_for(Duration::from_millis(1));
    }

    let recovered = link.run_until(start + Duration::from_secs(20), |l| {
        let conn = l.client.conn();
        conn.inflight_queue.is_empty() && conn.buffered_amount() == 0
    });
    assert!(recovered, "the sender never got past the abandoned message");
    assert_eq!(
        HashSet::from([1, 2]),
        message_ids(&link.server.received),
        "the two messages that were not lost"
    );
    assert!(
        link.dropped >= 2,
        "the filter dropped the DATA and a FORWARD TSN"
    );
    Ok(())
}

/// A path that loses everything for two minutes takes T3-rtx past six expiries in a row. It
/// must keep retransmitting (backed off to RTO.max), so the message gets through once the path
/// comes back. It used to stop re-arming the timer after the sixth expiry, which ended
/// recovery for good.
#[test]
fn retransmission_resumes_after_a_long_outage() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 5);
    link.connect();

    let ppi = PayloadProtocolIdentifier::Binary;
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, ppi)?
        .write_sctp(now, &message(9, 64), ppi)?;

    link.loss_percent = 100;
    link.run_for(Duration::from_secs(130));
    assert!(link.server.received.is_empty());
    assert!(
        link.client.conn().stats().get_num_t3timeouts() > 6,
        "the outage outlasted six T3-rtx expiries"
    );

    link.loss_percent = 0;
    let deadline = link.now + Duration::from_secs(130);
    let delivered = link.run_until(deadline, |l| !l.server.received.is_empty());
    assert!(
        delivered,
        "the message was never retransmitted after the outage"
    );
    assert_eq!(HashSet::from([9]), message_ids(&link.server.received));
    Ok(())
}

/// A finite `max_t3_rtx_retrans` is the RFC 9260 8.1 limit: past it the peer is unreachable and
/// the association closes with `TimedOut`, rather than leaving the timer stopped.
#[test]
fn a_finite_t3_limit_closes_the_association() -> Result<()> {
    let transport = TransportConfig::default().with_timer_config(TimerConfig {
        max_t3_rtx_retrans: 2,
        ..TimerConfig::default()
    });
    let mut link = Link::new(transport, TransportConfig::default(), 11);
    link.connect();

    let ppi = PayloadProtocolIdentifier::Binary;
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, ppi)?
        .write_sctp(now, &message(1, 64), ppi)?;

    link.loss_percent = 100;
    let deadline = link.now + Duration::from_secs(60);
    let closed = link.run_until(deadline, |l| l.client.conn().is_closed());
    assert!(closed, "the association outlived its T3-rtx limit");
    assert!(link.client.events.iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::TimedOut
        }
    )));
    Ok(())
}

/// Whether an SCTP packet carries a FORWARD TSN chunk anywhere in it.
fn carries_forward_tsn(datagram: &Bytes) -> bool {
    let mut offset = 12;
    while offset + 4 <= datagram.len() {
        if datagram[offset] == CT_FORWARD_TSN.0 {
            return true;
        }
        let length = u16::from_be_bytes([datagram[offset + 2], datagram[offset + 3]]) as usize;
        offset += length.max(4).next_multiple_of(4);
    }
    false
}

/// RFC 3758 3.5 F1: FORWARD TSN is used for nothing but skipping abandoned data. A reliable
/// stream over a link that loses 10% of the datagrams recovers everything by retransmission,
/// and no FORWARD TSN is ever sent, in any packet.
#[test]
fn a_reliable_stream_never_sends_a_forward_tsn() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 11);
    link.connect();
    let seen = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let counter = seen.clone();
    let mut rng = super::link_test::Rng::new(5);
    link.filter = Some(Box::new(move |_, datagram: &Bytes| {
        if carries_forward_tsn(datagram) {
            counter.set(counter.get() + 1);
        }
        rng.chance(10)
    }));
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    {
        let mut stream = link.client.conn().open_stream(1, ppi)?;
        for i in 0..300u32 {
            stream.write_sctp(start, &message(i, 100), ppi)?;
        }
    }
    assert!(link.run_until(start + Duration::from_secs(120), |l| {
        l.server.received.len() == 300
    }));
    assert_eq!(message_ids(&link.server.received).len(), 300);
    assert!(link.dropped > 0, "the link lost datagrams");
    assert_eq!(seen.get(), 0, "a FORWARD TSN on a reliable stream");
    Ok(())
}

/// RFC 3758 3.5 F3: a FORWARD TSN may be delayed to bundle it, by at most 200 ms (a SHOULD)
/// and never more than 500 ms (a MUST). The first message of a stream with
/// `maxRetransmits = 0` is lost; when its retransmission timeout abandons it and the
/// Advanced.Peer.Ack.Point moves past it, the FORWARD TSN leaves at the same instant.
#[test]
fn the_forward_tsn_leaves_as_soon_as_the_ack_point_advances() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 4);
    link.connect();
    let sent = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let counter = sent.clone();
    let mut data_seen = 0;
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if !from_client {
            return false;
        }
        if carries_forward_tsn(datagram) {
            counter.set(counter.get() + 1);
        }
        if first_chunk_type(datagram) == Some(CT_PAYLOAD_DATA.0) {
            data_seen += 1;
            return data_seen == 1;
        }
        false
    }));
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    link.client
        .conn()
        .open_stream(1, ppi)?
        .set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
    link.client
        .conn()
        .stream(1)?
        .write_sctp(start, &message(0, 100), ppi)?;
    let initial = link.client.conn().advanced_peer_tsn_ack_point;
    let mut advanced_at = None;
    let mut sent_at = None;
    link.run_until(start + Duration::from_secs(20), |l| {
        let now = l.now;
        if advanced_at.is_none() && l.client.conn().advanced_peer_tsn_ack_point != initial {
            advanced_at = Some(now);
        }
        if sent_at.is_none() && sent.get() > 0 {
            sent_at = Some(now);
        }
        sent_at.is_some()
    });
    let (advanced_at, sent_at) = (
        advanced_at.expect("the ack point advanced"),
        sent_at.expect("a FORWARD TSN was sent"),
    );
    assert!(
        sent_at.saturating_duration_since(advanced_at) <= Duration::from_millis(200),
        "the FORWARD TSN left {:?} after the ack point advanced",
        sent_at.saturating_duration_since(advanced_at)
    );
    Ok(())
}
