//! Upstream webrtc-rs/webrtc v0.17.1 `sctp/src/association/association_test.rs` tests that
//! were commented out here (they drove two associations over UDP sockets and tokio tasks),
//! ported to the in-memory, virtual-time link.

use super::link_test::{Link, first_chunk_type};
use super::*;
use crate::AssociationError;
use crate::association::Event;
use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;
use crate::chunk::chunk_type::CT_PAYLOAD_DATA;
use shared::error::Result;
use std::time::Duration;

/// 1) Send 4 messages and lose the first. 2) The other 3 arrive and their SACKs trigger fast
/// retransmission. 3) The first is retransmitted, which makes the stream readable, all before
/// an RTO (RFC 9260 7.2.4).
#[test]
fn test_assoc_congestion_control_fast_retransmission() -> Result<()> {
    let si: u16 = 6;
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.connect();

    let mut data_seen = 0;
    link.filter = Some(Box::new(
        move |from_client: bool, datagram: &Bytes| -> bool {
            if from_client && first_chunk_type(datagram) == Some(CT_PAYLOAD_DATA.0) {
                data_seen += 1;
                data_seen == 1
            } else {
                false
            }
        },
    ));

    let now = link.now;
    {
        let mut stream = link
            .client
            .conn()
            .open_stream(si, PayloadProtocolIdentifier::Binary)?;
        for i in 0..4u32 {
            let mut sbuf = vec![0u8; 1000];
            sbuf[..4].copy_from_slice(&i.to_be_bytes());
            let n =
                stream.write_sctp(now, &Bytes::from(sbuf), PayloadProtocolIdentifier::Binary)?;
            assert_eq!(1000, n);
        }
    }

    // Fast retransmission and recovery complete within 500 ms, well before the 1 s RTO.
    link.run_for(Duration::from_millis(500));

    let received: Vec<u32> = link
        .server
        .received
        .iter()
        .map(|(id, m)| {
            assert_eq!(si, *id);
            assert_eq!(1000, m.len());
            u32::from_be_bytes([m[0], m[1], m[2], m[3]])
        })
        .collect();
    assert_eq!(vec![0, 1, 2, 3], received, "all 4, in order");

    let client = link.client.conn();
    assert!(!client.in_fast_recovery, "should not be in fast-recovery");
    assert_eq!(1, client.stats().get_num_fast_retrans(), "should be 1");
    assert_eq!(0, client.stats().get_num_t3timeouts(), "no RTO");
    Ok(())
}

/// Each association counts the bytes of the packets it sends and receives, and the two counts
/// agree with what crossed the link.
#[test]
fn test_stats() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.connect();

    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PayloadProtocolIdentifier::Binary)?
        .write_sctp(
            now,
            &Bytes::from_static(b"counted"),
            PayloadProtocolIdentifier::Binary,
        )?;
    link.run_for(Duration::from_secs(1));
    assert_eq!(1, link.server.received.len());

    let (from_client, from_server) = (link.bytes_sent[0], link.bytes_sent[1]);
    assert!(from_client > 0 && from_server > 0);
    assert_eq!(from_client, link.client.conn().bytes_sent());
    assert_eq!(from_client, link.server.conn().bytes_received());
    assert_eq!(from_server, link.server.conn().bytes_sent());
    assert_eq!(from_server, link.client.conn().bytes_received());
    Ok(())
}

fn ended_with(events: &[Event], expected: AssociationError) -> bool {
    events
        .iter()
        .any(|e| matches!(e, Event::AssociationClosed { reason } if *reason == expected))
}

/// A graceful shutdown (RFC 9260 9.2) ends both associations: the initiator once it has sent
/// SHUTDOWN COMPLETE, the peer once it has received it.
#[test]
fn test_association_shutdown() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.connect();

    let now = link.now;
    let n = link
        .client
        .conn()
        .open_stream(1, PayloadProtocolIdentifier::String)?
        .write_sctp(
            now,
            &Bytes::from_static(b"test"),
            PayloadProtocolIdentifier::String,
        )?;
    assert_eq!(4, n);
    link.run_for(Duration::from_millis(100));
    assert_eq!(1, link.server.received.len());
    assert_eq!(&b"test"[..], &link.server.received[0].1[..]);

    link.client.conn().shutdown()?;
    let deadline = link.now + Duration::from_secs(1);
    assert!(
        link.run_until(deadline, |l| l.client.conn().is_ended()
            && l.server.conn().is_ended()),
        "shutdown timeout"
    );
    assert!(ended_with(
        &link.client.events,
        AssociationError::LocallyClosed
    ));
    assert!(ended_with(
        &link.server.events,
        AssociationError::AssociationClosed
    ));
    Ok(())
}

/// The peer keeps writing while this side shuts down. The peer's queued DATA is still
/// delivered (RFC 9260 9.2: the SHUTDOWN receiver sends what is queued, accepting nothing
/// new), its later writes fail, and both associations end.
#[test]
fn test_association_shutdown_during_write() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.connect();

    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PayloadProtocolIdentifier::String)?
        .write_sctp(
            now,
            &Bytes::from_static(b"test"),
            PayloadProtocolIdentifier::String,
        )?;
    link.run_for(Duration::from_millis(100));
    assert_eq!(1, link.server.received.len());

    // The server writes 100 one-byte messages per step on stream 1 until a write fails.
    let mut written = 0u32;
    let mut write_failed = false;
    let mut shut_down = false;
    for step in 0..200 {
        let now = link.now;
        if !write_failed {
            let server = link.server.conn();
            for _ in 0..100 {
                let byte = (written % 256) as u8;
                match server.stream(1).and_then(|mut s| {
                    s.write_sctp(
                        now,
                        &Bytes::from(vec![byte]),
                        PayloadProtocolIdentifier::String,
                    )
                }) {
                    Ok(_) => written += 1,
                    Err(_) => {
                        write_failed = true;
                        break;
                    }
                }
            }
        }
        if step == 2 && !shut_down {
            link.client.conn().shutdown()?;
            shut_down = true;
        }
        link.run_for(Duration::from_millis(20));
        if link.client.conn().is_ended() && link.server.conn().is_ended() {
            break;
        }
    }

    assert!(shut_down);
    assert!(write_failed, "writes after the SHUTDOWN must fail");
    assert!(link.client.conn().is_ended(), "the initiator ended");
    assert!(link.server.conn().is_ended(), "the peer ended");
    // "test" from the client, then every message the server accepted.
    let from_server = link.client.received.len() as u32;
    assert_eq!(written, from_server, "every accepted write was delivered");
    Ok(())
}

/// `shutdown()` with DATA still queued and in flight: the queue is sent and acknowledged
/// first, then SHUTDOWN (RFC 9260 9.2). SHUTDOWN used to go out at once and the queued DATA
/// was never sent.
#[test]
fn shutdown_sends_queued_data_first() -> Result<()> {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.connect();

    let now = link.now;
    {
        let mut stream = link
            .client
            .conn()
            .open_stream(1, PayloadProtocolIdentifier::Binary)?;
        // More than the initial congestion window, so most of it is still queued.
        for i in 0..50u32 {
            let mut m = vec![0u8; 1000];
            m[..4].copy_from_slice(&i.to_be_bytes());
            stream.write_sctp(now, &Bytes::from(m), PayloadProtocolIdentifier::Binary)?;
        }
    }
    link.client.conn().shutdown()?;
    assert_eq!(
        crate::association::state::AssociationState::ShutdownPending,
        link.client.conn().state()
    );

    let deadline = link.now + Duration::from_secs(10);
    assert!(
        link.run_until(deadline, |l| l.client.conn().is_ended()
            && l.server.conn().is_ended()),
        "the shutdown never completed"
    );
    let received: Vec<u32> = link
        .server
        .received
        .iter()
        .map(|(_, m)| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
        .collect();
    assert_eq!((0..50).collect::<Vec<_>>(), received, "all 50, in order");
    Ok(())
}
