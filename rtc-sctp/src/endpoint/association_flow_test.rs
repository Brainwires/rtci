//! Upstream webrtc-rs/webrtc v0.17.1 `sctp/src/association/association_test.rs` tests that
//! were commented out here (they drove two associations over UDP sockets and tokio tasks),
//! ported to the in-memory, virtual-time link.

use super::link_test::{Link, first_chunk_type};
use super::*;
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
