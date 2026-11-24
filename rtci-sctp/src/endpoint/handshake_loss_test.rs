//! The handshake completes over a link that loses and reorders datagrams, on an accepting
//! endpoint that holds one association at a time, as WebRTC's does (one association per DTLS
//! transport, RFC 8261 section 4).

use super::link_test::{Link, first_chunk_type};
use super::*;
use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;
use crate::chunk::chunk_type::CT_INIT_ACK;
use shared::error::Result;
use std::time::Duration;

/// A link to an accepting endpoint limited to one association.
fn single_association_link(seed: u64) -> Link {
    let mut server = ServerConfig::new(TransportConfig::default());
    server.concurrent_associations(1);
    Link::with_server_config(TransportConfig::default(), server, seed)
}

/// The first INIT ACK is lost, so the client sends its INIT again (RFC 9260 5.1 C). That INIT
/// belongs to the association the first one started, which answers it: it was taken for the
/// first packet of a second association, refused at the limit of one, and the client sent its
/// INIT unanswered until it gave up.
#[test]
fn a_retransmitted_init_reaches_the_association_it_started() {
    let mut link = single_association_link(1);
    let mut init_acks_dropped = 0;
    link.filter = Some(Box::new(
        move |from_client: bool, datagram: &Bytes| -> bool {
            let lose = !from_client
                && first_chunk_type(datagram) == Some(CT_INIT_ACK.0)
                && init_acks_dropped == 0;
            if lose {
                init_acks_dropped += 1;
            }
            lose
        },
    ));

    link.connect();

    assert_eq!(link.dropped, 1, "the first INIT ACK was dropped");
    assert_eq!(
        link.server.endpoint_associations(),
        1,
        "the retransmitted INIT started no second association"
    );
}

/// Netem's `loss` plus `delay <latency> <jitter>` and `reorder` on both directions: across many
/// seeds the handshake completes, and a message the accepting side sends as soon as it is
/// connected (a data channel's DATA_CHANNEL_OPEN, which may reach the client before the COOKIE
/// ACK does) is delivered and answered.
#[test]
fn the_handshake_and_a_stream_open_survive_loss_and_reordering() -> Result<()> {
    const STREAM: u16 = 1;
    let ppi = PayloadProtocolIdentifier::Dcep;
    for seed in 1..=200u64 {
        let mut link = single_association_link(seed);
        link.latency = Duration::from_millis(15);
        link.jitter = Duration::from_millis(30);
        link.loss_percent = 10;
        link.reorder_percent = 25;

        // Each phase's deadline leaves room for six consecutive losses under RFC 9260's
        // doubling RTO (1 + 2 + 4 + 8 + 16 + 32 s), far beyond what 10% loss produces.
        link.begin_connect();
        let deadline = link.now + Duration::from_secs(120);
        assert!(
            link.run_until(deadline, |l| l.server.connected()),
            "seed {seed}: the accepting side never connected (dropped {} datagrams)",
            link.dropped
        );
        let now = link.now;
        link.server.conn().open_stream(STREAM, ppi)?.write_sctp(
            now,
            &Bytes::from_static(b"open"),
            ppi,
        )?;

        let deadline = link.now + Duration::from_secs(120);
        assert!(
            link.run_until(deadline, |l| l.client.connected()
                && !l.client.received.is_empty()),
            "seed {seed}: the client did not connect and receive the open (dropped {} datagrams)",
            link.dropped
        );
        let now = link.now;
        link.client
            .conn()
            .stream(STREAM)?
            .write_sctp(now, &Bytes::from_static(b"ack"), ppi)?;

        let deadline = link.now + Duration::from_secs(120);
        assert!(
            link.run_until(deadline, |l| !l.server.received.is_empty()),
            "seed {seed}: the answer never arrived (dropped {} datagrams)",
            link.dropped
        );
        assert_eq!(
            link.client.received,
            vec![(STREAM, Bytes::from_static(b"open"))],
            "seed {seed}"
        );
        assert_eq!(
            link.server.received,
            vec![(STREAM, Bytes::from_static(b"ack"))],
            "seed {seed}"
        );
        assert_eq!(link.server.endpoint_associations(), 1, "seed {seed}");
    }
    Ok(())
}
