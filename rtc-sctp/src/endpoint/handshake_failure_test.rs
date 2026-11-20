//! A handshake that fails ends the association (RFC 9260 5.1, 9.1).

use super::link_test::{Link, first_chunk_type};
use super::*;
use crate::AssociationError;
use crate::association::Event;
use crate::chunk::chunk_type::CT_COOKIE_ECHO;
use std::time::Duration;

/// INIT runs out of retransmissions (nobody answers): the association reports HandshakeFailed
/// and is over, instead of staying in COOKIE-WAIT for good.
#[test]
fn an_unanswered_init_ends_the_association() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 1);
    link.loss_percent = 100;
    link.begin_connect();

    let deadline = link.now + Duration::from_secs(600);
    assert!(
        link.run_until(deadline, |l| l.client.conn().is_ended()),
        "the INIT retransmissions never gave up"
    );
    let conn = link.client.conn();
    assert!(conn.is_closed());
    assert!(conn.is_handshaking(), "it never connected");
    assert!(conn.poll_timeout().is_none(), "no timer left running");
    assert!(link.client.events.iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::HandshakeFailed(_)
        }
    )));
    assert!(
        link.client
            .events
            .iter()
            .any(|e| matches!(e, Event::HandshakeFailed { .. }))
    );
}

/// The accepting side is in SCTP's initial CLOSED state until the COOKIE ECHO. An ABORT in
/// that window must still end its association: `close` keyed on the CLOSED state and so closed
/// nothing, leaving it handshaking for good.
#[test]
fn an_abort_during_the_handshake_ends_the_accepting_association() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 2);
    // The COOKIE ECHO never arrives, so the server stays in its pre-cookie CLOSED state.
    link.filter = Some(Box::new(|from_client: bool, datagram: &Bytes| -> bool {
        from_client && first_chunk_type(datagram) == Some(CT_COOKIE_ECHO.0)
    }));
    link.begin_connect();

    // Wait for the dropped COOKIE ECHO, not just for the server's association: until the
    // INIT ACK arrives the client does not know the server's verification tag, and an ABORT
    // sent then (tag 0, not an INIT) is routed to no association.
    let deadline = link.now + Duration::from_secs(5);
    assert!(
        link.run_until(deadline, |l| l.server.association.is_some()
            && l.dropped > 0),
        "the INIT reached the server and the COOKIE ECHO was dropped"
    );
    assert!(!link.server.conn().is_ended());
    assert!(link.server.conn().is_handshaking());

    link.client.conn().abort().expect("abort");
    let deadline = link.now + Duration::from_secs(5);
    assert!(
        link.run_until(deadline, |l| l.server.conn().is_ended()),
        "the ABORT did not end the handshaking association"
    );
    assert!(
        link.server
            .events
            .iter()
            .any(|e| matches!(e, Event::AssociationClosed { .. }))
    );
}
