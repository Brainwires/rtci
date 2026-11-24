//! RFC 9260 MAYs of the handshake and of SACK processing: the Cookie Preservative after a
//! stale cookie (3.3.2.1.3, 5.2.6) and SACK loss found from Duplicate TSN reports (6.2).

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::Endpoint;
use crate::endpoint::link_test::{Link, first_chunk_type};
use crate::{ClientConfig, EndpointConfig};

const CAUSE_STALE_COOKIE: u16 = 3;
const PARAM_COOKIE_PRESERVATIVE: u16 = 9;

/// The Cookie Preservative's suggested increment in the INIT a client sends after a Stale
/// Cookie ERROR that arrives `rtt` after its COOKIE ECHO and says the cookie was
/// `staleness_us` late. `None` when the INIT carries none.
fn preservative_after_stale_cookie(rtt: Duration, staleness_us: u32) -> Option<u32> {
    let mut endpoint = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let start = Instant::now();
    let (_, mut a) = endpoint
        .connect(
            start,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let first = sent_datagrams(&mut a, start);
    let first_init = &chunks_of_type(&first, CT_INIT.0)[0];
    assert!(
        !tlvs(&first_init[20..])
            .iter()
            .any(|(t, _)| *t == PARAM_COOKIE_PRESERVATIVE),
        "the first INIT has none"
    );
    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, start, raw);
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, start), CT_COOKIE_ECHO.0).len()
    );
    let at = start + rtt;
    let stale = raw_chunk(
        CT_ERROR.0,
        0,
        &raw_tlv(CAUSE_STALE_COOKIE, &staleness_us.to_be_bytes()),
    );
    let raw = packet_to(&a, &[stale]);
    inject(&mut a, at, raw);
    assert_eq!(AssociationState::CookieWait, a.state(), "a new INIT");
    let sent = sent_datagrams(&mut a, at);
    let init = &chunks_of_type(&sent, CT_INIT.0)[0];
    // Chunk header (4) and the INIT's fixed fields (16).
    tlvs(&init[20..])
        .into_iter()
        .find(|(t, _)| *t == PARAM_COOKIE_PRESERVATIVE)
        .map(|(_, v)| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

/// RFC 9260 5.2.6: after a Stale Cookie ERROR the new INIT carries a Cookie Preservative
/// (3.3.2.1.3); its increment uses the round trip of the COOKIE ECHO / ERROR exchange and
/// adds no more than a second to it (the SHOULD of 5.2.6). It asks for what the cookie was
/// late by (the Measure of Staleness), at least that round trip, at most a second more.
#[test]
fn a_new_init_after_a_stale_cookie_asks_for_a_longer_cookie_life() {
    let rtt = Duration::from_millis(30);
    assert_eq!(Some(250), preservative_after_stale_cookie(rtt, 250_000));
    assert_eq!(
        Some(30),
        preservative_after_stale_cookie(rtt, 1_000),
        "at least the round trip"
    );
    assert_eq!(
        Some(1030),
        preservative_after_stale_cookie(rtt, 5_000_000),
        "no more than a second beyond the round trip"
    );
}

/// RFC 9260 6.2: "When an endpoint receives a SACK chunk, it MAY use the duplicate TSN
/// information to determine if SACK chunk loss is occurring." The server's first SACK is
/// lost; the client's T3-rtx sends the DATA again, the server reports it as a duplicate, and
/// the client counts one SACK loss. Without a lost SACK it counts none.
#[test]
fn a_duplicate_report_of_a_timer_retransmission_counts_a_lost_sack() {
    for lose_a_sack in [false, true] {
        let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 501);
        link.connect();
        let mut dropped = false;
        link.filter = Some(Box::new(move |from_client, d| {
            if lose_a_sack && !from_client && !dropped && first_chunk_type(d) == Some(CT_SACK.0) {
                dropped = true;
                return true;
            }
            false
        }));
        let now = link.now;
        link.client
            .conn()
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .unwrap()
            .write_sctp(
                now,
                &Bytes::from_static(b"once"),
                PayloadProtocolIdentifier::Binary,
            )
            .unwrap();
        link.run_for(Duration::from_secs(5));
        assert_eq!(1, link.server.received.len());
        let stats = link.client.conn().stats();
        let mut stats = stats;
        assert_eq!(u64::from(lose_a_sack), stats.get_num_t3timeouts());
        assert_eq!(
            u64::from(lose_a_sack),
            stats.get_num_sack_losses(),
            "lost a SACK: {lose_a_sack}"
        );
    }
}
