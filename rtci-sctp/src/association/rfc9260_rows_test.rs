//! RFC 9260 rows that were open: renege handling (6.2.1 D iii, 6.3.2 R4, 3.3.8), the
//! contents of this side's INIT and INIT ACK (3, 3.3.2, 3.3.3), and association restart
//! (5.2.1, 5.2.2, 5.2.4).

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_type::*;
use crate::endpoint::Endpoint;
use crate::{ClientConfig, EndpointConfig};

/// Ten 100-byte messages in flight as TSNs 100..=109.
fn ten_in_flight(now: Instant) -> Result<Association> {
    let mut a = timed_test_association();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    a.min_tsn2measure_rtt = 100;
    a.cwnd = 64 * a.mtu;
    a.ssthresh = a.cwnd;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    for _ in 0..10 {
        stream.write_sctp(now, &Bytes::from(vec![0x5a; 100]), ppi)?;
    }
    assert_eq!(10, transmitted_data(&a.gather_outbound(now).0).len());
    Ok(a)
}

fn sack(cumulative_tsn_ack: u32, gap_ack_blocks: Vec<(u16, u16)>) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack,
        advertised_receiver_window_credit: 1 << 20,
        gap_ack_blocks: gap_ack_blocks
            .into_iter()
            .map(|(start, end)| crate::chunk::chunk_selective_ack::GapAckBlock { start, end })
            .collect(),
        duplicate_tsn: vec![],
    }
}

/// RFC 9260 6.2.1 D iii and 6.3.2 R4: TSNs a Gap Ack Block acknowledged keep their payload
/// until the Cumulative TSN Ack covers them; a later SACK that no longer acknowledges them
/// is a renege: they are outstanding again, each gets one miss indication, T3-rtx is started
/// if it was not running, and they are sent again, payload intact.
#[test]
fn a_sack_that_drops_gap_acknowledged_tsns_is_a_renege() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    let outstanding = a.inflight_queue.get_num_bytes();
    // 100 cumulatively, 103 and 104 by a block: 101 and 102 missing.
    a.handle_sack(&sack(100, vec![(3, 4)]), now)?;
    for tsn in [103, 104] {
        let c = a.inflight_queue.get(tsn).unwrap();
        assert!(c.acknowledged && c.user_data.len() == 100, "TSN {tsn}");
    }
    assert_eq!(a.inflight_queue.get_num_bytes(), outstanding - 300);
    let misses = |a: &Association, tsn: u32| a.inflight_queue.get(tsn).unwrap().miss_indicator;
    let before = (misses(&a, 103), misses(&a, 104));

    // The receiver dropped them: the next SACK acknowledges 101 and no block.
    a.timers.stop(Timer::T3RTX);
    a.handle_sack(&sack(101, vec![]), now)?;
    for (tsn, before) in [(103, before.0), (104, before.1)] {
        let c = a.inflight_queue.get(tsn).unwrap();
        assert!(c.is_outstanding(), "TSN {tsn} is outstanding again");
        assert_eq!(
            c.miss_indicator,
            before + 1,
            "TSN {tsn}: one miss indication"
        );
    }
    // 100 and 101 acknowledged cumulatively; 103 and 104 count again.
    assert_eq!(a.inflight_queue.get_num_bytes(), outstanding - 200);
    assert!(a.timers.get(Timer::T3RTX).is_some(), "T3-rtx runs");

    // At T3-rtx they go out again, with their payload.
    let deadline = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(deadline);
    let again = transmitted_data(&a.gather_outbound(deadline).0);
    for tsn in [103, 104] {
        let resent = again.iter().find(|c| c.tsn == tsn);
        assert!(
            resent.is_some_and(|c| c.user_data == Bytes::from(vec![0x5a; 100])),
            "TSN {tsn} retransmitted whole"
        );
    }
    Ok(())
}

/// RFC 9260 3.3.8: a SHUTDOWN has no Gap Ack Blocks, and their absence is not a renege: what
/// a block acknowledged stays acknowledged.
#[test]
fn a_shutdown_without_gap_blocks_is_not_a_renege() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    a.handle_sack(&sack(100, vec![(3, 4)]), now)?;
    a.handle_shutdown(
        &ChunkShutdown {
            cumulative_tsn_ack: 101,
        },
        now,
    )?;
    assert_eq!(a.cumulative_tsn_ack_point, 101);
    for tsn in [103, 104] {
        assert!(
            a.inflight_queue.get(tsn).unwrap().acknowledged,
            "TSN {tsn} stays acknowledged"
        );
    }
    Ok(())
}

/// The fixed fields and parameters of an INIT or INIT ACK chunk (its bytes from the type on):
/// (a_rwnd, OS, MIS, parameter types).
fn init_fields(chunk: &[u8]) -> (u32, u16, u16, Vec<(u16, Vec<u8>)>) {
    let a_rwnd = u32::from_be_bytes(chunk[8..12].try_into().unwrap());
    let outbound = u16::from_be_bytes([chunk[12], chunk[13]]);
    let inbound = u16::from_be_bytes([chunk[14], chunk[15]]);
    let length = usize::from(u16::from_be_bytes([chunk[2], chunk[3]]));
    (a_rwnd, outbound, inbound, tlvs(&chunk[20..length]))
}

/// What RFC 9260 3, 3.3.2, 3.3.3, RFC 8261 6.1 and RFC 8831 6.1 ask of this side's INIT and
/// INIT ACK: alone in their packet; each parameter at most once; no Host Name Address, no
/// IPv4 / IPv6 Address and no Supported Address Types parameter; Supported Extensions that
/// names RE-CONFIG; an a_rwnd of at least 1500 and non-zero stream counts, whatever the
/// configuration asks for.
#[test]
fn this_sides_init_and_init_ack_carry_what_the_rfcs_allow() {
    const HOST_NAME_ADDRESS: u16 = 11;
    const IPV4_ADDRESS: u16 = 5;
    const IPV6_ADDRESS: u16 = 6;
    const SUPPORTED_ADDRESS_TYPES: u16 = 12;
    const SUPPORTED_EXTENSIONS: u16 = 0x8008;
    const RE_CONFIG: u8 = 0x82;
    let check = |what: &str, datagram: &Bytes, typ: u8| {
        let chunks = chunks_of(datagram);
        assert_eq!(chunks.len(), 1, "{what}: alone in its packet");
        assert_eq!(chunks[0][0], typ, "{what}");
        let (a_rwnd, outbound, inbound, params) = init_fields(&chunks[0]);
        assert!(a_rwnd >= 1500, "{what}: a_rwnd {a_rwnd}");
        assert!(
            outbound >= 1 && inbound >= 1,
            "{what}: OS {outbound}, MIS {inbound}"
        );
        let mut types: Vec<u16> = params.iter().map(|(t, _)| *t).collect();
        for forbidden in [
            HOST_NAME_ADDRESS,
            IPV4_ADDRESS,
            IPV6_ADDRESS,
            SUPPORTED_ADDRESS_TYPES,
        ] {
            assert!(!types.contains(&forbidden), "{what}: parameter {forbidden}");
        }
        let extensions = params
            .iter()
            .find(|(t, _)| *t == SUPPORTED_EXTENSIONS)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("{what}: Supported Extensions"));
        assert!(extensions.contains(&RE_CONFIG), "{what}: RE-CONFIG");
        let count = types.len();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), count, "{what}: a parameter twice");
    };

    // A configuration that asks for less than the RFC allows is raised to it.
    let config = TransportConfig::default()
        .with_max_receive_buffer_size(100)
        .with_max_num_outbound_streams(0)
        .with_max_num_inbound_streams(0);
    assert_eq!(config.max_receive_buffer_size(), 1500);
    assert_eq!(
        (
            config.max_num_outbound_streams(),
            config.max_num_inbound_streams()
        ),
        (1, 1)
    );
    let mut client = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = client
        .connect(
            now,
            ClientConfig::new(config.clone()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let init = sent_datagrams(&mut a, now);
    check("INIT", &init[0], CT_INIT.0);
    let (a_rwnd, outbound, inbound, _) = init_fields(&chunks_of(&init[0])[0]);
    assert_eq!((a_rwnd, outbound, inbound), (1500, 1, 1));

    let (_, _, answer) = accept_init(&[]);
    check("INIT ACK", &answer[0], CT_INIT_ACK.0);
}

/// RFC 9260 3.3.3: an endpoint takes an INIT ACK larger than 1500 bytes (its State Cookie
/// is the peer's to size).
#[test]
fn an_init_ack_larger_than_1500_bytes_is_taken() {
    let mut client = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = client
        .connect(
            now,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let init = sent_datagrams(&mut a, now);
    let init_chunk_bytes = &chunks_of(&init[0])[0];
    let peer_tag = u32::from_be_bytes(init_chunk_bytes[4..8].try_into().unwrap());
    let cookie = raw_tlv(7, &[0xc0; 2000]);
    let init_ack = raw_packet(
        5000,
        5000,
        peer_tag,
        &[init_chunk(CT_INIT_ACK.0, 0x1122_3344, 700, &[cookie])],
    );
    assert!(init_ack.len() > 1500);
    inject(&mut a, now, init_ack);
    let echoed = chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ECHO.0);
    assert_eq!(echoed.len(), 1, "the COOKIE ECHO follows");
    assert_eq!(echoed[0].len(), 4 + 2000, "with the whole cookie");
}

// ----------------------------------------------------------------------------------------
// Association restart (RFC 9260 5.2.1, 5.2.2, 5.2.4).
// ----------------------------------------------------------------------------------------

fn signer() -> Arc<crate::cookie::CookieSigner> {
    let now = Instant::now();
    Arc::new(
        crate::cookie::CookieSigner::new(
            crypto::default_provider().expect("a crypto provider"),
            0,
            now,
            now,
        )
        .expect("a signer"),
    )
}

/// An INIT from the peer, with `tag` as its Initiate Tag, between the association's ports.
fn init_from_peer(a: &Association, tag: u32) -> Bytes {
    raw_packet(
        a.destination_port,
        a.source_port,
        0,
        &[init_chunk(CT_INIT.0, tag, 900, &[])],
    )
}

/// The State Cookie of the INIT ACK in `datagrams`, and the INIT ACK's Initiate Tag.
fn cookie_of(datagrams: &[Bytes]) -> (Vec<u8>, u32) {
    let init_ack = &chunks_of_type(datagrams, CT_INIT_ACK.0)[0];
    let initiate_tag = u32::from_be_bytes(init_ack[4..8].try_into().unwrap());
    let (_, _, _, params) = init_fields(init_ack);
    let cookie = params
        .into_iter()
        .find(|(t, _)| *t == 7)
        .map(|(_, value)| value)
        .expect("a State Cookie");
    (cookie, initiate_tag)
}

/// RFC 9260 5.2.2 and 5.2.1: the Tie-Tags of a State Cookie are 0 for an INIT in CLOSED (and
/// COOKIE-WAIT), and the association's, random and non-zero, for one in COOKIE-ECHOED or
/// ESTABLISHED; the INIT ACK of an unexpected INIT carries a new tag and changes nothing in
/// the association.
#[test]
fn the_tie_tags_are_zero_without_an_association_and_its_own_with_one() -> Result<()> {
    let signer = signer();
    let now = Instant::now();

    // CLOSED: an accepting association answers its first INIT.
    let (_, Some(mut accepted), _) = accept_init(&[]) else {
        panic!("an association")
    };
    accepted.set_cookie_signer(signer.clone());
    // A new attempt (another Initiate Tag), so the cookie is made anew, with the signer.
    let init = init_from_peer(&accepted, 0xabcd_ef01);
    inject(&mut accepted, now, init);
    let (cookie, _) = cookie_of(&sent_datagrams(&mut accepted, now));
    let fields = signer.open(&cookie).expect("a cookie of this signer");
    assert_eq!(
        (fields.local_tie_tag, fields.peer_tie_tag),
        (0, 0),
        "CLOSED"
    );

    // COOKIE-ECHOED: an INIT collision.
    let mut a = create_association(TransportConfig::default());
    a.set_cookie_signer(signer.clone());
    a.set_state(AssociationState::CookieEchoed);
    a.peer_verification_tag = 0x0bad_cafe;
    let init = init_from_peer(&a, 0x0bad_cafe);
    inject(&mut a, now, init);
    let (cookie, initiate_tag) = cookie_of(&sent_datagrams(&mut a, now));
    let fields = signer.open(&cookie).unwrap();
    assert_ne!(fields.local_tie_tag, 0, "COOKIE-ECHOED");
    assert_eq!(
        (fields.local_tie_tag, fields.peer_tie_tag),
        (a.local_tie_tag, a.peer_tie_tag)
    );
    assert_eq!(
        initiate_tag, a.my_verification_tag,
        "its own tag, unchanged"
    );

    // ESTABLISHED: an unexpected INIT gets a new tag and the same Tie-Tags; the association
    // keeps its state and tags.
    let mut a = timed_test_association();
    a.set_cookie_signer(signer.clone());
    a.peer_verification_tag = 0x1111_2222;
    let (own, peer) = (a.my_verification_tag, a.peer_verification_tag);
    let init = init_from_peer(&a, 0x3333_4444);
    inject(&mut a, now, init);
    let (cookie, initiate_tag) = cookie_of(&sent_datagrams(&mut a, now));
    let fields = signer.open(&cookie).unwrap();
    assert_ne!(initiate_tag, own, "a new Initiate Tag");
    assert_eq!(fields.my_tag, initiate_tag);
    assert_eq!(fields.peer_tag, 0x3333_4444);
    assert_ne!(fields.local_tie_tag, 0);
    assert_eq!(
        (fields.local_tie_tag, fields.peer_tie_tag),
        (a.local_tie_tag, a.peer_tie_tag)
    );
    assert_eq!(a.state(), AssociationState::Established);
    assert_eq!(
        (a.my_verification_tag, a.peer_verification_tag),
        (own, peer)
    );
    // A second INIT: the same Tie-Tags (they are drawn once).
    let tie = (a.local_tie_tag, a.peer_tie_tag);
    let init = init_from_peer(&a, 0x5555_6666);
    inject(&mut a, now, init);
    let (cookie, _) = cookie_of(&sent_datagrams(&mut a, now));
    let fields = signer.open(&cookie).unwrap();
    assert_eq!((fields.local_tie_tag, fields.peer_tie_tag), tie);
    Ok(())
}

/// RFC 9260 5.2.4 action A: a peer that lost its state and starts over from the same ports
/// (a new INIT, then the COOKIE ECHO of the INIT ACK that answered it) takes the association
/// over: the association reports `Restarted`, has the new tags and TSNs, congestion control
/// from its initial values and no streams, is ESTABLISHED, and carries the restarted peer's
/// data. With State Cookies authenticated by a MAC and without.
#[test]
fn a_peer_that_restarts_takes_the_association_over() -> Result<()> {
    use crate::ServerConfig;
    use crate::endpoint::link_test::{Link, Peer};
    let ppi = PayloadProtocolIdentifier::Binary;
    for authenticated in [false, true] {
        let mut server = ServerConfig::new(TransportConfig::default());
        server.concurrent_associations(1);
        if authenticated {
            server.cookie_authentication(crypto::default_provider().expect("a provider"));
        }
        let mut link = Link::with_server_config(TransportConfig::default(), server, 7);
        link.server.endpoint_answers = true;
        link.connect();
        let (old_tag, old_peer_tag) = {
            let conn = link.server.conn();
            (conn.my_verification_tag, conn.peer_verification_tag)
        };
        link.client.conn().open_stream(1, ppi)?;
        link.client
            .conn()
            .stream(1)?
            .write_sctp(link.now, &Bytes::from_static(b"before"), ppi)?;
        link.run_for(Duration::from_secs(1));
        assert!(
            link.server
                .received
                .iter()
                .any(|(_, m)| m == &b"before"[..])
        );
        // Some loss history: a larger RTO and a smaller window than a new association has.
        link.server.conn().rto_mgr.backoff();
        link.server.conn().cwnd = 1200;

        // The client restarts: a new endpoint and association at the same address and port.
        let client_addr = link.client.addr;
        link.client = Peer::new(client_addr, None);
        link.begin_connect();
        let deadline = link.now + Duration::from_secs(30);
        assert!(
            link.run_until(deadline, |l| {
                l.client.connected()
                    && l.server
                        .events
                        .iter()
                        .any(|e| matches!(e, Event::Restarted))
            }),
            "authenticated cookies {authenticated}: the restart did not complete"
        );
        let new_client_tag = link.client.conn().my_verification_tag;
        let conn = link.server.conn();
        assert_eq!(conn.state(), AssociationState::Established);
        assert_ne!(conn.my_verification_tag, old_tag, "a new local tag");
        assert_ne!(conn.peer_verification_tag, old_peer_tag);
        assert_eq!(conn.peer_verification_tag, new_client_tag);
        assert!(conn.cwnd > 1200, "cwnd back at its initial value");
        assert_eq!(
            conn.rto_mgr.get_rto(),
            RtoManager::new().get_rto(),
            "the RTO too"
        );
        assert!(conn.streams.is_empty(), "the old streams are gone");
        assert_eq!(
            link.server.endpoint_associations(),
            1,
            "still one association"
        );

        // The restarted peer's data arrives.
        link.client.conn().open_stream(3, ppi)?;
        link.client
            .conn()
            .stream(3)?
            .write_sctp(link.now, &Bytes::from_static(b"after"), ppi)?;
        link.run_for(Duration::from_secs(1));
        assert!(
            link.server
                .received
                .iter()
                .any(|(id, m)| *id == 3 && m == &b"after"[..]),
            "authenticated cookies {authenticated}"
        );
    }
    Ok(())
}

/// RFC 9260 5.2.4 action A in SHUTDOWN-ACK-SENT: no new association; the SHUTDOWN ACK is
/// sent again and an ERROR "Cookie Received While Shutting Down" goes to the peer. And a
/// restart cookie past its lifetime gets an ERROR "Stale Cookie" (5.2.4 3)).
#[test]
fn a_restart_cookie_in_shutdown_ack_sent_or_stale_does_not_restart() -> Result<()> {
    for case in ["shutting down", "stale"] {
        let now = Instant::now();
        let mut a = timed_test_association();
        a.set_cookie_signer(signer());
        a.peer_verification_tag = 0x1111_2222;
        let own = a.my_verification_tag;
        let init = init_from_peer(&a, 0x7777_8888);
        inject(&mut a, now, init);
        let (cookie, new_tag) = cookie_of(&sent_datagrams(&mut a, now));
        let at = if case == "stale" {
            now + a.valid_cookie_life + Duration::from_secs(1)
        } else {
            a.set_state(AssociationState::ShutdownAckSent);
            now
        };
        let echo = raw_packet(
            a.destination_port,
            a.source_port,
            new_tag,
            &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)],
        );
        inject(&mut a, at, echo);
        let sent = sent_datagrams(&mut a, at);
        let errors = chunks_of_type(&sent, CT_ERROR.0);
        assert_eq!(errors.len(), 1, "{case}");
        let cause = u16::from_be_bytes([errors[0][4], errors[0][5]]);
        if case == "stale" {
            assert_eq!(cause, 3, "Stale Cookie");
            assert_eq!(a.state(), AssociationState::Established);
        } else {
            assert_eq!(cause, 10, "Cookie Received While Shutting Down");
            assert_eq!(a.state(), AssociationState::ShutdownAckSent);
            assert_eq!(
                chunks_of_type(&sent, CT_SHUTDOWN_ACK.0).len(),
                1,
                "the SHUTDOWN ACK again"
            );
        }
        assert_eq!(a.my_verification_tag, own, "{case}: no new association");
        assert!(a.events.iter().all(|e| !matches!(e, Event::Restarted)));
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------
// Rule A's zero window probe (6.1) and the order of cwnd updates (7.2.4).
// ----------------------------------------------------------------------------------------

/// RFC 9260 6.1 rule A: with the peer's window at 0, one DATA chunk goes out as a zero
/// window probe only when nothing is in flight, so within what cwnd allows; with a chunk in
/// flight, nothing new is sent.
#[test]
fn a_zero_window_probe_goes_only_with_nothing_in_flight() -> Result<()> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut a = timed_test_association();
    a.cwnd = 4 * a.mtu;
    a.rwnd = 0;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from(vec![1; 100]), ppi)?;
    stream.write_sctp(now, &Bytes::from(vec![2; 100]), ppi)?;
    let probe = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(probe.len(), 1, "one probe");
    assert!(a.inflight_queue.get_num_bytes() as u32 <= a.cwnd);
    a.rwnd = 0;
    let more = transmitted_data(&a.gather_outbound(now).0);
    assert!(
        more.is_empty(),
        "no second chunk while the probe is in flight"
    );
    Ok(())
}

/// RFC 9260 6.1 rule A: "The sender MUST also have an algorithm for sending new DATA chunks
/// to avoid silly window syndrome (SWS) as described in [RFC1122]". The sender never cuts a
/// chunk to fit a small window: a message is fragmented by the path's packet size alone, and a
/// window smaller than the next fragment sends nothing while data is in flight (the one
/// exception, the zero window probe with nothing in flight, is a whole fragment too). A
/// window that opens a little at a time is never filled with scraps.
#[test]
fn a_small_window_is_not_filled_with_small_chunks() -> Result<()> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut a = timed_test_association();
    a.cwnd = 8 * a.mtu;
    let fragment = a.max_payload_size as usize;
    a.rwnd = 300;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from(vec![1; 3 * fragment]), ppi)?;
    let probe = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(probe.len(), 1, "the zero window probe only");
    assert_eq!(
        probe[0].user_data.len(),
        fragment,
        "a whole fragment, not 300 bytes"
    );
    for window in [300, 600, fragment as u32 - 1] {
        a.rwnd = window;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert!(
            sent.is_empty(),
            "a window of {window}: {} chunks",
            sent.len()
        );
    }
    a.rwnd = fragment as u32;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user_data.len(), fragment);
    Ok(())
}

/// RFC 9260 7.2.4: the growth of cwnd a SACK earns (7.2.1, 7.2.2) is applied before the
/// adjustment for the loss the same SACK reports: the new ssthresh is half of the grown cwnd.
#[test]
fn cwnd_grows_before_the_loss_adjustment_of_the_same_sack() -> Result<()> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    // Twelve 1000-byte chunks in flight, cwnd in full use, slow start.
    let build = |misses: u32| -> Result<Association> {
        let mut a = timed_test_association();
        a.my_next_tsn = 100;
        a.cumulative_tsn_ack_point = 99;
        a.advanced_peer_tsn_ack_point = 99;
        a.min_tsn2measure_rtt = 100;
        a.cwnd = 64 * a.mtu;
        a.ssthresh = u32::MAX / 2;
        a.rwnd = 1 << 20;
        let mut stream = a.open_stream(1, ppi)?;
        for _ in 0..12 {
            stream.write_sctp(now, &Bytes::from(vec![0; 1000]), ppi)?;
        }
        assert_eq!(12, transmitted_data(&a.gather_outbound(now).0).len());
        a.cwnd = a.inflight_queue.get_num_bytes() as u32;
        a.inflight_queue.get_mut(101).unwrap().miss_indicator = misses;
        // 100 cumulatively, 102..=111 by a block: 101 is reported missing.
        a.handle_sack(&sack(100, vec![(2, 11)]), now)?;
        Ok(a)
    };
    let grown = build(0)?;
    assert!(!grown.in_fast_recovery);
    let lost = build(2)?;
    assert!(lost.in_fast_recovery, "the third miss indication");
    let expected = std::cmp::max(grown.cwnd / 2, 4 * lost.pmdcs);
    assert_eq!(lost.ssthresh, expected);
    assert_eq!(lost.cwnd, expected);
    assert!(grown.cwnd > 12_000, "the SACK did grow cwnd");
    Ok(())
}

/// RFC 8831 section 6.2: "the number of streams negotiated during SCTP association setup
/// SHOULD be 65535, which is the maximum number of streams that can be negotiated during the
/// association setup". The default INIT announces 65535 outbound and 65535 inbound streams.
#[test]
fn the_default_init_announces_65535_streams_each_way() {
    let mut client = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = client
        .connect(
            now,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let init = sent_datagrams(&mut a, now);
    let (_, outbound, inbound, _) = init_fields(&chunks_of(&init[0])[0]);
    assert_eq!((outbound, inbound), (u16::MAX, u16::MAX));
}

/// RFC 9260 6.9: "An implementation MAY allow the upper layer to disable fragmentation", and
/// then "MUST react just like an implementation that does NOT support fragmentation, i.e., it
/// MUST reject sends that exceed the current PMDCS". With `with_fragmentation(false)` a message
/// one byte larger than a DATA chunk can carry is refused, and one that fits goes in one chunk;
/// by default the larger one is sent in two fragments.
#[test]
fn an_upper_layer_can_turn_fragmentation_off() -> Result<()> {
    for fragmentation in [true, false] {
        let mut a =
            create_association(TransportConfig::default().with_fragmentation(fragmentation));
        a.set_state(AssociationState::Established);
        a.cwnd = 1 << 20;
        a.rwnd = 1 << 20;
        let now = Instant::now();
        let fits = a.fragment_size() as usize;
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut s = a.open_stream(1, ppi)?;
        s.write_sctp(now, &Bytes::from(vec![1u8; fits]), ppi)?;
        let larger = s.write_sctp(now, &Bytes::from(vec![2u8; fits + 1]), ppi);
        if fragmentation {
            assert!(larger.is_ok());
            assert_eq!(3, transmitted_data(&a.gather_outbound(now).0).len());
        } else {
            assert!(matches!(larger, Err(Error::ErrOutboundPacketTooLarge)));
            let sent = transmitted_data(&a.gather_outbound(now).0);
            assert_eq!(1, sent.len(), "the message that fits, whole");
            assert!(sent[0].beginning_fragment && sent[0].ending_fragment);
        }
    }
    Ok(())
}
