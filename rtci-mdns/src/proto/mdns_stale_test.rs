//! Cached records found stale before their TTL ends: reconfirmation on a client's hint (RFC
//! 6762 section 10.4) and passive observation of other hosts' unanswered queries (section
//! 10.5).

use super::testkit::*;
use super::*;

const OWNER: &str = "192.168.1.50";
const OWNER_SRC: &str = "192.168.1.50:5353";
/// Another host on the link that asks for the name.
const ASKER_SRC: &str = "192.168.1.60:5353";

/// A resolver that has `UUID_1` -> `OWNER` in its cache (TTL 120 s), from an announcement at
/// `base`.
fn caching(base: Instant) -> Mdns {
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    assert!(cached(&mut conn, base));
    conn
}

/// Whether a query for `UUID_1` at `now` is answered from the cache (no packet sent).
fn cached(conn: &mut Mdns, now: Instant) -> bool {
    let id = conn.query_now(now, UUID_1);
    let hit = answered(conn).iter().any(|&(q, _)| q == id);
    if !hit {
        conn.cancel_query(id);
    }
    let _ = sent(conn, now);
    hit
}

/// Queries for `UUID_1` among `out`.
fn queries_for_the_name(out: &[Sent]) -> usize {
    out.iter()
        .filter(|s| {
            !s.is_response()
                && s.multicast()
                && s.msg
                    .questions
                    .iter()
                    .any(|q| q.name == format!("{UUID_1}."))
        })
        .count()
}

/// Section 10.4: "When the cache receives this hint that it should reconfirm some record, it
/// MUST issue two or more queries for the resource record in dispute. If no response is
/// received within ten seconds, then [...] that record SHOULD be promptly flushed from the
/// cache."
#[test]
fn test_reconfirmation_sends_two_queries_and_flushes_an_unanswered_record_after_ten_seconds() {
    let base = Instant::now();
    let mut conn = caching(base);
    assert!(conn.reconfirm(base, UUID_1));
    assert!(conn.is_reconfirming(UUID_1));
    assert!(
        !conn.reconfirm(base, UUID_1),
        "one reconfirmation at a time"
    );
    let out = run(&mut conn, base, ms(0), ms(9_900));
    assert!(queries_for_the_name(&out) >= 2, "two or more queries");
    assert!(
        cached(&mut conn, base + ms(9_900)),
        "kept within the ten seconds"
    );

    run(&mut conn, base, ms(9_900), ms(10_000));
    assert!(!conn.is_reconfirming(UUID_1));
    assert!(
        !cached(&mut conn, base + ms(10_000)),
        "flushed although its TTL has 110 s to go"
    );
}

/// A response in the ten seconds keeps the record; a name not in the cache has nothing to
/// reconfirm.
#[test]
fn test_reconfirmed_record_stays_and_an_uncached_name_is_not_reconfirmed() {
    let base = Instant::now();
    let mut conn = caching(base);
    assert!(!conn.reconfirm(base, UUID_2));
    assert!(conn.reconfirm(base + ms(1_000), UUID_1));
    run(&mut conn, base, ms(1_000), ms(3_000));
    deliver(
        &mut conn,
        base + ms(3_000),
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    run(&mut conn, base, ms(3_000), ms(12_000));
    assert!(cached(&mut conn, base + ms(12_000)));
}

/// Section 10.5: "After seeing two or more of these queries, and seeing no multicast response
/// containing the expected answer within ten seconds, then even though its TTL may indicate
/// that it is not yet due to expire, that record SHOULD be flushed from the cache. The host
/// SHOULD NOT perform its own queries to reconfirm that the record is truly gone."
#[test]
fn test_record_other_hosts_ask_for_in_vain_is_flushed_without_queries_of_our_own() {
    let base = Instant::now();
    let mut conn = caching(base);
    deliver(&mut conn, base + ms(1_000), ASKER_SRC, &query_for(UUID_1));
    deliver(&mut conn, base + ms(2_000), ASKER_SRC, &query_for(UUID_1));
    let out = run(&mut conn, base, ms(2_000), ms(10_900));
    assert_eq!(queries_for_the_name(&out), 0, "no query of its own");
    assert!(
        cached(&mut conn, base + ms(10_900)),
        "not before ten seconds"
    );
    run(&mut conn, base, ms(10_900), ms(11_000));
    assert!(!cached(&mut conn, base + ms(11_000)));
}

/// One unanswered query is no indication, and a response with the record clears the count.
#[test]
fn test_one_unanswered_query_or_an_answered_pair_keeps_the_record() {
    let base = Instant::now();
    let mut conn = caching(base);
    deliver(&mut conn, base + ms(1_000), ASKER_SRC, &query_for(UUID_1));
    run(&mut conn, base, ms(1_000), ms(20_000));
    assert!(cached(&mut conn, base + ms(20_000)));

    let mut conn = caching(base);
    deliver(&mut conn, base + ms(1_000), ASKER_SRC, &query_for(UUID_1));
    deliver(&mut conn, base + ms(2_000), ASKER_SRC, &query_for(UUID_1));
    deliver(
        &mut conn,
        base + ms(2_100),
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    run(&mut conn, base, ms(2_100), ms(20_000));
    assert!(cached(&mut conn, base + ms(20_000)));
}
