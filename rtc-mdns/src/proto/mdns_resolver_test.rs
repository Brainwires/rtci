//! The resolver: query series, which responses resolve, and the cache (RFC 6762 sections 5,
//! 6, 6.1, 7.3, 10, 11, 16 to 18; draft-ietf-mmusic-mdns-ice-candidates sections 3.2.1, 3.2.2).

use super::testkit::*;
use super::wire::{CLASS_IN, CLASS_TOP_BIT, TYPE_A, TYPE_AAAA, TYPE_NSEC};
use super::*;
use sansio::Protocol;

/// The host that owns `UUID_1`, as address and as mDNS source.
const OWNER: &str = "192.168.1.50";
const OWNER_SRC: &str = "192.168.1.50:5353";

/// A resolver with a query for `UUID_1` sent at `base`, its packet taken off the queue.
fn asking(base: Instant, config: MdnsConfig) -> (Mdns, QueryId) {
    let mut conn = Mdns::new(base, config);
    let id = conn.query_now(base, UUID_1);
    assert_eq!(sent(&mut conn, base).len(), 1);
    (conn, id)
}

/// Whether `bytes` from `from`, received on the multicast group, resolves a query for
/// `UUID_1` to `OWNER`.
fn resolves(bytes: &[u8], from: &str) -> bool {
    let base = Instant::now();
    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, from, bytes);
    let answered = answered(&mut conn);
    if answered.is_empty() {
        assert!(conn.is_query_pending(id), "an ignored answer ends nothing");
        return false;
    }
    assert_eq!(answered, vec![(id, ip(OWNER))]);
    assert!(!conn.is_query_pending(id));
    true
}

fn query_times(packets: &[Sent]) -> Vec<Duration> {
    packets
        .iter()
        .filter(|p| !p.is_response())
        .map(|p| p.at)
        .collect()
}

// RFC 6762 section 5.2: one second between the first two queries, then at least double each
// time. Retries used to come every second for the life of the query.
#[test]
fn test_query_intervals_double() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().without_query_timeout());
    let id = conn.query_now(base, UUID_1);
    let out = run(&mut conn, base, ms(0), ms(130_000));
    let seconds: Vec<u64> = query_times(&out).iter().map(|t| t.as_secs()).collect();
    assert_eq!(seconds, vec![0, 1, 3, 7, 15, 31, 63, 127]);
    assert!(conn.is_query_pending(id));
}

// RFC 6762 section 5.2: the interval may stop growing at 60 minutes.
#[test]
fn test_query_interval_stops_growing_at_an_hour() {
    let base = Instant::now();
    let mut conn = Mdns::new(
        base,
        config()
            .without_query_timeout()
            .with_query_interval(Duration::from_secs(40 * 60)),
    );
    conn.query_now(base, UUID_1);
    let out = run(&mut conn, base, ms(0), Duration::from_secs(4 * 3600));
    let minutes: Vec<u64> = query_times(&out).iter().map(|t| t.as_secs() / 60).collect();
    assert_eq!(minutes, vec![0, 40, 100, 160, 220]);
}

// RFC 6762 section 5.2: at least one second between the first two queries, whatever is asked
// for.
#[test]
fn test_first_retry_is_no_sooner_than_a_second() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_query_interval(ms(100)));
    conn.query_now(base, UUID_1);
    assert_eq!(sent(&mut conn, base).len(), 1);
    assert_eq!(conn.poll_timeout(), Some(base + ms(1000)));
    let out = run(&mut conn, base, ms(0), ms(1000));
    assert_eq!(query_times(&out), vec![ms(1000)]);
}

// A query nobody answers ends by itself: it used to be retried for ever unless a timeout was
// configured.
#[test]
fn test_unanswered_query_ends_after_thirty_seconds_by_default() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    let id = conn.query_now(base, UUID_1);
    let out = run(&mut conn, base, ms(0), ms(29_999));
    assert_eq!(out.len(), 5, "sent at 0, 1, 3, 7 and 15 s");
    assert!(conn.is_query_pending(id));
    assert_eq!(conn.poll_timeout(), Some(base + ms(30_000)));

    let out = run(&mut conn, base, ms(29_999), ms(600_000));
    assert!(out.is_empty(), "nothing is sent for a query that ended");
    assert_eq!(ended(&mut conn), vec![id]);
    assert!(!conn.is_query_pending(id));
    assert!(conn.poll_timeout().is_none());
}

// RFC 6762 section 5.2: the first query of a series waits a random 20 to 120 ms, when the
// connection is configured to (the default sends it from the `handle_timeout` that starts it).
#[test]
fn test_scheduled_query_first_goes_out_after_20_to_120_ms() {
    let base = Instant::now();
    let mut waits = std::collections::HashSet::new();
    for seed in 0..20 {
        let delayed = MdnsConfig::default()
            .with_jitter_seed(seed)
            .with_first_query_delay(true);
        let mut conn = Mdns::new(base, delayed);
        let id = conn.schedule_query(UUID_1);
        assert!(conn.is_query_pending(id));
        assert_eq!(
            conn.poll_timeout(),
            Some(base),
            "the caller is asked for the time"
        );
        let out = run(&mut conn, base, ms(0), ms(500));
        assert_eq!(out.len(), 1);
        assert!((ms(20)..=ms(120)).contains(&out[0].at), "{:?}", out[0].at);
        // The retry is a second after the query, not after it was scheduled.
        assert_eq!(conn.poll_timeout(), Some(base + out[0].at + ms(1000)));
        waits.insert(out[0].at);
    }
    assert!(waits.len() > 10, "the wait is random: {waits:?}");

    let mut conn = Mdns::new(base, config());
    conn.schedule_query(UUID_1);
    assert!(
        sent(&mut conn, base).is_empty(),
        "not before the caller gives the time"
    );
    conn.handle_timeout(base).unwrap();
    assert_eq!(sent(&mut conn, base).len(), 1, "without the delay: at once");
}

// RFC 6762 sections 5.2, 18: a query leaves from port 5353 for the group, with ID, flags and
// record counts zero, asking for A and AAAA, and without the unicast-response bit.
#[test]
fn test_query_message_format() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    conn.query_now(base, UUID_1);
    let out = run(&mut conn, base, ms(0), ms(1000));
    assert_eq!(out.len(), 2, "the query and its first retry");
    for packet in &out {
        assert_eq!(packet.from, "0.0.0.0:5353".parse().unwrap());
        assert_eq!(packet.to, MDNS_DEST_ADDR);
        // ID 0; QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE all 0; two questions, no records.
        assert_eq!(&packet.raw[..12], &[0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
        let asked: Vec<(u16, u16, bool)> = packet
            .msg
            .questions
            .iter()
            .map(|q| (q.typ, q.class, q.unicast))
            .collect();
        assert_eq!(
            asked,
            vec![(TYPE_A, CLASS_IN, false), (TYPE_AAAA, CLASS_IN, false)]
        );
        assert!(
            packet
                .msg
                .questions
                .iter()
                .all(|q| q.name == format!("{UUID_1}."))
        );
    }
}

// draft-ietf-mmusic-mdns-ice-candidates section 3.2.1, RFC 6762 section 5.4: when asked to,
// the first query of a series sets the unicast-response bit; a retry never does.
#[test]
fn test_unicast_response_bit_is_set_on_the_first_query_only() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_unicast_response(true));
    conn.query_now(base, UUID_1);
    let out = run(&mut conn, base, ms(0), ms(3000));
    assert_eq!(out.len(), 3);
    let unicast: Vec<Vec<bool>> = out
        .iter()
        .map(|p| p.msg.questions.iter().map(|q| q.unicast).collect())
        .collect();
    assert_eq!(
        unicast,
        vec![vec![true, true], vec![false, false], vec![false, false]]
    );
    // The bit is the top bit of the class field, which stays IN.
    assert_eq!(&out[0].raw[out[0].raw.len() - 2..], &[0x80, 0x01]);
}

// RFC 6762 section 6: a unicast response is taken only for a question that asked for one
// within the last two seconds.
#[test]
fn test_unicast_response_is_taken_only_for_a_recent_unicast_question() {
    let base = Instant::now();
    let own: SocketAddr = "192.168.1.30:5353".parse().unwrap();
    let answer = response(&[addr(UUID_1, OWNER)]);

    let (mut conn, id) = asking(base, config().with_unicast_response(true));
    deliver_to(&mut conn, base + ms(500), OWNER_SRC, own, &answer);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    // More than two seconds after the question that asked for it.
    let (mut conn, id) = asking(base, config().with_unicast_response(true));
    run(&mut conn, base, ms(0), ms(2500));
    deliver_to(&mut conn, base + ms(2500), OWNER_SRC, own, &answer);
    assert!(answered(&mut conn).is_empty());
    assert!(conn.is_query_pending(id));
    // The same response on the group is taken.
    deliver(&mut conn, base + ms(2500), OWNER_SRC, &answer);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    // A caller that does not report destinations has every datagram taken as a multicast
    // arrival, whatever `local_addr` says (a socket's bound address, usually).
    let (mut conn, id) = asking(base, MdnsConfig::default());
    deliver_to(&mut conn, base + ms(500), OWNER_SRC, own, &answer);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    // A question that did not ask for a unicast response does not get one.
    let (mut conn, id) = asking(base, config());
    deliver_to(&mut conn, base + ms(500), OWNER_SRC, own, &answer);
    assert!(answered(&mut conn).is_empty());
    assert!(conn.is_query_pending(id));
    // Nor is what it carried kept for later.
    conn.cancel_query(id);
    let again = conn.query_now(base + ms(600), UUID_1);
    assert!(conn.is_query_pending(again));
}

// RFC 6762 section 6: a response from another source port is ignored.
#[test]
fn test_response_from_another_port_does_not_resolve() {
    let answer = response(&[addr(UUID_1, OWNER)]);
    assert!(resolves(&answer, OWNER_SRC));
    assert!(!resolves(&answer, "192.168.1.50:40000"));
}

// RFC 6762 sections 18.3, 18.11: a response with another OPCODE, or an RCODE, is ignored.
#[test]
fn test_response_with_another_opcode_or_an_rcode_does_not_resolve() {
    let with_flags = |flags: u16| message(0, flags, &[], &[addr(UUID_1, OWNER)], &[], &[]);
    assert!(resolves(&with_flags(RESPONSE), OWNER_SRC));
    assert!(
        !resolves(&with_flags(RESPONSE | 0x0003), OWNER_SRC),
        "RCODE 3"
    );
    assert!(
        !resolves(&with_flags(RESPONSE | 0x2800), OWNER_SRC),
        "OPCODE 5"
    );
    // The bits a receiver must ignore (AA clear; TC, RD, RA, Z, AD, CD set) change nothing,
    // and neither does the ID.
    assert!(resolves(&with_flags(0x8000 | 0x03F0), OWNER_SRC));
    let with_id = message(0xBEEF, RESPONSE, &[], &[addr(UUID_1, OWNER)], &[], &[]);
    assert!(resolves(&with_id, OWNER_SRC));
}

// RFC 6762 section 6.1: a record that is not understood must not hide the rest of the
// message. A TXT or NSEC record ahead of the address record used to end the scan.
#[test]
fn test_address_record_after_records_of_other_types_resolves() {
    let answer = response(&[
        other(UUID_1, TYPE_TXT, b"\x03abc"),
        // An NSEC record that is not in the restricted form.
        other(UUID_1, TYPE_NSEC, &[0xff, 0xff, 0xff]),
        // An unknown type.
        other(UUID_1, 65, &[1, 2, 3, 4]),
        addr(UUID_1, OWNER),
    ]);
    assert!(resolves(&answer, OWNER_SRC));
}

// RFC 6762 sections 6.4, 18.1: a responder aggregates. Only the first four Answer records used
// to be read, and the Additional section never.
#[test]
fn test_address_record_beyond_the_fourth_and_in_the_additional_section_resolves() {
    let mut answers: Vec<Rec> = (1..=9)
        .map(|i| addr(&format!("other-{i}.local"), OWNER))
        .collect();
    answers.push(addr(UUID_1, OWNER));
    assert!(resolves(&response(&answers), OWNER_SRC));

    let additional = message(
        0,
        RESPONSE,
        &[],
        &[addr("other.local", OWNER)],
        &[],
        &[addr(UUID_1, OWNER)],
    );
    assert!(resolves(&additional, OWNER_SRC));
    // The Authority section of a response answers nothing.
    let authority = message(0, RESPONSE, &[], &[], &[addr(UUID_1, OWNER)], &[]);
    assert!(!resolves(&authority, OWNER_SRC));
}

// RFC 6762 section 16, RFC 1035 section 2.3.3: a responder answers in its own spelling.
#[test]
fn test_answer_in_another_case_resolves() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    let id = conn.query_now(base, &UUID_1.to_ascii_uppercase());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);
}

// RFC 6762 section 16: names are UTF-8. A record whose name is not is stepped over, and what
// follows it is read.
#[test]
fn test_record_with_a_name_that_is_not_utf8_is_stepped_over() {
    let mut bytes = message(0, RESPONSE, &[], &[addr("xx.local", OWNER)], &[], &[]);
    // The first label of the first record: two bytes that are not UTF-8.
    assert_eq!(&bytes[12..15], &[2, b'x', b'x']);
    bytes[13] = 0xff;
    bytes[14] = 0xfe;
    let rest = message(0, RESPONSE, &[], &[addr(UUID_1, OWNER)], &[], &[]);
    bytes.extend_from_slice(&rest[12..]);
    bytes[7] = 2;
    assert!(resolves(&bytes, OWNER_SRC));
}

// RFC 6762 section 17: no mDNS message is over 9000 bytes.
#[test]
fn test_datagram_over_9000_bytes_is_ignored() {
    let mut answer = response(&[addr(UUID_1, OWNER)]);
    answer.resize(9000, 0);
    assert!(resolves(&answer, OWNER_SRC));
    answer.resize(9001, 0);
    assert!(!resolves(&answer, OWNER_SRC));
}

// draft-ietf-mmusic-mdns-ice-candidates section 3.2.2: a name with more than one address is
// not resolved. The first record used to win.
#[test]
fn test_name_with_two_addresses_does_not_resolve() {
    let base = Instant::now();
    let both = response(&[addr(UUID_1, OWNER), addr(UUID_1, "fe80::50")]);

    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, OWNER_SRC, &both);
    let events = events(&mut conn);
    assert!(
        matches!(&events[..], [MdnsEvent::QueryTimeout(ended)] if *ended == id),
        "{events:?}"
    );
    assert!(!conn.is_query_pending(id));
    assert!(conn.poll_timeout().is_none(), "the query is over");

    // The same address twice is one address.
    let (mut conn, id) = asking(base, config());
    let twice = response(&[addr(UUID_1, OWNER), addr(UUID_1, OWNER)]);
    deliver(&mut conn, base, OWNER_SRC, &twice);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    // A resolver that is not an ICE agent's may take the first.
    let (mut conn, id) = asking(base, config().with_multiple_addresses(true));
    deliver(&mut conn, base, OWNER_SRC, &both);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);
}

// RFC 6762 section 6.1: the restricted-form NSEC record is read. A name whose owner says it
// has neither an A nor an AAAA record resolves to nothing, at once.
#[test]
fn test_nsec_saying_the_name_has_no_address_ends_the_query() {
    let base = Instant::now();
    let nsec = |bitmap: &[u8]| {
        let mut rdata = wire_name(UUID_1);
        rdata.push(0);
        rdata.push(bitmap.len() as u8);
        rdata.extend_from_slice(bitmap);
        response(&[other(UUID_1, TYPE_NSEC, &rdata)])
    };

    // Only a TXT record (type 16) exists.
    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, OWNER_SRC, &nsec(&[0, 0, 0x80]));
    assert_eq!(ended(&mut conn), vec![id]);
    assert!(!conn.is_query_pending(id));

    // An A record exists (and no AAAA): the query waits for it.
    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, OWNER_SRC, &nsec(&[0x40]));
    assert!(events(&mut conn).is_empty());
    assert!(conn.is_query_pending(id));

    // Not from off the link.
    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, "203.0.113.9:5353", &nsec(&[0, 0, 0x80]));
    assert!(conn.is_query_pending(id));
}

// RFC 6762 section 11: with the link's subnets configured, they decide who is on the link.
#[test]
fn test_configured_subnets_decide_who_is_on_the_link() {
    let base = Instant::now();
    let subnets = vec![(ip("203.0.113.0"), 24), (ip("fe80::"), 10)];
    let public = response(&[addr(UUID_1, "203.0.113.9")]);

    let (mut conn, id) = asking(base, config().with_on_link_subnets(subnets.clone()));
    deliver(&mut conn, base, "203.0.113.9:5353", &public);
    assert_eq!(answered(&mut conn), vec![(id, ip("203.0.113.9"))]);

    // A private address that is not in a configured subnet is not on this link.
    let (mut conn, id) = asking(base, config().with_on_link_subnets(subnets.clone()));
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    assert!(answered(&mut conn).is_empty());
    let aaaa = response(&[addr(UUID_1, "2001:db8::7")]);
    deliver(&mut conn, base, OWNER_SRC, &aaaa);
    assert!(answered(&mut conn).is_empty());
    deliver(&mut conn, base, "[fe80::7]:5353", &aaaa);
    assert_eq!(answered(&mut conn), vec![(id, ip("2001:db8::7"))]);

    // Without subnets, the address scope decides: a public IPv4 sender is refused.
    let (mut conn, id) = asking(base, config());
    deliver(&mut conn, base, "203.0.113.9:5353", &public);
    assert!(conn.is_query_pending(id));
}

// RFC 6762 sections 5.2, 18.1: an address heard in a response is cached, so a name announced
// by its owner, or resolved before, answers without a query.
#[test]
fn test_announced_name_resolves_from_the_cache_without_a_query() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    assert!(events(&mut conn).is_empty());

    let id = conn.query_now(base + ms(5000), UUID_1);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);
    assert!(!conn.is_query_pending(id));
    assert!(sent(&mut conn, base).is_empty(), "no query goes out");

    let id = conn.schedule_query(&UUID_1.to_ascii_uppercase());
    let out = run(&mut conn, base, ms(6000), ms(7000));
    assert!(out.is_empty());
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);
}

// RFC 6762 section 5.2: a cached record is gone when its TTL is over.
#[test]
fn test_cached_address_expires_at_its_ttl() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER).ttl(120)]),
    );
    // Nobody asks for the name: the record is not kept alive with queries of our own.
    assert!(conn.poll_timeout().is_none());
    let id = conn.query_now(base + ms(119_999), UUID_1);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    let id = conn.query_now(base + ms(120_000), UUID_1);
    assert!(conn.is_query_pending(id), "the record has expired");
    assert_eq!(sent(&mut conn, base).len(), 1, "so the name is asked for");
}

// RFC 6762 section 10.1: a goodbye is acted on a second later, not at once; and it resolves
// nothing.
#[test]
fn test_goodbye_leaves_the_cache_a_second_later() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    let goodbye = response(&[addr(UUID_1, OWNER).ttl(0)]);
    deliver(&mut conn, base + ms(10_000), OWNER_SRC, &goodbye);

    let id = conn.query_now(base + ms(10_900), UUID_1);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))], "still there");
    let id = conn.query_now(base + ms(11_000), UUID_1);
    assert!(conn.is_query_pending(id), "gone a second after the goodbye");
    deliver(&mut conn, base + ms(11_000), OWNER_SRC, &goodbye);
    assert!(conn.is_query_pending(id));
    assert!(events(&mut conn).is_empty());
}

// RFC 6762 section 10.2: a record with the cache-flush bit replaces what was heard for its
// name and type more than a second ago; one without it is added.
#[test]
fn test_cache_flush_record_replaces_older_addresses() {
    let base = Instant::now();
    let newer = addr(UUID_1, "192.168.1.60");

    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    deliver(
        &mut conn,
        base + ms(5000),
        "192.168.1.60:5353",
        &response(std::slice::from_ref(&newer)),
    );
    let id = conn.query_now(base + ms(6001), UUID_1);
    assert_eq!(answered(&mut conn), vec![(id, ip("192.168.1.60"))]);

    // Without the bit both stay, and a name with two addresses does not resolve.
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    deliver(
        &mut conn,
        base + ms(5000),
        "192.168.1.60:5353",
        &response(&[newer.class(CLASS_IN)]),
    );
    let id = conn.query_now(base + ms(6001), UUID_1);
    assert_eq!(ended(&mut conn), vec![id]);
}

// Flood control: any host on the link can offer records, so the cache has a fixed size.
#[test]
fn test_cache_is_bounded() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    for batch in 0..10 {
        let records: Vec<Rec> = (0..50)
            .map(|i| addr(&format!("flood-{batch}-{i}.local"), "fe80::bad").ttl(100))
            .collect();
        deliver(&mut conn, base, "192.168.1.66:5353", &response(&records));
    }
    assert_eq!(conn.cache.len(), MAX_CACHED_ADDRESSES);

    // A record that lives longer than the one nearest its expiry takes its place; one that
    // does not is not taken.
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr("short.local", OWNER).ttl(50)]),
    );
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    assert_eq!(conn.cache.len(), MAX_CACHED_ADDRESSES);
    let id = conn.query_now(base, "short.local");
    assert!(conn.is_query_pending(id));
    let id = conn.query_now(base, UUID_1);
    assert_eq!(answered(&mut conn), vec![(id, ip(OWNER))]);

    // Expired entries make room.
    conn.handle_timeout(base + Duration::from_secs(200))
        .unwrap();
    assert!(conn.cache.is_empty());
}

// RFC 6762 section 7.1: the Known-Answer section of another host's query is not cached.
#[test]
fn test_known_answers_of_a_query_are_not_cached() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    let query = message(
        0,
        QUERY,
        &[(UUID_1, TYPE_A, CLASS_IN)],
        &[addr(UUID_1, OWNER)],
        &[],
        &[],
    );
    deliver(&mut conn, base, OWNER_SRC, &query);
    let id = conn.query_now(base, UUID_1);
    assert!(conn.is_query_pending(id));
    assert_eq!(sent(&mut conn, base).len(), 1);
}

// RFC 6762 section 7.3: the same question, multicast by another host, counts as ours sent.
#[test]
fn test_question_seen_from_another_host_counts_as_sent() {
    let base = Instant::now();
    let (mut conn, id) = asking(base, config().without_query_timeout());
    deliver(
        &mut conn,
        base + ms(500),
        "192.168.1.31:5353",
        &query_for(UUID_1),
    );
    assert!(sent(&mut conn, base).is_empty(), "we do not own the name");
    let out = run(&mut conn, base, ms(500), ms(6499));
    assert_eq!(
        query_times(&out),
        vec![ms(2500)],
        "the retry due at 1 s is not sent; the next comes two seconds after the question seen"
    );
    assert!(conn.is_query_pending(id));
}

#[test]
fn test_question_that_does_not_stand_for_ours_changes_nothing() {
    let base = Instant::now();
    let other_host = "192.168.1.31:5353";
    let retry_at = |bytes: &[u8], from: &str, after: Duration, config: MdnsConfig| {
        let (mut conn, _) = asking(base, config.without_query_timeout());
        deliver(&mut conn, base + after, from, bytes);
        let out = run(&mut conn, base, after, ms(1500));
        query_times(&out)
    };
    let on_time = vec![ms(1000)];

    // One that asks for a unicast response: its answer goes to the asker alone.
    let qu = message(
        0,
        QUERY,
        &[
            (UUID_1, TYPE_A, CLASS_IN | CLASS_TOP_BIT),
            (UUID_1, TYPE_AAAA, CLASS_IN | CLASS_TOP_BIT),
        ],
        &[],
        &[],
        &[],
    );
    assert_eq!(retry_at(&qu, other_host, ms(500), config()), on_time);

    // One whose known answers would keep the answer from us.
    let knowing = message(
        0,
        QUERY,
        &[(UUID_1, TYPE_A, CLASS_IN), (UUID_1, TYPE_AAAA, CLASS_IN)],
        &[addr(UUID_1, OWNER).class(CLASS_IN)],
        &[],
        &[],
    );
    assert_eq!(retry_at(&knowing, other_host, ms(500), config()), on_time);

    // Half of ours.
    let only_a = message(0, QUERY, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
    assert_eq!(retry_at(&only_a, other_host, ms(500), config()), on_time);

    // Our own, handed back by the link right after it went out, or coming from an address
    // of ours.
    let ours = query_for(UUID_1);
    assert_eq!(retry_at(&ours, other_host, ms(50), config()), on_time);
    let with_address = config()
        .with_local_names(vec![UUID_2.to_owned()])
        .with_local_ip(ip("192.168.1.31"));
    let out = retry_at(&ours, other_host, ms(500), with_address);
    assert!(out.contains(&ms(1000)), "{out:?}");
}

// RFC 6762 section 10.3: what was learned on another link is not carried over.
#[test]
fn test_network_change_empties_the_cache() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    deliver(
        &mut conn,
        base,
        OWNER_SRC,
        &response(&[addr(UUID_1, OWNER)]),
    );
    conn.network_changed();
    let id = conn.query_now(base, UUID_1);
    assert!(conn.is_query_pending(id));
    assert_eq!(sent(&mut conn, base).len(), 1);
}
