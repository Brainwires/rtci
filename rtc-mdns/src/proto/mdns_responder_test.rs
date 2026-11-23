//! The responder: probing, announcing, answering, defending and withdrawing a name (RFC 6762
//! sections 6 to 10, 17, 18; draft-ietf-mmusic-mdns-ice-candidates sections 3.1.1, 7.1).

use super::testkit::*;
use super::wire::{
    CLASS_ANY, CLASS_IN, CLASS_TOP_BIT, MAX_OUTBOUND_MESSAGE, TYPE_A, TYPE_AAAA, TYPE_ANY,
    TYPE_NSEC,
};
use super::*;
use crate::config::MdnsProbePolicy;
use sansio::Protocol;

/// The responder's address, and another host on its link.
const HOST: &str = "192.168.1.20";
const PEER: &str = "192.168.1.30:5353";

/// A name an application chose: probed for.
const CHOSEN: &str = "printer.local";

fn key(name: &str) -> String {
    format!("{}.", name.to_ascii_lowercase())
}

/// One question, no known answers.
fn question(name: &str, typ: u16, class: u16) -> Vec<u8> {
    message(0, QUERY, &[(name, typ, class)], &[], &[], &[])
}

/// A probe for `name` as another host sends it: type ANY, its proposed record in the
/// Authority section.
fn probe(name: &str, proposed: &str, class: u16) -> Vec<u8> {
    message(
        0,
        QUERY,
        &[(name, TYPE_ANY, class)],
        &[],
        &[addr(name, proposed).class(CLASS_IN)],
        &[],
    )
}

/// A responder that has just been told its name, at its first probe: the probe is out.
/// Returns it with the probe's time since `base`.
fn at_first_probe(base: Instant, name: &str, address: &str) -> (Mdns, Duration) {
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(name, ip(address)));
    // The probe waits a random 0 to 250 ms, which may be none at all.
    conn.handle_timeout(base).unwrap();
    let mut out = sent(&mut conn, base);
    let mut first = base;
    if out.is_empty() {
        first = conn.poll_timeout().expect("the first probe is scheduled");
        conn.handle_timeout(first).unwrap();
        out = sent(&mut conn, base);
    }
    assert_eq!(out.len(), 1, "the first probe");
    assert!(!out[0].is_response());
    (conn, first.duration_since(base))
}

// RFC 6762 sections 8.3, 10, 10.2, 18; draft-ietf-mmusic-mdns-ice-candidates section 3.1.1.
#[test]
fn test_new_name_is_announced_twice_a_second_apart() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert!(
        sent(&mut conn, base).is_empty(),
        "nothing goes out before the caller gives the time"
    );
    assert_eq!(conn.poll_timeout(), Some(base), "which it is asked for now");

    let out = run(&mut conn, base, ms(0), ms(120_000));
    let times: Vec<Duration> = out.iter().map(|p| p.at).collect();
    assert_eq!(times, vec![ms(0), ms(1000)], "two, one second apart");
    for packet in &out {
        assert_eq!(packet.to, MDNS_DEST_ADDR);
        assert_eq!(packet.from, format!("{HOST}:5353").parse().unwrap());
        // ID zero; QR and AA set; OPCODE, TC, RD, RA, Z, AD, CD and RCODE zero.
        assert_eq!(&packet.raw[..2], &[0, 0]);
        assert_eq!(packet.flags(), 0x8400);
        assert!(packet.msg.questions.is_empty(), "a response asks nothing");
        assert_eq!(packet.msg.answers.len(), 1);
        let record = &packet.msg.answers[0];
        assert_eq!(record.key, key(UUID_1));
        assert_eq!((record.typ, record.class), (TYPE_A, CLASS_IN));
        assert!(record.flush, "a unique record carries the cache-flush bit");
        assert_eq!(record.ttl, 120, "a host name's record lives 120 seconds");
        assert_eq!(record.addr(), Some(ip(HOST)));
    }
    assert!(
        conn.poll_timeout().is_none(),
        "no periodic announcements follow"
    );
}

// RFC 6762 section 8.3: up to eight, the interval doubling.
#[test]
fn test_announcements_up_to_eight_double_their_interval() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_announce_count(8));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    let out = run(&mut conn, base, ms(0), ms(600_000));
    let seconds: Vec<u64> = out.iter().map(|p| p.at.as_secs()).collect();
    assert_eq!(seconds, vec![0, 1, 3, 7, 15, 31, 63, 127]);
    assert!(out.iter().all(|p| p.is_response()));

    // More than eight are not offered, fewer than two neither.
    let mut conn = Mdns::new(base, config().with_announce_count(200));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert_eq!(run(&mut conn, base, ms(0), ms(600_000)).len(), 8);
    let mut conn = Mdns::new(base, config().with_announce_count(0));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert_eq!(run(&mut conn, base, ms(0), ms(600_000)).len(), 2);
}

// RFC 6762 section 8.1 (last paragraph); draft-ietf-mmusic-mdns-ice-candidates section 3.1.1.
#[test]
fn test_uuid_name_is_not_probed_for_and_answers_at_once() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));

    // Answered from the moment it is registered, before anything was announced.
    deliver(&mut conn, base, PEER, &question(UUID_1, TYPE_A, CLASS_IN));
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.answers[0].addr(), Some(ip(HOST)));

    let out = run(&mut conn, base, ms(0), ms(10_000));
    assert!(!out.is_empty());
    assert!(
        out.iter().all(|p| p.is_response()),
        "no probe query is sent for a random name"
    );
}

// RFC 6762 sections 8.1, 8.2: three probes 250 ms apart after a random 0 to 250 ms, type ANY,
// asking for a unicast response, the proposed record in the Authority section; then announced.
#[test]
fn test_chosen_name_is_probed_three_times_then_announced() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(CHOSEN, ip(HOST)));
    let out = run(&mut conn, base, ms(0), ms(60_000));

    let (probes, announcements): (Vec<&Sent>, Vec<&Sent>) =
        out.iter().partition(|p| !p.is_response());
    assert_eq!(probes.len(), 3);
    let first = probes[0].at;
    assert!(first <= ms(250), "the first probe waits 0 to 250 ms");
    assert_eq!(
        probes.iter().map(|p| p.at).collect::<Vec<_>>(),
        vec![first, first + ms(250), first + ms(500)]
    );
    for probe in &probes {
        assert_eq!(probe.to, MDNS_DEST_ADDR);
        assert_eq!(probe.flags(), 0, "a probe is a query");
        assert_eq!(probe.msg.questions.len(), 1);
        let question = &probe.msg.questions[0];
        assert_eq!(question.key, key(CHOSEN));
        assert_eq!((question.typ, question.class), (TYPE_ANY, CLASS_IN));
        assert!(question.unicast, "a probe asks for a unicast response");
        assert!(probe.msg.answers.is_empty());
        assert_eq!(probe.msg.authorities.len(), 1, "the proposed record");
        let proposed = &probe.msg.authorities[0];
        assert_eq!(proposed.key, key(CHOSEN));
        assert_eq!(proposed.addr(), Some(ip(HOST)));
        assert!(!proposed.flush);
    }
    assert_eq!(
        announcements.iter().map(|p| p.at).collect::<Vec<_>>(),
        vec![first + ms(750), first + ms(1750)],
        "announced 250 ms after the third probe, and a second later"
    );
    assert!(announcements[0].msg.answers[0].flush);
}

// RFC 6762 section 8.1: the name is not ours, so not answered, until probing is over.
#[test]
fn test_name_is_not_answered_while_it_is_probed_for() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, CHOSEN, HOST);
    deliver(
        &mut conn,
        base + first + ms(10),
        PEER,
        &question(CHOSEN, TYPE_A, CLASS_IN),
    );
    assert!(sent(&mut conn, base).is_empty());

    run(&mut conn, base, first + ms(10), ms(10_000));
    deliver(
        &mut conn,
        base + ms(10_000),
        PEER,
        &question(CHOSEN, TYPE_A, CLASS_IN),
    );
    assert_eq!(sent(&mut conn, base).len(), 1, "answered once it is ours");
}

// RFC 6762 sections 8.1, 9: a response for the name during probing means it is taken.
#[test]
fn test_probed_name_is_given_up_when_another_host_answers_for_it() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, CHOSEN, HOST);
    let now = base + first + ms(100);
    deliver(
        &mut conn,
        now,
        "192.168.1.99:5353",
        &response(&[addr(CHOSEN, "192.168.1.99")]),
    );
    let events = events(&mut conn);
    assert!(
        matches!(&events[..], [MdnsEvent::LocalNameConflict(name)] if name == CHOSEN),
        "{events:?}"
    );
    let out = run(&mut conn, base, first + ms(100), ms(30_000));
    assert!(out.is_empty(), "no more probes, no announcement");
    deliver(
        &mut conn,
        base + ms(30_000),
        PEER,
        &question(CHOSEN, TYPE_A, CLASS_IN),
    );
    assert!(sent(&mut conn, base).is_empty(), "the name is not answered");
    // The name is free to be registered again (the application picks another).
    assert!(conn.add_local_name("printer-2.local", ip(HOST)));
}

// RFC 6762 section 8.1: any record under the name, of any type, defends it against a probe
// for type ANY; the same record is no conflict (section 9).
#[test]
fn test_probing_meets_a_record_of_any_type_but_not_its_own() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, CHOSEN, HOST);
    let now = base + first + ms(100);
    deliver(
        &mut conn,
        now,
        "192.168.1.99:5353",
        &response(&[addr(CHOSEN, HOST)]),
    );
    assert!(events(&mut conn).is_empty(), "identical data: no conflict");
    deliver(
        &mut conn,
        now,
        "192.168.1.99:5353",
        &response(&[other(CHOSEN, TYPE_TXT, b"\x02hi")]),
    );
    assert!(matches!(
        &events(&mut conn)[..],
        [MdnsEvent::LocalNameConflict(_)]
    ));
}

// RFC 6762 section 8.1: what looks like a conflict before the first probe is out is ignored.
#[test]
fn test_response_before_the_first_probe_does_not_stop_probing() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(CHOSEN, ip(HOST)));
    deliver(
        &mut conn,
        base,
        "192.168.1.99:5353",
        &response(&[addr(CHOSEN, "192.168.1.99")]),
    );
    assert!(events(&mut conn).is_empty());
    // The record is in the resolver's cache now. Probing does not consult it: only what
    // arrives while probing counts.
    assert_eq!(conn.cache.len(), 1);
    let out = run(&mut conn, base, ms(0), ms(10_000));
    assert_eq!(out.iter().filter(|p| !p.is_response()).count(), 3);
    assert_eq!(out.iter().filter(|p| p.is_response()).count(), 2);
}

// RFC 6762 section 8.2, with its example: 169.254.200.50 is lexicographically later than
// 169.254.99.200 and wins; the loser waits one second and probes again.
#[test]
fn test_simultaneous_probe_with_later_data_makes_us_probe_again_a_second_later() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, "MyPrinter.local", "169.254.99.200");
    let seen = first + ms(100);
    deliver(
        &mut conn,
        base + seen,
        "169.254.200.50:5353",
        &probe(
            "MyPrinter.local",
            "169.254.200.50",
            CLASS_IN | CLASS_TOP_BIT,
        ),
    );
    assert!(events(&mut conn).is_empty(), "the name is not given up");
    // The same probe from off the link, later, changes nothing (RFC 6762 section 11).
    deliver(
        &mut conn,
        base + seen + ms(10),
        "203.0.113.5:5353",
        &probe(
            "MyPrinter.local",
            "169.254.200.50",
            CLASS_IN | CLASS_TOP_BIT,
        ),
    );
    let out = run(&mut conn, base, seen + ms(10), ms(20_000));
    let probes: Vec<Duration> = out
        .iter()
        .filter(|p| !p.is_response())
        .map(|p| p.at)
        .collect();
    assert_eq!(
        probes,
        vec![seen + ms(1000), seen + ms(1250), seen + ms(1500)],
        "three new probes, starting one second after the lost tiebreak"
    );
    assert_eq!(out.iter().filter(|p| p.is_response()).count(), 2);
}

#[test]
fn test_simultaneous_probe_with_earlier_or_equal_data_is_ignored() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, "MyPrinter.local", "169.254.200.50");
    let seen = first + ms(100);
    deliver(
        &mut conn,
        base + seen,
        "169.254.99.200:5353",
        &probe(
            "MyPrinter.local",
            "169.254.99.200",
            CLASS_IN | CLASS_TOP_BIT,
        ),
    );
    // Our own probe, handed back by the link, proposes the same data.
    deliver(
        &mut conn,
        base + seen,
        "169.254.200.50:5353",
        &probe(
            "myprinter.LOCAL",
            "169.254.200.50",
            CLASS_IN | CLASS_TOP_BIT,
        ),
    );
    assert!(
        sent(&mut conn, base).is_empty(),
        "a name being probed for is not defended"
    );
    let out = run(&mut conn, base, seen, ms(20_000));
    let probes: Vec<Duration> = out
        .iter()
        .filter(|p| !p.is_response())
        .map(|p| p.at)
        .collect();
    assert_eq!(probes, vec![first + ms(250), first + ms(500)]);
    assert_eq!(out.iter().filter(|p| p.is_response()).count(), 2);
}

// RFC 6762 section 8.2.1: a list that starts with our record and has more wins.
#[test]
fn test_simultaneous_probe_with_our_record_and_more_wins() {
    let base = Instant::now();
    let (mut conn, first) = at_first_probe(base, "MyPrinter.local", "169.254.99.200");
    let seen = first + ms(100);
    let theirs = message(
        0,
        QUERY,
        &[("MyPrinter.local", TYPE_ANY, CLASS_IN)],
        &[],
        &[
            addr("MyPrinter.local", "fe80::1").class(CLASS_IN),
            addr("MyPrinter.local", "169.254.99.200").class(CLASS_IN),
        ],
        &[],
    );
    deliver(&mut conn, base + seen, "169.254.99.200:5353", &theirs);
    let out = run(&mut conn, base, seen, ms(20_000));
    assert_eq!(
        out.iter().find(|p| !p.is_response()).map(|p| p.at),
        Some(seen + ms(1000))
    );
}

// RFC 6762 section 8.1: fifteen conflicts in ten seconds, and each further attempt waits five
// seconds.
#[test]
fn test_fifteen_conflicts_in_ten_seconds_delay_the_next_probe_by_five() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    let mut now = base;
    for i in 0..15 {
        let name = format!("host{i}.local");
        assert!(conn.add_local_name(&name, ip(HOST)));
        conn.handle_timeout(now).unwrap();
        let mut probes = sent(&mut conn, base).len();
        let mut first = now;
        if probes == 0 {
            first = conn.poll_timeout().unwrap();
            conn.handle_timeout(first).unwrap();
            probes = sent(&mut conn, base).len();
        }
        assert!(
            first.duration_since(now) <= ms(250),
            "attempt {i} is not held back"
        );
        assert_eq!(probes, 1);
        deliver(
            &mut conn,
            first,
            "192.168.1.99:5353",
            &response(&[addr(&name, "192.168.1.99")]),
        );
        assert!(matches!(
            &events(&mut conn)[..],
            [MdnsEvent::LocalNameConflict(lost)] if *lost == name
        ));
        now = first + ms(1);
    }
    assert!(now.duration_since(base) < Duration::from_secs(10));

    assert!(conn.add_local_name("host15.local", ip(HOST)));
    conn.handle_timeout(now).unwrap();
    let wait = conn.poll_timeout().unwrap().duration_since(now);
    assert!(
        (ms(5000)..=ms(5250)).contains(&wait),
        "the sixteenth attempt waits five seconds, not {wait:?}"
    );

    // Ten quiet seconds later the brake is off.
    let later = now + Duration::from_secs(20);
    run(&mut conn, base, now.duration_since(base), ms(20_000));
    assert!(conn.add_local_name("host16.local", ip(HOST)));
    conn.handle_timeout(later).unwrap();
    let wait = conn.poll_timeout().unwrap().duration_since(later);
    assert!(wait <= ms(250), "{wait:?}");
}

// RFC 6762 sections 6.6, 8.3, 9: other data under a name of ours sends it back to probing.
#[test]
fn test_conflicting_record_sends_a_live_name_back_to_probing() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = ms(10_000);
    // In the Additional section: a conflict in any section counts.
    let conflict = message(0, RESPONSE, &[], &[], &[], &[addr(UUID_1, "192.168.1.99")]);
    deliver(&mut conn, base + now, "192.168.1.99:5353", &conflict);
    let mut out = sent(&mut conn, base);
    assert!(
        events(&mut conn).is_empty(),
        "not given up yet: probing decides"
    );

    out.extend(run(&mut conn, base, now, now + ms(100)));
    deliver(
        &mut conn,
        base + now + ms(100),
        PEER,
        &question(UUID_1, TYPE_A, CLASS_IN),
    );
    out.extend(sent(&mut conn, base));
    out.extend(run(&mut conn, base, now + ms(100), ms(30_000)));

    let probes: Vec<&Sent> = out.iter().filter(|p| !p.is_response()).collect();
    assert_eq!(probes.len(), 3, "the name is probed for again");
    let first = probes[0].at;
    assert!((now..=now + ms(250)).contains(&first));
    assert_eq!(probes[0].msg.questions[0].typ, TYPE_ANY);
    let responses: Vec<Duration> = out
        .iter()
        .filter(|p| p.is_response())
        .map(|p| p.at)
        .collect();
    assert_eq!(
        responses,
        vec![first + ms(750), first + ms(1750)],
        "nothing is answered while probing; unopposed, the name is announced again"
    );
}

// RFC 6762 section 6.6: the same record from another responder is no conflict; with less than
// half its TTL (a goodbye included) ours goes out again.
#[test]
fn test_own_record_seen_with_a_short_ttl_is_multicast_again() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = base + ms(10_000);
    deliver(
        &mut conn,
        now,
        "192.168.1.77:5353",
        &response(&[addr(UUID_1, HOST).ttl(60)]),
    );
    assert!(
        sent(&mut conn, base).is_empty(),
        "half the TTL: nothing to do"
    );

    deliver(
        &mut conn,
        now,
        "192.168.1.77:5353",
        &response(&[addr(UUID_1, HOST).ttl(0)]),
    );
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert!(out[0].multicast() && out[0].is_response());
    assert_eq!(out[0].msg.answers[0].ttl, 120);
    assert!(events(&mut conn).is_empty());
}

// RFC 6762 section 6: at most one multicast of a record per second. The fixed-IP responder
// used to answer a query for A and AAAA twice.
#[test]
fn test_query_for_both_families_gets_one_response() {
    let base = Instant::now();
    let mut conn = Mdns::new(
        base,
        config()
            .with_local_names(vec![UUID_1.to_owned()])
            .with_local_ip(ip(HOST)),
    );
    deliver(&mut conn, base, PEER, &query_for(UUID_1));
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.answers.len(), 1);
    assert_eq!(out[0].msg.answers[0].typ, TYPE_A);
}

#[test]
fn test_record_is_not_multicast_twice_within_a_second() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = ms(10_000);
    let ask = question(UUID_1, TYPE_A, CLASS_IN);
    deliver(&mut conn, base + now, PEER, &ask);
    assert_eq!(sent(&mut conn, base).len(), 1, "answered at once");

    // Two more askers within the second: one more multicast, when the second is over.
    deliver(&mut conn, base + now + ms(200), PEER, &ask);
    deliver(&mut conn, base + now + ms(500), "192.168.1.31:5353", &ask);
    assert!(sent(&mut conn, base).is_empty());
    assert_eq!(conn.poll_timeout(), Some(base + now + ms(1000)));
    let out = run(&mut conn, base, now + ms(500), ms(20_000));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].at, now + ms(1000));
}

// RFC 6762 sections 6, 6.1: a question for a type the name lacks is answered with the NSEC
// record, not with the address record (which the fixed-IP responder used to send).
#[test]
fn test_question_for_a_type_the_name_lacks_gets_nsec() {
    let base = Instant::now();
    let mut conn = Mdns::new(
        base,
        config()
            .with_local_names(vec![UUID_1.to_owned()])
            .with_local_ip(ip(HOST)),
    );
    for typ in [TYPE_TXT, TYPE_AAAA] {
        let now = base + Duration::from_secs(u64::from(typ));
        deliver(&mut conn, now, PEER, &question(UUID_1, typ, CLASS_IN));
        let out = sent(&mut conn, base);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].msg.answers.len(), 1);
        let nsec = &out[0].msg.answers[0];
        assert_eq!(nsec.typ, TYPE_NSEC);
        assert_eq!(nsec.key, key(UUID_1));
        assert!(nsec.flush);
        assert_eq!(nsec.ttl, 120, "the TTL the address record has");
        assert_eq!(nsec.nsec_has(TYPE_A), Some(true));
        assert_eq!(nsec.nsec_has(TYPE_AAAA), Some(false));
        assert_eq!(
            nsec.nsec_has(TYPE_NSEC),
            Some(false),
            "the NSEC bit is clear"
        );
        // The restricted form, byte for byte: the name (44 bytes, at offset 12), type 47,
        // class IN with cache-flush, TTL, RDLENGTH 5, then a pointer to the record's own
        // name, window 0, one bitmap byte with the bit of type 1.
        let raw = &out[0].raw;
        assert_eq!(raw.len(), 12 + 44 + 10 + 5);
        assert_eq!(&raw[56..60], &[0, 47, 0x80, 1]);
        assert_eq!(&raw[64..], &[0, 5, 0xC0, 12, 0, 1, 0x40]);
    }
}

// RFC 6762 sections 6.1, 6.2: with an address record goes the NSEC record that says the
// other family does not exist, in the Additional section.
#[test]
fn test_address_answer_carries_nsec_for_the_other_family() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip("fe80::20")));
    deliver(&mut conn, base, PEER, &query_for(UUID_1));
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    let msg = &out[0].msg;
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].addr(), Some(ip("fe80::20")));
    assert_eq!(msg.additionals.len(), 1);
    let nsec = &msg.additionals[0];
    assert_eq!(nsec.typ, TYPE_NSEC);
    assert_eq!(nsec.nsec_has(TYPE_AAAA), Some(true));
    assert_eq!(nsec.nsec_has(TYPE_A), Some(false));
    // Window 0, four bitmap bytes, the bit of type 28 in the last.
    let raw = &out[0].raw;
    assert_eq!(&raw[raw.len() - 8..], &[0xC0, 12, 0, 4, 0, 0, 0, 0x08]);
    // An IPv6 record goes to the IPv4 group, from the unspecified address.
    assert_eq!(out[0].from, "0.0.0.0:5353".parse().unwrap());
}

// RFC 6762 sections 6, 6.5: type ANY and class ANY match; another class does not.
#[test]
fn test_any_type_and_any_class_match_and_another_class_does_not() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let mut now = base + ms(10_000);
    for (typ, class) in [
        (TYPE_ANY, CLASS_IN),
        (TYPE_A, CLASS_ANY),
        (TYPE_ANY, CLASS_ANY),
    ] {
        deliver(&mut conn, now, PEER, &question(UUID_1, typ, class));
        let out = sent(&mut conn, base);
        assert_eq!(out.len(), 1, "type {typ} class {class}");
        assert_eq!(out[0].msg.answers[0].addr(), Some(ip(HOST)));
        now += Duration::from_secs(2);
    }
    deliver(&mut conn, now, PEER, &question(UUID_1, TYPE_A, CLASS_CHAOS));
    assert!(sent(&mut conn, base).is_empty());
    assert!(conn.poll_timeout().is_none());
}

// RFC 6762 section 16, RFC 1035 section 2.3.3: ASCII letters compare without regard to case.
#[test]
fn test_question_in_another_case_is_answered() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    deliver(
        &mut conn,
        base + ms(10_000),
        PEER,
        &question(&UUID_1.to_ascii_uppercase(), TYPE_A, CLASS_IN),
    );
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.answers[0].addr(), Some(ip(HOST)));
}

// RFC 6762 section 6: questions in a response are ignored. They used to be answered, so two
// responders could be made to answer each other.
#[test]
fn test_question_in_a_response_is_not_answered() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let with_question = message(0, RESPONSE, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
    deliver(&mut conn, base + ms(10_000), PEER, &with_question);
    assert!(sent(&mut conn, base).is_empty());
    assert!(conn.poll_timeout().is_none());
}

// RFC 6762 sections 18.3, 18.11.
#[test]
fn test_query_with_another_opcode_or_an_rcode_is_ignored() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    for flags in [0x2800, 0x0003] {
        let query = message(0, flags, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
        deliver(&mut conn, base + ms(10_000), PEER, &query);
        assert!(sent(&mut conn, base).is_empty(), "flags {flags:#06x}");
    }
    assert!(conn.poll_timeout().is_none());
}

// RFC 6762 sections 6, 8.1: a probe for a name in use is answered at once, by unicast when it
// asks for that (whenever the record was last multicast).
#[test]
fn test_probe_for_a_live_name_is_answered_at_once_by_unicast() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    // Long after the last multicast: an ordinary QU question would be answered by multicast.
    let now = base + ms(100_000);
    deliver(
        &mut conn,
        now,
        "192.168.1.99:5353",
        &probe(UUID_1, "192.168.1.99", CLASS_IN | CLASS_TOP_BIT),
    );
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].at, ms(100_000), "no delay");
    assert_eq!(out[0].to, "192.168.1.99:5353".parse().unwrap());
    assert_eq!(out[0].msg.answers[0].addr(), Some(ip(HOST)));
    assert!(events(&mut conn).is_empty());
}

// RFC 6762 section 6: answering a probe by multicast needs only 250 ms since the record was
// last multicast, where anything else waits a second.
#[test]
fn test_probe_is_answered_by_multicast_250_ms_after_the_last() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = ms(10_000);
    deliver(
        &mut conn,
        base + now,
        PEER,
        &question(UUID_1, TYPE_A, CLASS_IN),
    );
    assert_eq!(sent(&mut conn, base).len(), 1);

    let theirs = probe(UUID_1, "192.168.1.99", CLASS_IN);
    deliver(
        &mut conn,
        base + now + ms(100),
        "192.168.1.99:5353",
        &theirs,
    );
    assert!(sent(&mut conn, base).is_empty(), "inside 250 ms");
    assert_eq!(conn.poll_timeout(), Some(base + now + ms(250)));
    let out = run(&mut conn, base, now + ms(100), now + ms(900));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].at, now + ms(250));
    assert!(out[0].multicast());
}

// RFC 6762 section 7.1.
#[test]
fn test_known_answer_with_half_the_ttl_suppresses_the_response() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = base + ms(10_000);
    let asking_with = |known: Rec| {
        message(
            0,
            QUERY,
            &[(UUID_1, TYPE_A, CLASS_IN)],
            &[known.class(CLASS_IN)],
            &[],
            &[],
        )
    };
    deliver(
        &mut conn,
        now,
        PEER,
        &asking_with(addr(UUID_1, HOST).ttl(60)),
    );
    assert!(sent(&mut conn, base).is_empty(), "the asker has the answer");
    assert!(conn.poll_timeout().is_none());

    // Less than half the TTL left, or another address: the asker needs ours.
    deliver(
        &mut conn,
        now,
        PEER,
        &asking_with(addr(UUID_1, HOST).ttl(59)),
    );
    assert_eq!(sent(&mut conn, base).len(), 1);
    let later = now + Duration::from_secs(5);
    deliver(
        &mut conn,
        later,
        PEER,
        &asking_with(addr(UUID_1, "192.168.1.99")),
    );
    assert_eq!(sent(&mut conn, base).len(), 1);
}

// RFC 6762 sections 6, 7.2, 18.5: a truncated query is answered 400 to 500 ms later.
#[test]
fn test_truncated_query_is_answered_after_400_to_500_ms() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = ms(10_000);
    let truncated = message(0, TC, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
    deliver(&mut conn, base + now, PEER, &truncated);
    assert!(sent(&mut conn, base).is_empty());
    let out = run(&mut conn, base, now, ms(20_000));
    assert_eq!(out.len(), 1);
    let waited = out[0].at - now;
    assert!((ms(400)..=ms(500)).contains(&waited), "{waited:?}");
}

// RFC 6762 section 7.2: a later Known-Answer packet from the same host calls the answer off;
// one from another host does not.
#[test]
fn test_known_answer_in_a_following_packet_calls_the_answer_off() {
    let base = Instant::now();
    let now = ms(10_000);
    let truncated = message(0, TC, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
    let more = message(
        0,
        QUERY,
        &[],
        &[addr(UUID_1, HOST).class(CLASS_IN)],
        &[],
        &[],
    );

    let mut conn = established(base, UUID_1, HOST);
    deliver(&mut conn, base + now, PEER, &truncated);
    deliver(&mut conn, base + now + ms(50), PEER, &more);
    assert!(run(&mut conn, base, now + ms(50), ms(20_000)).is_empty());

    let mut conn = established(base, UUID_1, HOST);
    deliver(&mut conn, base + now, PEER, &truncated);
    deliver(&mut conn, base + now + ms(50), "192.168.1.31:5353", &more);
    assert_eq!(run(&mut conn, base, now + ms(50), ms(20_000)).len(), 1);

    // Another truncated packet from the asker restarts the wait.
    let mut conn = established(base, UUID_1, HOST);
    deliver(&mut conn, base + now, PEER, &truncated);
    let more_to_come = message(0, TC, &[], &[addr("x.local", HOST)], &[], &[]);
    deliver(&mut conn, base + now + ms(300), PEER, &more_to_come);
    let out = run(&mut conn, base, now + ms(300), ms(20_000));
    assert_eq!(out.len(), 1);
    assert!((ms(700)..=ms(800)).contains(&(out[0].at - now)));
}

// RFC 6762 section 5.4: a question that asks for a unicast response gets one when the record
// was multicast within a quarter of its TTL, and a multicast response otherwise.
#[test]
fn test_unicast_response_question_is_answered_by_unicast_when_recently_multicast() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let qu = question(UUID_1, TYPE_A, CLASS_IN | CLASS_TOP_BIT);

    // Announced at 0 s and 1 s: 20 s is within 30 s of that.
    deliver(&mut conn, base + ms(20_000), PEER, &qu);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, PEER.parse().unwrap());
    assert_eq!(out[0].flags(), 0x8400);
    assert_eq!(&out[0].raw[..2], &[0, 0]);
    let record = &out[0].msg.answers[0];
    assert!(
        record.flush,
        "the cache-flush bit goes into a unicast response too"
    );
    assert_eq!(record.ttl, 120);

    // 40 s is not: the neighbours are due the record, so it is multicast.
    deliver(&mut conn, base + ms(40_000), PEER, &qu);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert!(out[0].multicast());

    // And 41 s is again.
    deliver(&mut conn, base + ms(41_000), PEER, &qu);
    assert_eq!(sent(&mut conn, base)[0].to, PEER.parse().unwrap());
}

// RFC 6762 section 11: a unicast response to a sender that looks off the link would not be
// believed, so the answer is multicast.
#[test]
fn test_unicast_response_question_from_off_the_link_is_answered_by_multicast() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let qu = question(UUID_1, TYPE_A, CLASS_IN | CLASS_TOP_BIT);
    deliver(&mut conn, base + ms(20_000), "203.0.113.5:5353", &qu);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert!(out[0].multicast());
}

#[test]
fn test_unicast_replies_can_be_turned_off() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_unicast_replies(false));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    run(&mut conn, base, ms(0), ms(10_000));
    let qu = question(UUID_1, TYPE_A, CLASS_IN | CLASS_TOP_BIT);
    deliver(&mut conn, base + ms(20_000), PEER, &qu);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert!(out[0].multicast());
}

// RFC 6762 section 5.5: a query that arrived by unicast is answered like a QU question, and
// ignored when its source is not on the link.
#[test]
fn test_query_received_by_unicast_is_answered_by_unicast_to_an_on_link_sender_only() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let own: SocketAddr = format!("{HOST}:5353").parse().unwrap();
    let ask = question(UUID_1, TYPE_A, CLASS_IN);

    deliver_to(&mut conn, base + ms(20_000), PEER, own, &ask);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, PEER.parse().unwrap());

    deliver_to(&mut conn, base + ms(21_000), "203.0.113.5:5353", own, &ask);
    assert!(sent(&mut conn, base).is_empty());
    assert!(conn.poll_timeout().is_none());

    // A caller that does not report destinations has every query taken as a multicast
    // arrival, and answered on the group.
    let mut conn = Mdns::new(base, MdnsConfig::default());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    deliver_to(&mut conn, base, "203.0.113.5:5353", own, &ask);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert!(out[0].multicast());
}

// RFC 6762 sections 6.7, 10.2: a query from another port is from a legacy resolver. It gets a
// conventional DNS reply, straight back: its ID and question repeated, no cache-flush bit, a
// TTL of at most ten seconds.
#[test]
fn test_legacy_query_gets_a_conventional_unicast_reply() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let legacy = "192.168.1.30:40000";
    let query = message(0x1234, 0x0100, &[(UUID_1, TYPE_A, CLASS_IN)], &[], &[], &[]);
    deliver(&mut conn, base + ms(50_000), legacy, &query);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    let reply = &out[0];
    assert_eq!(reply.to, legacy.parse().unwrap());
    assert_eq!(reply.from.port(), MDNS_PORT);
    assert_eq!(&reply.raw[..2], &[0x12, 0x34], "the query's ID");
    assert_eq!(reply.flags(), 0x8400);
    assert_eq!(reply.msg.questions.len(), 1);
    let echoed = &reply.msg.questions[0];
    assert_eq!(echoed.name, format!("{UUID_1}."));
    assert_eq!(
        (echoed.typ, echoed.class, echoed.unicast),
        (TYPE_A, CLASS_IN, false)
    );
    assert_eq!(reply.msg.answers.len(), 1);
    let record = &reply.msg.answers[0];
    assert_eq!(record.addr(), Some(ip(HOST)));
    assert!(!record.flush, "no cache-flush bit to a legacy resolver");
    assert_eq!(record.ttl, 10);
    assert!(reply.msg.additionals.is_empty());

    // Not held back by the one-second rule, which is about multicast; a type the name lacks
    // gets the question back with no answer; a sender off the link gets nothing.
    let txt = message(7, QUERY, &[(UUID_1, TYPE_TXT, CLASS_IN)], &[], &[], &[]);
    deliver(&mut conn, base + ms(50_100), legacy, &txt);
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.questions[0].typ, TYPE_TXT);
    assert!(out[0].msg.answers.is_empty());

    deliver(&mut conn, base + ms(50_200), "203.0.113.5:40000", &query);
    assert!(sent(&mut conn, base).is_empty());
}

// RFC 6762 sections 6, 6.3: a message with a question some other host may answer is answered
// after a random 20 to 120 ms; one that is all about our names, at once.
#[test]
fn test_query_with_a_question_for_another_host_is_answered_after_20_to_120_ms() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = ms(10_000);
    let mixed = message(
        0,
        QUERY,
        &[
            (UUID_1, TYPE_A, CLASS_IN),
            ("somebody-else.local", TYPE_A, CLASS_IN),
        ],
        &[],
        &[],
        &[],
    );
    deliver(&mut conn, base + now, PEER, &mixed);
    assert!(sent(&mut conn, base).is_empty());
    let out = run(&mut conn, base, now, ms(20_000));
    assert_eq!(out.len(), 1);
    let waited = out[0].at - now;
    assert!((ms(20)..=ms(120)).contains(&waited), "{waited:?}");
}

// RFC 6762 sections 6.3, 6.4: every question of a message is answered (four used to be
// read), and the answers share one message.
#[test]
fn test_six_questions_are_answered_in_one_message() {
    let base = Instant::now();
    let names: Vec<String> = (1..=6)
        .map(|i| format!("aaaaaaaa-0000-4000-8000-00000000000{i}.local"))
        .collect();
    let mut conn = Mdns::new(
        base,
        config()
            .with_local_names(names.clone())
            .with_local_ip(ip(HOST)),
    );
    let questions: Vec<(&str, u16, u16)> = names
        .iter()
        .map(|name| (name.as_str(), TYPE_A, CLASS_IN))
        .collect();
    deliver(
        &mut conn,
        base,
        PEER,
        &message(0, QUERY, &questions, &[], &[], &[]),
    );
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1, "one message, sent at once");
    let mut answered: Vec<&str> = out[0].msg.answers.iter().map(|r| r.key.as_str()).collect();
    answered.sort();
    let mut expected: Vec<String> = names.iter().map(|name| key(name)).collect();
    expected.sort();
    assert_eq!(answered, expected);
    // Names are compressed: the first answer's name takes 44 bytes, the others 37 and a
    // pointer to `local.`; each NSEC record names itself and its next domain by pointers.
    assert_eq!(out[0].raw.len(), 12 + 58 + 5 * 53 + 6 * 17);
}

// RFC 6762 section 10.1; draft-ietf-mmusic-mdns-ice-candidates section 7.1.
#[test]
fn test_removed_name_says_goodbye() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    assert!(conn.remove_local_name(UUID_1));
    assert!(sent(&mut conn, base).is_empty());
    let out = run(&mut conn, base, ms(10_000), ms(60_000));
    assert_eq!(out.len(), 1);
    let goodbye = &out[0];
    assert_eq!(goodbye.at, ms(10_000));
    assert!(goodbye.multicast() && goodbye.is_response());
    assert_eq!(goodbye.msg.answers.len(), 1);
    let record = &goodbye.msg.answers[0];
    assert_eq!(record.key, key(UUID_1));
    assert_eq!(record.addr(), Some(ip(HOST)), "the same data");
    assert_eq!(record.ttl, 0);

    deliver(
        &mut conn,
        base + ms(60_000),
        PEER,
        &question(UUID_1, TYPE_A, CLASS_IN),
    );
    assert!(sent(&mut conn, base).is_empty(), "the name is gone");
    assert!(!conn.remove_local_name(UUID_1));
}

// A goodbye is a multicast of the record: not within a second of the last one (RFC 6762
// section 6).
#[test]
fn test_goodbye_waits_out_the_record_s_second() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert_eq!(run(&mut conn, base, ms(0), ms(300)).len(), 1, "announced");
    assert!(conn.remove_local_name(UUID_1));
    let out = run(&mut conn, base, ms(300), ms(60_000));
    assert_eq!(out.len(), 1, "the goodbye, and no second announcement");
    assert_eq!(out[0].at, ms(1000));
    assert_eq!(out[0].msg.answers[0].ttl, 0);
}

#[test]
fn test_name_that_never_went_out_leaves_without_a_goodbye() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert!(conn.remove_local_name(UUID_1));
    assert!(run(&mut conn, base, ms(0), ms(60_000)).is_empty());

    // Registered again before its goodbye went out, a name is not withdrawn.
    let mut conn = established(base, UUID_1, HOST);
    assert!(conn.remove_local_name(UUID_1));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    let out = run(&mut conn, base, ms(10_000), ms(60_000));
    assert!(!out.is_empty());
    assert!(
        out.iter()
            .all(|p| p.msg.answers.iter().all(|r| r.ttl == 120))
    );
}

// RFC 6762 section 10.1; draft-ietf-mmusic-mdns-ice-candidates section 7.1.
#[test]
fn test_close_says_goodbye_for_every_name_that_went_out() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    assert!(conn.add_local_name(UUID_2, ip("192.168.7.20")));
    conn.close().unwrap();
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1, "one name went out, one did not");
    assert!(out[0].multicast());
    assert_eq!(out[0].msg.answers[0].key, key(UUID_1));
    assert_eq!(out[0].msg.answers[0].ttl, 0);
    assert!(conn.poll_timeout().is_none());
    assert!(conn.close().is_ok(), "closing twice is fine");
    assert!(sent(&mut conn, base).is_empty(), "and says goodbye once");
    assert!(!conn.add_local_name("late.local", ip(HOST)));
}

// draft-ietf-mmusic-mdns-ice-candidates section 7.1: one rate limit over every message.
#[test]
fn test_messages_wait_for_the_message_budget() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_rate_limit(MdnsRateLimit::new(2, 1)));
    for i in 1..=4 {
        // One address each, so one message each.
        let name = format!("aaaaaaaa-0000-4000-8000-00000000000{i}.local");
        assert!(conn.add_local_name(&name, ip(&format!("192.168.{i}.20"))));
    }
    conn.handle_timeout(base).unwrap();
    assert_eq!(sent(&mut conn, base).len(), 2, "the burst");
    assert_eq!(
        conn.poll_timeout(),
        Some(base + ms(1000)),
        "the rest waits for the budget"
    );
    let out = run(&mut conn, base, ms(0), ms(60_000));
    assert_eq!(out.len(), 6, "every announcement goes out in the end");
    let mut per_second = std::collections::HashMap::new();
    for packet in &out {
        *per_second.entry(packet.at.as_secs()).or_insert(0) += 1;
    }
    assert!(
        per_second.values().all(|&n| n == 1),
        "one a second: {per_second:?}"
    );
}

#[test]
fn test_connections_given_one_rate_limit_share_it() {
    let base = Instant::now();
    let limit = MdnsRateLimit::new(1, 1);
    let mut first = Mdns::new(base, config().with_rate_limit(limit.clone()));
    let mut second = Mdns::new(base, config().with_rate_limit(limit));
    first.query_now(base, UUID_1);
    second.query_now(base, UUID_2);
    assert_eq!(sent(&mut first, base).len(), 1);
    assert!(sent(&mut second, base).is_empty(), "the budget is spent");
    assert_eq!(second.poll_timeout(), Some(base + ms(1000)));
    assert_eq!(run(&mut second, base, ms(0), ms(1000)).len(), 1);
}

// RFC 6762 section 17: more records than fit one datagram go out in several messages.
#[test]
fn test_many_records_are_split_into_messages_of_one_datagram() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    for i in 0..MAX_LOCAL_NAMES {
        let name = format!("aaaaaaaa-0000-4000-8000-{i:012}.local");
        assert!(conn.add_local_name(&name, ip(&format!("fe80::{i:x}"))));
    }
    conn.handle_timeout(base).unwrap();
    let out = sent(&mut conn, base);
    assert!(out.len() > 1);
    assert!(out.iter().all(|p| p.raw.len() <= MAX_OUTBOUND_MESSAGE));
    let records: usize = out.iter().map(|p| p.msg.answers.len()).sum();
    assert_eq!(records, MAX_LOCAL_NAMES, "each record once");
}

// RFC 6762 appendix C: a name may be 255 bytes on the wire.
#[test]
fn test_name_of_255_bytes_is_published_and_a_longer_one_refused() {
    let base = Instant::now();
    let label = |c: char, n: usize| c.to_string().repeat(n);
    // 64 + 64 + 64 + 62 bytes of labels, and the root: 255.
    let longest = format!(
        "{}.{}.{}.{}",
        label('a', 63),
        label('b', 63),
        label('c', 63),
        label('d', 61)
    );
    assert_eq!(wire_name(&longest).len(), 255);
    let mut conn = Mdns::new(base, config().with_probe_policy(MdnsProbePolicy::Never));
    assert!(conn.add_local_name(&longest, ip(HOST)));
    deliver(&mut conn, base, PEER, &question(&longest, TYPE_A, CLASS_IN));
    let out = sent(&mut conn, base);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.answers[0].key, key(&longest));

    assert!(!conn.add_local_name(&format!("{longest}d"), ip(HOST)));
    assert!(!conn.add_local_name(&format!("{}.local", label('x', 64)), ip(HOST)));
    assert!(!conn.add_local_name("two..dots.local", ip(HOST)));
}

// The probe policy: every name, or none.
#[test]
fn test_probe_policy_always_and_never() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config().with_probe_policy(MdnsProbePolicy::Always));
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    let out = run(&mut conn, base, ms(0), ms(10_000));
    assert_eq!(out.iter().filter(|p| !p.is_response()).count(), 3);

    let mut conn = Mdns::new(base, config().with_probe_policy(MdnsProbePolicy::Never));
    assert!(conn.add_local_name(CHOSEN, ip(HOST)));
    let out = run(&mut conn, base, ms(0), ms(10_000));
    assert!(out.iter().all(|p| p.is_response()));
    assert_eq!(out.len(), 2);
}

// RFC 6762 sections 8, 10.2: after a change of network, names are probed for and announced
// again; at no other time (section 8.3).
#[test]
fn test_network_change_probes_and_announces_names_again() {
    let base = Instant::now();
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(UUID_1, ip(HOST)));
    assert!(conn.add_local_name(CHOSEN, ip("192.168.7.20")));
    run(&mut conn, base, ms(0), ms(100_000));
    assert!(conn.poll_timeout().is_none(), "nothing is sent unasked");

    conn.network_changed();
    assert_eq!(conn.poll_timeout(), Some(base + ms(100_000)));
    let out = run(&mut conn, base, ms(100_000), ms(200_000));
    let announced = |name: &str| {
        out.iter()
            .filter(|p| p.is_response() && p.msg.answers.iter().any(|r| r.key == key(name)))
            .count()
    };
    assert_eq!(announced(UUID_1), 2);
    assert_eq!(announced(CHOSEN), 2);
    let probes: Vec<&Sent> = out.iter().filter(|p| !p.is_response()).collect();
    assert_eq!(probes.len(), 3, "the chosen name is probed for again");
    assert!(probes.iter().all(|p| p.msg.questions[0].key == key(CHOSEN)));
    assert!(conn.poll_timeout().is_none());
}

// RFC 6762 section 6: only records this responder owns go into its responses, never what
// its resolver has cached from others.
#[test]
fn test_cached_record_of_another_host_is_not_served() {
    let base = Instant::now();
    let mut conn = established(base, UUID_1, HOST);
    let now = base + ms(10_000);
    deliver(
        &mut conn,
        now,
        "192.168.1.50:5353",
        &response(&[addr(UUID_2, "192.168.1.50")]),
    );
    // It is in the cache ...
    let id = conn.query_now(now, UUID_2);
    assert!(!conn.is_query_pending(id));
    assert!(sent(&mut conn, base).is_empty());
    // ... and a question for it is not ours to answer.
    deliver(&mut conn, now, PEER, &question(UUID_2, TYPE_A, CLASS_IN));
    assert!(sent(&mut conn, base).is_empty());
    // The only timer left is the resolver's watch on that question going unanswered (RFC
    // 6762 section 10.5).
    assert_eq!(conn.poll_timeout(), Some(now + ms(10_000)));
}

// RFC 6762 section 6.3: "for query messages containing more than one question, all
// (non-defensive) answers SHOULD be randomly delayed in the range 20-120 ms". With
// `with_multi_question_delay` an A and AAAA query for our own name waits too; a one-question
// query is still answered at once, and so is the two-question one without the option.
#[test]
fn test_multi_question_query_about_our_name_waits_20_to_120_ms_when_asked_to() {
    let base = Instant::now();
    let now = ms(10_000);
    let mut conn = Mdns::new(
        base,
        config()
            .with_multi_question_delay(true)
            .with_local_names(vec![UUID_1.to_owned()])
            .with_local_ip(ip(HOST)),
    );
    run(&mut conn, base, ms(0), now);
    deliver(&mut conn, base + now, PEER, &query_for(UUID_1));
    assert!(sent(&mut conn, base).is_empty(), "not at once");
    let out = run(&mut conn, base, now, ms(20_000));
    assert_eq!(out.len(), 1);
    let waited = out[0].at - now;
    assert!((ms(20)..=ms(120)).contains(&waited), "{waited:?}");

    deliver(
        &mut conn,
        base + ms(20_000),
        PEER,
        &question(UUID_1, TYPE_A, CLASS_IN),
    );
    assert_eq!(sent(&mut conn, base).len(), 1, "one question: at once");

    let mut plain = established(base, UUID_1, HOST);
    deliver(&mut plain, base + now, PEER, &query_for(UUID_1));
    assert_eq!(
        sent(&mut plain, base).len(),
        1,
        "without the option: at once"
    );
}
