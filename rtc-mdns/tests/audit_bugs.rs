//! The bugs the RFC 6762 clause audit found in the resolver and the bare responder, each as a
//! test through the public API with hand-built datagrams. Every test here failed on the code
//! the audit read (fork master 8916bc3); `docs/conformance/audit/rfc6762.md` lists them.

use bytes::BytesMut;
use rtc_mdns::{MDNS_DEST_ADDR, Mdns, MdnsConfig, MdnsEvent};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A name as an ICE agent publishes it, and the host that owns it.
const NAME: &str = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";
const OWNER: &str = "192.168.1.50";
const ASKER: &str = "192.168.1.30";

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_NSEC: u16 = 47;
const QUERY: u16 = 0;
const RESPONSE: u16 = 0x8400;

fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A record: name, type, class IN, TTL 120, the data.
fn record(name: &str, typ: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = wire_name(name);
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 120]);
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn a_record(name: &str, address: &str) -> Vec<u8> {
    let IpAddr::V4(v4) = address.parse().unwrap() else {
        panic!("an IPv4 address");
    };
    record(name, TYPE_A, &v4.octets())
}

/// A message with the given flags, questions (name, type; class IN) and answer records.
fn message(flags: u16, questions: &[(&str, u16)], answers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0, 0];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    for (name, typ) in questions {
        out.extend_from_slice(&wire_name(name));
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
    }
    for answer in answers {
        out.extend_from_slice(answer);
    }
    out
}

fn deliver(conn: &mut Mdns, now: Instant, from: &str, bytes: &[u8]) {
    conn.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: MDNS_DEST_ADDR,
            peer_addr: format!("{from}:5353").parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(bytes),
    })
    .unwrap();
}

fn written(conn: &mut Mdns) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| conn.poll_write())
        .map(|packet| packet.message.to_vec())
        .collect()
}

/// The type of the first record of a message without questions, whose first name is spelled
/// out.
fn first_record_type(message: &[u8]) -> u16 {
    assert_eq!(&message[4..6], &[0, 0], "no questions");
    let mut off = 12;
    while message[off] != 0 {
        off += 1 + usize::from(message[off]);
    }
    u16::from_be_bytes([message[off + 1], message[off + 2]])
}

/// What a query for `NAME` resolves to when `response` arrives from `OWNER`.
fn resolve(asked: &str, response: &[u8]) -> Option<IpAddr> {
    let now = Instant::now();
    let mut conn = Mdns::new(now, MdnsConfig::default());
    let id = conn.query_now(now, asked);
    written(&mut conn);
    deliver(&mut conn, now, OWNER, response);
    std::iter::from_fn(|| conn.poll_event()).find_map(|event| match event {
        MdnsEvent::QueryAnswered(answered, addr) if answered == id => Some(addr),
        _ => None,
    })
}

/// A responder that owns `NAME` at `OWNER`, in the fixed-IP form.
fn responder(now: Instant) -> Mdns {
    Mdns::new(
        now,
        MdnsConfig::default()
            .with_local_names(vec![NAME.to_owned()])
            .with_local_ip(OWNER.parse().unwrap()),
    )
}

// "A non-address record in the Answer section hides every record after it."
#[test]
fn test_address_record_after_a_txt_record_resolves() {
    let response = message(
        RESPONSE,
        &[],
        &[record(NAME, TYPE_TXT, b"\x02hi"), a_record(NAME, OWNER)],
    );
    assert_eq!(resolve(NAME, &response), Some(OWNER.parse().unwrap()));
}

// "Only the first four Answer records are examined."
#[test]
fn test_fifth_answer_record_resolves() {
    let mut answers: Vec<Vec<u8>> = (1..=4)
        .map(|i| a_record(&format!("other-{i}.local"), OWNER))
        .collect();
    answers.push(a_record(NAME, OWNER));
    let response = message(RESPONSE, &[], &answers);
    assert_eq!(resolve(NAME, &response), Some(OWNER.parse().unwrap()));
}

// "Query retries never back off": RFC 6762 section 5.2 has the interval at least double.
#[test]
fn test_query_retries_back_off() {
    let start = Instant::now();
    let mut conn = Mdns::new(start, MdnsConfig::default());
    conn.query_now(start, NAME);
    let mut sent_at = Vec::new();
    for tenth in 0..=160u64 {
        conn.handle_timeout(start + Duration::from_millis(tenth * 100))
            .unwrap();
        for _ in written(&mut conn) {
            sent_at.push(tenth * 100);
        }
    }
    assert_eq!(sent_at, vec![0, 1000, 3000, 7000, 15000]);
}

// "... and, without a timeout, never stop."
#[test]
fn test_unanswered_query_ends_without_a_configured_timeout() {
    let start = Instant::now();
    let mut conn = Mdns::new(start, MdnsConfig::default());
    let id = conn.query_now(start, NAME);
    let mut ended = false;
    for second in 1..=120u64 {
        conn.handle_timeout(start + Duration::from_secs(second))
            .unwrap();
        written(&mut conn);
        while let Some(event) = conn.poll_event() {
            ended |= matches!(event, MdnsEvent::QueryTimeout(timed_out) if timed_out == id);
        }
    }
    assert!(ended, "the query ends with QueryTimeout");
    assert!(!conn.is_query_pending(id));
    assert!(
        conn.poll_timeout().is_none(),
        "and asks for no more timeouts"
    );
}

// "Names are matched case-sensitively": the resolver, then the responder.
#[test]
fn test_names_match_whatever_their_case() {
    let response = message(RESPONSE, &[], &[a_record(NAME, OWNER)]);
    assert_eq!(
        resolve(&NAME.to_ascii_uppercase(), &response),
        Some(OWNER.parse().unwrap())
    );

    let now = Instant::now();
    let mut conn = responder(now);
    let query = message(QUERY, &[(&NAME.to_ascii_uppercase(), TYPE_A)], &[]);
    deliver(&mut conn, now, ASKER, &query);
    assert_eq!(written(&mut conn).len(), 1, "the question is answered");
}

// "Questions inside responses are answered."
#[test]
fn test_question_inside_a_response_is_not_answered() {
    let now = Instant::now();
    let mut conn = responder(now);
    deliver(
        &mut conn,
        now,
        ASKER,
        &message(RESPONSE, &[(NAME, TYPE_A)], &[]),
    );
    assert!(written(&mut conn).is_empty());
}

// "Non-zero OPCODE / RCODE messages are processed."
#[test]
fn test_message_with_an_rcode_or_another_opcode_is_ignored() {
    for extra in [0x0003, 0x2800] {
        let response = message(RESPONSE | extra, &[], &[a_record(NAME, OWNER)]);
        assert_eq!(resolve(NAME, &response), None, "flags {extra:#06x}");

        let now = Instant::now();
        let mut conn = responder(now);
        deliver(
            &mut conn,
            now,
            ASKER,
            &message(QUERY | extra, &[(NAME, TYPE_A)], &[]),
        );
        assert!(written(&mut conn).is_empty(), "flags {extra:#06x}");
    }
}

// "The fixed-IP responder answers one query twice."
#[test]
fn test_query_for_a_and_aaaa_is_answered_once() {
    let now = Instant::now();
    let mut conn = responder(now);
    let query = message(QUERY, &[(NAME, TYPE_A), (NAME, TYPE_AAAA)], &[]);
    deliver(&mut conn, now, ASKER, &query);
    assert_eq!(written(&mut conn).len(), 1);
}

// "The fixed-IP responder ignores the question type": a TXT question got the A record.
#[test]
fn test_txt_question_does_not_get_the_address_record() {
    let now = Instant::now();
    let mut conn = responder(now);
    deliver(
        &mut conn,
        now,
        ASKER,
        &message(QUERY, &[(NAME, TYPE_TXT)], &[]),
    );
    let out = written(&mut conn);
    // RFC 6762 section 6.1: the answer is the NSEC record saying the name has no TXT record.
    assert_eq!(out.len(), 1);
    assert_eq!(first_record_type(&out[0]), TYPE_NSEC);
}

// RFC 6762 section 6: "every question is answered at once", so a record was multicast as
// often as it was asked for.
#[test]
fn test_record_is_multicast_once_for_two_queries_in_a_second() {
    let now = Instant::now();
    let mut conn = Mdns::new(now, MdnsConfig::default());
    assert!(conn.add_local_name(NAME, OWNER.parse().unwrap()));
    let query = message(QUERY, &[(NAME, TYPE_A)], &[]);
    deliver(&mut conn, now, ASKER, &query);
    deliver(
        &mut conn,
        now + Duration::from_millis(100),
        "192.168.1.31",
        &query,
    );
    assert_eq!(written(&mut conn).len(), 1);
}
