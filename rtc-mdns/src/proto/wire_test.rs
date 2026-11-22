//! The message reader and writer (RFC 6762 sections 6.1, 10.2, 17, 18.12 to 18.14).

use super::testkit::*;
use super::wire::*;

fn record<'a>(name: &'a str, address: &str, nsec: bool) -> OutRecord<'a> {
    OutRecord {
        name,
        ip: ip(address),
        nsec,
        flush: true,
        ttl: 120,
    }
}

/// A response with one NSEC record for `UUID_1`, its data as given, then an address record.
fn nsec_then_address(nsec_rdata: &[u8]) -> Inbound {
    let bytes = message(
        0,
        RESPONSE,
        &[],
        &[
            other(UUID_1, TYPE_NSEC, nsec_rdata),
            addr(UUID_1, "192.168.1.50"),
        ],
        &[],
        &[],
    );
    parse(&bytes).unwrap()
}

// RFC 6762 section 6.1: the restricted form is read, with the next domain name as a pointer
// or spelled out, whatever name it is.
#[test]
fn test_restricted_nsec_is_read() {
    // A pointer to the record's own name (at offset 12), window 0, one byte: type 1.
    let msg = nsec_then_address(&[0xC0, 12, 0, 1, 0x40]);
    assert_eq!(msg.answers[0].nsec_has(TYPE_A), Some(true));
    assert_eq!(msg.answers[0].nsec_has(TYPE_AAAA), Some(false));
    assert_eq!(
        msg.answers[0].nsec_has(300),
        None,
        "the form says nothing above 255"
    );

    // Another next domain name, spelled out; 32 bitmap bytes, the last bit: type 255.
    let mut rdata = wire_name("something.else.local");
    rdata.extend_from_slice(&[0, 32]);
    rdata.extend_from_slice(&[0; 31]);
    rdata.push(0x01);
    let msg = nsec_then_address(&rdata);
    assert_eq!(msg.answers[0].nsec_has(255), Some(true));
    assert_eq!(msg.answers[0].nsec_has(TYPE_A), Some(false));
}

// RFC 6762 section 6.1: an NSEC record of another form may be ignored; the message it is in
// must not be.
#[test]
fn test_nsec_of_another_form_is_ignored_and_the_message_is_not() {
    let mut two_windows = vec![0xC0, 12, 0, 1, 0x40];
    two_windows.extend_from_slice(&[1, 1, 0x80]);
    let mut too_long = vec![0xC0, 12, 0, 33];
    too_long.extend_from_slice(&[0; 33]);
    for rdata in [
        vec![0xC0, 12, 1, 1, 0x40], // window 1
        vec![0xC0, 12, 0, 0],       // an empty bitmap
        too_long,
        two_windows,
        vec![0xC0, 12, 0, 4, 0x40], // shorter than it says
        vec![],
    ] {
        let msg = nsec_then_address(&rdata);
        assert_eq!(msg.answers.len(), 2, "{rdata:?}");
        assert_eq!(msg.answers[0].data, InData::Other, "{rdata:?}");
        assert_eq!(msg.answers[0].nsec_has(TYPE_A), None);
        assert_eq!(msg.answers[1].addr(), Some(ip("192.168.1.50")));
    }
}

// RFC 6762 sections 18.12, 18.13: the top bit of the class field is not part of the class.
#[test]
fn test_top_bit_of_the_class_is_read_apart_from_the_class() {
    let bytes = message(
        0,
        QUERY,
        &[(UUID_1, TYPE_A, 0x8001), (UUID_1, TYPE_A, 0x0001)],
        &[
            addr(UUID_1, "192.168.1.50").class(0x8001),
            addr(UUID_1, "192.168.1.50").class(0x0001),
        ],
        &[],
        &[],
    );
    let msg = parse(&bytes).unwrap();
    let questions: Vec<(u16, bool)> = msg.questions.iter().map(|q| (q.class, q.unicast)).collect();
    assert_eq!(questions, vec![(CLASS_IN, true), (CLASS_IN, false)]);
    let records: Vec<(u16, bool)> = msg.answers.iter().map(|r| (r.class, r.flush)).collect();
    assert_eq!(records, vec![(CLASS_IN, true), (CLASS_IN, false)]);
}

// RFC 6762 section 10.2: an OPT pseudo-record is not DNS data; its class field is a size.
#[test]
fn test_opt_pseudo_record_is_not_taken_for_a_record() {
    let bytes = message(
        0,
        RESPONSE,
        &[],
        &[addr(UUID_1, "192.168.1.50")],
        &[],
        &[other(".", TYPE_OPT, &[]).class(1440)],
    );
    let msg = parse(&bytes).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert!(msg.additionals.is_empty());
}

// A message that ends in the middle of a record keeps the records before the cut; one whose
// question section is cut is no message.
#[test]
fn test_message_cut_short() {
    let bytes = message(
        0,
        RESPONSE,
        &[],
        &[addr(UUID_1, "192.168.1.50"), addr(UUID_2, "192.168.1.51")],
        &[],
        &[],
    );
    let msg = parse(&bytes[..bytes.len() - 1]).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].addr(), Some(ip("192.168.1.50")));

    let query = query_for(UUID_1);
    assert!(parse(&query[..query.len() - 1]).is_none());
    assert!(parse(&query[..11]).is_none(), "not even a header");
    assert!(parse(&[]).is_none());
}

// Flood control: what is kept from one message is bounded, and what comes after the bound is
// still stepped over correctly.
#[test]
fn test_questions_and_records_kept_from_a_message_are_bounded() {
    let questions: Vec<(&str, u16, u16)> = vec![("a", TYPE_A, CLASS_IN); 260];
    let records: Vec<Rec> = vec![other("a", TYPE_TXT, &[]); 260];
    let last = [addr(UUID_1, "10.0.0.1")];
    let bytes = message(0, QUERY, &questions, &records, &records, &last);
    assert!(bytes.len() <= MAX_INBOUND_MESSAGE);
    let msg = parse(&bytes).unwrap();
    assert_eq!(msg.questions.len(), MAX_MESSAGE_QUESTIONS);
    assert_eq!(msg.answers.len(), 260);
    assert_eq!(msg.authorities.len(), MAX_MESSAGE_RECORDS - 260);
    assert!(msg.additionals.is_empty());

    // Under the bounds, everything is kept, the last record included.
    let bytes = message(
        0,
        QUERY,
        &questions[..10],
        &records[..10],
        &records[..10],
        &last,
    );
    let msg = parse(&bytes).unwrap();
    assert_eq!(msg.questions.len(), 10);
    assert_eq!(msg.additionals[0].addr(), Some(ip("10.0.0.1")));
}

// RFC 6762 section 18.14: names are compressed on the way out, and read back.
#[test]
fn test_written_names_are_compressed_and_read_back() {
    let name = format!("{UUID_1}.");
    let other_name = format!("{UUID_2}.");
    let questions = [OutQuestion {
        name: &name,
        typ: TYPE_ANY,
        class: CLASS_IN | CLASS_TOP_BIT,
    }];
    let records = [
        record(&name, "192.168.1.50", false),
        record(&other_name, "fe80::1", false),
        record(&name, "192.168.1.50", true),
    ];
    let bytes = pack(
        7,
        FLAGS_RESPONSE,
        &questions,
        &records[..1],
        &records[1..2],
        &records[2..],
    )
    .unwrap();
    // The question spells the name out (44 bytes); the first record points at it; the second
    // spells its first label and points at `local.`; the NSEC record points at the name twice.
    assert_eq!(
        bytes.len(),
        12 + (44 + 4) + (2 + 10 + 4) + (37 + 2 + 10 + 16) + (2 + 10 + 5)
    );
    let msg = parse(&bytes).unwrap();
    assert_eq!(msg.header.id, 7);
    assert!(msg.header.response && msg.header.authoritative);
    assert_eq!(msg.questions[0].name, name);
    assert!(msg.questions[0].unicast);
    assert_eq!(msg.answers[0].key, name);
    assert_eq!(msg.answers[0].addr(), Some(ip("192.168.1.50")));
    assert_eq!(msg.authorities[0].key, other_name);
    assert_eq!(msg.authorities[0].addr(), Some(ip("fe80::1")));
    assert_eq!(msg.additionals[0].key, name);
    assert_eq!(msg.additionals[0].nsec_has(TYPE_A), Some(true));
}

// What is not a DNS name is not written.
#[test]
fn test_names_that_are_not_dns_names_are_not_written() {
    let long_label = format!("{}.local.", "x".repeat(64));
    let long_name = format!("{}.", ["y".repeat(63).as_str(); 4].join("."));
    assert_eq!(long_name.len(), 256);
    for name in [
        "no-trailing-dot.local",
        "",
        "..",
        "a..local.",
        &long_label,
        &long_name,
    ] {
        assert!(
            pack(0, 0, &[], &[record(name, "10.0.0.1", false)], &[], &[]).is_none(),
            "{name:?}"
        );
    }
    let fits = format!(
        "{}.{}.",
        ["y".repeat(63).as_str(); 3].join("."),
        "z".repeat(61)
    );
    assert_eq!(fits.len(), 254);
    assert!(pack(0, 0, &[], &[record(&fits, "10.0.0.1", false)], &[], &[]).is_some());
    assert!(pack(0, 0, &[], &[record(".", "10.0.0.1", false)], &[], &[]).is_some());
}

// RFC 6762 section 17: a set of records is cut into messages that fit a datagram; a record
// that does not fit one goes alone.
#[test]
fn test_split_cuts_a_set_into_messages_that_fit() {
    let names: Vec<String> = (0..200).map(|i| format!("host-{i:03}.local.")).collect();
    let items: Vec<usize> = (0..names.len()).collect();
    let mut out = Vec::new();
    split(
        &items,
        &|items, full| {
            let answers: Vec<OutRecord<'_>> = items
                .iter()
                .map(|&i| record(&names[i], "fe80::1", false))
                .collect();
            let additionals: Vec<OutRecord<'_>> = items
                .iter()
                .filter(|_| full)
                .map(|&i| record(&names[i], "fe80::1", true))
                .collect();
            pack(0, FLAGS_RESPONSE, &[], &answers, &[], &additionals)
        },
        &mut out,
    );
    assert!(out.len() > 1);
    let mut seen = Vec::new();
    for packed in &out {
        let bytes = packed.bytes.as_ref().unwrap();
        assert!(bytes.len() <= MAX_OUTBOUND_MESSAGE);
        let msg = parse(bytes).unwrap();
        assert_eq!(msg.answers.len(), packed.items.len());
        assert_eq!(msg.additionals.is_empty(), packed.trimmed);
        seen.extend_from_slice(&packed.items);
    }
    assert_eq!(seen, items, "every item once, in order");
}
