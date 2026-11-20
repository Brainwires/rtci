//! Which mDNS answers resolve a query (RFC 6762 §6, §10, §11, §18.2).

use super::*;
use sansio::Protocol;

const NAME: &str = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";

/// A packed message answering `NAME` with `ip`.
fn answer_packet(ip: IpAddr, response: bool, ttl: u32) -> BytesMut {
    let (typ, body): (DnsType, Box<dyn crate::message::resource::ResourceBody>) = match ip {
        IpAddr::V4(v4) => (DnsType::A, Box::new(AResource { a: v4.octets() })),
        IpAddr::V6(v6) => (DnsType::Aaaa, Box::new(AaaaResource { aaaa: v6.octets() })),
    };
    let mut msg = Message {
        header: Header {
            response,
            authoritative: response,
            ..Default::default()
        },
        answers: vec![Resource {
            header: ResourceHeader {
                typ,
                class: DNSCLASS_INET,
                name: Name::new(&format!("{NAME}.")).unwrap(),
                ttl,
                ..Default::default()
            },
            body: Some(body),
        }],
        ..Default::default()
    };
    BytesMut::from(&msg.pack().unwrap()[..])
}

/// A connection with a pending query for `NAME`, given `packet` from `src`; returns what the
/// query resolved to, if anything.
fn resolve(packet: BytesMut, src: &str) -> Option<IpAddr> {
    let now = Instant::now();
    let mut conn = Mdns::new(now, MdnsConfig::default());
    let id = conn.query_now(now, NAME);
    while conn.poll_write().is_some() {}
    conn.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT),
            peer_addr: SocketAddr::new(src.parse().unwrap(), MDNS_PORT),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: packet,
    })
    .unwrap();
    let mut resolved = None;
    while let Some(event) = conn.poll_event() {
        if let MdnsEvent::QueryAnswered(qid, ip) = event {
            assert_eq!(qid, id);
            resolved = Some(ip);
        }
    }
    if resolved.is_none() {
        assert!(
            conn.is_query_pending(id),
            "an ignored answer leaves the query pending"
        );
    }
    resolved
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn test_answer_from_its_owner_resolves() {
    assert_eq!(
        resolve(answer_packet(ip("192.168.1.50"), true, 120), "192.168.1.50"),
        Some(ip("192.168.1.50"))
    );
}

#[test]
fn test_query_carrying_an_answer_does_not_resolve() {
    // QR = 0: a query's known-answer section, unicast to us, naming loopback.
    assert_eq!(
        resolve(answer_packet(ip("127.0.0.1"), false, 120), "127.0.0.1"),
        None
    );
    assert_eq!(
        resolve(
            answer_packet(ip("192.168.1.50"), false, 120),
            "192.168.1.50"
        ),
        None
    );
}

#[test]
fn test_a_record_naming_another_address_does_not_resolve() {
    assert_eq!(
        resolve(answer_packet(ip("127.0.0.1"), true, 120), "192.168.1.60"),
        None
    );
    assert_eq!(
        resolve(answer_packet(ip("10.0.0.7"), true, 120), "192.168.1.60"),
        None
    );
}

#[test]
fn test_answer_from_off_link_does_not_resolve() {
    assert_eq!(
        resolve(answer_packet(ip("203.0.113.9"), true, 120), "203.0.113.9"),
        None
    );
    assert_eq!(
        resolve(answer_packet(ip("2001:db8::9"), true, 120), "203.0.113.9"),
        None
    );
}

#[test]
fn test_goodbye_record_does_not_resolve() {
    assert_eq!(
        resolve(answer_packet(ip("192.168.1.50"), true, 0), "192.168.1.50"),
        None
    );
}

#[test]
fn test_aaaa_from_an_on_link_sender_resolves() {
    // A host answers for its IPv6 names over the IPv4 group.
    assert_eq!(
        resolve(answer_packet(ip("2001:db8::20"), true, 120), "192.168.1.20"),
        Some(ip("2001:db8::20"))
    );
    assert_eq!(
        resolve(answer_packet(ip("2001:db8::20"), true, 120), "fe80::20"),
        Some(ip("2001:db8::20"))
    );
}

#[test]
fn test_on_link_source_scopes() {
    for on in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "fe80::1",
        "fd00::1",
        "::1",
        "::ffff:192.168.0.1",
    ] {
        assert!(is_on_link_source(ip(on)), "{on}");
    }
    for off in ["8.8.8.8", "100.128.0.1", "2001:db8::1", "::ffff:8.8.8.8"] {
        assert!(!is_on_link_source(ip(off)), "{off}");
    }
}
