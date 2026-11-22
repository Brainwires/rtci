use super::*;
use crate::error_code::{CODE_SERVER_ERROR, ErrorCode};
use crate::integrity::MessageIntegritySha256;
use crate::validated::Validator;
use crypto::RTCCryptoProvider;
use std::sync::Arc;

const KEY: &[u8] = b"the long-term key";

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn error_response(code: ErrorCode, attrs: Vec<Box<dyn Setter + '_>>) -> Message {
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
        Box::new(TransactionId([1; TRANSACTION_ID_SIZE])),
        Box::new(code),
    ];
    setters.extend(attrs);
    let mut built = Message::new();
    built.build(&setters).unwrap();
    let mut received = Message::new();
    received.unmarshal_binary(&built.raw).unwrap();
    received
}

fn alternate(addr: &str) -> Box<AlternateServer> {
    let addr: SocketAddr = addr.parse().unwrap();
    Box::new(AlternateServer {
        ip: addr.ip(),
        port: addr.port(),
    })
}

/// RFC 8489 sections 10, 14.15 and 14.16: an authenticated 300 names the alternate server
/// (one per address family) and, for (D)TLS, the domain its certificate is checked against.
#[test]
fn test_an_authenticated_300_gives_the_alternate_servers_and_domain() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let response = error_response(
        CODE_TRY_ALTERNATE,
        vec![
            alternate("192.0.2.7:3478"),
            alternate("[2001:db8::7]:3478"),
            Box::new(TextAttribute::new(
                ATTR_ALTERNATE_DOMAIN,
                "turn2.example.org".to_owned(),
            )),
            Box::new(MessageIntegritySha256::new_raw(KEY.to_vec(), crypto)),
        ],
    );
    let valid = Validator::new()
        .authenticate(&response, KEY, crypto)
        .expect("the response authenticates");
    let redirect = TryAlternate::from_response(&valid)?.expect("a redirection");
    assert_eq!(
        redirect.servers,
        vec![
            "192.0.2.7:3478".parse().unwrap(),
            "[2001:db8::7]:3478".parse().unwrap()
        ]
    );
    assert_eq!(redirect.domain.as_deref(), Some("turn2.example.org"));
    // The alternate of the family the request went to.
    assert_eq!(
        redirect.server_for("198.51.100.1".parse().unwrap()),
        Some("192.0.2.7:3478".parse().unwrap())
    );
    assert_eq!(
        redirect.server_for("2001:db8::1".parse().unwrap()),
        Some("[2001:db8::7]:3478".parse().unwrap())
    );
    assert_eq!(redirect.server_attributes().len(), 2);

    // Without ALTERNATE-DOMAIN the original domain applies.
    let no_domain = error_response(
        CODE_TRY_ALTERNATE,
        vec![
            alternate("192.0.2.7:3478"),
            Box::new(MessageIntegritySha256::new_raw(KEY.to_vec(), crypto)),
        ],
    );
    let valid = Validator::new()
        .authenticate(&no_domain, KEY, crypto)
        .unwrap();
    let redirect = TryAlternate::from_response(&valid)?.expect("a redirection");
    assert_eq!(redirect.domain, None);
    assert_eq!(
        redirect.server_for("2001:db8::1".parse().unwrap()),
        Some("192.0.2.7:3478".parse().unwrap()),
        "the only alternate, whatever its family"
    );
    Ok(())
}

/// RFC 8489 sections 6.3.4, 10 and 14.8: a 300 is followed only when its integrity was
/// validated and it carries ALTERNATE-SERVER; otherwise the transaction has simply failed.
#[test]
fn test_a_300_that_is_unauthenticated_or_empty_is_not_a_redirection() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();

    let unsigned = error_response(CODE_TRY_ALTERNATE, vec![alternate("192.0.2.7:3478")]);
    let view = Validator::new().unauthenticated(&unsigned).unwrap();
    assert_eq!(TryAlternate::from_response(&view)?, None);

    // An ALTERNATE-SERVER put after the integrity attribute is not part of the response.
    let appended = error_response(
        CODE_TRY_ALTERNATE,
        vec![
            Box::new(MessageIntegritySha256::new_raw(KEY.to_vec(), crypto)),
            alternate("192.0.2.66:3478"),
        ],
    );
    let valid = Validator::new()
        .authenticate(&appended, KEY, crypto)
        .unwrap();
    assert_eq!(TryAlternate::from_response(&valid)?, None);

    // Another error code with the attribute is not a redirection.
    let other_code = error_response(
        CODE_SERVER_ERROR,
        vec![
            alternate("192.0.2.7:3478"),
            Box::new(MessageIntegritySha256::new_raw(KEY.to_vec(), crypto)),
        ],
    );
    let valid = Validator::new()
        .authenticate(&other_code, KEY, crypto)
        .unwrap();
    assert_eq!(TryAlternate::from_response(&valid)?, None);
    Ok(())
}

/// RFC 8489 section 10: a redirection to a server the request was already sent to within the
/// last five minutes is ignored.
#[test]
fn test_a_redirection_back_within_five_minutes_is_refused() {
    let base = Instant::now();
    let at = |secs| base + Duration::from_secs(secs);
    let a: SocketAddr = "192.0.2.1:3478".parse().unwrap();
    let b: SocketAddr = "192.0.2.2:3478".parse().unwrap();

    let mut guard = RedirectGuard::new();
    guard.sent_to(a, at(0));
    assert!(guard.follow(b, at(1)), "a server not tried yet");
    assert!(
        !guard.follow(a, at(2)),
        "b sends the client back to a: a loop"
    );
    assert!(!guard.allows(b, at(2)));
    assert!(!guard.allows(a, at(299)));
    assert!(guard.allows(a, at(300)), "five minutes after it was tried");
    assert!(guard.follow(a, at(300)));
    assert!(!guard.allows(a, at(301)));
    assert!(!guard.allows(b, at(300)), "b was tried at second 1");
    assert!(guard.allows(b, at(301)));
}

/// RFC 8489 section 14.16: ALTERNATE-DOMAIN is a DNS name of at most 255 bytes.
#[test]
fn test_alternate_domain_is_a_dns_name_of_at_most_255_bytes() -> Result<()> {
    let domain = |text: String| TextAttribute::new(ATTR_ALTERNATE_DOMAIN, text);
    let label = "a".repeat(63);
    let longest = format!("{label}.{label}.{label}.{}", "b".repeat(63));
    assert_eq!(longest.len(), 255);

    for name in [
        "example.org",
        "xn--bcher-kva.example",
        "a-1.b",
        longest.as_str(),
    ] {
        let mut m = Message::new();
        m.write_header();
        domain(name.to_owned()).add_to(&mut m)?;
        assert_eq!(m.get(ATTR_ALTERNATE_DOMAIN)?, name.as_bytes());
        assert_eq!(
            TextAttribute::get_from_as(&m, ATTR_ALTERNATE_DOMAIN)?.text,
            name
        );
    }
    for name in [
        String::new(),
        format!("{longest}c"),
        "b\u{fc}cher.example".to_owned(),
        "-a.example".to_owned(),
        "a..example".to_owned(),
        "under_score.example".to_owned(),
        "a b.example".to_owned(),
        format!("{}.example", "a".repeat(64)),
    ] {
        let mut m = Message::new();
        m.write_header();
        assert!(domain(name.clone()).add_to(&mut m).is_err(), "{name:?}");
        // The same on receipt.
        m.add(ATTR_ALTERNATE_DOMAIN, name.as_bytes());
        assert!(
            TextAttribute::get_from_as(&m, ATTR_ALTERNATE_DOMAIN).is_err(),
            "{name:?}"
        );
    }
    Ok(())
}
