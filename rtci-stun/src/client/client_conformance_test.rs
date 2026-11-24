use super::*;
use crate::addr::MappedAddress;
use crate::error_code::ErrorCodeAttribute;
use crate::fingerprint::FINGERPRINT;
use crate::textattrs::TextAttribute;
use crate::xoraddr::XorMappedAddress;
use sansio::Protocol;
use std::net::IpAddr;

fn addrs() -> (SocketAddr, SocketAddr) {
    (
        "127.0.0.1:5000".parse().unwrap(),
        "127.0.0.1:3478".parse().unwrap(),
    )
}

fn binding_request() -> Message {
    let mut msg = Message::new();
    msg.build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
        .expect("a binding request encodes");
    msg
}

fn datagram(now: Instant, from: SocketAddr, to: SocketAddr, raw: &[u8]) -> TaggedBytesMut {
    TransportMessage {
        now,
        transport: TransportContext {
            local_addr: to,
            peer_addr: from,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(raw),
    }
}

/// Runs the client with no response for `until_ms` of virtual time, one millisecond at a time,
/// and returns when each request left and when the transaction ended.
fn run_unanswered(client: &mut Client, base: Instant, until_ms: u64) -> (Vec<u64>, Option<u64>) {
    let mut sent = vec![];
    let mut ended = None;
    for ms in 0..=until_ms {
        let now = base + Duration::from_millis(ms);
        if ms > 0 {
            client.handle_timeout(now).unwrap();
        }
        while let Some(event) = client.poll_event() {
            if matches!(event, StunEvent::TransactionTimeOut) {
                ended = Some(ms);
            }
        }
        while client.poll_write().is_some() {
            sent.push(ms);
        }
    }
    (sent, ended)
}

/// RFC 8489 section 6.2.1: with RTO 100 ms, Rc 7 and Rm 16, requests leave at 0, 100, 300, 700,
/// 1500, 3100 and 6300 ms and the transaction fails at 7900 ms.
#[test]
fn test_requests_double_the_rto_and_fail_rm_rto_after_the_last() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new()
        .with_rto(Duration::from_millis(100))
        .build(base, local, remote, TransportProtocol::UDP)?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;

    let (sent, ended) = run_unanswered(&mut client, base, 9000);
    assert_eq!(sent, vec![0, 100, 300, 700, 1500, 3100, 6300]);
    assert_eq!(ended, Some(7900));
    Ok(())
}

/// A Binding success response of 132 bytes, what coturn sends over IPv6, reaches the caller
/// whole.
#[test]
fn test_a_response_longer_than_120_bytes_is_delivered_whole() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let request = binding_request();
    let id = request.transaction_id;
    client.handle_write(TaggedMessage {
        now: base,
        message: request,
    })?;

    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let mut response = Message::new();
    response.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(XorMappedAddress { ip, port: 40000 }),
        Box::new(MappedAddress { ip, port: 40000 }),
        Box::new(RawAttribute {
            typ: ATTR_RESPONSE_ORIGIN,
            length: 0,
            value: {
                let mut origin = Message::new();
                origin.write_header();
                MappedAddress { ip, port: 3478 }.add_to_as(&mut origin, ATTR_RESPONSE_ORIGIN)?;
                origin.attributes.0[0].value.clone()
            },
        }),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "a STUN server, version 4.6.2".to_owned(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    assert_eq!(response.raw.len(), 132);

    client.handle_read(datagram(base, remote, local, &response.raw))?;
    match client.poll_event() {
        Some(StunEvent::Message(m)) => {
            assert_eq!(m.raw, response.raw);
            let mut mapped = XorMappedAddress::default();
            mapped.get_from(&m)?;
            assert_eq!((mapped.ip, mapped.port), (ip, 40000));
        }
        other => panic!("expected the response, got {other:?}"),
    }
    Ok(())
}

/// RFC 8489 section 6.3: a transaction is answered only by a response (success or error) of
/// the request's method that comes from the server. A request or an indication carrying the
/// transaction id, or a response from another address, leaves the transaction running.
#[test]
fn test_only_a_response_from_the_server_ends_the_transaction() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let other: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let request = binding_request();
    let id = request.transaction_id;
    client.handle_write(TaggedMessage {
        now: base,
        message: request,
    })?;

    let message = |typ: MessageType| {
        let mut m = Message::new();
        m.build(&[Box::new(typ), Box::new(id)]).unwrap();
        m
    };
    let indication = MessageType::new(METHOD_BINDING, CLASS_INDICATION);
    let other_method = MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE);

    // The same id in a request, an indication, or a response of another method.
    for typ in [BINDING_REQUEST, indication, other_method] {
        let _ = client.handle_read(datagram(base, remote, local, &message(typ).raw));
        assert!(
            client.poll_event().is_none(),
            "{typ} is not a response to it"
        );
    }
    // A response from an address that is not the server.
    let _ = client.handle_read(datagram(base, other, local, &message(BINDING_SUCCESS).raw));
    assert!(client.poll_event().is_none(), "not from the server");

    // The transaction is still open: the server's response ends it.
    client.handle_read(datagram(base, remote, local, &message(BINDING_SUCCESS).raw))?;
    assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));
    Ok(())
}

fn request_with_id(id: TransactionId) -> Message {
    let mut msg = Message::new();
    msg.build(&[Box::new(id), Box::new(BINDING_REQUEST)])
        .expect("a binding request encodes");
    msg
}

fn response(typ: MessageType, id: TransactionId, attrs: Vec<Box<dyn Setter + '_>>) -> Message {
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![Box::new(typ), Box::new(id)];
    setters.extend(attrs);
    let mut m = Message::new();
    m.build(&setters).expect("the response encodes");
    m
}

/// Starts a transaction at `now` and returns its id.
fn start(client: &mut Client, now: Instant) -> TransactionId {
    let request = binding_request();
    let id = request.transaction_id;
    client
        .handle_write(TaggedMessage {
            now,
            message: request,
        })
        .expect("the request is accepted");
    while client.poll_write().is_some() {}
    id
}

fn mapped() -> Box<XorMappedAddress> {
    Box::new(XorMappedAddress {
        ip: "192.0.2.1".parse().unwrap(),
        port: 40000,
    })
}

/// RFC 8489 section 6.2.1: the defaults are an initial RTO of 500 ms, Rc = 7 and Rm = 16, so
/// an unanswered request leaves at 0, 500, 1500, 3500, 7500, 15500 and 31500 ms and the
/// transaction fails after 39500 ms.
#[test]
fn test_default_timer_is_500_ms_seven_requests_and_39500_ms() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    assert_eq!(client.rto(), Duration::from_millis(500));
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    let (sent, ended) = run_unanswered(&mut client, base, 40_000);
    assert_eq!(sent, vec![0, 500, 1500, 3500, 7500, 15500, 31500]);
    assert_eq!(ended, Some(39_500));
    assert_eq!(client.poll_timeout(), None);
    Ok(())
}

/// RFC 8489 section 6.2.1: Rc and Rm are configurable.
#[test]
fn test_rc_and_rm_are_configurable() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new()
        .with_rto(Duration::from_millis(100))
        .with_rc(3)
        .with_rm(4)
        .build(base, local, remote, TransportProtocol::UDP)?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    let (sent, ended) = run_unanswered(&mut client, base, 2000);
    assert_eq!(sent, vec![0, 100, 300]);
    assert_eq!(
        ended,
        Some(700),
        "Rm x RTO after the third and last request"
    );

    // One request and no retransmission.
    let mut client = ClientBuilder::new()
        .with_rto(Duration::from_millis(100))
        .with_no_retransmit()
        .build(base, local, remote, TransportProtocol::UDP)?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    let (sent, ended) = run_unanswered(&mut client, base, 2000);
    assert_eq!(sent, vec![0]);
    assert_eq!(ended, Some(1600));
    Ok(())
}

/// RFC 8489 section 6.2.2: over a reliable transport the request is sent once, and the
/// transaction fails after Ti, 39.5 s unless configured.
#[test]
fn test_over_tcp_a_request_is_sent_once_and_fails_at_ti() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::TCP)?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    assert_eq!(
        client.poll_timeout(),
        Some(base + Duration::from_millis(39_500))
    );
    let (sent, ended) = run_unanswered(&mut client, base, 40_000);
    assert_eq!(sent, vec![0], "TCP retransmits, STUN does not");
    assert_eq!(ended, Some(39_500));

    let mut client = ClientBuilder::new()
        .with_ti(Duration::from_millis(2500))
        .build(base, local, remote, TransportProtocol::TCP)?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    let (sent, ended) = run_unanswered(&mut client, base, 5000);
    assert_eq!(sent, vec![0]);
    assert_eq!(ended, Some(2500));
    Ok(())
}

/// RFC 8489 section 6.2.1 with RFC 6298: the RTO follows the measured round-trip time
/// (SRTT + 4 x RTTVAR, to the millisecond, never below the initial value), only requests that
/// were not retransmitted are measured, and the value is kept for the server's next
/// transaction but not past ten minutes without one.
#[test]
fn test_rto_follows_round_trip_time_and_is_cached_for_ten_minutes() -> Result<()> {
    let base = Instant::now();
    let t = |ms: u64| base + Duration::from_millis(ms);
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let answer = |client: &mut Client, id: TransactionId, at: Instant| {
        let reply = response(BINDING_SUCCESS, id, vec![mapped()]);
        client
            .handle_read(datagram(at, remote, local, &reply.raw))
            .unwrap();
        assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));
    };

    // First measurement, R = 300 ms: SRTT = R, RTTVAR = R / 2, RTO = 300 + 4 x 150 = 900 ms.
    let id = start(&mut client, t(0));
    answer(&mut client, id, t(300));
    assert_eq!(client.rto(), Duration::from_millis(900));

    // The next transaction starts with it: its first retransmission is 900 ms after it.
    let id = start(&mut client, t(1000));
    assert_eq!(client.poll_timeout(), Some(t(1900)));
    // Second measurement, R = 300 ms again: RTTVAR = 3/4 x 150 = 112.5 ms, SRTT = 300 ms,
    // RTO = 750 ms. Not rounded to a second.
    answer(&mut client, id, t(1300));
    assert_eq!(client.rto(), Duration::from_millis(750));

    // Karn's algorithm: a request that was retransmitted gives no measurement.
    let id = start(&mut client, t(2000));
    client.handle_timeout(t(2750))?;
    assert!(client.poll_write().is_some(), "retransmitted at the RTO");
    answer(&mut client, id, t(2760));
    assert_eq!(client.rto(), Duration::from_millis(750));

    // A fast server does not take the RTO below the configured initial value.
    for i in 0..40u64 {
        let id = start(&mut client, t(3000 + i * 10));
        answer(&mut client, id, t(3000 + i * 10 + 1));
    }
    assert_eq!(client.rto(), Duration::from_millis(500));

    // A slow one raises it again. The value is kept for ten minutes without a transaction
    // (the next one still starts with it) and not a second longer.
    let id = start(&mut client, t(10_000));
    answer(&mut client, id, t(10_450));
    let raised = client.rto();
    assert!(raised > Duration::from_millis(500), "{raised:?}");
    let within = t(10_450) + Duration::from_secs(600);
    let id = start(&mut client, within);
    assert_eq!(client.poll_timeout(), Some(within + raised), "still cached");
    answer(&mut client, id, within + Duration::from_millis(450));
    let raised = client.rto();
    assert!(raised > Duration::from_millis(500), "{raised:?}");
    let stale = within + Duration::from_millis(450) + Duration::from_secs(601);
    start(&mut client, stale);
    assert_eq!(
        client.poll_timeout(),
        Some(stale + Duration::from_millis(500)),
        "stale after ten minutes: back to the initial RTO"
    );

    // Estimation off: every transaction starts at the initial RTO.
    let mut fixed = ClientBuilder::new().with_rto_estimation(false).build(
        base,
        local,
        remote,
        TransportProtocol::UDP,
    )?;
    let id = start(&mut fixed, t(0));
    answer(&mut fixed, id, t(450));
    assert_eq!(fixed.rto(), Duration::from_millis(500));
    Ok(())
}

/// RFC 8489 section 6.2: at most ten transactions are outstanding to a server at once.
#[test]
fn test_at_most_ten_transactions_are_outstanding() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let ids: Vec<TransactionId> = (0..10).map(|_| start(&mut client, base)).collect();
    assert_eq!(client.outstanding_transactions(), 10);
    let eleventh = client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    });
    assert!(eleventh.is_err(), "an eleventh outstanding transaction");
    assert!(
        client.poll_write().is_none(),
        "the refused request is not sent"
    );

    // A transaction id in use is refused too, whatever the count.
    let duplicate = client.handle_write(TaggedMessage {
        now: base,
        message: request_with_id(ids[0]),
    });
    assert_eq!(duplicate, Err(Error::ErrTransactionExists));

    // One answered: there is room for one more.
    let reply = response(BINDING_SUCCESS, ids[3], vec![mapped()]);
    client.handle_read(datagram(base, remote, local, &reply.raw))?;
    assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));
    start(&mut client, base);
    assert_eq!(client.outstanding_transactions(), 10);

    // The limit is the caller's to lift when it limits its rate some other way.
    let mut unlimited = ClientBuilder::new()
        .with_max_outstanding_transactions(0)
        .build(base, local, remote, TransportProtocol::UDP)?;
    for _ in 0..25 {
        start(&mut unlimited, base);
    }
    assert_eq!(unlimited.outstanding_transactions(), 25);
    Ok(())
}

/// RFC 8489 sections 6.3.3 and 6.3.4: a success or error response with an unknown
/// comprehension-required attribute is discarded and its transaction has failed; unknown
/// comprehension-optional attributes are ignored (section 6.3).
#[test]
fn test_response_with_unknown_required_attribute_fails_the_transaction() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let unknown = || {
        Box::new(RawAttribute {
            typ: AttrType(0x7f01),
            length: 0,
            value: vec![1, 2, 3, 4],
        })
    };
    let optional = || {
        Box::new(RawAttribute {
            typ: AttrType(0xff01),
            length: 0,
            value: vec![1, 2, 3, 4],
        })
    };

    for typ in [BINDING_SUCCESS, BINDING_ERROR] {
        let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
        let id = start(&mut client, base);
        let reply = response(
            typ,
            id,
            vec![
                mapped(),
                Box::new(crate::error_code::CODE_BAD_REQUEST),
                unknown(),
            ],
        );
        client.handle_read(datagram(base, remote, local, &reply.raw))?;
        match client.poll_event() {
            Some(StunEvent::TransactionFailed {
                id: failed,
                reason: TransactionFailure::UnknownAttributes(list),
            }) => {
                assert_eq!(failed, id);
                assert_eq!(list, vec![AttrType(0x7f01)]);
            }
            other => panic!("expected a failed transaction, got {other:?}"),
        }
        assert_eq!(client.outstanding_transactions(), 0);
        assert_eq!(client.poll_timeout(), None, "no retransmission after it");
    }

    // An optional one, and what an RFC 3489 server adds, do not stand in the way.
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let id = start(&mut client, base);
    let reply = response(
        BINDING_SUCCESS,
        id,
        vec![
            mapped(),
            optional(),
            Box::new(RawAttribute {
                typ: ATTR_SOURCE_ADDRESS,
                length: 0,
                value: vec![0, 1, 0x0d, 0x96, 192, 0, 2, 9],
            }),
        ],
    );
    client.handle_read(datagram(base, remote, local, &reply.raw))?;
    assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));

    // The usage says what it knows.
    let mut client = ClientBuilder::new()
        .with_known_attributes(&[&STUN_ATTRIBUTES[..], &[AttrType(0x7f01)]].concat())
        .build(base, local, remote, TransportProtocol::UDP)?;
    let id = start(&mut client, base);
    let reply = response(BINDING_SUCCESS, id, vec![mapped(), unknown()]);
    client.handle_read(datagram(base, remote, local, &reply.raw))?;
    assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));
    Ok(())
}

/// RFC 8489 sections 6.3.1.1 and 6.3.4: an error response carries ERROR-CODE; one without it
/// fails the transaction.
#[test]
fn test_error_response_without_error_code_fails_the_transaction() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;

    let id = start(&mut client, base);
    let reply = response(BINDING_ERROR, id, vec![]);
    client.handle_read(datagram(base, remote, local, &reply.raw))?;
    assert!(matches!(
        client.poll_event(),
        Some(StunEvent::TransactionFailed {
            reason: TransactionFailure::MissingErrorCode,
            ..
        })
    ));

    let id = start(&mut client, base);
    let reply = response(
        BINDING_ERROR,
        id,
        vec![Box::new(crate::error_code::CODE_SERVER_ERROR)],
    );
    client.handle_read(datagram(base, remote, local, &reply.raw))?;
    match client.poll_event() {
        Some(StunEvent::Message(m)) => {
            let mut code = ErrorCodeAttribute::default();
            code.get_from(&m)?;
            assert_eq!(code.code, crate::error_code::CODE_SERVER_ERROR);
        }
        other => panic!("expected the error response, got {other:?}"),
    }
    Ok(())
}

/// RFC 8489 sections 6.3 and 14.7: a response whose FINGERPRINT does not match is not a STUN
/// message for this client: it is dropped and the transaction goes on.
#[test]
fn test_response_with_a_wrong_fingerprint_is_dropped() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let id = start(&mut client, base);
    let good = response(BINDING_SUCCESS, id, vec![mapped(), Box::new(FINGERPRINT)]);
    let mut bad = good.raw.clone();
    let end = bad.len() - 1;
    bad[end] ^= 0x01;

    client.handle_read(datagram(base, remote, local, &bad))?;
    assert!(client.poll_event().is_none());
    assert_eq!(client.outstanding_transactions(), 1);
    client.handle_read(datagram(base, remote, local, &good.raw))?;
    assert!(matches!(client.poll_event(), Some(StunEvent::Message(_))));
    Ok(())
}

/// RFC 8489 section 9.1.4, unreliable transport: a response whose integrity is absent or
/// wrong is discarded as if it had not arrived, retransmissions continue, and when no
/// authentic response comes the transaction ends with an integrity violation, not a timeout.
/// An authentic response is delivered with its authenticated attributes only.
#[test]
fn test_unauthentic_responses_are_discarded_and_reported_as_integrity_violation() -> Result<()> {
    use crate::integrity::MessageIntegrity;

    let provider = crypto::default_provider().expect("a built-in crypto provider");
    let crypto = provider.crypto();
    let key = b"short-term password";
    let base = Instant::now();
    let t = |ms: u64| base + Duration::from_millis(ms);
    let (local, remote) = addrs();
    let build = || {
        ClientBuilder::new()
            .with_rto(Duration::from_millis(100))
            .with_response_integrity(key.to_vec(), provider.clone())
            .build(base, local, remote, TransportProtocol::UDP)
    };
    let signed = |id: TransactionId, key: &[u8]| {
        response(
            BINDING_SUCCESS,
            id,
            vec![
                mapped(),
                Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                    key.to_vec(),
                    crypto,
                )),
            ],
        )
    };

    // Forged and unsigned responses, then silence.
    let mut client = build()?;
    let request = binding_request();
    let id = request.transaction_id;
    client.handle_write(TaggedMessage {
        now: base,
        message: request,
    })?;
    client.handle_read(datagram(t(10), remote, local, &signed(id, b"not it").raw))?;
    let unsigned = response(BINDING_SUCCESS, id, vec![mapped()]);
    client.handle_read(datagram(t(20), remote, local, &unsigned.raw))?;
    assert!(client.poll_event().is_none(), "discarded, not reported");
    let mut sent = vec![];
    let mut end = None;
    for ms in 0..=9000 {
        if ms > 0 {
            client.handle_timeout(t(ms))?;
        }
        while client.poll_write().is_some() {
            sent.push(ms);
        }
        if let Some(event) = client.poll_event() {
            end = Some((ms, event));
            break;
        }
    }
    assert_eq!(
        sent,
        vec![0, 100, 300, 700, 1500, 3100, 6300],
        "retransmissions continue"
    );
    match end {
        Some((
            7900,
            StunEvent::TransactionFailed {
                id: failed,
                reason: TransactionFailure::IntegrityViolation,
            },
        )) => assert_eq!(failed, id),
        other => panic!("expected an integrity violation at 7900 ms, got {other:?}"),
    }

    // Silence alone is a timeout.
    let mut client = build()?;
    client.handle_write(TaggedMessage {
        now: base,
        message: binding_request(),
    })?;
    let (_, ended) = run_unanswered(&mut client, base, 9000);
    assert_eq!(ended, Some(7900));

    // A forged response first, the authentic one after it, with an attribute appended behind
    // its integrity attribute.
    let mut client = build()?;
    let id = start(&mut client, base);
    client.handle_read(datagram(t(10), remote, local, &signed(id, b"not it").raw))?;
    let mut authentic = signed(id, key);
    authentic.add(ATTR_SOFTWARE, b"appended");
    client.handle_read(datagram(t(20), remote, local, &authentic.raw))?;
    match client.poll_event() {
        Some(StunEvent::Message(m)) => {
            assert!(m.contains(ATTR_XORMAPPED_ADDRESS));
            assert!(!m.contains(ATTR_SOFTWARE), "what follows the integrity");
        }
        other => panic!("expected the authentic response, got {other:?}"),
    }
    Ok(())
}

/// RFC 8489 section 9.1.4, reliable transport: a response whose integrity does not hold ends
/// the transaction at once with an integrity violation.
#[test]
fn test_over_tcp_an_unauthentic_response_ends_the_transaction_at_once() -> Result<()> {
    let provider = crypto::default_provider().expect("a built-in crypto provider");
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new()
        .with_response_integrity(b"key".to_vec(), provider)
        .build(base, local, remote, TransportProtocol::TCP)?;
    let id = start(&mut client, base);
    let unsigned = response(BINDING_SUCCESS, id, vec![mapped()]);
    client.handle_read(datagram(base, remote, local, &unsigned.raw))?;
    assert!(matches!(
        client.poll_event(),
        Some(StunEvent::TransactionFailed {
            reason: TransactionFailure::IntegrityViolation,
            ..
        })
    ));
    assert_eq!(client.outstanding_transactions(), 0);
    assert_eq!(client.poll_timeout(), None);
    Ok(())
}

/// RFC 8489 sections 6.1 and 6.3.2: an indication is sent and has no transaction: no
/// retransmission, no response, no timeout.
#[test]
fn test_an_indication_has_no_transaction() -> Result<()> {
    let base = Instant::now();
    let (local, remote) = addrs();
    let mut client = ClientBuilder::new().build(base, local, remote, TransportProtocol::UDP)?;
    let mut indication = Message::new();
    indication.build(&[
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(METHOD_BINDING, CLASS_INDICATION)),
    ])?;
    client.handle_write(TaggedMessage {
        now: base,
        message: indication.clone(),
    })?;
    let sent = client.poll_write().expect("the indication is sent");
    assert_eq!(&sent.message[..], &indication.raw[..]);
    assert_eq!(client.outstanding_transactions(), 0);
    assert_eq!(client.poll_timeout(), None);
    let (sent, ended) = run_unanswered(&mut client, base, 2000);
    assert!(sent.is_empty() && ended.is_none());
    Ok(())
}

/// RFC 8489 section 6.1: over UDP a message fits the path MTU; when that is unknown, an IP
/// packet of 576 bytes (IPv4) or 1280 bytes (IPv6), which leaves 548 or 1232 bytes of STUN.
/// A reliable transport has no such limit.
#[test]
fn test_udp_message_larger_than_the_path_mtu_is_refused() -> Result<()> {
    let base = Instant::now();
    let local4: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let remote4: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let local6: SocketAddr = "[::1]:5000".parse().unwrap();
    let remote6: SocketAddr = "[::1]:3478".parse().unwrap();
    // A request of exactly `size` bytes: the header and one opaque attribute.
    let request_of = |size: usize| {
        let mut m = Message::new();
        m.build(&[
            Box::new(TransactionId::new()),
            Box::new(BINDING_REQUEST),
            Box::new(RawAttribute {
                typ: AttrType(0xff00),
                length: 0,
                value: vec![0; size - MESSAGE_HEADER_SIZE - ATTRIBUTE_HEADER_SIZE],
            }),
        ])
        .unwrap();
        assert_eq!(m.raw.len(), size);
        m
    };
    let write = |client: &mut Client, size: usize| {
        client.handle_write(TaggedMessage {
            now: base,
            message: request_of(size),
        })
    };
    let udp = TransportProtocol::UDP;

    let mut v4 = ClientBuilder::new().build(base, local4, remote4, udp)?;
    assert_eq!(v4.max_message_size(), 548);
    write(&mut v4, 548)?;
    assert_eq!(write(&mut v4, 552), Err(Error::ErrPacketTooBig));
    assert_eq!(
        v4.outstanding_transactions(),
        1,
        "the refused one was not sent"
    );

    let mut v6 = ClientBuilder::new().build(base, local6, remote6, udp)?;
    assert_eq!(v6.max_message_size(), 1232);
    write(&mut v6, 1232)?;
    assert_eq!(write(&mut v6, 1236), Err(Error::ErrPacketTooBig));

    // A known path MTU of 1500 bytes: 1472 bytes of STUN over IPv4.
    let mut known = ClientBuilder::new()
        .with_path_mtu(1500)
        .build(base, local4, remote4, udp)?;
    write(&mut known, 1472)?;
    assert_eq!(write(&mut known, 1476), Err(Error::ErrPacketTooBig));

    let mut tcp = ClientBuilder::new().build(base, local4, remote4, TransportProtocol::TCP)?;
    write(&mut tcp, 4000)?;
    Ok(())
}
