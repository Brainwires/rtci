//! What an Allocate can ask for and what the client takes from the answer (RFC 8656 §7): the
//! address family, a second (IPv6) address, a lifetime, DONT-FRAGMENT, an even or reserved
//! port; SOFTWARE; the retries the RFC allows; and the ICMP errors a relay reports.
use super::test_server::*;
use super::*;
use crate::proto::addfamily::{ATTR_ADDITIONAL_ADDRESS_FAMILY, AdditionalAddressFamily};
use crate::proto::addrerror::AddressErrorCode;
use crate::proto::evenport::EvenPort;
use crate::proto::icmp::Icmp;
use crate::proto::reqfamily::{REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6};
use crate::proto::rsrvtoken::ReservationToken;
use sansio::Protocol;
use stun::error_code::*;

fn relayed_v6() -> RelayedAddr {
    "[2001:db8::15]:50000".parse().unwrap()
}

fn peer_v4() -> SocketAddr {
    "198.51.100.7:4000".parse().unwrap()
}

fn peer_v6() -> SocketAddr {
    "[2001:db8:1::7]:4000".parse().unwrap()
}

fn lifetime_of(request: &Message) -> Result<Duration> {
    let mut lifetime = Lifetime::default();
    lifetime.get_from(request)?;
    Ok(lifetime.0)
}

fn allocated(client: &mut Client, tid: TransactionId) -> RelayedAddr {
    match client.poll_event() {
        Some(Event::AllocateResponse(id, addr)) => {
            assert_eq!(id, tid, "reported under the id allocate_with() returned");
            addr
        }
        other => panic!("expected AllocateResponse, got {other:?}"),
    }
}

fn dual() -> AllocateOptions {
    AllocateOptions {
        additional_ipv6: true,
        ..Default::default()
    }
}

fn ipv6_only() -> AllocateOptions {
    AllocateOptions {
        address_family: Some(REQUESTED_FAMILY_IPV6),
        ..Default::default()
    }
}

/// RFC 8656 §7.1: LIFETIME, DONT-FRAGMENT and EVEN-PORT (with the R bit) go into the Allocate
/// request, the one without the credential and the one with it, beside REQUESTED-TRANSPORT.
#[test]
fn test_allocate_options_are_in_both_requests() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let options = AllocateOptions {
        lifetime: Some(Duration::from_secs(3600)),
        dont_fragment: true,
        even_port: Some(EvenPort { reserve_port: true }),
        ..Default::default()
    };
    let (_, first, authenticated) = server.begin_allocate(&mut client, now, options)?;

    for request in [&first, &authenticated] {
        assert_eq!(request.typ.method, METHOD_ALLOCATE);
        assert_eq!(
            values_of(request, ATTR_REQUESTED_TRANSPORT),
            vec![vec![17, 0, 0, 0]],
            "REQUESTED-TRANSPORT is UDP"
        );
        assert_eq!(lifetime_of(request)?, Duration::from_secs(3600));
        assert_eq!(
            values_of(request, ATTR_DONT_FRAGMENT),
            vec![Vec::<u8>::new()]
        );
        assert_eq!(
            values_of(request, ATTR_EVEN_PORT),
            vec![vec![0x80]],
            "EVEN-PORT with the R bit"
        );
        assert!(!request.contains(ATTR_REQUESTED_ADDRESS_FAMILY));
        assert!(!request.contains(ATTR_ADDITIONAL_ADDRESS_FAMILY));
        assert!(!request.contains(ATTR_RESERVATION_TOKEN));
        assert!(request.contains(ATTR_FINGERPRINT));
    }
    assert!(!first.contains(ATTR_MESSAGE_INTEGRITY));
    assert!(authenticated.contains(ATTR_MESSAGE_INTEGRITY));
    client.close()
}

/// RFC 8656 §7.1: the options that exclude each other never reach the wire together.
#[test]
fn test_option_combinations_the_rfc_forbids_are_refused_before_anything_is_sent() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let token = Some(ReservationToken(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    let forbidden = [
        // REQUESTED-ADDRESS-FAMILY with RESERVATION-TOKEN.
        AllocateOptions {
            address_family: Some(REQUESTED_FAMILY_IPV6),
            reservation_token: token.clone(),
            ..Default::default()
        },
        // REQUESTED-ADDRESS-FAMILY with ADDITIONAL-ADDRESS-FAMILY.
        AllocateOptions {
            address_family: Some(REQUESTED_FAMILY_IPV4),
            additional_ipv6: true,
            ..Default::default()
        },
        // ADDITIONAL-ADDRESS-FAMILY with RESERVATION-TOKEN.
        AllocateOptions {
            additional_ipv6: true,
            reservation_token: token.clone(),
            ..Default::default()
        },
        // ADDITIONAL-ADDRESS-FAMILY with EVEN-PORT, R = 1.
        AllocateOptions {
            additional_ipv6: true,
            even_port: Some(EvenPort { reserve_port: true }),
            ..Default::default()
        },
        // RESERVATION-TOKEN with EVEN-PORT.
        AllocateOptions {
            reservation_token: token,
            even_port: Some(EvenPort {
                reserve_port: false,
            }),
            ..Default::default()
        },
        // A family that is neither IPv4 nor IPv6.
        AllocateOptions {
            address_family: Some(crate::proto::reqfamily::RequestedAddressFamily(3)),
            ..Default::default()
        },
    ];
    for options in forbidden {
        assert!(
            client.allocate_with(now, options.clone()).is_err(),
            "{options:?}"
        );
        assert!(
            client.poll_write().is_none(),
            "{options:?}: nothing is sent"
        );
    }

    // What the RFC allows: an even port without a reservation beside the second family.
    client.allocate_with(
        now,
        AllocateOptions {
            additional_ipv6: true,
            even_port: Some(EvenPort {
                reserve_port: false,
            }),
            ..Default::default()
        },
    )?;
    assert!(client.poll_write().is_some());
    client.close()
}

/// RFC 8656 §7.1: one REQUESTED-ADDRESS-FAMILY asks for a relayed address of that family.
/// §10.1, §12.1: permissions and channels on it are for peers of that family only.
#[test]
fn test_a_requested_address_family_gets_an_ipv6_relayed_address() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, authenticated) = server.allocate_with(
        &mut client,
        now,
        ipv6_only(),
        vec![relayed(relayed_v6()), lifetime(600)],
    )?;
    assert_eq!(
        values_of(&authenticated, ATTR_REQUESTED_ADDRESS_FAMILY),
        vec![vec![0x02, 0, 0, 0]],
        "one REQUESTED-ADDRESS-FAMILY, IPv6, reserved bytes zero"
    );
    assert!(!authenticated.contains(ATTR_ADDITIONAL_ADDRESS_FAMILY));
    assert_eq!(allocated(&mut client, tid), relayed_v6());
    assert_eq!(
        client.relay(relayed_v6())?.relayed_addrs(),
        vec![relayed_v6()]
    );

    // A peer of the other family is refused here, not by a 443 from the server that would
    // take the refresh of every other permission down with it.
    assert!(
        client
            .relay(relayed_v6())?
            .create_permission(now, peer_v4())
            .is_err()
    );
    assert!(server.requests(&mut client).is_empty());
    assert!(
        client
            .relay(relayed_v6())?
            .send_to(now, b"x", peer_v4())
            .is_err()
    );

    server.permit(&mut client, now, relayed_v6(), peer_v6())?;
    client.relay(relayed_v6())?.send_to(now, b"x", peer_v6())?;
    let bind = server.next_request(&mut client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    assert_eq!(peers_of(&bind), vec![peer_v6()]);
    client.close()
}

/// The same the other way: an IPv4 allocation takes no IPv6 peer.
#[test]
fn test_an_ipv4_allocation_refuses_an_ipv6_peer() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    assert!(
        client
            .relay(relayed)?
            .create_permission(now, peer_v6())
            .is_err()
    );
    assert!(server.requests(&mut client).is_empty());
    client.close()
}

/// RFC 8656 §7.1, §18.11: ADDITIONAL-ADDRESS-FAMILY (0x02) asks for an IPv6 relayed address
/// beside the IPv4 one. The allocation then has both, is found by either, and takes peers of
/// both families (§10.1).
#[test]
fn test_an_additional_address_family_gets_two_relayed_addresses() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, authenticated) = server.allocate_with(
        &mut client,
        now,
        dual(),
        // The server may list them in either order.
        vec![
            relayed(relayed_v6()),
            relayed(relayed_addr()),
            lifetime(600),
        ],
    )?;
    let mut additional = AdditionalAddressFamily(REQUESTED_FAMILY_IPV4);
    additional.get_from(&authenticated)?;
    assert_eq!(additional.0, REQUESTED_FAMILY_IPV6);
    assert_eq!(
        values_of(&authenticated, ATTR_ADDITIONAL_ADDRESS_FAMILY),
        vec![vec![0x02, 0, 0, 0]]
    );
    assert!(!authenticated.contains(ATTR_REQUESTED_ADDRESS_FAMILY));

    assert_eq!(allocated(&mut client, tid), relayed_addr());
    assert!(client.poll_event().is_none(), "one allocation, one event");
    for addr in [relayed_addr(), relayed_v6()] {
        assert_eq!(
            client.relay(addr)?.relayed_addrs(),
            vec![relayed_addr(), relayed_v6()],
            "IPv4 first, whatever the order of the response"
        );
    }
    assert!(client.relay(relayed_addr())?.address_error().is_none());

    server.permit(&mut client, now, relayed_addr(), peer_v4())?;
    server.permit(&mut client, now, relayed_v6(), peer_v6())?;
    client.relay(relayed_v6())?.send_to(now, b"x", peer_v4())?;
    client
        .relay(relayed_addr())?
        .send_to(now, b"x", peer_v6())?;

    // One allocation: one Refresh keeps both addresses, and names no family.
    let _ = server.requests(&mut client);
    client.refresh_allocations(now)?;
    let refreshes = server.requests(&mut client);
    assert_eq!(refreshes.len(), 1);
    assert_eq!(refreshes[0].typ.method, METHOD_REFRESH);
    assert!(!refreshes[0].contains(ATTR_REQUESTED_ADDRESS_FAMILY));
    client.close()
}

/// RFC 8656 §7.3, §18.12: with one of two families refused the success response says why in
/// ADDRESS-ERROR-CODE. After 440 the client does not ask for that family again; after 508
/// not for a minute.
#[test]
fn test_an_address_error_code_stops_requests_for_the_refused_family() -> Result<()> {
    for (code, wait) in [
        (CODE_ADDR_FAMILY_NOT_SUPPORTED, None),
        (CODE_INSUFFICIENT_CAPACITY, Some(Duration::from_secs(60))),
    ] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(TransportProtocol::UDP)?;
        let (tid, _) = server.allocate_with(
            &mut client,
            now,
            dual(),
            vec![
                relayed(relayed_addr()),
                lifetime(600),
                Box::new(AddressErrorCode {
                    family: REQUESTED_FAMILY_IPV6,
                    code,
                    reason: b"no".to_vec(),
                }),
            ],
        )?;
        assert_eq!(allocated(&mut client, tid), relayed_addr());
        let mut relay = client.relay(relayed_addr())?;
        assert_eq!(relay.relayed_addrs(), vec![relayed_addr()]);
        let refused = relay.address_error().expect("the ADDRESS-ERROR-CODE");
        assert_eq!(refused.family, REQUESTED_FAMILY_IPV6);
        assert!(refused.code == code, "{refused:?}");
        // The IPv4 half works as any allocation.
        assert!(relay.create_permission(now, peer_v6()).is_err());
        assert!(relay.create_permission(now, peer_v4())?.is_some());
        let _ = server.requests(&mut client);

        for options in [dual(), ipv6_only()] {
            assert!(
                client.allocate_with(now, options.clone()).is_err(),
                "{}: {options:?} asks for the refused family again",
                code.0
            );
            assert!(server.requests(&mut client).is_empty());
        }
        // The other family is not refused.
        client.allocate_with(
            now,
            AllocateOptions {
                address_family: Some(REQUESTED_FAMILY_IPV4),
                ..Default::default()
            },
        )?;
        assert_eq!(server.requests(&mut client).len(), 1);

        match wait {
            Some(wait) => {
                let just_before = now + wait - Duration::from_secs(1);
                assert!(client.allocate_with(just_before, ipv6_only()).is_err());
                client.allocate_with(now + wait, ipv6_only())?;
            }
            None => {
                let much_later = now + Duration::from_secs(86_400);
                assert!(client.allocate_with(much_later, ipv6_only()).is_err());
                // Until the application says the cause is gone.
                client.clear_allocate_restrictions();
                client.allocate_with(much_later, ipv6_only())?;
            }
        }
        assert_eq!(server.requests(&mut client).len(), 1);
        client.close()?;
    }
    Ok(())
}

/// RFC 8656 §7.4: after a 440 (Address Family not Supported) to an Allocate the client "MUST
/// NOT retry the request".
#[test]
fn test_a_440_to_an_allocate_is_not_asked_again() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) = server.begin_allocate(&mut client, now, ipv6_only())?;
    server.reject(
        &mut client,
        now,
        &authenticated,
        CODE_ADDR_FAMILY_NOT_SUPPORTED,
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, err)) if id == tid && err.is(CODE_ADDR_FAMILY_NOT_SUPPORTED)
    ));

    assert!(client.allocate_with(now, ipv6_only()).is_err());
    assert!(client.allocate_with(now, dual()).is_err());
    assert!(server.requests(&mut client).is_empty());
    // An IPv4 address was never refused.
    client.allocate(now)?;
    assert_eq!(server.requests(&mut client).len(), 1);
    client.close()
}

/// RFC 8656 §7.3: an allocation whose relayed address is not of a family the client asked
/// for is deleted, and no other is asked for until the mismatch is believed fixed.
#[test]
fn test_an_allocation_of_the_wrong_family_is_deleted_and_not_asked_for_again() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    // IPv6 asked for, IPv4 given.
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        ipv6_only(),
        vec![relayed(relayed_addr()), lifetime(600)],
    )?;
    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Failed(_))) => assert_eq!(id, tid),
        other => panic!("expected AllocateError, got {other:?}"),
    }
    assert!(client.relay(relayed_addr()).is_err());

    let mut release = server.next_request(&mut client);
    assert_eq!(release.typ.method, METHOD_REFRESH);
    assert_eq!(
        lifetime_of(&release)?,
        Duration::ZERO,
        "the allocation is deleted"
    );
    MessageIntegrity::check(&mut release, &server.key, test_crypto_provider().crypto())?;
    server.accept(&mut client, now, &release)?;

    assert!(client.allocate(now).is_err());
    assert!(client.allocate_with(now, ipv6_only()).is_err());
    assert!(server.requests(&mut client).is_empty());
    client.clear_allocate_restrictions();
    client.allocate(now)?;
    assert_eq!(server.requests(&mut client).len(), 1);
    client.close()
}

/// The same for the default request, which is for IPv4 (RFC 8656 §7.2), and for two
/// addresses where one was asked for.
#[test]
fn test_addresses_that_were_not_asked_for_are_a_family_mismatch() -> Result<()> {
    let answers: [Vec<SocketAddr>; 2] = [vec![relayed_v6()], vec![relayed_addr(), relayed_v6()]];
    for addrs in answers {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(TransportProtocol::UDP)?;
        let mut attrs: Vec<Box<dyn Setter>> = addrs.iter().map(|addr| relayed(*addr)).collect();
        attrs.push(lifetime(600));
        let (tid, _) = server.allocate_with(&mut client, now, AllocateOptions::default(), attrs)?;
        assert!(
            matches!(client.poll_event(), Some(Event::AllocateError(id, _)) if id == tid),
            "{addrs:?}"
        );
        assert!(client.relays.is_empty());
        let release = server.next_request(&mut client);
        assert_eq!(lifetime_of(&release)?, Duration::ZERO);
        client.close()?;
    }
    Ok(())
}

/// RFC 8656 §8.1: a Refresh with LIFETIME 0 and REQUESTED-ADDRESS-FAMILY deletes that
/// family's relayed address and leaves the other, with its permissions and channels. The
/// attribute only ever names a family the allocation holds.
#[test]
fn test_one_family_of_a_dual_allocation_is_released_on_its_own() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        dual(),
        vec![
            relayed(relayed_addr()),
            relayed(relayed_v6()),
            lifetime(600),
        ],
    )?;
    allocated(&mut client, tid);
    server.permit(&mut client, now, relayed_addr(), peer_v4())?;
    server.permit(&mut client, now, relayed_addr(), peer_v6())?;

    client
        .relay(relayed_addr())?
        .release_family(now, REQUESTED_FAMILY_IPV4)?;
    let release = server.next_request(&mut client);
    assert_eq!(release.typ.method, METHOD_REFRESH);
    assert_eq!(lifetime_of(&release)?, Duration::ZERO);
    assert_eq!(
        values_of(&release, ATTR_REQUESTED_ADDRESS_FAMILY),
        vec![vec![0x01, 0, 0, 0]]
    );
    // Until the server answers, both addresses are in use.
    client
        .relay(relayed_addr())?
        .send_to(now, b"x", peer_v4())?;
    let _ = sent(&mut client);
    server.accept(&mut client, now, &release)?;

    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationReleased(addr)) if addr == relayed_addr()
    ));
    assert!(client.poll_event().is_none());
    assert!(
        client.relay(relayed_addr()).is_err(),
        "the released address no longer names the allocation"
    );
    let mut relay = client.relay(relayed_v6())?;
    assert_eq!(relay.relayed_addrs(), vec![relayed_v6()]);
    relay.send_to(now, b"x", peer_v6())?;
    assert!(
        relay.send_to(now, b"x", peer_v4()).is_err(),
        "the IPv4 permission went with the IPv4 address"
    );
    assert!(relay.create_permission(now, peer_v4()).is_err());
    // A family the allocation does not hold is never named.
    assert!(relay.release_family(now, REQUESTED_FAMILY_IPV4).is_err());
    let _ = sent(&mut client);

    // The allocation lives on and is refreshed as before.
    let (out, events) = drive_accepting(&server, &mut client, now + Duration::from_secs(300))?;
    assert!(out.iter().any(|s| matches!(s, Sent::Request(r)
        if r.typ.method == METHOD_REFRESH
            && lifetime_of(r).is_ok_and(|l| l == Duration::from_secs(600))
            && !r.contains(ATTR_REQUESTED_ADDRESS_FAMILY))));
    assert!(events.is_empty(), "{events:?}");

    // Releasing the last family is releasing the allocation.
    let at = now + Duration::from_secs(300);
    client
        .relay(relayed_v6())?
        .release_family(at, REQUESTED_FAMILY_IPV6)?;
    let release = server
        .requests(&mut client)
        .into_iter()
        .rfind(|r| r.typ.method == METHOD_REFRESH)
        .expect("the release");
    assert_eq!(lifetime_of(&release)?, Duration::ZERO);
    assert!(!release.contains(ATTR_REQUESTED_ADDRESS_FAMILY));
    client.close()
}

/// RFC 8656 §7.3: the XOR-MAPPED-ADDRESS of the success response is the client's
/// server-reflexive address; §7.1: the RESERVATION-TOKEN names the port EVEN-PORT reserved,
/// and a later Allocate uses it, without EVEN-PORT.
#[test]
fn test_the_mapped_address_and_the_reservation_token_reach_the_application() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let reflexive: SocketAddr = "192.0.2.1:7000".parse().unwrap();
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        AllocateOptions {
            even_port: Some(EvenPort { reserve_port: true }),
            ..Default::default()
        },
        vec![
            relayed(relayed_addr()),
            lifetime(1200),
            Box::new(XorMappedAddress {
                ip: reflexive.ip(),
                port: reflexive.port(),
            }),
            Box::new(ReservationToken(vec![9, 8, 7, 6, 5, 4, 3, 2])),
        ],
    )?;
    allocated(&mut client, tid);
    let relay = client.relay(relayed_addr())?;
    assert_eq!(relay.mapped_addr(), Some(reflexive));
    assert_eq!(
        relay.lifetime(),
        Some(Duration::from_secs(1200)),
        "the lifetime the server returned, not the default"
    );
    let token = relay
        .reservation_token()
        .expect("the reserved port's token");
    assert_eq!(token.0, vec![9, 8, 7, 6, 5, 4, 3, 2]);

    let (_, first, authenticated) = server.begin_allocate(
        &mut client,
        now,
        AllocateOptions {
            reservation_token: Some(token),
            ..Default::default()
        },
    )?;
    for request in [&first, &authenticated] {
        assert_eq!(
            values_of(request, ATTR_RESERVATION_TOKEN),
            vec![vec![9, 8, 7, 6, 5, 4, 3, 2]]
        );
        assert!(!request.contains(ATTR_EVEN_PORT));
        assert!(!request.contains(ATTR_REQUESTED_ADDRESS_FAMILY));
    }
    client.close()
}

/// RFC 8656 §7.1: the lifetime the server returns is the one the client goes by, whatever it
/// asked for: the Refresh is sent at half of it and asks for it again.
#[test]
fn test_the_granted_lifetime_sets_the_refresh() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, authenticated) = server.allocate_with(
        &mut client,
        now,
        AllocateOptions {
            lifetime: Some(Duration::from_secs(7200)),
            ..Default::default()
        },
        vec![relayed(relayed_addr()), lifetime(1800)],
    )?;
    assert_eq!(lifetime_of(&authenticated)?, Duration::from_secs(7200));
    allocated(&mut client, tid);

    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(899))?;
    assert!(
        requests.is_empty(),
        "nothing before half the granted lifetime"
    );
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(900))?;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].typ.method, METHOD_REFRESH);
    assert_eq!(lifetime_of(&requests[0])?, Duration::from_secs(1800));
    client.close()
}

/// RFC 8656 §11.1: a Send indication may carry DONT-FRAGMENT. §7.1: the client that will use
/// it asks with the Allocate, which tells it whether the server knows the attribute.
#[test]
fn test_dont_fragment_goes_in_a_send_indication_on_an_allocation_made_with_it() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        AllocateOptions {
            dont_fragment: true,
            ..Default::default()
        },
        vec![relayed(relayed_addr()), lifetime(600)],
    )?;
    allocated(&mut client, tid);
    assert!(client.relay(relayed_addr())?.dont_fragment());
    server.permit(&mut client, now, relayed_addr(), peer_v4())?;

    // Bind the channel, so plain data goes as ChannelData.
    client
        .relay(relayed_addr())?
        .send_to(now, b"x", peer_v4())?;
    let bind = server.next_request(&mut client);
    server.succeed(&mut client, now, &bind)?;
    client
        .relay(relayed_addr())?
        .send_to(now, b"x", peer_v4())?;
    assert!(matches!(
        sent(&mut client).as_slice(),
        [Sent::ChannelData(_)]
    ));

    client
        .relay(relayed_addr())?
        .send_to_dont_fragment(now, b"probe", peer_v4())?;
    match sent(&mut client).as_slice() {
        [Sent::Indication(indication)] => {
            assert_eq!(indication.typ.method, METHOD_SEND);
            assert!(indication.contains(ATTR_DONT_FRAGMENT));
            assert_eq!(peers_of(indication), vec![peer_v4()]);
            let mut data = Data::default();
            data.get_from(indication)?;
            assert_eq!(data.0, b"probe");
        }
        other => panic!("expected one Send indication, got {other:?}"),
    }
    // A permission is needed as for any send.
    let stranger: SocketAddr = "203.0.113.9:1".parse().unwrap();
    assert_eq!(
        client
            .relay(relayed_addr())?
            .send_to_dont_fragment(now, b"x", stranger)
            .err(),
        Some(Error::ErrNoPermission)
    );
    client.close()
}

/// Without DONT-FRAGMENT in the Allocate the server is not known to support it, and the
/// attribute is not sent.
#[test]
fn test_dont_fragment_is_refused_on_an_allocation_made_without_it() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer_v4())?;
    assert!(!client.relay(relayed)?.dont_fragment());
    assert!(
        client
            .relay(relayed)?
            .send_to_dont_fragment(now, b"x", peer_v4())
            .is_err()
    );
    assert!(sent(&mut client).is_empty());
    client.close()
}

/// RFC 8656 §7.4: a 420 naming DONT-FRAGMENT says the server does not support it; the
/// Allocate is made again without it, and the allocation does not have it.
#[test]
fn test_a_420_for_dont_fragment_is_retried_without_it() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) = server.begin_allocate(
        &mut client,
        now,
        AllocateOptions {
            dont_fragment: true,
            lifetime: Some(Duration::from_secs(900)),
            ..Default::default()
        },
    )?;
    assert!(authenticated.contains(ATTR_DONT_FRAGMENT));
    server.answer(
        &mut client,
        now,
        &authenticated,
        CLASS_ERROR_RESPONSE,
        vec![
            Box::new(ErrorCodeAttribute {
                code: CODE_UNKNOWN_ATTRIBUTE,
                reason: b"Unknown Attribute".to_vec(),
            }),
            Box::new(stun::uattrs::UnknownAttributes(vec![ATTR_DONT_FRAGMENT])),
        ],
        Some(&server.key),
    )?;
    assert!(client.poll_event().is_none(), "not a failure yet");

    let mut again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_ALLOCATE);
    assert_ne!(again.transaction_id, authenticated.transaction_id);
    assert!(!again.contains(ATTR_DONT_FRAGMENT));
    assert_eq!(
        lifetime_of(&again)?,
        Duration::from_secs(900),
        "the rest is kept"
    );
    MessageIntegrity::check(&mut again, &server.key, test_crypto_provider().crypto())?;
    server.answer(
        &mut client,
        now,
        &again,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(900)],
        Some(&server.key),
    )?;
    assert_eq!(allocated(&mut client, tid), relayed_addr());
    assert!(!client.relay(relayed_addr())?.dont_fragment());
    client.close()
}

/// A 420 that does not name DONT-FRAGMENT, or one to a request without it, is an error like
/// any other, with the attributes the server listed.
#[test]
fn test_a_420_for_anything_else_fails_the_allocate() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) = server.begin_allocate(
        &mut client,
        now,
        AllocateOptions {
            dont_fragment: true,
            ..Default::default()
        },
    )?;
    server.answer(
        &mut client,
        now,
        &authenticated,
        CLASS_ERROR_RESPONSE,
        vec![
            Box::new(ErrorCodeAttribute {
                code: CODE_UNKNOWN_ATTRIBUTE,
                reason: b"Unknown Attribute".to_vec(),
            }),
            Box::new(stun::uattrs::UnknownAttributes(vec![ATTR_EVEN_PORT])),
        ],
        Some(&server.key),
    )?;
    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Rejected(response))) => {
            assert_eq!(id, tid);
            assert!(response.code == CODE_UNKNOWN_ATTRIBUTE);
            assert_eq!(response.unknown_attributes, vec![ATTR_EVEN_PORT]);
        }
        other => panic!("expected AllocateError, got {other:?}"),
    }
    assert!(server.requests(&mut client).is_empty());
    client.close()
}

/// RFC 8489 §9.2.5, RFC 8656 §7.4: a 438 (Stale Nonce) to the authenticated Allocate is
/// answered with the same request and the new nonce, once.
#[test]
fn test_a_stale_nonce_to_an_allocate_is_retried_once() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let options = AllocateOptions {
        lifetime: Some(Duration::from_secs(900)),
        ..Default::default()
    };
    let (tid, _, authenticated) = server.begin_allocate(&mut client, now, options)?;
    assert_eq!(nonce_of(&authenticated), "nonce");
    server.stale_nonce(&mut client, now, &authenticated, "fresh", REALM)?;
    assert!(client.poll_event().is_none());

    let mut again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_ALLOCATE);
    assert_ne!(
        again.transaction_id, authenticated.transaction_id,
        "a new request takes a new transaction id"
    );
    assert_eq!(nonce_of(&again), "fresh");
    assert_eq!(lifetime_of(&again)?, Duration::from_secs(900));
    MessageIntegrity::check(&mut again, &server.key, test_crypto_provider().crypto())?;

    // A second 438 ends it.
    server.stale_nonce(&mut client, now, &again, "fresher", REALM)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, err)) if id == tid && err.is(CODE_STALE_NONCE)
    ));
    assert!(server.requests(&mut client).is_empty());

    // And the retry that is answered makes the allocation, under the caller's id.
    let (tid, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;
    server.stale_nonce(&mut client, now, &authenticated, "fresh", REALM)?;
    let again = server.next_request(&mut client);
    server.answer(
        &mut client,
        now,
        &again,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(600)],
        Some(&server.key),
    )?;
    assert_eq!(allocated(&mut client, tid), relayed_addr());
    // The allocation's requests carry the nonce it was made with.
    client.refresh_allocations(now)?;
    assert_eq!(nonce_of(&server.next_request(&mut client)), "fresh");
    client.close()
}

struct AlternateServer(SocketAddr);

impl Setter for AlternateServer {
    fn add_to(&self, m: &mut Message) -> Result<()> {
        stun::addr::MappedAddress {
            ip: self.0.ip(),
            port: self.0.port(),
        }
        .add_to_as(m, ATTR_ALTERNATE_SERVER)
    }
}

/// An XOR-RELAYED-ADDRESS of 0.0.0.0:0 names no relayed address. coturn 4.6 sends one beside
/// the real address in the Allocate after it refused the same client an IPv6 one with 440
/// (seen in the test environment): the allocation is the real address, not a family mismatch.
/// An answer with nothing but such an address is no allocation.
#[test]
fn test_an_all_zero_relayed_address_is_passed_over() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let unusable: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let options = AllocateOptions {
        address_family: Some(REQUESTED_FAMILY_IPV4),
        ..Default::default()
    };

    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        options.clone(),
        vec![relayed(relayed_addr()), relayed(unusable), lifetime(600)],
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));
    assert_eq!(
        client.relay(relayed_addr())?.relayed_addrs(),
        vec![relayed_addr()]
    );
    assert!(
        client.allocate_with(now, options.clone()).is_ok(),
        "nothing was held against the server"
    );

    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        options,
        vec![relayed(unusable), lifetime(600)],
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, RequestError::Failed(_))) if id == tid
    ));
    client.close()
}

/// RFC 8656 §7.4, RFC 8489 §10: a 300 (Try Alternate) names the server to use instead in
/// ALTERNATE-SERVER. The client does not go there by itself: which server it talks to is the
/// application's, which gets the address with the error and tries it first.
#[test]
fn test_a_300_reports_the_alternate_server() -> Result<()> {
    for alternate in ["192.0.2.99:3478", "[2001:db8::99]:3478"] {
        let alternate: SocketAddr = alternate.parse().unwrap();
        for authenticate_first in [false, true] {
            let now = Instant::now();
            let server = TestServer::new()?;
            let mut client = new_client(TransportProtocol::UDP)?;
            let tid = client.allocate(now)?;
            let mut request = server.next_request(&mut client);
            if authenticate_first {
                server.challenge(&mut client, now, &request)?;
                request = server.next_request(&mut client);
            }
            server.answer(
                &mut client,
                now,
                &request,
                CLASS_ERROR_RESPONSE,
                vec![
                    Box::new(ErrorCodeAttribute {
                        code: CODE_TRY_ALTERNATE,
                        reason: b"Try Alternate".to_vec(),
                    }),
                    Box::new(AlternateServer(alternate)),
                ],
                authenticate_first.then_some(server.key.as_slice()),
            )?;
            match client.poll_event() {
                Some(Event::AllocateError(id, RequestError::Rejected(response))) => {
                    assert_eq!(id, tid);
                    assert!(response.code == CODE_TRY_ALTERNATE);
                    assert_eq!(response.alternate_server, Some(alternate));
                }
                other => panic!("expected AllocateError, got {other:?}"),
            }
            assert!(
                server.requests(&mut client).is_empty(),
                "nothing is sent to either server"
            );
            assert_eq!(client.turn_server_addr(), Some(server_addr()));
            client.close()?;
        }
    }
    Ok(())
}

/// RFC 8656 §5: SOFTWARE goes in every Allocate and Refresh request, and may go in any other.
#[test]
fn test_software_is_in_every_request() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = Client::new(
        ClientConfig {
            turn_serv_addr: server_addr().to_string(),
            local_addr: local_addr(),
            transport_protocol: TransportProtocol::UDP,
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            software: "rtc test 1.0".to_owned(),
            ..Default::default()
        },
        test_crypto_provider(),
    )?;
    let software_of = |request: &Message| -> Option<String> {
        Software::get_from_as(request, ATTR_SOFTWARE)
            .ok()
            .map(|s| s.text)
    };

    let (tid, first, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;
    for request in [&first, &authenticated] {
        assert_eq!(software_of(request).as_deref(), Some("rtc test 1.0"));
    }
    // It is covered by the MESSAGE-INTEGRITY.
    let mut signed = authenticated.clone();
    MessageIntegrity::check(&mut signed, &server.key, test_crypto_provider().crypto())?;
    server.answer(
        &mut client,
        now,
        &authenticated,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(600)],
        Some(&server.key),
    )?;
    allocated(&mut client, tid);

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    assert_eq!(refresh.typ.method, METHOD_REFRESH);
    assert_eq!(software_of(&refresh).as_deref(), Some("rtc test 1.0"));
    server.accept(&mut client, now, &refresh)?;

    client
        .relay(relayed_addr())?
        .create_permission(now, peer_v4())?;
    let permission = server.next_request(&mut client);
    assert_eq!(software_of(&permission).as_deref(), Some("rtc test 1.0"));
    server.succeed(&mut client, now, &permission)?;

    client
        .relay(relayed_addr())?
        .send_to(now, b"x", peer_v4())?;
    let bind = server.next_request(&mut client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    assert_eq!(software_of(&bind).as_deref(), Some("rtc test 1.0"));
    client.close()?;

    // A client without one sends none.
    let mut plain = new_client(TransportProtocol::UDP)?;
    plain.allocate(now)?;
    assert!(!server.next_request(&mut plain).contains(ATTR_SOFTWARE));
    plain.close()
}

fn data_indication_with(
    now: Instant,
    attrs: Vec<Box<dyn Setter>>,
) -> Result<TransportMessage<BytesMut>> {
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
    ];
    setters.extend(attrs);
    let mut msg = Message::new();
    msg.build(&setters)?;
    Ok(TransportMessage {
        now,
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&msg.raw[..]),
    })
}

fn peer_attr(addr: SocketAddr) -> Box<dyn Setter> {
    Box::new(PeerAddress {
        ip: addr.ip(),
        port: addr.port(),
    })
}

/// RFC 8656 §11.6: a Data indication with an ICMP attribute reports the ICMP error a relayed
/// datagram met. The client checks it has the peer address and a permission for it, and gives
/// the application the peer, the type, the code and the error data.
#[test]
fn test_an_icmp_error_from_a_permitted_peer_reaches_the_application() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer_v4())?;

    // Fragmentation needed and DF set; the next hop takes 1400 bytes.
    let icmp = Icmp {
        icmp_type: 3,
        code: 4,
        error_data: 1400,
    };
    client.handle_read(data_indication_with(
        now,
        vec![peer_attr(peer_v4()), Box::new(icmp)],
    )?)?;
    match client.poll_event() {
        Some(Event::IcmpError(from, got)) => {
            assert_eq!(from, peer_v4());
            assert_eq!(got, icmp);
        }
        other => panic!("expected IcmpError, got {other:?}"),
    }

    // No permission for the address: discarded.
    let stranger: SocketAddr = "203.0.113.99:7".parse().unwrap();
    client.handle_read(data_indication_with(
        now,
        vec![peer_attr(stranger), Box::new(icmp)],
    )?)?;
    assert!(client.poll_event().is_none());

    // No XOR-PEER-ADDRESS: discarded.
    let _ = client.handle_read(data_indication_with(now, vec![Box::new(icmp)])?);
    assert!(client.poll_event().is_none());

    // Neither DATA nor ICMP: discarded (RFC 8656 §11.4).
    let _ = client.handle_read(data_indication_with(now, vec![peer_attr(peer_v4())])?);
    assert!(client.poll_event().is_none());

    // With both, it is the peer's data.
    client.handle_read(data_indication_with(
        now,
        vec![
            peer_attr(peer_v4()),
            Box::new(Data(b"hello".to_vec())),
            Box::new(icmp),
        ],
    )?)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::DataIndicationOrChannelData(None, from, data))
            if from == peer_v4() && &data[..] == b"hello"
    ));
    client.close()
}
