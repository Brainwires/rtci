//! RFC 9260 sections 5, 8.4, 8.5 and 9: Verification Tags, out-of-the-blue packets, ABORT,
//! the State Cookie, unexpected handshake chunks and the shutdown sequence in every state.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::Link;
use crate::endpoint::{DatagramEvent, Endpoint};
use crate::packet::PartialDecode;
use crate::{ClientConfig, EndpointConfig, TimerConfig};

const CAUSE_MISSING_MANDATORY_PARAMETER: u16 = 2;
const CAUSE_STALE_COOKIE: u16 = 3;
const CAUSE_OUT_OF_RESOURCE: u16 = 4;
const CAUSE_UNRESOLVABLE_ADDRESS: u16 = 5;
const CAUSE_PROTOCOL_VIOLATION: u16 = 13;

fn server_addr() -> SocketAddr {
    "10.0.0.2:5000".parse().unwrap()
}

/// A client association that has sent its INIT and waits for the INIT ACK.
fn connecting_client(config: TransportConfig) -> (Endpoint, Association, Instant) {
    let mut endpoint = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = endpoint
        .connect(now, ClientConfig::new(config), server_addr())
        .unwrap();
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_INIT.0).len());
    (endpoint, a, now)
}

/// The Verification Tag of a datagram.
fn tag_of(datagram: &Bytes) -> u32 {
    u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]])
}

/// The datagrams whose first chunk has type `typ`.
fn datagrams_with(datagrams: &[Bytes], typ: u8) -> Vec<Bytes> {
    datagrams
        .iter()
        .filter(|d| d.get(12) == Some(&typ))
        .cloned()
        .collect()
}

fn abort_chunk(t_bit: bool) -> Vec<u8> {
    raw_chunk(CT_ABORT.0, u8::from(t_bit), &raw_tlv(12, &[]))
}

fn events(a: &mut Association) -> Vec<Event> {
    let mut out = vec![];
    while let Some(e) = a.poll() {
        out.push(e);
    }
    out
}

fn sack_chunk(cumulative: u32, gaps: &[(u16, u16)]) -> Vec<u8> {
    chunk_bytes(&ChunkSelectiveAck {
        cumulative_tsn_ack: cumulative,
        advertised_receiver_window_credit: 1 << 20,
        gap_ack_blocks: gaps
            .iter()
            .map(
                |(start, end)| crate::chunk::chunk_selective_ack::GapAckBlock {
                    start: *start,
                    end: *end,
                },
            )
            .collect(),
        duplicate_tsn: vec![],
    })
}

// ---- 8.5: Verification Tags --------------------------------------------------------------------

/// RFC 9260 8.5: a packet whose Verification Tag is not this endpoint's own is discarded.
/// The association never looked at the tag: only the endpoint's routing did.
#[test]
fn a_packet_with_another_verification_tag_is_discarded() {
    let mut link = connected_link(101);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    for tag in [
        a.my_verification_tag.wrapping_add(1),
        a.peer_verification_tag,
        0,
    ] {
        let raw = raw_packet(
            a.destination_port,
            a.source_port,
            tag,
            &[data_chunk(tsn, 1, 0, b"x")],
        );
        inject(a, now, raw);
        assert_eq!(tsn.wrapping_sub(1), a.peer_last_tsn, "tag {tag:#x}");
    }
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"x")]);
    inject(a, now, raw);
    assert_eq!(tsn, a.peer_last_tsn, "the association's own tag");
}

/// RFC 9260 8.5.1 A, 5.1: an INIT travels alone with tag 0, an INIT ACK alone. A packet that
/// bundles either with another chunk, or an INIT with another tag, is discarded.
#[test]
fn a_bundled_init_or_init_ack_is_discarded() {
    let (_, a, _) = accept_init(&[]);
    let a = a.unwrap();
    for (tag, chunks) in [
        (
            0,
            vec![
                init_chunk(CT_INIT.0, 0x55, 9, &[]),
                data_chunk(1, 0, 0, b"x"),
            ],
        ),
        (
            a.my_verification_tag,
            vec![init_chunk(CT_INIT.0, 0x55, 9, &[])],
        ),
    ] {
        let mut endpoint = accepting_endpoint();
        let raw = raw_packet(5000, 5000, tag, &chunks);
        let accepted = endpoint.handle(Instant::now(), remote(), None, raw);
        if let Some((_, DatagramEvent::NewAssociation(mut made))) = accepted {
            assert!(
                chunks_of_type(&sent_datagrams(&mut made, Instant::now()), CT_INIT_ACK.0)
                    .is_empty(),
                "an INIT that is not alone with tag 0 was answered"
            );
        }
    }

    let (_, mut client, now) = connecting_client(TransportConfig::default());
    let raw = packet_to(
        &client,
        &[
            init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]),
            raw_chunk(CT_COOKIE_ACK.0, 0, &[]),
        ],
    );
    inject(&mut client, now, raw);
    assert_eq!(AssociationState::CookieWait, client.state());
    assert!(chunks_of_type(&sent_datagrams(&mut client, now), CT_COOKIE_ECHO.0).is_empty());
}

/// RFC 9260 8.5.1 B, 9.1: an ABORT is accepted with this side's tag and the T bit clear, or
/// with the peer's tag and the T bit set. The T bit was never read.
#[test]
fn an_abort_is_accepted_with_the_own_tag_or_the_reflected_peer_tag() {
    for (own_tag, t_bit, accepted) in [
        (true, false, true),
        (false, true, true),
        (true, true, false),
        (false, false, false),
    ] {
        let mut link = connected_link(102);
        let now = link.now;
        let a = link.server.conn();
        let tag = if own_tag {
            a.my_verification_tag
        } else {
            a.peer_verification_tag
        };
        let raw = raw_packet(
            a.destination_port,
            a.source_port,
            tag,
            &[abort_chunk(t_bit)],
        );
        inject(a, now, raw);
        assert_eq!(
            accepted,
            a.is_ended(),
            "ABORT with {} tag and T = {t_bit}",
            if own_tag { "the own" } else { "the peer's" }
        );
        assert!(
            sent_datagrams(a, now).is_empty(),
            "an ABORT is never answered"
        );
    }
}

/// RFC 9260 8.5.1 C, 9.2: a SHUTDOWN COMPLETE follows the same tag rule and counts only in
/// SHUTDOWN-ACK-SENT.
#[test]
fn a_shutdown_complete_needs_the_right_tag_and_state() {
    for (state, own_tag, t_bit, ends) in [
        (AssociationState::ShutdownAckSent, true, false, true),
        (AssociationState::ShutdownAckSent, false, true, true),
        (AssociationState::ShutdownAckSent, true, true, false),
        (AssociationState::ShutdownAckSent, false, false, false),
        (AssociationState::Established, true, false, false),
        (AssociationState::ShutdownSent, true, false, false),
    ] {
        let mut link = connected_link(103);
        let now = link.now;
        let a = link.server.conn();
        a.set_state(state);
        let tag = if own_tag {
            a.my_verification_tag
        } else {
            a.peer_verification_tag
        };
        let raw = raw_packet(
            a.destination_port,
            a.source_port,
            tag,
            &[raw_chunk(CT_SHUTDOWN_COMPLETE.0, u8::from(t_bit), &[])],
        );
        inject(a, now, raw);
        assert_eq!(
            ends,
            a.is_ended(),
            "SHUTDOWN COMPLETE in {state}, own tag {own_tag}, T = {t_bit}"
        );
    }
}

/// RFC 9260 8.5.1 E, 9.2: a SHUTDOWN ACK that arrives while this side is setting an
/// association up is answered as an out-of-the-blue packet: SHUTDOWN COMPLETE, alone, with
/// the tag of the SHUTDOWN ACK and the T bit. The setup goes on.
#[test]
fn a_shutdown_ack_during_setup_is_answered_with_a_reflected_shutdown_complete() {
    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let raw = raw_packet(
        a.destination_port,
        a.source_port,
        0x0DDB_A11,
        &[raw_chunk(CT_SHUTDOWN_ACK.0, 0, &[])],
    );
    inject(&mut a, now, raw);

    assert_eq!(AssociationState::CookieWait, a.state());
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, sent.len());
    assert_eq!(0x0DDB_A11, tag_of(&sent[0]));
    assert_eq!(
        vec![raw_chunk(CT_SHUTDOWN_COMPLETE.0, 1, &[])],
        chunks_of(&sent[0]),
        "a lone SHUTDOWN COMPLETE with the T bit"
    );
    assert!(a.poll_timeout().is_some(), "T1-init keeps running");
}

// ---- 8.4: out-of-the-blue packets ----------------------------------------------------------------

fn endpoint_answers(endpoint: &mut Endpoint) -> Vec<Bytes> {
    let mut out = vec![];
    while let Some(transmit) = endpoint.poll_transmit() {
        assert_eq!(remote(), transmit.transport.peer_addr);
        if let Payload::RawEncode(datagrams) = transmit.message {
            out.extend(datagrams);
        }
    }
    out
}

/// RFC 9260 8.4: what an endpoint does with a packet that belongs to none of its
/// associations. Every one of them used to be dropped, so a peer that had missed this side's
/// ABORT retransmitted to nobody until its own limit.
#[test]
fn out_of_the_blue_packets_are_answered_or_dropped_by_their_chunks() {
    let mut endpoint = accepting_endpoint();
    let now = Instant::now();
    let tag = 0x1234_5678;
    let stale_cookie = raw_chunk(CT_ERROR.0, 0, &raw_tlv(CAUSE_STALE_COOKIE, &[0; 4]));
    let other_error = raw_chunk(CT_ERROR.0, 0, &raw_tlv(1, &[0; 4]));

    // Answered with ABORT, the tag reflected and the T bit set.
    for chunks in [
        vec![data_chunk(1, 0, 0, b"x")],
        vec![sack_chunk(1, &[])],
        vec![other_error],
        vec![raw_chunk(CT_SHUTDOWN.0, 0, &[0; 4])],
    ] {
        let raw = raw_packet(5001, 5000, tag, &chunks);
        assert!(endpoint.handle(now, remote(), None, raw).is_none());
        let answers = endpoint_answers(&mut endpoint);
        assert_eq!(1, answers.len(), "one answer to {chunks:?}");
        assert_eq!(tag, tag_of(&answers[0]), "the tag is reflected");
        assert_eq!(
            (5000, 5001),
            (
                u16::from_be_bytes([answers[0][0], answers[0][1]]),
                u16::from_be_bytes([answers[0][2], answers[0][3]])
            ),
            "between the same ports, the other way"
        );
        assert_eq!(
            vec![raw_chunk(CT_ABORT.0, 1, &[])],
            chunks_of(&answers[0]),
            "a lone ABORT with the T bit"
        );
        assert!(
            PartialDecode::unmarshal(&answers[0]).is_ok(),
            "with a correct checksum"
        );
    }

    // A SHUTDOWN ACK is answered with SHUTDOWN COMPLETE, the tag reflected and the T bit set.
    let raw = raw_packet(5001, 5000, tag, &[raw_chunk(CT_SHUTDOWN_ACK.0, 0, &[])]);
    assert!(endpoint.handle(now, remote(), None, raw).is_none());
    let answers = endpoint_answers(&mut endpoint);
    assert_eq!(1, answers.len());
    assert_eq!(tag, tag_of(&answers[0]));
    assert_eq!(
        vec![raw_chunk(CT_SHUTDOWN_COMPLETE.0, 1, &[])],
        chunks_of(&answers[0])
    );

    // Not answered at all.
    for (packet_tag, chunks) in [
        (tag, vec![abort_chunk(false)]),
        (tag, vec![data_chunk(1, 0, 0, b"x"), abort_chunk(true)]),
        (tag, vec![raw_chunk(CT_SHUTDOWN_COMPLETE.0, 0, &[])]),
        (tag, vec![raw_chunk(CT_COOKIE_ACK.0, 0, &[])]),
        (tag, vec![stale_cookie]),
        (
            tag,
            vec![raw_chunk(CT_COOKIE_ECHO.0, 0, b"not a cookie of ours")],
        ),
        (0, vec![data_chunk(1, 0, 0, b"x")]),
        (tag, vec![init_chunk(CT_INIT.0, 77, 1, &[])]),
    ] {
        let raw = raw_packet(5001, 5000, packet_tag, &chunks);
        assert!(endpoint.handle(now, remote(), None, raw).is_none());
        assert!(
            endpoint_answers(&mut endpoint).is_empty(),
            "an answer to {chunks:?} with tag {packet_tag:#x}"
        );
    }
}

/// The answers the endpoint keeps for its owner are bounded.
#[test]
fn out_of_the_blue_answers_are_bounded() {
    let mut endpoint = accepting_endpoint();
    let now = Instant::now();
    for tsn in 0..1000 {
        let raw = raw_packet(5001, 5000, 0x77, &[data_chunk(tsn, 0, 0, b"x")]);
        let _ = endpoint.handle(now, remote(), None, raw);
    }
    assert_eq!(16, endpoint_answers(&mut endpoint).len());
}

/// RFC 9260 5.1, 8.4 3): an INIT the endpoint cannot accept (it is full, or accepts none) is
/// answered with an ABORT sent to the INIT's Initiate Tag, T bit clear.
#[test]
fn a_refused_init_is_answered_with_an_abort_to_its_initiate_tag() {
    let now = Instant::now();
    let other: SocketAddr = "10.0.0.9:6000".parse().unwrap();
    let init = raw_packet(5001, 5000, 0, &[init_chunk(CT_INIT.0, 0xFEED_F00D, 5, &[])]);

    let (mut full, first, _) = accept_init(&[]);
    assert!(first.is_some());
    let mut none_accepted = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    for endpoint in [&mut full, &mut none_accepted] {
        assert!(endpoint.handle(now, other, None, init.clone()).is_none());
        let transmit = endpoint.poll_transmit().expect("an answer");
        assert_eq!(other, transmit.transport.peer_addr);
        let Payload::RawEncode(answers) = transmit.message else {
            panic!("an encoded packet");
        };
        assert_eq!(0xFEED_F00D, tag_of(&answers[0]));
        let aborts = chunks_of_type(&answers, CT_ABORT.0);
        assert_eq!(1, aborts.len());
        assert_eq!(0, aborts[0][1] & 1, "T bit clear");
        assert_eq!(vec![(CAUSE_OUT_OF_RESOURCE, vec![])], tlvs(&aborts[0][4..]));
    }
}

// ---- ABORT where the RFC asks for one ----------------------------------------------------------

fn init_value(tag: u32, a_rwnd: u32, os: u16, mis: u16, params: &[u8]) -> Vec<u8> {
    let mut value = vec![];
    value.extend_from_slice(&tag.to_be_bytes());
    value.extend_from_slice(&a_rwnd.to_be_bytes());
    value.extend_from_slice(&os.to_be_bytes());
    value.extend_from_slice(&mis.to_be_bytes());
    value.extend_from_slice(&9u32.to_be_bytes());
    value.extend_from_slice(params);
    value
}

/// RFC 9260 3.3.2: an INIT with an a_rwnd below 1500 or without streams is answered with an
/// ABORT sent to its Initiate Tag; one with Initiate Tag 0 is discarded silently. The
/// association the endpoint made for it ends at once and gives its place back.
#[test]
fn an_invalid_init_is_answered_with_an_abort() {
    for (tag, a_rwnd, os, mis, answered) in [
        (7u32, 1499u32, 10u16, 10u16, true),
        (7, 128 * 1024, 0, 10, true),
        (7, 128 * 1024, 10, 0, true),
        (0, 128 * 1024, 10, 10, false),
    ] {
        let mut endpoint = accepting_endpoint();
        let now = Instant::now();
        let init = raw_chunk(CT_INIT.0, 0, &init_value(tag, a_rwnd, os, mis, &[]));
        let raw = raw_packet(5001, 5000, 0, &[init]);
        let Some((_, DatagramEvent::NewAssociation(mut a))) =
            endpoint.handle(now, remote(), None, raw)
        else {
            panic!("no association");
        };
        let sent = sent_datagrams(&mut a, now);
        assert!(chunks_of_type(&sent, CT_INIT_ACK.0).is_empty());
        let aborts = chunks_of_type(&sent, CT_ABORT.0);
        if answered {
            assert_eq!(
                1,
                aborts.len(),
                "INIT with a_rwnd {a_rwnd}, OS {os}, MIS {mis}"
            );
            assert_eq!(7, tag_of(&sent[0]), "to the INIT's Initiate Tag");
            assert_eq!(0, aborts[0][1] & 1, "T bit clear");
            assert_eq!(
                (5000, 5001),
                (
                    u16::from_be_bytes([sent[0][0], sent[0][1]]),
                    u16::from_be_bytes([sent[0][2], sent[0][3]])
                )
            );
        } else {
            assert!(
                sent.is_empty(),
                "an INIT with Initiate Tag 0 is not answered"
            );
        }
        assert!(
            a.is_ended(),
            "nothing is kept for an INIT that is not valid"
        );
        assert!(a.poll_timeout().is_none());
    }
}

/// The same INIT sent to an association that exists is answered and changes nothing.
#[test]
fn an_invalid_init_for_an_existing_association_is_answered_and_changes_nothing() {
    let mut link = connected_link(104);
    let now = link.now;
    let a = link.server.conn();
    let init = raw_chunk(CT_INIT.0, 0, &init_value(7, 100, 10, 10, &[]));
    let raw = raw_packet(a.destination_port, a.source_port, 0, &[init]);
    inject(a, now, raw);
    assert!(!a.is_ended());
    assert_eq!(AssociationState::Established, a.state());
    let sent = sent_datagrams(a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_ABORT.0).len());
    assert_eq!(7, tag_of(&sent[0]));
}

/// RFC 9260 3.3.3: an invalid INIT ACK in COOKIE-WAIT. Without a tag or without streams it
/// ends the attempt and is answered with an ABORT (with the T bit and the reflected tag when
/// the INIT ACK gave no tag to send to). With an a_rwnd below 1500 it is discarded and
/// answered with an ABORT, and the attempt goes on.
#[test]
fn an_invalid_init_ack_in_cookie_wait_is_answered_with_an_abort() {
    for (tag, a_rwnd, os, mis, ends) in [
        (0u32, 128 * 1024u32, 10u16, 10u16, true),
        (9, 128 * 1024, 0, 10, true),
        (9, 128 * 1024, 10, 0, true),
        (9, 1499, 10, 10, false),
    ] {
        let (_, mut a, now) = connecting_client(TransportConfig::default());
        let own_tag = a.my_verification_tag;
        let value = init_value(tag, a_rwnd, os, mis, &raw_tlv(7, b"cookie"));
        let raw = packet_to(&a, &[raw_chunk(CT_INIT_ACK.0, 0, &value)]);
        inject(&mut a, now, raw);

        let what = format!("INIT ACK with tag {tag}, a_rwnd {a_rwnd}, OS {os}, MIS {mis}");
        assert_eq!(ends, a.is_ended(), "{what}");
        let sent = sent_datagrams(&mut a, now);
        let aborts = chunks_of_type(&sent, CT_ABORT.0);
        assert_eq!(1, aborts.len(), "{what}");
        if tag == 0 {
            assert_eq!(own_tag, tag_of(&sent[0]), "the tag is reflected");
            assert_eq!(1, aborts[0][1] & 1, "T bit set");
        } else {
            assert_eq!(tag, tag_of(&sent[0]), "to the INIT ACK's Initiate Tag");
            assert_eq!(0, aborts[0][1] & 1, "T bit clear");
        }
        if !ends {
            assert_eq!(AssociationState::CookieWait, a.state());
            assert!(a.poll_timeout().is_some(), "T1-init keeps running");
        }
    }
}

/// RFC 9260 5.1.2, 3.3.3: an INIT or INIT ACK with a Host Name Address is answered with an
/// ABORT ("Unresolvable Address") and sets nothing up.
#[test]
fn a_host_name_address_is_answered_with_an_abort() {
    let host_name = raw_tlv(11, b"example.org\0");

    let (_, a, sent) = accept_init(std::slice::from_ref(&host_name));
    let a = a.unwrap();
    assert!(a.is_ended());
    assert!(chunks_of_type(&sent, CT_INIT_ACK.0).is_empty());
    let aborts = chunks_of_type(&sent, CT_ABORT.0);
    assert_eq!(1, aborts.len());
    assert_eq!(0xAABB_CCDD, tag_of(&sent[0]), "to the INIT's Initiate Tag");
    let causes = tlvs(&aborts[0][4..]);
    assert_eq!(CAUSE_UNRESOLVABLE_ADDRESS, causes[0].0);
    assert_eq!(host_name, causes[0].1, "the cause holds the parameter");

    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let init_ack = init_chunk(
        CT_INIT_ACK.0,
        4242,
        9000,
        &[raw_tlv(7, b"cookie"), host_name],
    );
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    assert!(a.is_ended());
    let sent = sent_datagrams(&mut a, now);
    assert!(chunks_of_type(&sent, CT_COOKIE_ECHO.0).is_empty());
    let aborts = chunks_of_type(&sent, CT_ABORT.0);
    assert_eq!(1, aborts.len());
    assert_eq!(4242, tag_of(&sent[0]));
    assert_eq!(CAUSE_UNRESOLVABLE_ADDRESS, tlvs(&aborts[0][4..])[0].0);
}

/// RFC 9260 3.3.3: the State Cookie is mandatory in an INIT ACK. Without it the attempt ends
/// with an ABORT "Missing Mandatory Parameter" naming parameter 7, and `HandshakeFailed`,
/// not a transport error.
#[test]
fn an_init_ack_without_a_state_cookie_ends_the_attempt_with_an_abort() {
    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let raw = packet_to(&a, &[init_chunk(CT_INIT_ACK.0, 4242, 9000, &[])]);
    inject(&mut a, now, raw);

    assert!(a.is_ended());
    let sent = sent_datagrams(&mut a, now);
    let aborts = chunks_of_type(&sent, CT_ABORT.0);
    assert_eq!(1, aborts.len());
    assert_eq!(4242, tag_of(&sent[0]));
    assert_eq!(
        vec![(CAUSE_MISSING_MANDATORY_PARAMETER, vec![0, 0, 0, 1, 0, 7])],
        tlvs(&aborts[0][4..])
    );
    assert!(events(&mut a).iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::HandshakeFailed(_)
        }
    )));
}

/// RFC 9260 6.2.1, 12.4: a SACK that acknowledges a TSN never sent, by its Cumulative TSN
/// Ack or by a Gap Ack Block, aborts the association with "Protocol Violation".
#[test]
fn a_sack_for_data_never_sent_aborts_the_association() {
    for gap in [false, true] {
        let mut link = connected_link(105);
        let now = link.now;
        let a = link.server.conn();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)
            .unwrap()
            .write_sctp(now, &Bytes::from_static(b"sent"), ppi)
            .unwrap();
        let sent = sent_datagrams(a, now);
        assert_eq!(1, chunks_of_type(&sent, 0).len());
        let last_sent = a.my_next_tsn.wrapping_sub(1);
        let sack = if gap {
            sack_chunk(last_sent.wrapping_sub(1), &[(3, 3)])
        } else {
            sack_chunk(last_sent.wrapping_add(5), &[])
        };
        let peer_tag = a.peer_verification_tag;
        let raw = packet_to(a, &[sack]);
        inject(a, now, raw);

        assert!(a.is_ended(), "gap block: {gap}");
        let sent = sent_datagrams(a, now);
        let aborts = chunks_of_type(&sent, CT_ABORT.0);
        assert_eq!(1, aborts.len(), "gap block: {gap}");
        assert_eq!(peer_tag, tag_of(&sent[0]));
        assert_eq!(CAUSE_PROTOCOL_VIOLATION, tlvs(&aborts[0][4..])[0].0);
    }
}

/// RFC 9260 9.1: an ABORT is alone in its packet with the peer's tag, and a packet that
/// carries an ABORT is never answered, whatever came bundled before the ABORT.
#[test]
fn an_abort_is_sent_alone_and_never_answered() {
    let mut link = connected_link(106);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"x"), abort_chunk(false)]);
    inject(a, now, raw);
    assert!(a.is_ended());
    assert!(sent_after(a, now, Duration::from_secs(1)).is_empty());

    let mut link = connected_link(107);
    let now = link.now;
    let a = link.client.conn();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"queued"), ppi)
        .unwrap();
    let peer_tag = a.peer_verification_tag;
    a.abort().unwrap();
    let sent = sent_datagrams(a, now);
    let with_abort = datagrams_with(&sent, CT_ABORT.0);
    assert_eq!(1, with_abort.len());
    assert_eq!(1, chunks_of(&with_abort[0]).len(), "the ABORT is alone");
    assert_eq!(peer_tag, tag_of(&with_abort[0]));
}

// ---- The State Cookie ---------------------------------------------------------------------------

fn cookie_of(sent: &[Bytes]) -> Vec<u8> {
    let init_ack = &chunks_of_type(sent, CT_INIT_ACK.0)[0];
    tlvs(&init_ack[20..])
        .into_iter()
        .find(|(typ, _)| *typ == 7)
        .expect("a State Cookie")
        .1
}

/// RFC 9260 4, 5.1.5: a cookie that is not the one this side sent, or that comes between
/// other ports, is discarded with its whole packet, DATA included, and the state stays
/// CLOSED.
#[test]
fn a_cookie_that_was_not_sent_discards_its_packet() {
    let (_, a, sent) = accept_init(&[]);
    let mut a = a.unwrap();
    let now = Instant::now();
    let cookie = cookie_of(&sent);
    let mut forged = cookie.clone();
    forged[0] ^= 1;

    let raw = packet_to(
        &a,
        &[
            raw_chunk(CT_COOKIE_ECHO.0, 0, &forged),
            data_chunk(100, 1, 0, b"x"),
        ],
    );
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::Closed, a.state());
    assert!(a.is_handshaking());
    assert_eq!(99, a.peer_last_tsn, "the DATA bundled with it is discarded");
    assert!(sent_datagrams(&mut a, now).is_empty());

    // The right cookie from other ports.
    let raw = raw_packet(
        6000,
        a.source_port,
        a.my_verification_tag,
        &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)],
    );
    inject(&mut a, now, raw);
    assert!(
        a.is_handshaking(),
        "the ports of the INIT are part of the cookie"
    );

    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)]);
    inject(&mut a, now, raw);
    assert!(!a.is_handshaking());
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ACK.0).len()
    );
}

/// RFC 9260 5.1.3, 5.1.5: a State Cookie has a lifetime (Valid.Cookie.Life, 60 s). Echoed
/// later it is refused with an ERROR "Stale Cookie" that says by how much, its packet is
/// discarded, and a new INIT gets a new cookie.
#[test]
fn a_stale_cookie_is_refused_with_an_error() {
    let (mut endpoint, a, sent) = accept_init(&[]);
    let mut a = a.unwrap();
    let start = Instant::now();
    let cookie = cookie_of(&sent);

    let late = start + Duration::from_millis(60_500);
    let raw = packet_to(
        &a,
        &[
            raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie),
            data_chunk(100, 1, 0, b"x"),
        ],
    );
    inject(&mut a, late, raw);
    assert!(a.is_handshaking(), "a stale cookie establishes nothing");
    assert_eq!(99, a.peer_last_tsn, "its packet is discarded");
    let sent = sent_datagrams(&mut a, late);
    assert!(chunks_of_type(&sent, CT_COOKIE_ACK.0).is_empty());
    let errors = chunks_of_type(&sent, CT_ERROR.0);
    assert_eq!(1, errors.len());
    let causes = tlvs(&errors[0][4..]);
    assert_eq!(CAUSE_STALE_COOKIE, causes[0].0);
    let staleness = u32::from_be_bytes(causes[0].1[..4].try_into().unwrap());
    assert!(
        (400_000..=600_000).contains(&staleness),
        "about half a second, in microseconds: {staleness}"
    );

    // The peer starts over: the same INIT gets a cookie that is good now.
    let init = raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, &[])],
    );
    let Some((_, DatagramEvent::AssociationEvent(event))) =
        endpoint.handle(late, remote(), None, init)
    else {
        panic!("the INIT is the association's");
    };
    a.handle_event(event);
    let new_cookie = cookie_of(&sent_datagrams(&mut a, late));
    assert_ne!(cookie, new_cookie);
    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &new_cookie)]);
    inject(&mut a, late, raw);
    assert!(!a.is_handshaking());
}

/// Valid.Cookie.Life is configurable, and an INIT sent again within it gets the same cookie,
/// so the cookie of an INIT ACK already on its way stays good.
#[test]
fn the_cookie_lifetime_is_configurable_and_a_repeated_init_keeps_its_cookie() {
    let mut server = ServerConfig::new(
        TransportConfig::default().with_valid_cookie_life(Duration::from_secs(5)),
    );
    server.concurrent_associations(1);
    let mut endpoint = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server)),
    );
    let start = Instant::now();
    let init = raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, &[])],
    );
    let Some((_, DatagramEvent::NewAssociation(mut a))) =
        endpoint.handle(start, remote(), None, init.clone())
    else {
        panic!("no association");
    };
    let cookie = cookie_of(&sent_datagrams(&mut a, start));

    let again = start + Duration::from_secs(2);
    let Some((_, DatagramEvent::AssociationEvent(event))) =
        endpoint.handle(again, remote(), None, init)
    else {
        panic!("a repeated INIT is the association's");
    };
    a.handle_event(event);
    assert_eq!(cookie, cookie_of(&sent_datagrams(&mut a, again)));

    let late = start + Duration::from_secs(6);
    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)]);
    inject(&mut a, late, raw);
    assert!(
        a.is_handshaking(),
        "5 s after the first INIT ACK it is stale"
    );
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, late), CT_ERROR.0).len()
    );
}

/// RFC 9260 5.2.4 (action D, and case E of 5.2): the COOKIE ECHO of the association that
/// exists is acknowledged again, however old the cookie, and establishes nothing twice.
#[test]
fn a_repeated_cookie_echo_is_acknowledged_again() {
    for state in [
        AssociationState::Established,
        AssociationState::ShutdownPending,
        AssociationState::ShutdownReceived,
    ] {
        let mut link = connected_link(108);
        let late = link.now + Duration::from_secs(3600);
        let a = link.server.conn();
        a.set_state(state);
        let cookie = a.my_cookie.as_ref().unwrap().cookie.clone();
        let raw = packet_to(a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)]);
        inject(a, late, raw);
        assert_eq!(state, a.state());
        assert!(events(a).is_empty(), "no second Connected in {state}");
        assert_eq!(
            1,
            chunks_of_type(&sent_datagrams(a, late), CT_COOKIE_ACK.0).len(),
            "COOKIE ACK in {state}"
        );
    }
}

/// RFC 9260 5.2.4 (action C and the cases not in the table): a COOKIE ECHO with a cookie
/// that is not the association's changes nothing and is not answered.
#[test]
fn a_cookie_echo_with_another_cookie_changes_nothing() {
    let mut link = connected_link(109);
    let now = link.now;
    let a = link.server.conn();
    let raw = packet_to(a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &[7; 32])]);
    inject(a, now, raw);
    assert_eq!(AssociationState::Established, a.state());
    assert!(events(a).is_empty());
    assert!(sent_datagrams(a, now).is_empty());
}

/// RFC 9260 5.1, 5.1.5: the first DATA chunk of an association, and DATA that comes with the
/// COOKIE ECHO, are acknowledged with a SACK at once, not after the delayed-ack time.
#[test]
fn the_first_data_is_acknowledged_without_delay() {
    // Bundled with the COOKIE ECHO.
    let (_, a, sent) = accept_init(&[]);
    let mut a = a.unwrap();
    let now = Instant::now();
    let cookie = cookie_of(&sent);
    let raw = packet_to(
        &a,
        &[
            raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie),
            data_chunk(100, 1, 0, b"with the cookie"),
        ],
    );
    inject(&mut a, now, raw);
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_COOKIE_ACK.0).len());
    assert_eq!(1, chunks_of_type(&sent, CT_SACK.0).len(), "a SACK at once");
    for datagram in datagrams_with(&sent, CT_COOKIE_ACK.0) {
        assert_eq!(
            CT_COOKIE_ACK.0, datagram[12],
            "COOKIE ACK is the first chunk"
        );
    }

    // The first DATA after the handshake; the second is acknowledged with delay.
    let mut link = connected_link(110);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"first")]);
    inject(a, now, raw);
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).len(),
        "the first DATA of the association"
    );
    let raw = packet_to(a, &[data_chunk(tsn.wrapping_add(1), 1, 1, b"second")]);
    inject(a, now, raw);
    assert!(
        chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).is_empty(),
        "the next one waits for the delayed-ack timer"
    );
}

/// RFC 9260 5.2.6: a "Stale Cookie" ERROR counts in COOKIE-ECHOED only. There the setup
/// starts over with a new INIT, a bounded number of times.
#[test]
fn a_stale_cookie_error_restarts_the_setup_in_cookie_echoed_only() {
    let stale = raw_chunk(CT_ERROR.0, 0, &raw_tlv(CAUSE_STALE_COOKIE, &[0, 0, 1, 0]));

    let mut link = connected_link(111);
    let now = link.now;
    let a = link.client.conn();
    let raw = packet_to(a, std::slice::from_ref(&stale));
    inject(a, now, raw);
    assert_eq!(AssociationState::Established, a.state());
    assert!(
        sent_datagrams(a, now).is_empty(),
        "ignored once established"
    );

    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let mut restarts = 0;
    for round in 0..20 {
        let init_ack = init_chunk(CT_INIT_ACK.0, 4242 + round, 9000, &[raw_tlv(7, b"cookie")]);
        let raw = packet_to(&a, &[init_ack]);
        inject(&mut a, now, raw);
        if a.is_ended() {
            break;
        }
        assert_eq!(AssociationState::CookieEchoed, a.state());
        assert_eq!(
            1,
            chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ECHO.0).len()
        );

        let raw = packet_to(&a, std::slice::from_ref(&stale));
        inject(&mut a, now, raw);
        if a.is_ended() {
            break;
        }
        restarts += 1;
        assert_eq!(
            AssociationState::CookieWait,
            a.state(),
            "back to a new INIT"
        );
        let sent = sent_datagrams(&mut a, now);
        assert_eq!(1, chunks_of_type(&sent, CT_INIT.0).len());
        assert_eq!(0, tag_of(&sent[0]), "an INIT has tag 0");
        assert!(a.poll_timeout().is_some(), "T1-init runs");
    }
    assert_eq!(8, restarts, "Max.Init.Retransmits new attempts");
    assert!(a.is_ended(), "then the setup fails");
    assert!(
        events(&mut a)
            .iter()
            .any(|e| matches!(e, Event::HandshakeFailed { .. }))
    );
}

// ---- Unexpected handshake chunks -------------------------------------------------------------------

/// RFC 9260 5.2.1, 5.2.4 B: an INIT that crosses this side's own (both sides start at once)
/// is answered with an INIT ACK that repeats this side's INIT, tag unchanged, with a State
/// Cookie; the state, T1-init and the TCB stay as they are. When the cookie comes back the
/// association is established with the peer's tag from that INIT.
#[test]
fn a_crossing_init_is_answered_without_touching_the_tcb() {
    for echoed in [false, true] {
        let (_, mut a, now) = connecting_client(TransportConfig::default());
        if echoed {
            // The peer's INIT ACK came first: COOKIE-ECHOED, with the peer's tag from it.
            let init_ack = init_chunk(CT_INIT_ACK.0, 0x0707, 500, &[raw_tlv(7, b"peer cookie")]);
            let raw = packet_to(&a, &[init_ack]);
            inject(&mut a, now, raw);
            let _ = sent_datagrams(&mut a, now);
        }
        let state = a.state();
        let before = (a.peer_verification_tag, a.peer_last_tsn, a.rwnd);
        let own = (a.my_verification_tag, a.my_next_tsn);

        let init = raw_packet(
            a.destination_port,
            a.source_port,
            0,
            &[init_chunk(CT_INIT.0, 0x0808, 700, &[])],
        );
        inject(&mut a, now, init);

        assert_eq!(state, a.state(), "the state does not change");
        assert_eq!(before, (a.peer_verification_tag, a.peer_last_tsn, a.rwnd));
        assert!(a.poll_timeout().is_some(), "the T1 timer keeps running");
        let sent = sent_datagrams(&mut a, now);
        let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
        assert_eq!(1, init_acks.len());
        assert_eq!(0x0808, tag_of(&sent[0]), "sent to the INIT's Initiate Tag");
        assert_eq!(
            own.0,
            u32::from_be_bytes(init_acks[0][4..8].try_into().unwrap()),
            "this side's Initiate Tag, unchanged"
        );
        assert_eq!(
            own.1,
            u32::from_be_bytes(init_acks[0][16..20].try_into().unwrap()),
            "and its initial TSN"
        );
        let cookie = cookie_of(&sent);

        let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)]);
        inject(&mut a, now, raw);
        assert_eq!(AssociationState::Established, a.state());
        assert_eq!(
            0x0808, a.peer_verification_tag,
            "the tag that came with the cookie"
        );
        assert_eq!(699, a.peer_last_tsn);
        assert!(a.poll_timeout().is_none(), "the T1 timers are stopped");
        let sent = sent_datagrams(&mut a, now);
        assert_eq!(1, chunks_of_type(&sent, CT_COOKIE_ACK.0).len());
        assert_eq!(0x0808, tag_of(&sent[0]));
        assert!(events(&mut a).iter().any(|e| matches!(e, Event::Connected)));
    }
}

/// RFC 9260 5.2.3, 5.2.5: an INIT ACK outside COOKIE-WAIT and a COOKIE ACK outside
/// COOKIE-ECHOED are discarded.
#[test]
fn a_late_init_ack_or_cookie_ack_is_discarded() {
    let mut link = connected_link(112);
    let now = link.now;
    let a = link.client.conn();
    let before = (a.peer_verification_tag, a.peer_last_tsn);
    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    for chunk in [init_ack, raw_chunk(CT_COOKIE_ACK.0, 0, &[])] {
        let raw = packet_to(a, &[chunk]);
        inject(a, now, raw);
        assert_eq!(AssociationState::Established, a.state());
        assert_eq!(before, (a.peer_verification_tag, a.peer_last_tsn));
        assert!(sent_datagrams(a, now).is_empty());
        assert!(events(a).is_empty());
    }

    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ACK.0, 0, &[])]);
    inject(&mut a, now, raw);
    assert_eq!(
        AssociationState::CookieWait,
        a.state(),
        "COOKIE ACK in COOKIE-WAIT"
    );
}

// ---- 9.2: shutdown ---------------------------------------------------------------------------------

fn shutdown_chunk(cumulative: u32) -> Vec<u8> {
    raw_chunk(CT_SHUTDOWN.0, 0, &cumulative.to_be_bytes())
}

/// A connected link whose client has sent SHUTDOWN, with nothing answered yet.
fn client_in_shutdown_sent(seed: u64, config: TransportConfig) -> (Link, Instant) {
    let mut link = Link::new(config, TransportConfig::default(), seed);
    link.connect();
    let now = link.now;
    let a = link.client.conn();
    a.shutdown().unwrap();
    let sent = sent_datagrams(a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_SHUTDOWN.0).len());
    assert_eq!(AssociationState::ShutdownSent, a.state());
    (link, now)
}

/// RFC 9260 4, 9.2: in SHUTDOWN-SENT a packet with DATA is answered at once with a SACK and
/// with the SHUTDOWN again, and T2-shutdown starts over.
#[test]
fn data_in_shutdown_sent_is_answered_with_a_sack_and_the_shutdown() {
    let (mut link, now) = client_in_shutdown_sent(121, TransportConfig::default());
    let a = link.client.conn();
    let t2 = a.timers.get(Timer::T2Shutdown).expect("T2 runs");
    let tsn = a.peer_last_tsn.wrapping_add(1);

    let later = now + Duration::from_millis(300);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"still sending")]);
    inject(a, later, raw);

    let sent = sent_datagrams(a, later);
    let sacks = chunks_of_type(&sent, CT_SACK.0);
    assert_eq!(1, sacks.len(), "a SACK without delay");
    let shutdowns = chunks_of_type(&sent, CT_SHUTDOWN.0);
    assert_eq!(1, shutdowns.len(), "and the SHUTDOWN again");
    assert_eq!(
        tsn,
        u32::from_be_bytes(shutdowns[0][4..8].try_into().unwrap()),
        "with the new Cumulative TSN Ack"
    );
    assert!(
        a.timers.get(Timer::T2Shutdown).unwrap() > t2,
        "T2-shutdown is restarted"
    );

    // A gap is reported in the SACK that goes with it.
    let raw = packet_to(a, &[data_chunk(tsn.wrapping_add(2), 1, 2, b"after a gap")]);
    inject(a, later, raw);
    let sent = sent_datagrams(a, later);
    let sacks = chunks_of_type(&sent, CT_SACK.0);
    assert_eq!(
        1,
        u16::from_be_bytes([sacks[0][12], sacks[0][13]]),
        "a Gap Ack Block"
    );
    assert_eq!(1, chunks_of_type(&sent, CT_SHUTDOWN.0).len());
}

/// RFC 9260 9.2: any packet from the peer in SHUTDOWN-SENT clears the count of SHUTDOWN
/// retransmissions, so a peer that is still sending its queue is not given up on.
#[test]
fn a_packet_from_the_peer_restarts_the_shutdown_retransmissions() {
    let config = TransportConfig::default().with_timer_config(TimerConfig {
        max_t2_shutdown_retrans: 2,
        ..TimerConfig::default()
    });
    let (mut link, mut now) = client_in_shutdown_sent(122, config);
    let a = link.client.conn();
    let mut tsn = a.peer_last_tsn;
    // Far more expiries than the limit, each followed by a packet from the peer.
    for _ in 0..6 {
        for _ in 0..2 {
            now = a.timers.get(Timer::T2Shutdown).expect("T2 runs");
            a.handle_timeout(now);
            let _ = sent_datagrams(a, now);
            assert!(!a.is_ended());
        }
        tsn = tsn.wrapping_add(1);
        let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"x")]);
        inject(a, now, raw);
        let _ = sent_datagrams(a, now);
    }
    assert_eq!(AssociationState::ShutdownSent, a.state());

    // Left alone, the limit is reached.
    for _ in 0..3 {
        now = a.timers.get(Timer::T2Shutdown).expect("T2 runs");
        a.handle_timeout(now);
        let _ = sent_datagrams(a, now);
    }
    assert!(a.is_ended());
}

/// RFC 9260 9.2: T5-shutdown-guard (5 x RTO.Max) bounds a shutdown that the peer keeps alive
/// without finishing: the association is aborted and the upper layer told.
#[test]
fn the_shutdown_guard_aborts_a_shutdown_that_never_finishes() {
    let (mut link, start) = client_in_shutdown_sent(123, TransportConfig::default());
    let a = link.client.conn();
    let peer_tag = a.peer_verification_tag;
    let mut tsn = a.peer_last_tsn;
    let mut now = start;
    let mut sent = vec![];
    let mut rounds = 0;
    while !a.is_ended() {
        now = a.poll_timeout().expect("a timer runs while shutting down");
        a.handle_timeout(now);
        sent = sent_datagrams(a, now);
        if a.is_ended() {
            break;
        }
        // The peer keeps talking, which keeps T2-shutdown from giving up.
        tsn = tsn.wrapping_add(1);
        let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"x")]);
        inject(a, now, raw);
        let _ = sent_datagrams(a, now);
        rounds += 1;
        assert!(rounds < 10_000, "the shutdown never ended");
    }
    assert_eq!(Duration::from_secs(300), now - start, "5 x RTO.Max");
    let aborts = datagrams_with(&sent, CT_ABORT.0);
    assert_eq!(1, aborts.len(), "the peer is told");
    assert_eq!(peer_tag, tag_of(&aborts[0]));
    assert!(events(a).iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::TimedOut
        }
    )));
}

/// RFC 9260 9.2, 16: SHUTDOWN is retransmitted on T2-shutdown at most Association.Max.Retrans
/// (10) times by default, with the latest Cumulative TSN Ack; then the peer is unreachable.
#[test]
fn an_unanswered_shutdown_is_retransmitted_and_given_up_by_default() {
    let (mut link, start) = client_in_shutdown_sent(124, TransportConfig::default());
    let a = link.client.conn();
    let cumulative = a.peer_last_tsn;
    let mut now = start;
    let mut retransmissions = 0;
    while let Some(at) = a.poll_timeout() {
        now = at;
        a.handle_timeout(now);
        for shutdown in chunks_of_type(&sent_datagrams(a, now), CT_SHUTDOWN.0) {
            assert_eq!(cumulative.to_be_bytes().to_vec(), shutdown[4..8].to_vec());
            retransmissions += 1;
        }
        assert!(retransmissions <= 10, "more than Association.Max.Retrans");
    }
    assert!(a.is_ended());
    assert!((8..=10).contains(&retransmissions), "{retransmissions}");
    assert!(now - start <= Duration::from_secs(304));
    assert!(events(a).iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::TimedOut
        }
    )));
}

/// RFC 9260 9.2: a SHUTDOWN received in SHUTDOWN-PENDING (both sides shut down, the peer's
/// SHUTDOWN first) is taken: SHUTDOWN-RECEIVED, then SHUTDOWN ACK once the queue is empty.
#[test]
fn a_shutdown_received_in_shutdown_pending_is_taken() {
    let mut link = connected_link(125);
    let now = link.now;
    let a = link.client.conn();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"not yet acknowledged"), ppi)
        .unwrap();
    let _ = sent_datagrams(a, now);
    a.shutdown().unwrap();
    assert_eq!(AssociationState::ShutdownPending, a.state());
    let last_sent = a.my_next_tsn.wrapping_sub(1);

    // The peer's SHUTDOWN does not acknowledge the DATA yet.
    let raw = packet_to(a, &[shutdown_chunk(last_sent.wrapping_sub(1))]);
    inject(a, now, raw);
    assert_eq!(AssociationState::ShutdownReceived, a.state());

    // A second SHUTDOWN acknowledges it: SHUTDOWN ACK follows.
    let raw = packet_to(a, &[shutdown_chunk(last_sent)]);
    inject(a, now, raw);
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(a, now), CT_SHUTDOWN_ACK.0).len()
    );
}

/// RFC 9260 9.2: in SHUTDOWN-RECEIVED a shutdown request from the upper layer is refused and
/// no new data is accepted; in SHUTDOWN-ACK-SENT neither.
#[test]
fn nothing_new_is_accepted_once_the_peer_has_shut_down() {
    for state in [
        AssociationState::ShutdownReceived,
        AssociationState::ShutdownAckSent,
    ] {
        let mut link = connected_link(126);
        let now = link.now;
        let a = link.client.conn();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi).unwrap();
        a.set_state(state);
        assert!(a.shutdown().is_err(), "shutdown() in {state}");
        assert_eq!(state, a.state());
        assert!(
            a.stream(1)
                .unwrap()
                .write_sctp(now, &Bytes::from_static(b"x"), ppi)
                .is_err(),
            "a write in {state}"
        );
    }
}

/// RFC 9260 9.2: both sides send SHUTDOWN at once. Each answers the other's SHUTDOWN with
/// SHUTDOWN ACK and enters SHUTDOWN-ACK-SENT; a SHUTDOWN ACK received there is answered with
/// SHUTDOWN COMPLETE and ends the association. T2 retransmits the SHUTDOWN ACK meanwhile.
#[test]
fn simultaneous_shutdown_completes() {
    let (mut link, now) = client_in_shutdown_sent(127, TransportConfig::default());
    let a = link.client.conn();
    let cumulative = a.my_next_tsn.wrapping_sub(1);
    let raw = packet_to(a, &[shutdown_chunk(cumulative)]);
    inject(a, now, raw);
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(a, now), CT_SHUTDOWN_ACK.0).len()
    );

    // Unanswered, the SHUTDOWN ACK is sent again when T2-shutdown expires.
    let at = a.timers.get(Timer::T2Shutdown).expect("T2 runs");
    a.handle_timeout(at);
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(a, at), CT_SHUTDOWN_ACK.0).len(),
        "retransmitted"
    );

    let peer_tag = a.peer_verification_tag;
    let raw = packet_to(a, &[raw_chunk(CT_SHUTDOWN_ACK.0, 0, &[])]);
    inject(a, at, raw);
    let sent = sent_datagrams(a, at);
    let complete = datagrams_with(&sent, CT_SHUTDOWN_COMPLETE.0);
    assert_eq!(1, complete.len());
    assert_eq!(peer_tag, tag_of(&complete[0]));
    assert_eq!(0, complete[0][13] & 1, "with a TCB the T bit is clear");
    assert!(a.is_ended());
    assert!(a.poll_timeout().is_none());
}

/// RFC 9260 9.2: a SHUTDOWN while the association is being set up is discarded.
#[test]
fn a_shutdown_during_setup_is_discarded() {
    let (_, mut a, now) = connecting_client(TransportConfig::default());
    let raw = packet_to(&a, &[shutdown_chunk(1)]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::CookieWait, a.state());
    assert!(sent_datagrams(&mut a, now).is_empty());

    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    let _ = sent_datagrams(&mut a, now);
    let raw = packet_to(&a, &[shutdown_chunk(1)]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::CookieEchoed, a.state());
    assert!(sent_datagrams(&mut a, now).is_empty());
}
