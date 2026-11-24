//! RFC 9653: the zero checksum over DTLS, and the entry point for the path MTU.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::Link;
use crate::param::param_zero_checksum_acceptable::ParamZeroChecksumAcceptable;
use std::cell::RefCell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn over_dtls() -> TransportConfig {
    TransportConfig::default().with_zero_checksum(true)
}

/// Whether the checksum field holds the packet's CRC32c.
fn has_crc32c(datagram: &Bytes) -> bool {
    let mut raw = datagram.to_vec();
    let field = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    raw[8..12].fill(0);
    crc32c::crc32c(&raw) == field
}

fn checksum_is_zero(datagram: &Bytes) -> bool {
    datagram[8..12] == [0u8; 4]
}

/// Every datagram on the link: (from the client, the datagram).
fn capture(link: &mut Link) -> Rc<RefCell<Vec<(bool, Bytes)>>> {
    let seen: Rc<RefCell<Vec<(bool, Bytes)>>> = Rc::default();
    let record = seen.clone();
    link.filter = Some(Box::new(move |from_client, datagram: &Bytes| {
        record.borrow_mut().push((from_client, datagram.clone()));
        false
    }));
    seen
}

fn exchange(link: &mut Link) {
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from(vec![7; 4000]), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(10);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
    let now = link.now;
    link.server
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(now, &Bytes::from(vec![8; 4000]), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(10);
    assert!(link.run_until(deadline, |l| !l.client.received.is_empty()));
    // A HEARTBEAT and its acknowledgement as well.
    link.run_for(Duration::from_secs(40));
}

/// RFC 9653 section 4: the Zero Checksum Acceptable parameter, type 0x8001, length 8.
#[test]
fn the_zero_checksum_acceptable_parameter_is_encoded_and_decoded() -> Result<()> {
    let param = ParamZeroChecksumAcceptable { edmid: 1 };
    let raw = param.marshal()?;
    assert_eq!(&[0x80, 0x01, 0, 8, 0, 0, 0, 1][..], &raw[..]);
    let built = crate::param::build_param(&raw)?;
    assert_eq!(
        Some(&param),
        built.as_any().downcast_ref::<ParamZeroChecksumAcceptable>()
    );
    // "the value MUST be 8": anything else is not this parameter, and is skipped as one
    // that is not known.
    let long = Bytes::from_static(&[0x80, 0x01, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0]);
    let built = crate::param::build_param(&long)?;
    assert!(built.as_any().is::<ParamUnknown>());
    Ok(())
}

/// RFC 9653 5.1 to 5.3 and 6: with both sides over DTLS, each announces that it takes a zero
/// checksum and sends one. The INIT and the COOKIE ECHO keep a correct CRC32c (5.2).
#[test]
fn both_sides_over_dtls_send_a_zero_checksum() {
    let mut link = Link::new(over_dtls(), over_dtls(), 961);
    let seen = capture(&mut link);
    link.connect();
    exchange(&mut link);
    assert!(link.client.conn().zero_checksum() && link.server.conn().zero_checksum());

    let seen = seen.borrow();
    let mut zero = 0;
    for (from_client, datagram) in seen.iter() {
        let first = datagram[12];
        if first == CT_INIT.0 || first == CT_INIT_ACK.0 {
            let params = tlvs(&chunks_of(datagram)[0][20..]);
            assert_eq!(
                1,
                params
                    .iter()
                    .filter(|(typ, value)| *typ == 0x8001 && value == &[0, 0, 0, 1])
                    .count(),
                "the parameter, once, with the DTLS method"
            );
        }
        if first == CT_INIT.0 || first == CT_COOKIE_ECHO.0 {
            assert!(has_crc32c(datagram), "chunk type {first} needs its CRC32c");
            assert!(!checksum_is_zero(datagram));
            continue;
        }
        assert!(
            checksum_is_zero(datagram),
            "from the client: {from_client}, first chunk {first}"
        );
        zero += 1;
    }
    for typ in [
        CT_INIT_ACK,
        CT_COOKIE_ACK,
        CT_PAYLOAD_DATA,
        CT_SACK,
        CT_HEARTBEAT,
    ] {
        assert!(
            seen.iter()
                .any(|(_, d)| chunks_of(d).iter().any(|c| c[0] == typ.0)),
            "no {typ} was seen"
        );
    }
    assert!(zero > 10);
    assert_eq!(vec![7u8; 4000], link.server.received[0].1.to_vec());
    assert_eq!(vec![8u8; 4000], link.client.received[0].1.to_vec());
}

/// RFC 9653 5.2 1.: a peer that did not announce the parameter gets a correct CRC32c in
/// every packet, and the side that announced it takes them; by default nothing is announced.
#[test]
fn a_zero_checksum_is_sent_only_to_a_peer_that_takes_it() {
    for (n, (client, server)) in [
        (over_dtls(), TransportConfig::default()),
        (TransportConfig::default(), over_dtls()),
        (TransportConfig::default(), TransportConfig::default()),
    ]
    .into_iter()
    .enumerate()
    {
        let announces = [client.zero_checksum(), server.zero_checksum()];
        let mut link = Link::new(client, server, 962 + n as u64);
        let seen = capture(&mut link);
        link.connect();
        exchange(&mut link);
        assert!(!link.client.conn().zero_checksum() && !link.server.conn().zero_checksum());
        for (from_client, datagram) in seen.borrow().iter() {
            assert!(has_crc32c(datagram), "case {n}");
            let first = &chunks_of(datagram)[0];
            if first[0] == CT_INIT.0 || first[0] == CT_INIT_ACK.0 {
                let announced = tlvs(&first[20..]).iter().any(|(typ, _)| *typ == 0x8001);
                assert_eq!(announces[usize::from(!*from_client)], announced, "case {n}");
            }
        }
    }
}

/// RFC 9653 5.3: an endpoint that announced the parameter takes a packet whose checksum is
/// zero; one that did not drops it, as it drops any packet with a wrong CRC32c. A packet for
/// no association is not taken with a zero checksum either.
#[test]
fn a_zero_checksum_is_taken_only_when_it_was_announced() {
    for (config, taken) in [(over_dtls(), true), (TransportConfig::default(), false)] {
        let mut link = Link::new(config.clone(), config, 965);
        link.connect();
        let now = link.now;
        let a = link.server.conn();
        let tsn = a.peer_last_tsn.wrapping_add(1);
        let mut raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"data")]).to_vec();
        raw[8..12].fill(0);
        inject(a, now, Bytes::from(raw));
        assert_eq!(taken, a.peer_last_tsn == tsn, "taken: {taken}");
        assert_eq!(taken, read_all(a, 1).len() == 1);
    }

    // An INIT with a zero checksum, to an endpoint that would announce the parameter.
    let mut endpoint = crate::endpoint::Endpoint::new(
        SocketAddr::from(([10, 0, 0, 2], 5000)),
        TransportProtocol::UDP,
        Arc::new(crate::EndpointConfig::default()),
        Some(Arc::new(crate::ServerConfig::new(over_dtls()))),
    );
    let init = raw_packet(5000, 5000, 0, &[init_chunk(CT_INIT.0, 77, 100, &[])]);
    let mut zeroed = init.to_vec();
    zeroed[8..12].fill(0);
    let remote = SocketAddr::from(([10, 0, 0, 1], 5000));
    let now = Instant::now();
    assert!(
        endpoint
            .handle(now, remote, None, Bytes::from(zeroed))
            .is_none()
    );
    assert!(endpoint.poll_transmit().is_none());
    assert!(endpoint.handle(now, remote, None, init).is_some());
}

/// RFC 9653 5.2 1.b: the answer to an out-of-the-blue packet carries a correct CRC32c.
#[test]
fn an_answer_to_an_out_of_the_blue_packet_has_its_crc32c() {
    let mut endpoint = crate::endpoint::Endpoint::new(
        SocketAddr::from(([10, 0, 0, 2], 5000)),
        TransportProtocol::UDP,
        Arc::new(crate::EndpointConfig::default()),
        Some(Arc::new(crate::ServerConfig::new(over_dtls()))),
    );
    let stray = raw_packet(5000, 5000, 0x1234_5678, &[data_chunk(1, 1, 0, b"stray")]);
    let remote = SocketAddr::from(([10, 0, 0, 1], 5000));
    assert!(
        endpoint
            .handle(Instant::now(), remote, None, stray)
            .is_none()
    );
    let Some(TransportMessage {
        message: Payload::RawEncode(answer),
        ..
    }) = endpoint.poll_transmit()
    else {
        panic!("an ABORT answers the packet");
    };
    assert_eq!(CT_ABORT.0, answer[0][12]);
    assert!(has_crc32c(&answer[0]) && !checksum_is_zero(&answer[0]));
}

/// RFC 9653 5.3 (MAY: "faster SCTP association failure detection"), RFC 9260 8.4: an
/// association that ended on one side, without the other hearing of it, is ended on the other
/// by the ABORT that answers its next packet, zero checksum and all. A lossy-link run found
/// the case: one side's handshake ran out of COOKIE ECHO retransmissions while the other,
/// whose COOKIE ACKs were all lost, was established and kept sending its DATA (the data
/// channel's DATA_CHANNEL_OPEN) and HEARTBEATs into the void; the out-of-the-blue packets
/// had a zero checksum and were dropped unanswered, and the data channel neither opened nor
/// failed for minutes after. An endpoint that does not run under DTLS still drops them.
#[test]
fn a_peer_whose_association_ended_here_is_aborted_by_its_next_packet() {
    {
        let config = over_dtls();
        let aborted = true;
        let mut link = Link::new(config.clone(), config, 966);
        link.connect();
        link.server.endpoint_answers = true;
        // The server's association ends and says nothing.
        link.server
            .conn()
            .close(AssociationError::TimedOut)
            .expect("close");
        assert!(link.server.conn().is_ended());

        let now = link.now;
        link.client
            .conn()
            .open_stream(1, PPI)
            .unwrap()
            .write_sctp(now, &Bytes::from_static(b"open"), PPI)
            .unwrap();
        let deadline = link.now + Duration::from_secs(5);
        let ended = link.run_until(deadline, |l| {
            l.client
                .association
                .as_ref()
                .is_some_and(|(_, conn)| conn.is_ended())
        });
        assert_eq!(ended, aborted, "the client's association is aborted");
        assert!(
            link.client
                .events
                .iter()
                .any(|event| matches!(event, Event::AssociationClosed { .. })),
            "the application hears of it"
        );
    }

    // The same stray packet with a zero checksum: answered by an endpoint that announces the
    // zero checksum, dropped by one that does not (it cannot tell a zero from corruption).
    for (config, answered) in [(over_dtls(), true), (TransportConfig::default(), false)] {
        let mut endpoint = crate::endpoint::Endpoint::new(
            SocketAddr::from(([10, 0, 0, 2], 5000)),
            TransportProtocol::UDP,
            Arc::new(crate::EndpointConfig::default()),
            Some(Arc::new(crate::ServerConfig::new(config))),
        );
        let mut stray =
            raw_packet(5000, 5000, 0x1234_5678, &[data_chunk(1, 1, 0, b"stray")]).to_vec();
        stray[8..12].fill(0);
        let remote = SocketAddr::from(([10, 0, 0, 1], 5000));
        assert!(
            endpoint
                .handle(Instant::now(), remote, None, Bytes::from(stray))
                .is_none()
        );
        let answer = endpoint.poll_transmit();
        assert_eq!(answer.is_some(), answered, "answered: {answered}");
        if let Some(TransportMessage {
            message: Payload::RawEncode(answer),
            ..
        }) = answer
        {
            assert_eq!(CT_ABORT.0, answer[0][12]);
            assert!(has_crc32c(&answer[0]), "RFC 9653 5.2 1.b");
        }
    }
}

// ---- path MTU -----------------------------------------------------------------------------

/// RFC 9260 7.3, RFC 8261 4: the transport tells the association the path MTU, and packets,
/// fragments and the congestion control's packet size follow it.
#[test]
fn the_path_mtu_can_be_set_by_the_transport() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.cwnd = 1 << 20;
    a.rwnd = 1 << 20;
    a.open_stream(1, PPI)?;
    let largest = |a: &mut Association, now: Instant| -> Result<(usize, usize)> {
        a.stream(1)?
            .write_sctp(now, &Bytes::from(vec![1; 20_000]), PPI)?;
        let packets = a.gather_outbound(now).0;
        let chunk = transmitted_data(&packets)
            .iter()
            .map(|c| c.user_data.len())
            .max()
            .unwrap();
        Ok((packets.iter().map(Bytes::len).max().unwrap(), chunk))
    };

    assert_eq!(1428, a.path_mtu());
    assert_eq!((1428, 1400), largest(&mut a, now)?);

    a.set_path_mtu(1200);
    assert_eq!(1200, a.path_mtu());
    assert_eq!(1188, a.pmdcs);
    assert_eq!((1200, 1172), largest(&mut a, now)?);

    a.set_path_mtu(9000);
    assert_eq!((9000, 8972), largest(&mut a, now)?);

    // Too small to carry a DATA chunk: raised to the smallest packet that does.
    a.set_path_mtu(0);
    assert_eq!(crate::MIN_DATA_PACKET_MTU, a.path_mtu());
    Ok(())
}

/// A message fragmented before a reduction keeps its fragments (RFC 9260 6.9: no
/// re-fragmentation): each goes alone in its packet.
#[test]
fn fragments_made_before_a_reduction_are_sent_as_they_are() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.cwnd = 0;
    a.rwnd = 1 << 20;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from(vec![1; 4000]), PPI)?;
    a.set_path_mtu(1000);
    a.cwnd = 1 << 20;
    let packets = a.gather_outbound(now).0;
    let sizes: Vec<usize> = transmitted_data(&packets)
        .iter()
        .map(|c| c.user_data.len())
        .collect();
    assert_eq!(vec![1400, 1400, 1200], sizes);
    assert_eq!(3, packets.len(), "one fragment to a packet");
    Ok(())
}
