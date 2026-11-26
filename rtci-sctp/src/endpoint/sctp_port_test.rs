//! RFC 8841 section 5: the SCTP ports are the two `a=sctp-port` values, not a fixed 5000.

use super::link_test::Link;
use super::*;
use crate::packet::Packet;

/// The initiating side sends its INIT from its own port to the peer's.
#[test]
fn init_goes_from_the_local_port_to_the_remote_port() {
    let mut endpoint = Endpoint::new(
        SocketAddr::from(([10, 0, 0, 1], 1)),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let config = TransportConfig::default()
        .with_sctp_port(5001)
        .with_remote_sctp_port(6000);
    let (_, mut conn) = endpoint
        .connect(
            Instant::now(),
            ClientConfig::new(config),
            SocketAddr::from(([10, 0, 0, 2], 2)),
        )
        .expect("connect");
    let transmit = conn
        .poll_transmit(Instant::now())
        .expect("the INIT is queued");
    let Payload::RawEncode(datagrams) = transmit.message else {
        panic!("an encoded INIT");
    };
    let init = Packet::unmarshal(&datagrams[0]).expect("a valid packet");
    assert_eq!(5001, init.common_header.source_port);
    assert_eq!(6000, init.common_header.destination_port);
}

/// The accepting side answers on the INIT's ports whatever its own configuration says, and the
/// association comes up.
#[test]
fn an_association_between_non_default_ports_connects() {
    let client = TransportConfig::default()
        .with_sctp_port(5001)
        .with_remote_sctp_port(6000);
    let server = TransportConfig::default().with_sctp_port(6000);
    let mut link = Link::new(client, server, 1);
    link.connect();
    let server_conn = link.server.conn();
    assert_eq!(6000, server_conn.source_port);
    assert_eq!(5001, server_conn.destination_port);
}

/// RFC 9260 3.1: "The Source Port Number 0 MUST NOT be used" and "The Destination Port Number
/// 0 MUST NOT be used". An association to be started from or to a configured port 0 is refused
/// before anything is sent (`ConnectError::ZeroSctpPort`). An accepting endpoint answers on the
/// INIT's ports (an INIT from or to port 0 is not answered: `a_packet_with_port_zero_is_not_answered`),
/// so its own configured port 0 never reaches the wire either.
#[test]
fn port_zero_is_never_put_on_the_wire() {
    let mut endpoint = Endpoint::new(
        SocketAddr::from(([10, 0, 0, 1], 1)),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    for (local, remote) in [(0u16, 5000u16), (5000, 0), (0, 0)] {
        let config = TransportConfig::default()
            .with_sctp_port(local)
            .with_remote_sctp_port(remote);
        let result = endpoint.connect(
            Instant::now(),
            ClientConfig::new(config),
            SocketAddr::from(([10, 0, 0, 2], 2)),
        );
        assert_eq!(
            Some(ConnectError::ZeroSctpPort),
            result.err(),
            "an association from port {local} to port {remote}"
        );
    }

    // The accepting side configured with port 0 sends from the port the INIT went to.
    let ports = std::rc::Rc::new(std::cell::RefCell::new(vec![]));
    let mut link = Link::new(
        TransportConfig::default(),
        TransportConfig::default()
            .with_sctp_port(0)
            .with_remote_sctp_port(0),
        2,
    );
    let seen = ports.clone();
    link.filter = Some(Box::new(move |_, datagram: &Bytes| {
        let packet = Packet::unmarshal(datagram).expect("a valid packet");
        seen.borrow_mut().push((
            packet.common_header.source_port,
            packet.common_header.destination_port,
        ));
        false
    }));
    link.connect();
    let ports = ports.borrow();
    assert!(ports.len() >= 4, "the handshake: {ports:?}");
    assert!(
        ports
            .iter()
            .all(|&(source, destination)| source == 5000 && destination == 5000),
        "{ports:?}"
    );
}
