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
