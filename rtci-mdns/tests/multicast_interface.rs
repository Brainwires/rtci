//! `MulticastSocket::with_interface`: what the socket sends leaves by that interface (RFC 6762
//! section 14), not by the system's route for the group. Real multicast: ignored by default,
//! run by `scripts/windows-poisoned-mdns-route.sh` on a Windows host whose route for
//! 224.0.0.251 has been left on loopback (the destination-cache entry a process that sent to
//! the group from 127.0.0.1 leaves behind), where a socket that followed the route sent with
//! source 127.0.0.1.

use rtci_mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, MulticastSocket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The default route's address (a socket connected to a documentation address sends nothing).
fn default_route_v4() -> Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    match socket.local_addr().unwrap().ip() {
        IpAddr::V4(ip) => ip,
        other => panic!("no IPv4 default route: {other}"),
    }
}

#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn a_socket_given_an_interface_sends_from_it_whatever_the_group_route() {
    let interface = default_route_v4();
    let sender: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let receiver: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    receiver.set_nonblocking(false).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let group = SocketAddr::from((MDNS_MULTICAST_IPV4, MDNS_PORT));
    let nonce = std::process::id().to_be_bytes();
    let message = [nonce[2], nonce[3], 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut buf = [0u8; 1500];
    let until = Instant::now() + Duration::from_secs(3);
    let mut from = None;
    while Instant::now() < until && from.is_none() {
        sender.send_to(&message, group).unwrap();
        while let Ok((n, source)) = receiver.recv_from(&mut buf) {
            if buf[..n] == message {
                from = Some(source.ip());
                break;
            }
        }
    }
    let from = from.expect("the datagram came back to the receiver");
    println!("### sent by {interface}, received from {from}");
    assert_eq!(
        from,
        IpAddr::V4(interface),
        "the datagram left by the system's route for the group, not by the socket's interface"
    );
}
