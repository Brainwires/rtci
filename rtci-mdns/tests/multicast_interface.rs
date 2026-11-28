//! `MulticastSocket::with_interface`: what the socket sends leaves by that interface (RFC 6762
//! section 14), not by the system's route for the group; and on Windows `MulticastSocket::new()`
//! without an interface joins and sends on the default route's interface. Real multicast: ignored by
//! default, run by `scripts/windows-poisoned-mdns-route.sh` on a Windows host whose route for
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

/// Sends a datagram of this process from `sender` to the mDNS group until `receiver` gets it, at
/// most 3 s, and returns the source it came from.
fn source_seen(sender: &std::net::UdpSocket, receiver: &std::net::UdpSocket) -> IpAddr {
    receiver.set_nonblocking(false).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let group = SocketAddr::from((MDNS_MULTICAST_IPV4, MDNS_PORT));
    let nonce = (std::process::id()
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default())
    .to_be_bytes();
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
    from.expect("the datagram came back to the receiver")
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
    let from = source_seen(&sender, &receiver);
    println!("### sent by {interface}, received from {from}");
    assert_eq!(
        from,
        IpAddr::V4(interface),
        "the datagram left by the system's route for the group, not by the socket's interface"
    );
}

/// On Windows a socket built without an interface sends by the default route's interface, not
/// by the group's route (on loopback on the host the script prepared). The receiver is joined on
/// the default route's interface, as a peer on the network is. Windows only: elsewhere `new()`
/// follows the group's route on purpose.
#[cfg(windows)]
#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn on_windows_a_socket_without_an_interface_sends_by_the_default_route() {
    let interface = default_route_v4();
    let sender: std::net::UdpSocket = MulticastSocket::new().into_std().unwrap();
    let receiver: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let from = source_seen(&sender, &receiver);
    println!("### new() sent, default route {interface}, received from {from}");
    assert_eq!(
        from,
        IpAddr::V4(interface),
        "MulticastSocket::new() sent by the system's route for the group, not by the default route"
    );
}

/// On Windows a socket built without an interface also listens on the default route's
/// interface: a datagram sent there (by a socket given that interface, as a peer on the network
/// sends) reaches it. On the host the script prepared a join on `INADDR_ANY` lands on loopback
/// and hears nothing from the network (agent-test run 46123619860: the interop probe, a `new()`
/// socket that sent by the network interface, never heard itself). Windows only, as above.
#[cfg(windows)]
#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn on_windows_a_socket_without_an_interface_hears_the_default_route() {
    let interface = default_route_v4();
    let sender: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let receiver: std::net::UdpSocket = MulticastSocket::new().into_std().unwrap();
    let from = source_seen(&sender, &receiver);
    println!("### new() received from {from}, default route {interface}");
    assert_eq!(from, IpAddr::V4(interface));
}
