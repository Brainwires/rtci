//! The driver's server-side socket choices on real sockets: port ranges, the local address
//! list, and a passive ICE-TCP port shared by several engines.

use rtci_stream_driver::sockets::{
    AddressFilter, PortRange, accept_by_ufrag, bind_tcp_listener_in_range, bind_udp_in_range,
};
use rtci_stream_driver::{DriverConfig, DriverInput, StreamDriver, sockets};
use shared::stream::{Framing, StreamCommand, StreamEvent, StreamTable};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn binding_request(username: &str) -> Vec<u8> {
    let mut attrs = vec![];
    attrs.extend_from_slice(&0x0006u16.to_be_bytes());
    attrs.extend_from_slice(&(username.len() as u16).to_be_bytes());
    attrs.extend_from_slice(username.as_bytes());
    while attrs.len() % 4 != 0 {
        attrs.push(0);
    }
    let mut m = vec![0x00, 0x01];
    m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    m.extend_from_slice(&[3; 12]);
    m.extend(attrs);
    m
}

/// The first port of `n` consecutive ports on 127.0.0.1 this host lets the test bind (`bind`
/// succeeds on each, all held at once), released for the test to use. An ephemeral port says
/// nothing about its neighbours: Windows hands ephemeral ports out in sequence, right up to
/// the start of an excluded port range (Hyper-V, WinNAT: `netsh interface ipv4 show
/// excludedportrange`), whose ports then refuse a bind with WSAEACCES. Bounded: 200 tries
/// spread over 20000..60000.
fn bindable_block<S>(n: u16, bind: impl Fn(u16) -> std::io::Result<S>) -> u16 {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let seed = probe.local_addr().unwrap().port();
    for attempt in 0..200u32 {
        let base = 20000 + ((u32::from(seed) + attempt * 997) % 40000) as u16;
        let held: Result<Vec<S>, _> = (base..base + n).map(&bind).collect();
        if held.is_ok() {
            return base;
        }
    }
    panic!("no {n} consecutive bindable ports found in 200 tries");
}

#[test]
fn sockets_bind_inside_their_port_range_until_it_is_full() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let base = bindable_block(4, |port| std::net::UdpSocket::bind((lo, port)));
    let range = PortRange::new(base, base + 3).unwrap();
    let mut held = vec![];
    while let Ok(socket) = bind_udp_in_range(lo, range) {
        let port = socket.local_addr().unwrap().port();
        assert!(
            (range.min..=range.max).contains(&port),
            "port {port} outside the range"
        );
        held.push(socket);
        assert!(held.len() <= 4);
    }
    assert!(!held.is_empty());
    let err = bind_udp_in_range(lo, range).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

#[tokio::test]
async fn listeners_bind_inside_the_range_the_driver_is_given() {
    let base = bindable_block(21, |port| std::net::TcpListener::bind(("127.0.0.1", port)));
    let range = PortRange::new(base, base + 20).unwrap();
    let listener = bind_tcp_listener_in_range("127.0.0.1".parse().unwrap(), range, false).unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!((range.min..=range.max).contains(&port));
    drop(listener);

    let mut driver = StreamDriver::new(DriverConfig {
        tcp_port_range: Some(range),
        ..Default::default()
    });
    let mut table = StreamTable::default();
    let id = table.listen("127.0.0.1:0".parse().unwrap(), Framing::Rfc4571, 0, false);
    while let Some(c) = table.poll_command() {
        driver.execute(c);
    }
    match driver.next().await {
        DriverInput::Event(StreamEvent::Listening { listener, local }) => {
            assert_eq!(listener, id);
            assert!((range.min..=range.max).contains(&local.port()), "{local}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_local_address_list_has_loopback_only_when_asked() {
    let without = AddressFilter::default().local_addresses().unwrap();
    assert!(without.iter().all(|ip| !ip.is_loopback()), "{without:?}");
    let with = AddressFilter {
        include_loopback: true,
        ..Default::default()
    }
    .local_addresses()
    .unwrap();
    assert!(with.iter().any(|ip| ip.is_loopback()), "{with:?}");
}

#[tokio::test]
async fn a_shared_passive_port_hands_each_connection_to_the_engine_its_first_check_names() {
    let shared = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let shared_addr = shared.local_addr().unwrap();

    // The engine's passive listener is answered with the shared address, and nothing binds.
    let mut driver = StreamDriver::new(DriverConfig {
        shared_passive: Some(shared_addr),
        ..Default::default()
    });
    let mut table = StreamTable::default();
    let listener = table.listen("127.0.0.1:0".parse().unwrap(), Framing::Rfc4571, 0, false);
    while let Some(c) = table.poll_command() {
        assert!(matches!(c, StreamCommand::Listen { .. }));
        driver.execute(c);
    }
    match driver.next().await {
        DriverInput::Event(e) => {
            assert_eq!(
                e,
                StreamEvent::Listening {
                    listener,
                    local: shared_addr
                }
            );
            table.handle_event(e).unwrap();
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(driver.shared_listener(), Some(listener));
    assert_eq!(driver.sockets().1, 0, "no socket of its own");

    // A peer's check arrives in three pieces, with the next frame behind it.
    let request = binding_request("ours:theirs");
    let mut wire = Framing::Rfc4571.encode(&request).unwrap();
    wire.extend(Framing::Rfc4571.encode(b"\x17next").unwrap());
    let client = tokio::spawn(async move {
        let mut s = tokio::net::TcpStream::connect(shared_addr).await.unwrap();
        for piece in wire.chunks(9) {
            s.write_all(piece).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let accepted = accept_by_ufrag(&shared, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(accepted.ufrag, "ours");
    let id = table
        .accept(listener, accepted.local, accepted.remote)
        .unwrap();
    driver.adopt_shared(id, accepted);
    let mut messages = vec![];
    while messages.len() < 2 {
        match tokio::time::timeout(Duration::from_secs(5), driver.next())
            .await
            .unwrap()
        {
            DriverInput::Read { id: got, data } => {
                assert_eq!(got, id);
                messages.extend(table.read(id, &data).unwrap());
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        messages,
        vec![request, b"\x17next".to_vec()],
        "nothing lost in the routing"
    );
    client.await.unwrap();
}

/// The ranges of `netsh interface ipv4 show excludedportrange protocol=udp`.
#[cfg(windows)]
fn excluded_udp_ranges() -> Vec<(u16, u16)> {
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "show",
            "excludedportrange",
            "protocol=udp",
        ])
        .output()
        .expect("netsh");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut ports = line.split_whitespace().map(str::parse::<u16>);
            match (ports.next(), ports.next()) {
                (Some(Ok(a)), Some(Ok(b))) => Some((a, b)),
                _ => None,
            }
        })
        .collect()
}

/// Windows: a range that reaches into an excluded port range binds its ports outside it,
/// every time, whatever port the rotation starts at; the excluded ports refuse a bind with
/// WSAEACCES (10013), which is not "range full". Runs where the host has an excluded UDP range
/// with a bindable port just below it (GitHub's windows runners do).
#[cfg(windows)]
#[test]
fn on_windows_a_range_reaching_into_an_excluded_range_uses_its_other_ports() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let ranges = excluded_udp_ranges();
    println!("excluded UDP ranges: {ranges:?}");
    let Some(&(start, _)) = ranges.iter().find(|(start, end)| {
        *start > 1025
            && *end >= start + 2
            && !ranges.iter().any(|(a, b)| (*a..=*b).contains(&(start - 1)))
            && std::net::UdpSocket::bind((lo, start - 1)).is_ok()
    }) else {
        println!("no excluded UDP range with a free port below it: nothing to check");
        return;
    };
    let refused = std::net::UdpSocket::bind((lo, start)).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(10013), "{refused:?}");
    // One usable port, then three excluded ones.
    let range = PortRange::new(start - 1, start + 2).unwrap();
    for _ in 0..8 {
        let socket = bind_udp_in_range(lo, range).unwrap();
        assert_eq!(socket.local_addr().unwrap().port(), start - 1);
        let full = bind_udp_in_range(lo, range).unwrap_err();
        assert_eq!(full.kind(), std::io::ErrorKind::AddrInUse, "{full:?}");
    }
}

/// `sockets::set_traffic_class` sets the TOS / Traffic Class byte the operating system then
/// reports (`getsockopt` of `IP_TOS`, `IPV6_TCLASS`): EF (46) with ECT(0) is 186. Printed on
/// every platform (`--nocapture`: what Windows answers is recorded, not asserted, since it
/// ignores `IP_TOS`); asserted where the platform marks.
#[test]
fn a_udp_socket_reports_the_traffic_class_it_was_given() {
    let tos = (46u8 << 2) | 0b10;
    for (address, ipv6) in [("127.0.0.1:0", false), ("[::1]:0", true)] {
        let Ok(socket) = std::net::UdpSocket::bind(address) else {
            println!("{address}: no socket of this family here");
            continue;
        };
        let set = sockets::set_traffic_class(socket2::SockRef::from(&socket), ipv6, tos);
        let read = sockets::traffic_class(socket2::SockRef::from(&socket), ipv6);
        println!("{address}: set {set:?}, read back {read:?}");
        #[cfg(not(windows))]
        {
            assert!(set.is_ok(), "{address}: {set:?}");
            assert_eq!(read.ok(), Some(u32::from(tos)), "{address}");
        }
    }
}
