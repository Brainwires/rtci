//! The driver's server-side socket choices on real sockets: port ranges, the local address
//! list, and a passive ICE-TCP port shared by several engines.

use rtc_stream_driver::sockets::{
    AddressFilter, PortRange, accept_by_ufrag, bind_tcp_listener_in_range, bind_udp_in_range,
};
use rtc_stream_driver::{DriverConfig, DriverInput, StreamDriver};
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

#[test]
fn sockets_bind_inside_their_port_range_until_it_is_full() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    // A range nothing else on the host is likely to use, found free first.
    let base = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port().clamp(20000, 60000)
    };
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
    let base = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port().clamp(20000, 60000)
    };
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
