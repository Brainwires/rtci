//! The driver against two `StreamTable`s over real loopback sockets: one listens, the other
//! connects; framed messages cross both ways whatever segmentation the kernel applies, the
//! write window is honoured, and a close and a reset reach the other side.

use rtc_stream_driver::{DriverInput, StreamDriver};
use shared::stream::{Framing, StreamCommand, StreamConfig, StreamNotice, StreamTable};
use std::time::Duration;

/// One engine half: a table and the driver that owns its sockets.
struct Side {
    table: StreamTable,
    driver: StreamDriver,
    received: Vec<Vec<u8>>,
    notices: Vec<StreamNotice>,
}

impl Side {
    fn new(config: StreamConfig) -> Self {
        Self {
            table: StreamTable::new(config),
            driver: StreamDriver::default(),
            received: Vec::new(),
            notices: Vec::new(),
        }
    }

    /// Hands the table's commands and transmits to the driver.
    fn pump(&mut self) {
        loop {
            let mut progress = false;
            while let Some(command) = self.table.poll_command() {
                self.driver.execute(command);
                progress = true;
            }
            while let Some(transmit) = self.table.poll_transmit() {
                assert!(
                    transmit.data.len() <= self.table.config().window.max(70_000),
                    "a transmit beyond the window"
                );
                self.driver.write(transmit);
                progress = true;
            }
            if !progress {
                break;
            }
        }
        while let Some(notice) = self.table.poll_notice() {
            self.notices.push(notice);
        }
    }

    /// Takes what the driver has, for up to `wait`.
    async fn step(&mut self, wait: Duration) {
        self.pump();
        let input = match tokio::time::timeout(wait, self.driver.next()).await {
            Ok(input) => input,
            Err(_) => return,
        };
        self.deliver(input);
        while let Some(input) = self.driver.try_next() {
            self.deliver(input);
        }
        self.pump();
    }

    fn deliver(&mut self, input: DriverInput) {
        match input {
            DriverInput::Event(event) => self.table.handle_event(event).unwrap(),
            DriverInput::Read { id, data } => {
                if let Ok(messages) = self.table.read(id, &data) {
                    self.received.extend(messages);
                }
            }
            DriverInput::Accepted(accepted) => {
                if let Some(id) =
                    self.table
                        .accept(accepted.listener, accepted.local, accepted.remote)
                {
                    self.driver.adopt(id, accepted);
                }
            }
        }
    }
}

fn messages(seed: u8) -> Vec<Vec<u8>> {
    let mut out = vec![vec![], vec![seed; 65535]];
    for i in 0..300usize {
        out.push(vec![seed ^ i as u8; 1 + (i * 37) % 4000]);
    }
    out
}

#[tokio::test]
async fn framed_messages_cross_real_sockets_both_ways_and_the_connection_closes() {
    let config = StreamConfig {
        window: 16 * 1024,
        max_queued: 64 * 1024 * 1024,
        ..StreamConfig::default()
    };
    let mut server = Side::new(config);
    let mut client = Side::new(config);
    let listener = server
        .table
        .listen("127.0.0.1:0".parse().unwrap(), Framing::Rfc4571, 1, false);
    server.pump();
    let mut bound = None;
    for _ in 0..100 {
        server.step(Duration::from_millis(20)).await;
        bound = server.table.listener_address(listener);
        if bound.is_some() {
            break;
        }
    }
    let bound = bound.expect("the listener is bound");

    let id = client
        .table
        .connect(
            "127.0.0.1:0".parse().unwrap(),
            bound,
            Framing::Rfc4571,
            2,
            false,
            None,
        )
        .unwrap();
    let to_server = messages(1);
    for m in &to_server {
        assert!(client.table.send(id, m).unwrap(), "queued");
    }
    let to_client = messages(2);
    let mut answered = false;
    for _ in 0..2000 {
        client.step(Duration::from_millis(5)).await;
        server.step(Duration::from_millis(5)).await;
        let first = server.table.connections().next().map(|c| c.id);
        if !answered && let Some(accepted) = first {
            for m in &to_client {
                assert!(server.table.send(accepted, m).unwrap());
            }
            answered = true;
        }
        if server.received.len() == to_server.len() && client.received.len() == to_client.len() {
            break;
        }
    }
    assert_eq!(server.received, to_server, "client to server, in order");
    assert_eq!(client.received, to_client, "server to client, in order");
    assert!(
        client
            .notices
            .iter()
            .any(|n| matches!(n, StreamNotice::Connected { id: c, .. } if *c == id))
    );

    // A close from the client reaches the server as the end of the stream.
    client.table.close(id);
    for _ in 0..400 {
        client.step(Duration::from_millis(5)).await;
        server.step(Duration::from_millis(5)).await;
        if server
            .notices
            .iter()
            .any(|n| matches!(n, StreamNotice::Closed { reset: false, .. }))
        {
            break;
        }
    }
    assert!(
        server
            .notices
            .iter()
            .any(|n| matches!(n, StreamNotice::Closed { reset: false, .. })),
        "the server saw the close: {:?}",
        server.notices
    );
}

#[tokio::test]
async fn a_connection_to_a_closed_port_fails_and_a_reset_reaches_the_peer() {
    let mut client = Side::new(StreamConfig::default());
    // A port held bound for the whole connect, never listening: a SYN to it is refused (RST)
    // on Linux, macOS and Windows alike, and while it is bound no other socket on 127.0.0.1
    // can be given it, so the client cannot pick it as its own source port and connect to
    // itself (a port found free and closed again could be: seen on Linux).
    let held = tokio::net::TcpSocket::new_v4().unwrap();
    held.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let closed = held.local_addr().unwrap();
    let failed = client
        .table
        .connect(
            "127.0.0.1:0".parse().unwrap(),
            closed,
            Framing::Rfc4571,
            0,
            false,
            None,
        )
        .unwrap();
    for _ in 0..200 {
        client.step(Duration::from_millis(10)).await;
        if !client.notices.is_empty() {
            break;
        }
    }
    assert!(
        matches!(
            client.notices.first(),
            Some(StreamNotice::ConnectFailed { id, .. }) if *id == failed
        ),
        "{:?}",
        client.notices
    );
    drop(held);

    // A reset from one side is a reset on the other.
    let mut server = Side::new(StreamConfig::default());
    let listener = server
        .table
        .listen("127.0.0.1:0".parse().unwrap(), Framing::Rfc4571, 0, false);
    let mut bound = None;
    for _ in 0..100 {
        server.step(Duration::from_millis(10)).await;
        bound = server.table.listener_address(listener);
        if bound.is_some() {
            break;
        }
    }
    let id = client
        .table
        .connect(
            "127.0.0.1:0".parse().unwrap(),
            bound.unwrap(),
            Framing::Rfc4571,
            0,
            false,
            None,
        )
        .unwrap();
    client.table.send(id, b"before the reset").unwrap();
    for _ in 0..400 {
        client.step(Duration::from_millis(5)).await;
        server.step(Duration::from_millis(5)).await;
        if !server.received.is_empty() {
            break;
        }
    }
    assert_eq!(server.received, vec![b"before the reset".to_vec()]);
    client.table.reset(id);
    assert_eq!(
        client.table.poll_command(),
        Some(StreamCommand::Reset { id })
    );
    client.driver.execute(StreamCommand::Reset { id });
    for _ in 0..400 {
        server.step(Duration::from_millis(5)).await;
        if server
            .notices
            .iter()
            .any(|n| matches!(n, StreamNotice::Closed { .. }))
        {
            break;
        }
    }
    assert!(
        server
            .notices
            .iter()
            .any(|n| matches!(n, StreamNotice::Closed { reset: true, .. })),
        "the server saw a reset: {:?}",
        server.notices
    );
}

/// A socket connected to itself is not a connection: a connect from 127.0.0.1:P to 127.0.0.1:P
/// (simultaneous open with itself, RFC 9293 section 3.5: what Linux does when nothing listens
/// on P) is reported as `ConnectFailed`, as the refusal other systems give is.
#[tokio::test]
async fn a_socket_connected_to_itself_is_a_failed_connection() {
    let mut client = Side::new(StreamConfig::default());
    for _ in 0..5 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        client.notices.clear();
        let id = client
            .table
            .connect(addr, addr, Framing::Rfc4571, 0, false, None)
            .unwrap();
        for _ in 0..400 {
            client.step(Duration::from_millis(10)).await;
            if !client.notices.is_empty() {
                break;
            }
        }
        assert!(
            matches!(
                client.notices.first(),
                Some(StreamNotice::ConnectFailed { id: failed, .. }) if *failed == id
            ),
            "{addr}: {:?}",
            client.notices
        );
    }
}
