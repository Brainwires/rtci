//! The driver's UDP receive loop (`runtime::receive_datagrams`) over a real socket: with a
//! batch per receive (`recvmmsg` with `TokioRuntime` on Linux) every datagram is handed over
//! once, in order, with its sender and its bytes.

use rtci_stream_driver::runtime::{self, Runtime, TokioRuntime};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn a_batched_receive_hands_over_every_datagram_with_its_sender_in_order() {
    let runtime = TokioRuntime::new();
    let socket = runtime.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!(socket.max_receive_batch(), 32, "recvmmsg on Linux");
    }
    let to = socket.local_addr().unwrap();
    let senders: Vec<std::net::UdpSocket> = (0..2)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    // Queued before the first receive, so that receives find many waiting.
    let mut expected: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    for i in 0..100u16 {
        let sender = &senders[usize::from(i % 2)];
        let data: Vec<u8> = i.to_be_bytes().repeat(usize::from(i % 7) + 1);
        sender.send_to(&data, to).unwrap();
        expected.push((sender.local_addr().unwrap(), data));
    }
    let mut got: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let receive = runtime::receive_datagrams(socket.as_ref(), 2048, 32, |from, data| {
        got.push((from, data.to_vec()));
        got.len() < expected.len()
    });
    runtime::timeout(&runtime, Duration::from_secs(10), receive)
        .await
        .expect("every datagram within 10 s");
    assert_eq!(got, expected);
}
