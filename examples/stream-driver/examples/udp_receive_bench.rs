//! Receive throughput of the driver's UDP receive loop (`runtime::receive_datagrams`, what
//! `PeerDriver`'s sockets run), one datagram per receive against a batch per receive
//! (`recvmmsg` with `TokioRuntime` on Linux; elsewhere the socket takes one at a time either
//! way).
//!
//! `cargo run --release -p rtci-stream-driver --example udp_receive_bench`
//!
//! A sender thread writes `DATAGRAMS` datagrams of 1200 bytes over loopback as fast as it can;
//! the receiver hands each to a channel, as the driver does. Each line is one trial: what
//! arrived (loopback drops what the receiver's buffer cannot hold) and the receive rate between
//! the first and the last datagram. The median of the trials is printed last for each batch.

use rtci_stream_driver::runtime::{self, Runtime, TokioRuntime};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const DATAGRAMS: usize = 200_000;
const SIZE: usize = 1200;
const TRIALS: usize = 5;

/// One trial: (received, receive rate in datagrams per second).
async fn trial(runtime: Arc<dyn Runtime>, batch: usize) -> (usize, f64) {
    let socket = runtime
        .bind_udp("127.0.0.1:0".parse().unwrap())
        .expect("a receiving socket");
    let to: SocketAddr = socket.local_addr().unwrap();
    let (tx, rx) = async_channel::unbounded::<(SocketAddr, Vec<u8>)>();
    let done = Arc::new(AtomicBool::new(false));
    let consumer = {
        let done = done.clone();
        runtime.spawn(Box::pin(async move {
            while let Ok((_, data)) = rx.recv().await {
                std::hint::black_box(data);
                if done.load(Ordering::Relaxed) && rx.is_empty() {
                    return;
                }
            }
        }))
    };
    let first: Arc<std::sync::Mutex<Option<Instant>>> = Arc::default();
    let last: Arc<std::sync::Mutex<Option<Instant>>> = Arc::default();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let receiver = {
        let (first, last, count) = (first.clone(), last.clone(), count.clone());
        let socket = socket.clone();
        runtime.spawn(Box::pin(async move {
            runtime::receive_datagrams(socket.as_ref(), 2048, batch, |from, data| {
                let now = Instant::now();
                first.lock().unwrap().get_or_insert(now);
                *last.lock().unwrap() = Some(now);
                count.fetch_add(1, Ordering::Relaxed);
                tx.try_send((from, data.to_vec())).is_ok()
            })
            .await;
        }))
    };
    let sender = std::thread::spawn(move || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = [7u8; SIZE];
        for _ in 0..DATAGRAMS {
            let _ = socket.send_to(&payload, to);
        }
    });
    let _ = sender.join();
    // Whatever was going to arrive has arrived once the count stops moving.
    let mut seen = usize::MAX;
    loop {
        runtime::sleep(runtime.as_ref(), Duration::from_millis(200)).await;
        let now = count.load(Ordering::Relaxed);
        if now == seen {
            break;
        }
        seen = now;
    }
    receiver.abort();
    done.store(true, Ordering::Relaxed);
    consumer.abort();
    let received = count.load(Ordering::Relaxed);
    let span = match (*first.lock().unwrap(), *last.lock().unwrap()) {
        (Some(a), Some(b)) if b > a => b - a,
        _ => Duration::from_nanos(1),
    };
    (received, received as f64 / span.as_secs_f64())
}

fn main() {
    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a tokio runtime");
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime::with_handle(tokio.handle().clone()));
    let socket = runtime.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    println!(
        "{} datagrams of {} bytes per trial, {} trials; the socket takes up to {} per receive",
        DATAGRAMS,
        SIZE,
        TRIALS,
        socket.max_receive_batch()
    );
    drop(socket);
    for batch in [1, 32] {
        let mut rates = Vec::new();
        for n in 0..TRIALS {
            let (received, rate) = tokio.block_on(trial(runtime.clone(), batch));
            println!(
                "batch {batch:>2} trial {n}: received {received:>6} of {DATAGRAMS}, {:>9.0} datagrams/s ({:.1} MB/s)",
                rate,
                rate * SIZE as f64 / 1e6
            );
            rates.push(rate);
        }
        rates.sort_by(f64::total_cmp);
        println!(
            "batch {batch:>2} median: {:.0} datagrams/s ({:.1} MB/s)",
            rates[TRIALS / 2],
            rates[TRIALS / 2] * SIZE as f64 / 1e6
        );
    }
}
