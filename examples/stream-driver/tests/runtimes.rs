//! Built-in runtimes side by side: a `PeerDriver` on tokio and one on smol, in one process,
//! connect and carry data-channel messages. Each runtime owns its driver's sockets, tasks and
//! timers; nothing is shared between them but the loopback network.

mod common;

use common::{Peer, Result, connect_and_exchange};
use rtci_stream_driver::runtime::{Runtime, SmolRuntime, TokioRuntime};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn a_peer_on_tokio_and_a_peer_on_smol_connect_and_exchange_messages() -> Result<()> {
    // Tokio's reactor and timers run on its own worker thread; the test's loop is smol's.
    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let on_tokio: Arc<dyn Runtime> = Arc::new(TokioRuntime::with_handle(tokio.handle().clone()));
    let on_smol: Arc<dyn Runtime> = Arc::new(SmolRuntime::new());
    let mut a = Peer::new(on_tokio, LOOPBACK)?;
    let mut b = Peer::new(on_smol.clone(), LOOPBACK)?;
    let mut outcome = None;
    on_smol.block_on(Box::pin(async {
        outcome =
            Some(connect_and_exchange(&mut a, &mut b, Duration::from_millis(2), 10_000).await);
    }));
    outcome.ok_or("block_on ran the future")??;
    assert!(a.connected() && b.connected());
    Ok(())
}

#[test]
fn two_peers_on_smol_alone_connect_and_exchange_messages() -> Result<()> {
    let runtime: Arc<dyn Runtime> = Arc::new(SmolRuntime::new());
    let mut a = Peer::new(runtime.clone(), LOOPBACK)?;
    let mut b = Peer::new(runtime.clone(), LOOPBACK)?;
    let mut outcome = None;
    runtime.block_on(Box::pin(async {
        outcome =
            Some(connect_and_exchange(&mut a, &mut b, Duration::from_millis(2), 10_000).await);
    }));
    outcome.ok_or("block_on ran the future")??;
    Ok(())
}
