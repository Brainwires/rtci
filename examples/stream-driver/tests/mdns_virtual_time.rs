//! `PeerDriver`'s mDNS on virtual time: two drivers whose connections publish their host
//! addresses behind `.local` names (draft-ietf-mmusic-mdns-ice-candidates section 3.1), on one
//! `MockRuntime`'s in-memory network. Their mDNS sockets meet on the mock network's multicast
//! group, so the whole path (the driver's mDNS sockets, its socket bookkeeping for `.local`
//! candidates, the engine's resolver) runs on every platform without a multicast route and
//! without a privacy prompt. The real-multicast tests are `tests/mdns.rs`.
#![cfg(feature = "runtime-mock")]

mod common;

use common::{Peer, Result, negotiate, run_until};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::MDNS_PORT;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// The longest a driver waits in one step.
const STEP: Duration = Duration::from_millis(10);

/// `QueryAndGather` over UDP only: an ICE-TCP pair would connect without the UDP sockets whose
/// bookkeeping this test is about (0.1.0 closed every UDP socket of a `.local` candidate when
/// the signalling state returned to stable, and a TCP pair hid it).
fn publishing() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
        .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
        .with_tcp_candidate_gathering(false)
}

/// Both connections offer only `.local` names; each driver's mDNS socket carries the other's
/// queries and answers, the names resolve, and the connections connect over UDP on the sockets
/// the drivers keep for their `.local` candidates.
#[test]
fn two_publishing_drivers_resolve_each_other_and_connect_on_virtual_time() -> Result<()> {
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(shared.clone(), A, publishing())?;
    let mut b = Peer::with_settings(shared, B, publishing())?;
    let mut up = false;
    runtime.run(async {
        negotiate(&mut a, &mut b)?;
        up = run_until(&mut a, &mut b, STEP, 2_000, |a, b| {
            a.connected() && b.connected()
        })
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let mdns: Vec<_> = runtime
        .net()
        .log()
        .into_iter()
        .filter(|d| d.to.port() == MDNS_PORT)
        .collect();
    let state = |p: &Peer| {
        format!(
            "{:?}, mDNS sent {} received {}, unsent {}",
            p.driver.pc().connection_state(),
            p.driver.mdns_datagrams_sent(),
            p.driver.mdns_datagrams_received(),
            p.driver.unsent_datagrams()
        )
    };
    assert!(
        up,
        "connected over the resolved .local candidates: a {} / b {}",
        state(&a),
        state(&b)
    );
    assert!(
        mdns.iter().any(|d| d.from.ip() == A) && mdns.iter().any(|d| d.from.ip() == B),
        "each driver's mDNS answers left from the address of their record: {mdns:?}"
    );
    assert_eq!(
        (
            a.driver.local_addresses().len(),
            b.driver.local_addresses().len()
        ),
        (1, 1),
        "each driver still holds the UDP socket of its .local candidate"
    );
    Ok(())
}
