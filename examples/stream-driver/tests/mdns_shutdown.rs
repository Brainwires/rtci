//! Leaving the link cleanly: a publishing `PeerDriver` withdraws its names when it ends
//! (RFC 6762 section 10.1: a goodbye, the record with TTL 0, so that the neighbours' caches
//! drop it at once rather than after its 120 s), through `PeerDriver::shutdown`, and as far as
//! it can without waiting when it is dropped. On virtual time, every platform.
#![cfg(feature = "runtime-mock")]

mod common;

use common::{Peer, Result, negotiate, run_until};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::{MDNS_PORT, MdnsRateLimit};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci_stream_driver::peer::PeerDriverConfig;
use rtci_stream_driver::runtime::mock::MockDatagram;
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const STEP: Duration = Duration::from_millis(10);

fn publishing() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
        .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
        .with_tcp_candidate_gathering(false)
}

/// The offset just past the DNS name at `at` (labels, or a compression pointer).
fn skip_name(data: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *data.get(at)?;
        if len == 0 {
            return Some(at + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        at += 1 + usize::from(len);
    }
}

/// Whether `data` is an mDNS response whose first answer has TTL 0: a goodbye.
fn is_goodbye(data: &[u8]) -> bool {
    let word = |at: usize| u16::from_be_bytes([data[at], data[at + 1]]);
    if data.len() < 12 || data[2] & 0x80 == 0 || word(6) == 0 {
        return false;
    }
    let mut at = 12;
    for _ in 0..word(4) {
        let Some(next) = skip_name(data, at) else {
            return false;
        };
        at = next + 4;
    }
    let Some(at) = skip_name(data, at) else {
        return false;
    };
    data.get(at + 4..at + 8) == Some(&[0, 0, 0, 0][..])
}

/// Two publishing drivers, connected; then the mock network's mDNS goodbyes are recorded by
/// sender.
/// The senders of the goodbyes seen on the mock network.
type Goodbyes = Arc<Mutex<Vec<IpAddr>>>;

fn connected_pair(runtime: &MockRuntime) -> Result<(Peer, Peer, Goodbyes)> {
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    // A budget of the test's own: the process's is shared with the other test of this binary,
    // whose virtual clock runs elsewhere.
    let config = |ip| PeerDriverConfig {
        mdns_rate_limit: Some(MdnsRateLimit::default()),
        ..PeerDriverConfig::on(vec![ip])
    };
    let mut a = Peer::with_config(shared.clone(), publishing(), config(A))?;
    let mut b = Peer::with_config(shared, publishing(), config(B))?;
    let up = runtime.run(async {
        negotiate(&mut a, &mut b)?;
        run_until(&mut a, &mut b, STEP, 2_000, |a, b| {
            a.connected() && b.connected()
        })
        .await
    })?;
    assert!(up, "connected");
    let goodbyes = Arc::new(Mutex::new(Vec::new()));
    let seen = goodbyes.clone();
    runtime
        .net()
        .set_filter(Box::new(move |d: &MockDatagram<'_>| {
            if d.to.port() == MDNS_PORT && is_goodbye(d.data) {
                seen.lock().unwrap().push(d.from.ip());
            }
            true
        }));
    Ok((a, b, goodbyes))
}

#[test]
fn shutdown_sends_the_goodbyes_of_the_published_names_and_closes_the_sockets() -> Result<()> {
    let runtime = MockRuntime::new();
    let (mut a, _b, goodbyes) = connected_pair(&runtime)?;
    runtime.run(a.driver.shutdown(Duration::from_secs(2)))?;
    assert!(
        goodbyes.lock().unwrap().contains(&A),
        "a's goodbye left from its address: {:?}",
        goodbyes.lock().unwrap()
    );
    assert!(!a.driver.mdns_available(false), "the mDNS socket is closed");
    assert!(
        a.driver.local_addresses().is_empty(),
        "the UDP sockets are closed"
    );
    Ok(())
}

#[test]
fn dropping_a_driver_sends_the_goodbyes_it_can_at_once() -> Result<()> {
    let runtime = MockRuntime::new();
    let (a, _b, goodbyes) = connected_pair(&runtime)?;
    drop(a);
    assert!(
        goodbyes.lock().unwrap().contains(&A),
        "a's goodbye left as it was dropped: {:?}",
        goodbyes.lock().unwrap()
    );
    Ok(())
}
