//! The process-wide mDNS budget and drivers on a virtual clock (a binary of its own: it
//! empties the process's budget). The budget is keyed on the wall clock; a mock clock's times
//! are elsewhere, so a driver on one takes from a budget of its own: here the process budget
//! is used up as late as an hour from now, so it cannot refill before then on any clock that
//! reads now, and two publishing drivers on a mock runtime still resolve each other and
//! connect. (Sharing it, they sent no mDNS at all.)
#![cfg(feature = "runtime-mock")]

mod common;

use common::{Peer, Result, negotiate, run_until};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::MdnsRateLimit;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci_stream_driver::peer::{process_mdns_rate_limit, set_process_mdns_rate_limit};
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn drivers_on_a_virtual_clock_do_not_share_the_process_mdns_budget() -> Result<()> {
    // Once used, the process budget can no longer be replaced.
    let late = Instant::now() + Duration::from_secs(3600);
    let budget = process_mdns_rate_limit();
    while budget.take(late) {}
    assert!(
        set_process_mdns_rate_limit(MdnsRateLimit::new(1, 1)).is_err(),
        "set once, before first use"
    );

    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let settings = || {
        SettingEngineBuilder::new()
            .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
            .with_tcp_candidate_gathering(false)
    };
    let mut a = Peer::with_settings(
        shared.clone(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        settings(),
    )?;
    let mut b = Peer::with_settings(shared, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), settings())?;
    let up = runtime.run(async {
        negotiate(&mut a, &mut b)?;
        run_until(&mut a, &mut b, Duration::from_millis(10), 2_000, |a, b| {
            a.connected() && b.connected()
        })
        .await
    })?;
    assert!(
        up && a.driver.mdns_datagrams_sent() > 0,
        "connected over mDNS on their own budgets: a sent {}, {:?}",
        a.driver.mdns_datagrams_sent(),
        a.driver.pc().connection_state()
    );
    Ok(())
}
