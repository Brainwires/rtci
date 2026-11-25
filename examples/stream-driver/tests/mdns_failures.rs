//! `PeerDriver` where mDNS cannot be sent: the sockets bind but the system refuses every send
//! to the group, as on GitHub's macOS image (no multicast route) or in a Mac application
//! before the Local Network permission is granted. On virtual time, the mock network refusing
//! the sends (`MockNet::set_send_error`), so it runs on every platform.
#![cfg(feature = "runtime-mock")]

mod common;

use common::{Peer, Result, negotiate, run_until};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::MDNS_MULTICAST_IPV4;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::transport::RTCIceCandidateType;
use rtci_stream_driver::peer::{MDNS_MULTICAST_IPV6, MdnsStage, PeerDriverEvent};
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const STEP: Duration = Duration::from_millis(10);

fn settings(mode: MulticastDnsMode) -> SettingEngineBuilder {
    SettingEngineBuilder::new()
        .with_multicast_dns_mode(mode)
        .with_tcp_candidate_gathering(false)
}

/// Both groups refuse every send with "no route to host", or let them through again.
fn refuse_mdns(runtime: &MockRuntime, refuse: bool) {
    let error = refuse.then_some(io::ErrorKind::HostUnreachable);
    runtime
        .net()
        .set_send_error(IpAddr::V4(MDNS_MULTICAST_IPV4), error);
    runtime
        .net()
        .set_send_error(IpAddr::V6(MDNS_MULTICAST_IPV6), error);
}

/// Every driver event the peer's application saw so far.
fn driver_events(peer: &mut Peer) -> Vec<PeerDriverEvent> {
    std::iter::from_fn(|| peer.driver.poll_driver_event()).collect()
}

fn ipv4_unavailable(events: &[PeerDriverEvent]) -> bool {
    events.iter().any(|e| {
        matches!(e, PeerDriverEvent::MdnsUnavailable(f)
            if !f.ipv6 && f.stage == MdnsStage::Send && f.kind == io::ErrorKind::HostUnreachable)
    })
}

/// The publishing side's mDNS sends are all refused: its application is told (an event with
/// the system's error, the failures counted), the family is no longer reported available,
/// and the connection still connects over what remains (the peer's literal host candidate:
/// the publisher's checks reach it, and the peer learns the publisher peer-reflexively).
#[test]
fn refused_mdns_sends_are_reported_and_the_connection_goes_on_over_other_candidates() -> Result<()>
{
    let runtime = MockRuntime::new();
    refuse_mdns(&runtime, true);
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(
        shared.clone(),
        A,
        settings(MulticastDnsMode::QueryAndGather),
    )?;
    let mut b = Peer::with_settings(shared, B, settings(MulticastDnsMode::Disabled))?;
    let up = runtime.run(async {
        negotiate(&mut a, &mut b)?;
        run_until(&mut a, &mut b, STEP, 2_000, |a, b| {
            a.connected() && b.connected()
        })
        .await
    })?;
    let events = driver_events(&mut a);
    assert!(
        ipv4_unavailable(&events),
        "the application was told: {events:?}"
    );
    assert!(a.driver.mdns_send_failures() > 0);
    assert_eq!(a.driver.mdns_datagrams_sent(), 0);
    assert!(!a.driver.mdns_available(false));
    assert!(
        up,
        "connected over the remaining candidates: a {:?} b {:?}",
        a.driver.pc().connection_state(),
        b.driver.pc().connection_state()
    );
    Ok(())
}

/// Both sides publish and every mDNS send is refused at first: each application is told at
/// once (nothing sits silently in Connecting). When the sends go through again, the driver
/// tries after its back-off, says mDNS works again, and the names resolve: they connect over
/// the resolved `.local` candidates (RFC 6762 queries are retried for 30 s).
#[test]
fn refused_mdns_is_reported_on_both_sides_and_tried_again_once_it_works() -> Result<()> {
    let runtime = MockRuntime::new();
    refuse_mdns(&runtime, true);
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(
        shared.clone(),
        A,
        settings(MulticastDnsMode::QueryAndGather),
    )?;
    let mut b = Peer::with_settings(shared, B, settings(MulticastDnsMode::QueryAndGather))?;
    let start = runtime.now();
    let (told, up) = runtime.run(async {
        negotiate(&mut a, &mut b)?;
        // Two seconds of refused sends.
        run_until(&mut a, &mut b, STEP, 2_000, |a, _| {
            a.now() >= start + Duration::from_secs(2)
        })
        .await?;
        let told = (driver_events(&mut a), driver_events(&mut b));
        refuse_mdns(&runtime, false);
        let up = run_until(&mut a, &mut b, STEP, 5_000, |a, b| {
            a.connected()
                && b.connected()
                && a.selected_remote_type() == Some(RTCIceCandidateType::Host)
                && b.selected_remote_type() == Some(RTCIceCandidateType::Host)
        })
        .await?;
        Ok::<_, Box<dyn std::error::Error>>((told, up))
    })?;
    assert!(ipv4_unavailable(&told.0), "a was told: {:?}", told.0);
    assert!(ipv4_unavailable(&told.1), "b was told: {:?}", told.1);
    let again = driver_events(&mut a);
    assert!(
        again.contains(&PeerDriverEvent::MdnsAvailable { ipv6: false }),
        "a was told mDNS works again: {again:?}"
    );
    assert!(a.driver.mdns_available(false));
    assert!(
        up,
        "connected over the resolved names once mDNS worked: a {:?} {:?} b {:?} {:?}",
        a.driver.pc().connection_state(),
        a.selected_remote_type(),
        b.driver.pc().connection_state(),
        b.selected_remote_type()
    );
    Ok(())
}

/// Any host on the link can send mDNS: what the driver's mDNS sockets receive waits in a
/// bounded queue (256), the oldest dropped and counted, so a driver that is not stepped does
/// not grow with the link's traffic.
#[test]
fn received_mdns_waits_in_a_bounded_queue_and_the_oldest_is_dropped() -> Result<()> {
    const FLOOD: u64 = 400;
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(
        shared.clone(),
        A,
        settings(MulticastDnsMode::QueryAndGather),
    )?;
    let mut b = Peer::with_settings(shared.clone(), B, settings(MulticastDnsMode::Disabled))?;
    let neighbour = shared.bind_udp(SocketAddr::new(IpAddr::from([10, 0, 0, 9]), 5353))?;
    let group = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_IPV4), 5353);
    runtime.run(async {
        negotiate(&mut a, &mut b)?;
        a.driver.step(Duration::ZERO).await?;
        let before = a.driver.mdns_datagrams_received();
        for _ in 0..FLOOD {
            // A DNS header with no question: the engine ignores it.
            neighbour.send_to(&[0u8; 12], group).await?;
        }
        // The driver's mDNS reader runs, filling the queue; then one step takes what waits.
        rtci_stream_driver::runtime::yield_now().await;
        a.driver.step(Duration::ZERO).await?;
        let received = a.driver.mdns_datagrams_received() - before;
        let dropped = a.driver.mdns_datagrams_dropped();
        assert!(dropped > 0, "the oldest were dropped: received {received}");
        assert!(
            received <= 256 + 8,
            "at most the queue's bound at once: {received}"
        );
        assert!(
            received + dropped >= FLOOD,
            "every datagram is either fed or counted"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
