//! draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.3 through a `PeerDriver`: the driver
//! reads which of its addresses the operating system flags as RFC 4941 temporary
//! (`shared::ifaces::temporary_ipv6_addresses`) and marks them for the connection; with
//! `with_multicast_dns_expose_temporary_ipv6_addresses(true)` the temporary address's host
//! candidate goes out with the address, the stable one's under a `.local` name.
//!
//! Needs a host with a temporary address, which a test cannot make without root: ignored
//! unless run by hand, on Linux, after (as root)
//!
//! ```sh
//! ip link add rtcitmp0 type dummy
//! sysctl -w net.ipv6.conf.rtcitmp0.disable_ipv6=0 net.ipv6.conf.rtcitmp0.use_tempaddr=2
//! ip link set rtcitmp0 up
//! ip -6 addr add 2a0a:e5c0:ffff:1::1/64 dev rtcitmp0 mngtmpaddr valid_lft 3600 preferred_lft 3600
//! ```
//!
//! with `RTCI_STABLE_V6=2a0a:e5c0:ffff:1::1` (the kernel makes a temporary address from the
//! `mngtmpaddr` one, as stateless autoconfiguration would): `cargo test -p rtci-stream-driver
//! --features peer --test mdns_temporary -- --ignored`.

use rtci::ice::mdns::{MulticastDnsMode, is_global_unicast};
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The candidates a driver gathering on `addresses` signals for a `QueryAndGather`
/// connection.
async fn signalled(addresses: Vec<IpAddr>, expose_temporary: bool) -> Result<Vec<String>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
                .with_multicast_dns_expose_temporary_ipv6_addresses(expose_temporary)
                .build(),
        )
        .build(Instant::now())?;
    let mut driver = PeerDriver::new(
        pc,
        PeerDriverConfig {
            // No multicast: the names are not published, which changes nothing here.
            mdns_sockets: false,
            ..PeerDriverConfig::on(addresses)
        },
    );
    driver
        .pc_mut()
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = driver.pc_mut().create_offer(None)?;
    driver
        .pc_mut()
        .set_local_description(Instant::now(), offer)?;
    let mut signalled = vec![];
    for _ in 0..20 {
        driver.step(Duration::from_millis(5)).await?;
        while let Some(event) = driver.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
                && let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                && let Ok(init) = candidate.to_json()
            {
                signalled.push(init.candidate);
            }
        }
    }
    Ok(signalled)
}

#[tokio::test]
#[ignore = "needs a temporary IPv6 address on the host (see the module documentation)"]
async fn the_driver_marks_the_temporary_address_the_os_reports_and_only_it_goes_out_unwrapped()
-> Result<()> {
    let stable: Ipv6Addr = std::env::var("RTCI_STABLE_V6")?.parse()?;
    let temporary = shared::ifaces::temporary_ipv6_addresses()?
        .into_iter()
        .find(|t| t.segments()[..4] == stable.segments()[..4])
        .ok_or("the kernel made no temporary address on the stable one's prefix")?;
    assert!(is_global_unicast(IpAddr::V6(temporary)));
    assert!(
        !shared::ifaces::temporary_ipv6_addresses()?.contains(&stable),
        "the mngtmpaddr address is not temporary"
    );
    let addresses = vec![IpAddr::V6(temporary), IpAddr::V6(stable)];

    let on = signalled(addresses.clone(), true).await?;
    // One UDP host candidate per address (the engine's ICE-TCP ones follow the same rule).
    let hosts: Vec<&String> = on
        .iter()
        .filter(|c| c.contains(" udp ") && c.contains("typ host"))
        .collect();
    assert_eq!(hosts.len(), 2, "{on:?}");
    assert!(
        hosts
            .iter()
            .any(|c| c.contains(&format!(" {temporary} ")) && c.contains("typ host")),
        "the temporary address goes out as it is: {on:?}"
    );
    assert!(
        on.iter().all(|c| !c.contains(&stable.to_string())),
        "the stable address stays hidden: {on:?}"
    );
    assert_eq!(
        hosts.iter().filter(|c| c.contains(".local ")).count(),
        1,
        "{on:?}"
    );

    let off = signalled(addresses, false).await?;
    assert!(
        off.iter()
            .all(|c| !c.contains(&temporary.to_string()) && !c.contains(&stable.to_string())),
        "without the setting both are hidden: {off:?}"
    );
    Ok(())
}
