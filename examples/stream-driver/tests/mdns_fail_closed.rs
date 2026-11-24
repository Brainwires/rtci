//! A `PeerDriver` that has no mDNS socket (`PeerDriverConfig::mdns_sockets` off, as when the
//! host refuses them) tells its `QueryAndGather` connection, before it adds the first host
//! candidates, that no name can be published (draft-ietf-mmusic-mdns-ice-candidates section
//! 3.1.1 step 4 fails). With `with_multicast_dns_fail_closed(true)` the connection then offers no
//! host candidate; by default (the draft's form) one under a `.local` name that is not
//! published. The address is signalled in neither.
//!
//! No multicast: the driver binds no mDNS socket here, only its UDP socket on loopback, so the
//! tests run on every platform.

use rtci::ice::mdns::MulticastDnsMode;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::RTCIceCandidateType;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A driver without mDNS sockets for a `QueryAndGather` connection that has offered audio and
/// gathered for a moment; the candidates it signalled.
async fn gathered(fail_closed: bool) -> Result<(PeerDriver, Vec<String>)> {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
                .with_multicast_dns_fail_closed(fail_closed)
                .build(),
        )
        .build(Instant::now())?;
    let mut driver = PeerDriver::new(
        pc,
        PeerDriverConfig {
            mdns_sockets: false,
            ..PeerDriverConfig::on(vec![LOOPBACK])
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
    assert!(
        !driver.local_addresses().is_empty(),
        "the driver gathered: it bound its UDP socket"
    );
    assert_eq!(
        driver.mdns_datagrams_sent(),
        0,
        "no mDNS socket, nothing sent"
    );
    Ok((driver, signalled))
}

/// Fail closed: no host candidate, neither signalled nor held by the transport.
#[tokio::test]
async fn without_mdns_sockets_a_fail_closed_connection_offers_no_host_candidate() -> Result<()> {
    let (driver, signalled) = gathered(true).await?;
    assert!(
        signalled.iter().all(|c| !c.contains("typ host")),
        "no host candidate is signalled: {signalled:?}"
    );
    let held: Vec<String> = driver
        .pc()
        .dtls_transports()
        .iter()
        .flat_map(|t| t.ice_transport().get_local_candidates())
        .filter(|c| c.typ == RTCIceCandidateType::Host)
        .map(|c| format!("{}:{}", c.address, c.port))
        .collect();
    assert!(
        held.is_empty(),
        "the transport holds no host candidate: {held:?}"
    );
    Ok(())
}

/// The default, the draft's form: the host candidate goes out under a `.local` name, never with
/// the address.
#[tokio::test]
async fn without_mdns_sockets_a_connection_offers_its_host_candidate_under_an_unpublished_name()
-> Result<()> {
    let (_driver, signalled) = gathered(false).await?;
    let hosts: Vec<&String> = signalled
        .iter()
        .filter(|c| c.contains("typ host"))
        .collect();
    assert!(
        !hosts.is_empty(),
        "a host candidate is signalled: {signalled:?}"
    );
    for candidate in hosts {
        assert!(candidate.contains(".local "), "{candidate}");
        assert!(!candidate.contains("127.0.0.1"), "{candidate}");
    }
    Ok(())
}
