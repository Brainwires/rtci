//! `PeerDriver` on the host's real network where mDNS may not work: two publishing drivers on
//! the host's default-route address must, within a bound, either connect or each have told its
//! application why mDNS cannot be sent (`PeerDriverEvent::MdnsUnavailable`), never sit in
//! Connecting silently. On GitHub's macOS image every send to the mDNS group fails; a Mac
//! application without the Local Network permission behaves the same.
//!
//! Ignored by default: on a desktop Mac (and our self-hosted macOS runner) a multicast socket
//! raises the Local Network privacy prompt. Run it on a hosted runner with `--ignored`. The
//! same behaviour on every platform, on virtual time: `tests/mdns_failures.rs`.

use rtci::ice::mdns::MulticastDnsMode;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig, PeerDriverEvent};
use std::net::IpAddr;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Side {
    driver: PeerDriver,
    outgoing: Vec<RTCIceCandidateInit>,
    told: Vec<PeerDriverEvent>,
}

impl Side {
    fn new(ip: IpAddr) -> Result<Self> {
        let settings = SettingEngineBuilder::new()
            .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
            .with_tcp_candidate_gathering(false);
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(settings.build())
            .build(Instant::now())?;
        Ok(Self {
            driver: PeerDriver::new(pc, PeerDriverConfig::on(vec![ip])),
            outgoing: vec![],
            told: vec![],
        })
    }

    fn collect(&mut self) {
        while let Some(event) = self.driver.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
                && let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                && let Ok(init) = candidate.to_json()
            {
                self.outgoing.push(init);
            }
        }
        while self.driver.pc_mut().poll_read().is_some() {}
        self.told
            .extend(std::iter::from_fn(|| self.driver.poll_driver_event()));
    }

    fn connected(&self) -> bool {
        self.driver.pc().connection_state() == RTCPeerConnectionState::Connected
    }

    fn reported(&self) -> bool {
        self.told
            .iter()
            .any(|e| matches!(e, PeerDriverEvent::MdnsUnavailable(_)))
    }
}

/// The address the host's default route leaves from (a UDP connect sends nothing).
fn default_route_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

#[tokio::test]
#[ignore = "real multicast: raises the Local Network prompt on a desktop Mac; run on a hosted runner with --ignored"]
async fn publishing_drivers_connect_or_report_why_mdns_cannot_be_sent() -> Result<()> {
    let ip = default_route_ip().ok_or("no default-route address")?;
    let mut a = Side::new(ip)?;
    let mut b = Side::new(ip)?;
    let channel = a.driver.pc_mut().create_data_channel("probe", None)?;
    let _ = channel;
    let now = Instant::now();
    let offer = a.driver.pc_mut().create_offer(None)?;
    a.driver
        .pc_mut()
        .set_local_description(now, offer.clone())?;
    b.driver.pc_mut().set_remote_description(now, offer)?;
    let answer = b.driver.pc_mut().create_answer(None)?;
    b.driver
        .pc_mut()
        .set_local_description(now, answer.clone())?;
    a.driver.pc_mut().set_remote_description(now, answer)?;
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        a.driver.step(Duration::from_millis(5)).await?;
        b.driver.step(Duration::from_millis(5)).await?;
        a.collect();
        b.collect();
        for c in std::mem::take(&mut a.outgoing) {
            b.driver.pc_mut().add_remote_candidate(c)?;
        }
        for c in std::mem::take(&mut b.outgoing) {
            a.driver.pc_mut().add_remote_candidate(c)?;
        }
        if (a.connected() && b.connected()) || (a.reported() && b.reported()) {
            break;
        }
    }
    println!(
        "on {ip}: a {:?}, mDNS sent {} failed {}, told {:?}; b {:?}, sent {} failed {}, told {:?}",
        a.driver.pc().connection_state(),
        a.driver.mdns_datagrams_sent(),
        a.driver.mdns_send_failures(),
        a.told,
        b.driver.pc().connection_state(),
        b.driver.mdns_datagrams_sent(),
        b.driver.mdns_send_failures(),
        b.told
    );
    assert!(
        (a.connected() && b.connected()) || (a.reported() && b.reported()),
        "neither connected nor told why mDNS does not work"
    );
    if a.driver.mdns_send_failures() > 0 {
        assert!(a.reported(), "a's refused sends were reported");
    }
    if b.driver.mdns_send_failures() > 0 {
        assert!(b.reported(), "b's refused sends were reported");
    }
    Ok(())
}
