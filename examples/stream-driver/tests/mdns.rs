//! `PeerDriver`'s mDNS over the host's real mDNS group: two driven connections publish their
//! host addresses behind `.local` names (draft-ietf-mmusic-mdns-ice-candidates section 3.1)
//! and resolve each other's through the driver's mDNS sockets, within one budget shared by both
//! (section 7.1).
//!
//! Linux and Windows. Multicast needs a route that carries it back to this host: GitHub's macOS
//! image has none (an mDNS send fails with "No route to host"; `cargo.yml` reroutes it for the
//! root crate's interop tests only), and on a desktop Mac a multicast socket raises the Local
//! Network privacy prompt. The same connection on virtual time, on every platform, is
//! `tests/mdns_virtual_time.rs`; the budget's own rules are unit tests of the crate
//! (`mdns_io.rs`).
#![cfg(any(target_os = "linux", target_os = "windows"))]

use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, MdnsRateLimit};
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use std::net::IpAddr;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The tests share the host's mDNS group: one at a time, so that what a test counts is its own.
static MDNS_GROUP_IN_USE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The address of the interface multicast to the mDNS group leaves by: the one a UDP socket
/// connected to the group sends from. An mDNS answer leaves from it, and the resolver believes
/// an A record only from the address it names, so the candidates are gathered there.
fn mdns_egress_ip() -> Option<IpAddr> {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect((MDNS_MULTICAST_IPV4, MDNS_PORT))?;
            socket.local_addr()
        })
        .ok()
        .map(|addr| addr.ip())
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

struct Side {
    driver: PeerDriver,
    outgoing: Vec<RTCIceCandidateInit>,
    signalled: Vec<String>,
}

impl Side {
    fn new(ip: IpAddr, limit: Option<MdnsRateLimit>) -> Result<Self> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let settings =
            SettingEngineBuilder::new().with_multicast_dns_mode(MulticastDnsMode::QueryAndGather);
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(settings.build())
            .build(Instant::now())?;
        Ok(Self {
            driver: PeerDriver::new(
                pc,
                PeerDriverConfig {
                    mdns_rate_limit: limit,
                    ..PeerDriverConfig::on(vec![ip])
                },
            ),
            outgoing: vec![],
            signalled: vec![],
        })
    }

    fn collect(&mut self) {
        while let Some(event) = self.driver.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
                && let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                && let Ok(init) = candidate.to_json()
            {
                self.signalled.push(init.candidate.clone());
                self.outgoing.push(init);
            }
        }
        while self.driver.pc_mut().poll_read().is_some() {}
    }

    fn connected(&self) -> bool {
        self.driver.pc().connection_state() == RTCPeerConnectionState::Connected
    }
}

async fn round(a: &mut Side, b: &mut Side) -> Result<()> {
    a.driver.step(Duration::from_millis(5)).await?;
    b.driver.step(Duration::from_millis(5)).await?;
    a.collect();
    b.collect();
    for candidate in std::mem::take(&mut a.outgoing) {
        b.driver.pc_mut().add_remote_candidate(candidate)?;
    }
    for candidate in std::mem::take(&mut b.outgoing) {
        a.driver.pc_mut().add_remote_candidate(candidate)?;
    }
    Ok(())
}

/// `a` offers an audio transceiver, `b` answers; rounds until both are connected or `limit`.
async fn connect(a: &mut Side, b: &mut Side, limit: Duration) -> Result<bool> {
    a.driver.pc_mut().add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
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
    let until = Instant::now() + limit;
    while Instant::now() < until {
        round(a, b).await?;
        if a.connected() && b.connected() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn assert_only_local_names(who: &str, side: &Side, ip: IpAddr) {
    assert!(!side.signalled.is_empty(), "{who}: candidates signalled");
    for candidate in &side.signalled {
        assert!(
            candidate.contains(".local ") && !candidate.contains(&ip.to_string()),
            "{who}: the host address is hidden behind a .local name: {candidate}"
        );
    }
}

/// Both connections publish `.local` names only; each resolves the other's through its
/// driver's mDNS sockets (nothing else carries an mDNS datagram), and they connect.
#[tokio::test]
async fn driven_connections_resolve_each_others_mdns_candidates_and_connect() -> Result<()> {
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let Some(ip) = mdns_egress_ip() else {
        panic!("this test needs an interface that carries multicast to the mDNS group");
    };
    let limit = MdnsRateLimit::default();
    let mut a = Side::new(ip, Some(limit.clone()))?;
    let mut b = Side::new(ip, Some(limit))?;
    let up = connect(&mut a, &mut b, Duration::from_secs(30)).await?;
    assert_only_local_names("a", &a, ip);
    assert_only_local_names("b", &b, ip);
    assert!(
        a.driver.mdns_datagrams_sent() > 0 && b.driver.mdns_datagrams_sent() > 0,
        "both drivers sent mDNS: {} and {}",
        a.driver.mdns_datagrams_sent(),
        b.driver.mdns_datagrams_sent()
    );
    for (who, side) in [("a", &a), ("b", &b)] {
        assert!(
            side.driver.mdns_datagrams_received() > 0,
            "{who}: the driver's mDNS sockets received the group's datagrams"
        );
    }
    assert!(
        up,
        "connected over the resolved .local candidates: a {:?} / b {:?}",
        a.driver.pc().connection_state(),
        b.driver.pc().connection_state()
    );
    Ok(())
}

/// draft-ietf-mmusic-mdns-ice-candidates section 7.1: one rate limit over all mDNS queries and
/// responses. Two connections whose drivers share a small budget (1 at once, then 1 a second)
/// send together no more than it allows over the whole exchange (probes, announcements,
/// queries and answers of both), and still connect: what the budget refused waited, and
/// leaves later at the budget's rate.
#[tokio::test]
async fn two_driven_connections_send_their_mdns_within_one_shared_budget() -> Result<()> {
    const BURST: u32 = 1;
    const PER_SECOND: u32 = 1;
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let Some(ip) = mdns_egress_ip() else {
        panic!("this test needs an interface that carries multicast to the mDNS group");
    };
    let limit = MdnsRateLimit::new(BURST, PER_SECOND);
    let start = Instant::now();
    let mut a = Side::new(ip, Some(limit.clone()))?;
    let mut b = Side::new(ip, Some(limit))?;
    let up = connect(&mut a, &mut b, Duration::from_secs(40)).await?;
    // The drivers bind their mDNS sockets when gathering begins, so each may take the other's
    // first announcement into its cache and connect after a single datagram: the exchange
    // goes on for a while, and what the budget held leaves at its rate.
    while start.elapsed() < Duration::from_secs(4) {
        round(&mut a, &mut b).await?;
    }
    let elapsed = start.elapsed();
    let sent = a.driver.mdns_datagrams_sent() + b.driver.mdns_datagrams_sent();
    let allowed = u64::from(BURST) + (elapsed.as_secs_f64() * f64::from(PER_SECOND)).ceil() as u64;
    assert!(
        sent <= allowed,
        "{sent} mDNS datagrams in {elapsed:?}: the shared budget allows {allowed}"
    );
    assert!(
        sent > u64::from(BURST),
        "the held mDNS left after the burst: {sent}"
    );
    assert!(up, "connected, the held mDNS sent as the budget allowed");
    Ok(())
}

/// RFC 6762 section 14: the driver sends each mDNS message on the interface of the address it
/// is about and joins the group there, not only on the system's default multicast interface.
/// Two drivers whose only address is loopback publish names of 127.0.0.1, announce and answer
/// them on the loopback interface, resolve each other's, and connect. (Sent on the default
/// interface, as 0.2.0-dev did before, the answers came from another address and were
/// refused: the names never resolved.)
#[tokio::test]
async fn drivers_on_loopback_resolve_each_other_on_the_loopback_interface() -> Result<()> {
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let ip = IpAddr::from([127, 0, 0, 1]);
    let limit = MdnsRateLimit::default();
    let mut a = Side::new(ip, Some(limit.clone()))?;
    let mut b = Side::new(ip, Some(limit))?;
    let up = connect(&mut a, &mut b, Duration::from_secs(30)).await?;
    assert_only_local_names("a", &a, ip);
    assert_only_local_names("b", &b, ip);
    assert!(
        up,
        "connected over the resolved .local candidates on loopback: a {:?} (mDNS sent {}, received {}) / b {:?} (sent {}, received {})",
        a.driver.pc().connection_state(),
        a.driver.mdns_datagrams_sent(),
        a.driver.mdns_datagrams_received(),
        b.driver.pc().connection_state(),
        b.driver.mdns_datagrams_sent(),
        b.driver.mdns_datagrams_received()
    );
    Ok(())
}
