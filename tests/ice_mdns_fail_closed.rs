//! draft-ietf-mmusic-mdns-ice-candidates section 3.1.1, a host candidate whose mDNS name
//! cannot be registered ("the local network does not support mDNS or mDNS registration fails
//! in step 4"), here because the application has no mDNS socket
//! (`RTCPeerConnection::set_multicast_dns_publishing`):
//!
//! - by default the draft's form: "the ICE agent SHOULD still provide mDNS candidates in step
//!   6": the candidate goes out under a `.local` name that is not published;
//! - with `SettingEngineBuilder::with_multicast_dns_fail_closed(true)` no host candidate at
//!   all, while the server-reflexive candidate of the address is still gathered (without the
//!   address: raddr `0.0.0.0` rport 9, section 3.1.2.2).
//!
//! The literal address appears in neither: not in the description, not in an
//! `OnIceCandidateEvent`, not among the transport's local candidates.

use rtci::ice::mdns::{MulticastDnsMode, MulticastDnsPublishing};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{RTCIceCandidateInit, RTCIceCandidateType};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use rtci::stun::xoraddr::XorMappedAddress;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const HOST_IP: &str = "192.168.77.20";
const HOST: &str = "192.168.77.20:50000";
const STUN_SERVER: &str = "192.0.2.10:3478";

/// A `QueryAndGather` connection with a STUN server whose application has no mDNS socket for
/// either family; it has made its offer and added its one host candidate.
fn gathered(fail_closed: bool) -> Result<(RTCPeerConnection, Vec<String>)> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![format!("stun:{STUN_SERVER}")],
                    ..Default::default()
                }])
                .build(),
        )
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
                .with_multicast_dns_fail_closed(fail_closed)
                .build(),
        )
        .build(Instant::now())?;
    pc.set_multicast_dns_publishing(MulticastDnsPublishing {
        ipv4: false,
        ipv6: false,
    });
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    let host: SocketAddr = HOST.parse()?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            host.ip(),
            host.port()
        ),
        ..Default::default()
    })?;
    let signalled = signalled(&mut pc);
    Ok((pc, signalled))
}

/// The candidates of the `OnIceCandidateEvent`s fired so far.
fn signalled(pc: &mut RTCPeerConnection) -> Vec<String> {
    let mut candidates = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
            && let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
            && let Ok(init) = candidate.to_json()
        {
            candidates.push(init.candidate);
        }
    }
    candidates
}

/// The local description after gathering, and the addresses of the transport's local host
/// candidates.
fn described(pc: &mut RTCPeerConnection) -> Result<(String, Vec<String>)> {
    let offer = pc.create_offer(None)?;
    let held = pc
        .dtls_transports()
        .iter()
        .flat_map(|t| t.ice_transport().get_local_candidates())
        .filter(|c| c.typ == RTCIceCandidateType::Host)
        .map(|c| format!("{}:{}", c.address, c.port))
        .collect();
    Ok((offer.sdp, held))
}

/// Answers the engine's Binding request to the STUN server with a mapped address; returns the
/// candidates signalled then.
fn answer_stun(pc: &mut RTCPeerConnection) -> Result<Vec<String>> {
    let server: SocketAddr = STUN_SERVER.parse()?;
    let mut now = Instant::now();
    let mut request = None;
    for _ in 0..40 {
        while let Some(datagram) = pc.poll_write() {
            let mut message = Message::new();
            if datagram.transport.peer_addr == server
                && message.unmarshal_binary(&datagram.message).is_ok()
                && message.typ == BINDING_REQUEST
            {
                request = Some((datagram.transport.local_addr, message));
            }
        }
        if request.is_some() {
            break;
        }
        now += Duration::from_millis(50);
        pc.handle_timeout(now)?;
    }
    let (local, request) = request.ok_or("a Binding request to the STUN server")?;
    assert_eq!(
        local,
        HOST.parse::<SocketAddr>()?,
        "asked from the host's socket"
    );
    let mut response = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(request.transaction_id),
        Box::new(BINDING_SUCCESS),
        Box::new(XorMappedAddress {
            ip: "203.0.113.5".parse()?,
            port: 61000,
        }),
    ];
    response.build(&setters)?;
    pc.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: local,
            peer_addr: server,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: response.raw.as_slice().into(),
    })?;
    Ok(signalled(pc))
}

/// `with_multicast_dns_fail_closed(true)`: a host address whose name cannot be published gets
/// no host candidate, neither signalled nor described nor held by the transport (so nothing is
/// paired with it); its server-reflexive candidate is still gathered, without the address.
#[test]
fn fail_closed_withholds_a_host_candidate_whose_name_cannot_be_published() -> Result<()> {
    let (mut pc, signalled) = gathered(true)?;
    assert!(
        signalled.iter().all(|c| !c.contains("typ host")),
        "no host candidate is signalled: {signalled:?}"
    );
    let (sdp, held) = described(&mut pc)?;
    assert!(
        held.is_empty(),
        "the transport holds no host candidate: {held:?}"
    );
    assert!(!sdp.contains("typ host"), "{sdp}");
    assert!(!sdp.contains(HOST_IP), "{sdp}");

    let srflx = answer_stun(&mut pc)?;
    assert_eq!(srflx.len(), 1, "the server-reflexive candidate: {srflx:?}");
    assert!(
        srflx[0].contains("203.0.113.5 61000 typ srflx raddr 0.0.0.0 rport 9"),
        "{}",
        srflx[0]
    );
    assert!(!srflx[0].contains(HOST_IP), "{}", srflx[0]);
    Ok(())
}

/// The default, the draft's form: the host candidate is provided under a `.local` name, which
/// is not published, and the address is written nowhere.
#[test]
fn by_default_a_host_candidate_whose_name_cannot_be_published_goes_out_under_an_unpublished_name()
-> Result<()> {
    let (mut pc, signalled) = gathered(false)?;
    let hosts: Vec<&String> = signalled
        .iter()
        .filter(|c| c.contains("typ host"))
        .collect();
    assert_eq!(
        hosts.len(),
        1,
        "one host candidate is signalled: {signalled:?}"
    );
    assert!(hosts[0].contains(".local 50000 typ host"), "{}", hosts[0]);
    assert!(!hosts[0].contains(HOST_IP), "{}", hosts[0]);
    let (sdp, held) = described(&mut pc)?;
    assert_eq!(held.len(), 1, "the transport holds it: {held:?}");
    assert!(held[0].ends_with(".local:50000"), "{held:?}");
    assert!(sdp.contains(".local 50000 typ host"), "{sdp}");
    assert!(!sdp.contains(HOST_IP), "{sdp}");
    // Nothing announces the name: no mDNS datagram leaves.
    let mut now = Instant::now();
    for _ in 0..40 {
        while let Some(datagram) = pc.poll_write() {
            assert_ne!(
                datagram.transport.peer_addr.port(),
                5353,
                "the unpublished name is not announced"
            );
        }
        now += Duration::from_millis(100);
        pc.handle_timeout(now)?;
    }
    Ok(())
}
