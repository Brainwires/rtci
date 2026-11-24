//! The two opt-in cases in which a `QueryAndGather` peer connection leaves a host address
//! unwrapped (draft-ietf-mmusic-mdns-ice-candidates sections 3.1.1 step 1, 3.1.2.2, 3.1.2.3),
//! through the peer connection: its own STUN gathering, its ICE restart and
//! `set_configuration`, and `set_temporary_ipv6_addresses`.

use rtci::ice::mdns::MulticastDnsMode;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use rtci::stun::xoraddr::XorMappedAddress;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A global unicast address, not behind a NAT: the STUN server sees it as it is.
const PUBLIC_IP: &str = "93.184.216.34";
const PUBLIC: &str = "93.184.216.34:50000";
const PRIVATE: &str = "192.168.77.20:50002";
const STUN_SERVER: &str = "192.0.2.10:3478";
const TEMPORARY_V6: &str = "2a00:1450:4001:80b::1";
const STABLE_V6: &str = "2a00:1450:4001:80b::2";

fn connection(known_public: bool, temporary: bool) -> Result<RTCPeerConnection> {
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
                .with_multicast_dns_expose_known_public_addresses(known_public)
                .with_multicast_dns_expose_temporary_ipv6_addresses(temporary)
                .build(),
        )
        .build(Instant::now())?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    Ok(pc)
}

fn add_host(pc: &mut RTCPeerConnection, host: &str) -> Result<()> {
    let host: SocketAddr = host.parse()?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            host.ip(),
            host.port()
        ),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        ..Default::default()
    })?;
    Ok(())
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

/// Answers the engine's Binding request from `from` to the STUN server with `mapped`.
fn answer_stun(pc: &mut RTCPeerConnection, from: &str, mapped: &str) -> Result<()> {
    let server: SocketAddr = STUN_SERVER.parse()?;
    let from: SocketAddr = from.parse()?;
    let mapped: SocketAddr = mapped.parse()?;
    let mut now = Instant::now();
    let mut request = None;
    for _ in 0..40 {
        while let Some(datagram) = pc.poll_write() {
            let mut message = Message::new();
            if datagram.transport.peer_addr == server
                && datagram.transport.local_addr == from
                && message.unmarshal_binary(&datagram.message).is_ok()
                && message.typ == BINDING_REQUEST
            {
                request = Some(message);
            }
        }
        if request.is_some() {
            break;
        }
        now += Duration::from_millis(50);
        pc.handle_timeout(now)?;
    }
    let request = request.ok_or("a Binding request to the STUN server")?;
    let mut response = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(request.transaction_id),
        Box::new(BINDING_SUCCESS),
        Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        }),
    ];
    response.build(&setters)?;
    pc.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: from,
            peer_addr: server,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: response.raw.as_slice().into(),
    })?;
    Ok(())
}

/// An ICE restart through a new local offer; returns the candidates signalled for it once
/// the application has added its host candidates again.
fn restart(pc: &mut RTCPeerConnection, hosts: &[&str]) -> Result<Vec<String>> {
    signalled(pc);
    pc.restart_ice();
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    for host in hosts {
        add_host(pc, host)?;
    }
    Ok(signalled(pc))
}

fn hosts(candidates: &[String]) -> Vec<&String> {
    candidates
        .iter()
        .filter(|c| c.contains("typ host"))
        .collect()
}

/// Gathers the public and the private host candidates and answers the public one's STUN
/// request with its own address (no NAT).
fn first_gathering(pc: &mut RTCPeerConnection) -> Result<Vec<String>> {
    add_host(pc, PUBLIC)?;
    add_host(pc, PRIVATE)?;
    answer_stun(pc, PUBLIC, PUBLIC)?;
    Ok(signalled(pc))
}

/// Section 3.1.2.2 with `with_multicast_dns_expose_known_public_addresses(true)`: the first
/// gathering provides the `.local` candidate, then the server-reflexive candidate on the
/// same address (not redundant, raddr 0.0.0.0 rport 9); the ICE restart's gathering
/// provides the host candidate with its address; the private address stays hidden.
#[test]
fn an_address_the_stun_server_shows_public_is_unwrapped_after_the_ice_restart() -> Result<()> {
    let mut pc = connection(true, false)?;
    let first = first_gathering(&mut pc)?;
    let first_hosts = hosts(&first);
    assert_eq!(first_hosts.len(), 2, "{first:?}");
    assert!(
        first_hosts.iter().all(|c| c.contains(".local ")),
        "{first:?}"
    );
    let srflx: Vec<&String> = first.iter().filter(|c| c.contains("typ srflx")).collect();
    assert_eq!(srflx.len(), 1, "{first:?}");
    assert!(
        srflx[0].contains(&format!(
            "{PUBLIC_IP} 50000 typ srflx raddr 0.0.0.0 rport 9"
        )),
        "{}",
        srflx[0]
    );

    let second = restart(&mut pc, &[PUBLIC, PRIVATE])?;
    let second_hosts = hosts(&second);
    assert!(
        second_hosts
            .iter()
            .any(|c| c.contains(&format!("{PUBLIC_IP} 50000 typ host"))),
        "{second:?}"
    );
    // The private address stays behind its name: in what is signalled and in the
    // transport's candidates (which the descriptions are written from).
    let held: Vec<String> = pc
        .dtls_transports()
        .iter()
        .flat_map(|t| t.ice_transport().get_local_candidates())
        .map(|c| format!("{}:{}", c.address, c.port))
        .collect();
    assert!(held.iter().any(|c| c.ends_with(".local:50002")), "{held:?}");
    assert!(held.contains(&PUBLIC.to_owned()), "{held:?}");
    assert!(
        second.iter().all(|c| !c.contains("192.168.77.20")),
        "{second:?}"
    );
    Ok(())
}

/// The setting off (the default): the host candidate stays hidden in every gathering, the
/// restart's included.
#[test]
fn without_the_setting_the_public_address_stays_hidden() -> Result<()> {
    let mut pc = connection(false, false)?;
    let first = first_gathering(&mut pc)?;
    assert!(hosts(&first).iter().all(|c| c.contains(".local ")));
    let second = restart(&mut pc, &[PUBLIC, PRIVATE])?;
    assert!(
        second
            .iter()
            .all(|c| !(c.contains(PUBLIC_IP) && c.contains("typ host"))),
        "{second:?}"
    );
    Ok(())
}

/// draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.2 at the peer connection, in the
/// default hiding mode (no exposure setting): "Regardless of whether the address turns out to
/// be public or private, a server-reflexive candidate will be generated; [...] and as such
/// MUST NOT be considered redundant" (MDNSICE-3.1.2.2-1), and "this server-reflexive candidate
/// MUST have its raddr field set to \"0.0.0.0\"/\"::\" and its rport field set to \"9\""
/// (MDNSICE-3.1.2.2-2). The engine's own STUN gathering provides it when the answer equals the
/// base; without mDNS hiding (`QueryOnly`) the same answer stays redundant (RFC 8445 section
/// 5.1.3), the host candidate carrying the address already.
#[test]
fn in_hiding_mode_a_stun_answer_equal_to_its_base_is_a_candidate_with_the_base_hidden() -> Result<()>
{
    let mut pc = connection(false, false)?;
    let first = first_gathering(&mut pc)?;
    assert!(
        hosts(&first).iter().all(|c| c.contains(".local ")),
        "{first:?}"
    );
    let srflx: Vec<&String> = first.iter().filter(|c| c.contains("typ srflx")).collect();
    assert_eq!(
        srflx.len(),
        1,
        "not redundant with the mDNS candidate: {first:?}"
    );
    assert!(
        srflx[0].contains(&format!(
            "{PUBLIC_IP} 50000 typ srflx raddr 0.0.0.0 rport 9"
        )),
        "{}",
        srflx[0]
    );

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut plain = RTCPeerConnectionBuilder::new()
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
                .with_multicast_dns_mode(MulticastDnsMode::QueryOnly)
                .build(),
        )
        .build(Instant::now())?;
    plain.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = plain.create_offer(None)?;
    plain.set_local_description(Instant::now(), offer)?;
    let first = first_gathering(&mut plain)?;
    assert!(
        first
            .iter()
            .any(|c| c.contains(&format!("{PUBLIC_IP} 50000 typ host"))),
        "{first:?}"
    );
    assert!(
        first.iter().all(|c| !c.contains("typ srflx")),
        "redundant with the host candidate: {first:?}"
    );
    Ok(())
}

/// Section 3.1.2.2: "if the set of STUN servers changes, any cached information SHOULD be
/// discarded": a `set_configuration` with other ICE servers before the restart keeps the
/// address hidden.
#[test]
fn new_ice_servers_discard_what_was_shown_public() -> Result<()> {
    let mut pc = connection(true, false)?;
    first_gathering(&mut pc)?;
    pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:192.0.2.11:3478".to_owned()],
                ..Default::default()
            }])
            .build(),
    )?;
    let second = restart(&mut pc, &[PUBLIC, PRIVATE])?;
    assert!(
        hosts(&second).iter().all(|c| c.contains(".local ")),
        "{second:?}"
    );
    assert!(
        second
            .iter()
            .all(|c| !c.contains(&format!("{PUBLIC_IP} 50000 typ host"))),
        "{second:?}"
    );
    Ok(())
}

/// Section 3.1.2.3 with `with_multicast_dns_expose_temporary_ipv6_addresses(true)`: the
/// address the application marks temporary goes out as it is; the stable one stays hidden,
/// and without the setting both are hidden.
#[test]
fn a_marked_temporary_ipv6_address_goes_out_unwrapped() -> Result<()> {
    for on in [true, false] {
        let mut pc = connection(false, on)?;
        pc.set_temporary_ipv6_addresses(vec![TEMPORARY_V6.parse()?]);
        add_host(&mut pc, &format!("[{TEMPORARY_V6}]:50010"))?;
        add_host(&mut pc, &format!("[{STABLE_V6}]:50011"))?;
        let candidates = signalled(&mut pc);
        assert_eq!(hosts(&candidates).len(), 2, "{candidates:?}");
        assert_eq!(
            candidates
                .iter()
                .any(|c| c.contains(&format!("{TEMPORARY_V6} 50010 typ host"))),
            on,
            "{candidates:?}"
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.contains(".local 50011 typ host")),
            "{candidates:?}"
        );
        assert!(
            candidates.iter().all(|c| !c.contains(STABLE_V6)),
            "{candidates:?}"
        );
    }
    Ok(())
}
