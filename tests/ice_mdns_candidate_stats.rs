//! A remote mDNS candidate in the statistics (draft-ietf-mmusic-mdns-ice-candidates section
//! 3.3.1): its object exists from the moment it is submitted, whether or not its name has
//! resolved ("statistics [...] SHOULD NOT leak whether the mDNS resolution succeeds or fails",
//! and an `RTCIceCandidateStats` exists for every submitted candidate); it shows the name,
//! never the address the name resolved to; and once the name has resolved, the candidate pair
//! names that object.
//!
//! The browser interop cell "mDNS-hidden browser candidates resolve on the Rust side" reads
//! exactly this: the report had a `host` remote candidate with a null address, because the
//! candidate got its statistics object only when it resolved, as one "learned from a check".
//!
//! No sockets and no wall clock: the name's owner is played by an `rtci-mdns` responder.

use anyhow::Result;
use rtci::mdns::{Mdns, MdnsConfig};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCIceCandidateType,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const NAME: &str = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";
const OWNER: &str = "192.168.0.9";
const GROUP: &str = "224.0.0.251:5353";

/// The remote candidates of the report: (address, port, type).
fn remote_candidates(
    pc: &mut RTCPeerConnection,
    now: Instant,
) -> Vec<(String, Option<String>, u16, RTCIceCandidateType)> {
    pc.get_stats(now, StatsSelector::None)
        .iter()
        .filter_map(|entry| match entry {
            RTCStatsReportEntry::RemoteCandidate(c) => Some((
                c.stats.id.clone(),
                c.address.clone(),
                c.port,
                c.candidate_type,
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn a_remote_mdns_candidate_has_its_statistics_before_and_after_its_name_resolves() -> Result<()> {
    let mut now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    let mut other = RTCPeerConnectionBuilder::new().build(now)?;
    other.create_data_channel("mdns", None)?;
    let offer = other.create_offer(None)?;
    other.set_local_description(now, offer.clone())?;
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;

    let local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&local).to_json()?)?;
    // The application takes its candidate's event to trickle it: only then is it paired (RFC
    // 8838 section 10).
    while pc.poll_event().is_some() {}
    pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mline_index: Some(0),
        candidate: format!("candidate:1114572465 1 udp 2113939711 {NAME} 61163 typ host"),
        ..Default::default()
    })?;

    // Submitted, not resolved: the object is there, with the name.
    let before = remote_candidates(&mut pc, now);
    assert_eq!(before.len(), 1, "{before:?}");
    assert_eq!(before[0].1.as_deref(), Some(NAME));
    assert_eq!(
        (before[0].2, before[0].3),
        (61163, RTCIceCandidateType::Host)
    );
    assert_eq!(
        pc.get_stats(now, StatsSelector::None)
            .candidate_pairs()
            .count(),
        0,
        "no pair before the name resolves"
    );

    // The name's owner answers the query.
    let mut owner = Mdns::new(
        now,
        MdnsConfig::new()
            .with_local_names(vec![NAME.to_owned()])
            .with_local_ip(OWNER.parse()?),
    );
    let group: SocketAddr = GROUP.parse()?;
    let owner_addr: SocketAddr = format!("{OWNER}:5353").parse()?;
    let mdns = |local_addr: SocketAddr, peer_addr: SocketAddr| TransportContext {
        local_addr,
        peer_addr,
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    };
    let until = now + Duration::from_secs(5);
    let mut resolved = false;
    while now < until && !resolved {
        pc.handle_timeout(now)?;
        owner.handle_timeout(now)?;
        while let Some(out) = pc.poll_write() {
            if out.transport.peer_addr == group {
                owner.handle_read(TaggedBytesMut {
                    now,
                    transport: mdns(group, "192.168.0.2:5353".parse()?),
                    message: out.message,
                })?;
            }
        }
        while let Some(out) = owner.poll_write() {
            pc.handle_read(TaggedBytesMut {
                now,
                transport: mdns(group, owner_addr),
                message: out.message,
            })?;
        }
        resolved = pc
            .get_stats(now, StatsSelector::None)
            .candidate_pairs()
            .count()
            > 0;
        now += Duration::from_millis(10);
    }
    assert!(resolved, "the name did not resolve into a candidate pair");

    // Resolved: still one object, still the name (not the address), and the pair names it.
    let report = pc.get_stats(now, StatsSelector::None);
    let pairs: Vec<String> = report
        .candidate_pairs()
        .map(|p| p.remote_candidate_id.clone())
        .collect();
    let after = remote_candidates(&mut pc, now);
    assert_eq!(after.len(), 1, "{after:?}");
    assert_eq!(after[0].1.as_deref(), Some(NAME));
    assert_eq!(after[0].3, RTCIceCandidateType::Host);
    assert_eq!(pairs, vec![after[0].0.clone()]);
    assert!(
        after.iter().all(|c| c.1.as_deref() != Some(OWNER)),
        "the address the name hides is in the statistics"
    );
    Ok(())
}

/// The order browsers usually produce: the browser's checks arrive (from the address its name
/// hides) before the name resolves, so the agent first learns a peer-reflexive candidate and
/// connects on it; then the name resolves to that address, and the signalled candidate takes
/// the learned one's place, keeping its id and its pairs. The report must then show what was
/// signalled, a `host` candidate with the name, and that candidate's pair must be the
/// succeeded one: the browser interop cell read a `host` candidate with a null address there.
#[test]
fn a_learned_candidate_that_a_resolved_name_replaces_shows_the_name() -> Result<()> {
    let mut now = Instant::now();
    let pc_addr: SocketAddr = "192.168.0.2:5000".parse()?;
    let owner_ice: SocketAddr = format!("{OWNER}:61163").parse()?;
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    let mut browser = RTCPeerConnectionBuilder::new().build(now)?;
    browser.create_data_channel("mdns", None)?;
    let offer = browser.create_offer(None)?;
    browser.set_local_description(now, offer.clone())?;
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    browser.set_remote_description(now, answer)?;

    let host = |addr: SocketAddr| -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    };
    pc.add_local_candidate(host(pc_addr)?)?;
    browser.add_local_candidate(host(owner_ice)?)?;
    // The application takes the candidates' events to trickle it: only then is it paired (RFC
    // 8838 section 10).
    while pc.poll_event().is_some() {}
    while browser.poll_event().is_some() {}
    browser.add_remote_candidate(host(pc_addr)?)?;
    // The browser signals its candidate under its name only.
    pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mline_index: Some(0),
        candidate: format!("candidate:1114572465 1 udp 2113939711 {NAME} 61163 typ host"),
        ..Default::default()
    })?;

    let mut owner = Mdns::new(
        now,
        MdnsConfig::new()
            .with_local_names(vec![NAME.to_owned()])
            .with_local_ip(OWNER.parse()?),
    );
    let group: SocketAddr = GROUP.parse()?;
    let owner_mdns: SocketAddr = format!("{OWNER}:5353").parse()?;
    let path = |local_addr: SocketAddr, peer_addr: SocketAddr| TransportContext {
        local_addr,
        peer_addr,
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    };
    let succeeded_pair = |pc: &mut RTCPeerConnection, now: Instant| {
        pc.get_stats(now, StatsSelector::None)
            .candidate_pairs()
            .filter(|p| p.state == rtci::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState::Succeeded)
            .map(|p| p.remote_candidate_id.clone())
            .collect::<Vec<_>>()
    };

    // Run the checks with mDNS held back, then let the name resolve.
    let mut mdns_held = Vec::new();
    let mut learned = None;
    let until = now + Duration::from_secs(10);
    while now < until {
        pc.handle_timeout(now)?;
        browser.handle_timeout(now)?;
        owner.handle_timeout(now)?;
        while let Some(out) = pc.poll_write() {
            if out.transport.peer_addr == group {
                mdns_held.push(out.message);
            } else if out.transport.peer_addr == owner_ice {
                browser.handle_read(TaggedBytesMut {
                    now,
                    transport: path(owner_ice, pc_addr),
                    message: out.message,
                })?;
            }
        }
        while let Some(out) = browser.poll_write() {
            if out.transport.peer_addr == pc_addr {
                pc.handle_read(TaggedBytesMut {
                    now,
                    transport: path(pc_addr, owner_ice),
                    message: out.message,
                })?;
            }
        }
        if learned.is_none() {
            let report = remote_candidates(&mut pc, now);
            if let Some(prflx) = report
                .iter()
                .find(|c| c.3 == RTCIceCandidateType::Prflx)
                .filter(|c| succeeded_pair(&mut pc, now).contains(&c.0))
            {
                learned = Some(prflx.0.clone());
            }
        } else {
            for query in mdns_held.drain(..) {
                owner.handle_read(TaggedBytesMut {
                    now,
                    transport: path(group, "192.168.0.2:5353".parse()?),
                    message: query,
                })?;
            }
            while let Some(out) = owner.poll_write() {
                pc.handle_read(TaggedBytesMut {
                    now,
                    transport: path(group, owner_mdns),
                    message: out.message,
                })?;
            }
            let report = remote_candidates(&mut pc, now);
            if report.iter().all(|c| c.3 != RTCIceCandidateType::Prflx) {
                break;
            }
        }
        now += Duration::from_millis(10);
    }
    let learned = learned.expect("the browser's checks taught a peer-reflexive candidate");

    let report = remote_candidates(&mut pc, now);
    let shown: Vec<_> = report.iter().filter(|c| c.0 == learned).collect();
    assert_eq!(
        shown.len(),
        1,
        "the learned candidate's id is kept: {report:?}"
    );
    assert_eq!(
        (shown[0].1.as_deref(), shown[0].2, shown[0].3),
        (Some(NAME), 61163, RTCIceCandidateType::Host),
        "{report:?}"
    );
    assert_eq!(
        report.len(),
        1,
        "the object made when the name was submitted gives way: {report:?}"
    );
    assert!(
        succeeded_pair(&mut pc, now).contains(&learned),
        "the succeeded pair names the candidate that shows the name"
    );
    assert!(report.iter().all(|c| c.1.as_deref() != Some(OWNER)));
    Ok(())
}

/// A local candidate the peer connection announces carries the username fragment of its ICE
/// generation (RFC 8838 section 9: trickled candidates are tied to their ICE session, so a
/// stale one is recognised), and `to_json` hands it on.
#[test]
fn an_announced_local_candidate_names_its_ice_generation() -> Result<()> {
    use rtci::peer_connection::event::RTCPeerConnectionEvent;

    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    pc.create_data_channel("generation", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    let ufrag = offer
        .sdp
        .lines()
        .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
        .expect("an ice-ufrag")
        .trim()
        .to_owned();

    let local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&local).to_json()?)?;
    let announced = std::iter::from_fn(|| pc.poll_event())
        .find_map(|event| match event {
            RTCPeerConnectionEvent::OnIceCandidateEvent(e) => e.candidate,
            _ => None,
        })
        .expect("the candidate is announced");
    assert_eq!(announced.username_fragment.as_deref(), Some(ufrag.as_str()));
    assert_eq!(
        announced.to_json()?.username_fragment.as_deref(),
        Some(ufrag.as_str())
    );
    Ok(())
}
