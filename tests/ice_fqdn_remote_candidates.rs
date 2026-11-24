//! Remote candidates whose address is a name the engine does not resolve
//! (draft-ietf-mmusic-mdns-ice-candidates sections 3.2.1 and 4; RFC 8839 section 5.1).
//!
//! RFC 8839 section 5.1: "An agent processing remote candidates MUST ignore "candidate" lines
//! that include candidates with FQDNs or IP address versions that are not supported or
//! recognized." The draft's section 3.2.1 step 1 sends an address that does not end with
//! ".local", or has more than one ".", to RFC 8445 processing, and its section 4 leaves the
//! restriction on other FQDNs "unaffected". Such a line is well formed (the grammar allows an
//! FQDN), so W3C `addIceCandidate` adds it as RFC 9429 describes and resolves: it is ignored,
//! not refused. A host `.local` name of the draft's form is resolved by mDNS instead
//! (`ice_mdns_candidate_stats.rs`).
//!
//! No sockets and no wall clock.

use anyhow::Result;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use std::time::Instant;

/// A connection with a remote description (one data channel section), ready for candidates.
fn answered(now: Instant) -> Result<RTCPeerConnection> {
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    let mut other = RTCPeerConnectionBuilder::new().build(now)?;
    other.create_data_channel("fqdn", None)?;
    let offer = other.create_offer(None)?;
    other.set_local_description(now, offer.clone())?;
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;
    Ok(pc)
}

fn remote_candidate_count(pc: &mut RTCPeerConnection, now: Instant) -> usize {
    pc.get_stats(now, StatsSelector::None)
        .iter()
        .filter(|entry| matches!(entry, RTCStatsReportEntry::RemoteCandidate(_)))
        .count()
}

fn trickle(pc: &mut RTCPeerConnection, line: &str) -> rtci::shared::error::Result<()> {
    pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mline_index: Some(0),
        candidate: format!("candidate:{line}"),
        ..Default::default()
    })
}

#[test]
fn a_trickled_candidate_with_an_fqdn_address_is_ignored_not_refused() -> Result<()> {
    let now = Instant::now();
    let mut pc = answered(now)?;
    for line in [
        // An FQDN: not `.local` (step 1, then RFC 8839 section 5.1).
        "1 1 udp 2113939711 turn.example.com 3478 typ host",
        // Two labels before `.local`: "more than one '.'" (step 1).
        "2 1 udp 2113939711 host.lan.local 3478 typ host",
        // A server-reflexive candidate with a name: the draft hides host addresses only
        // (section 3.1.2.2), and an FQDN is ignored whatever the type.
        "3 1 udp 1677729535 srflx.example.net 40000 typ srflx raddr 0.0.0.0 rport 0",
        "4 1 udp 1677729535 61b445d2-6503-41ac-96ce-ee3edac00e9f.local 40000 typ srflx raddr 0.0.0.0 rport 0",
    ] {
        trickle(&mut pc, line).unwrap_or_else(|e| panic!("{line}: ignored, not an error: {e}"));
    }
    assert_eq!(
        remote_candidate_count(&mut pc, now),
        0,
        "none of them reaches the agent or the statistics"
    );
    // The connection goes on taking candidates: an IP address one is taken.
    trickle(&mut pc, "5 1 udp 2113939711 192.0.2.7 3478 typ host")?;
    assert_eq!(remote_candidate_count(&mut pc, now), 1);
    Ok(())
}

#[test]
fn a_candidate_line_that_does_not_parse_is_still_refused() -> Result<()> {
    let now = Instant::now();
    let mut pc = answered(now)?;
    // Not an FQDN case: the port is not a number (RFC 9429 section 4.1.19, "invalid values").
    assert!(trickle(&mut pc, "1 1 udp 2113939711 192.0.2.7 port typ host").is_err());
    Ok(())
}
