//! ICE with mDNS host candidates between two hosts on a real LAN segment (multicast across a
//! bridge), in the real-network test environment (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! The ports of the old async suite's `test_multicast_dns_only_connection` (both sides hide
//! their addresses) and `test_multicast_dns_mixed_connection` (one hides, one only queries).
//! Both use `QueryAndGather` without a fixed IP: one `<uuid>.local` name per address, resolved
//! over multicast by the other side.

mod common;
mod testenv;

use rtci::ice::mdns::MulticastDnsMode;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use std::time::{Duration, Instant};
use testenv::{Env, EnvPeer, Gather, negotiate_in_sdp, pump};

fn mdns_pc(mode: MulticastDnsMode) -> RTCPeerConnection {
    let se = SettingEngineBuilder::new()
        .with_multicast_dns_mode(mode)
        .with_multicast_dns_timeout(Some(Duration::from_secs(10)))
        .build();
    RTCPeerConnectionBuilder::new()
        .with_setting_engine(se)
        .build(Instant::now())
        .expect("peer connection")
}

fn candidate_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|l| l.starts_with("a=candidate:"))
        .collect()
}

fn mdns_connect(mode_a: MulticastDnsMode, mode_b: MulticastDnsMode) {
    common::install_crypto_provider();
    let env = Env::get();
    let mut a = EnvPeer::new("a", "m-a", Gather::HOST, &env, mdns_pc(mode_a)).expect("peer a");
    let mut b = EnvPeer::new("b", "m-b", Gather::HOST, &env, mdns_pc(mode_b)).expect("peer b");
    a.enable_mdns().expect("mdns a");
    b.enable_mdns().expect("mdns b");
    a.pc.create_data_channel("mdns", None)
        .expect("data channel");
    let (offer, answer) = negotiate_in_sdp(&mut a, &mut b).expect("negotiate");
    for (who, sdp, mode, ip) in [
        ("a", &offer, mode_a, a.local.ip()),
        ("b", &answer, mode_b, b.local.ip()),
    ] {
        let lines = candidate_lines(sdp);
        assert!(
            !lines.is_empty(),
            "{who}'s description carries no candidates:\n{sdp}"
        );
        let hidden = mode == MulticastDnsMode::QueryAndGather;
        for l in &lines {
            assert_eq!(l.contains(".local "), hidden, "{who} ({mode:?}): {l}");
            assert_eq!(
                !l.contains(&ip.to_string()),
                hidden,
                "{who} ({mode:?}) leaks or hides {ip}: {l}"
            );
        }
    }
    let open = |p: &EnvPeer| {
        p.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
            )
        })
    };
    let ok = pump(&mut [&mut a, &mut b], Duration::from_secs(30), |p| {
        p[0].connected() && p[1].connected() && open(p[0]) && open(p[1])
    })
    .expect("pump");
    assert!(
        ok,
        "no connection over mDNS candidates: a {:?}, b {:?}",
        a.connection_state(),
        b.connection_state()
    );
    let (ta, tb) = (
        a.selected_pair_types().unwrap(),
        b.selected_pair_types().unwrap(),
    );
    assert_eq!(
        (ta.0.as_str(), tb.0.as_str()),
        ("host", "host"),
        "{ta:?} {tb:?}"
    );
}

#[test]
#[ignore = "needs the real-network test environment (a LAN with multicast): scripts/test-env/run.sh"]
fn test_multicast_dns_only_connection() {
    mdns_connect(
        MulticastDnsMode::QueryAndGather,
        MulticastDnsMode::QueryAndGather,
    );
}

#[test]
#[ignore = "needs the real-network test environment (a LAN with multicast): scripts/test-env/run.sh"]
fn test_multicast_dns_mixed_connection() {
    mdns_connect(
        MulticastDnsMode::QueryAndGather,
        MulticastDnsMode::QueryOnly,
    );
}
