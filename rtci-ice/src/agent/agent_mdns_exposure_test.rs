//! The two opt-in cases in which `QueryAndGather` leaves a host address unwrapped
//! (draft-ietf-mmusic-mdns-ice-candidates Sections 3.1.1 step 1, 3.1.2.2 and 3.1.2.3; see
//! `crate::mdns::exposure`), and that nothing else is ever unwrapped.

use std::net::Ipv6Addr;
use std::time::Instant;

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::mdns::MulticastDnsMode;

/// Global unicast addresses (the documentation ranges are not global, so they cannot serve).
const PUBLIC_V4: &str = "93.184.216.34";
const PUBLIC_V6: &str = "2a00:1450:4001:80b::1";
const STABLE_V6: &str = "2a00:1450:4001:80b::2";

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn agent(mode: MulticastDnsMode, known_public: bool, temporary: bool) -> Agent {
    Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            multicast_dns_mode: mode,
            multicast_dns_first_query_delay: Some(false),
            multicast_dns_expose_known_public_addresses: known_public,
            multicast_dns_expose_temporary_ipv6_addresses: temporary,
            urls: vec![Url::parse_url("stun:stun.example.org:3478").unwrap()],
            ..Default::default()
        }),
        provider(),
    )
    .unwrap()
}

fn host(address: &str, port: u16) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// The server-reflexive candidate a STUN server's answer `mapped` makes for `base`.
fn srflx(mapped: &str, mapped_port: u16, base: &str, base_port: u16) -> Candidate {
    CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: mapped.to_owned(),
            port: mapped_port,
            component: 1,
            ..Default::default()
        },
        rel_addr: base.to_owned(),
        rel_port: base_port,
        url: Some("stun:stun.example.org:3478".to_owned()),
    }
    .new_candidate_server_reflexive()
    .unwrap()
}

fn restart(a: &mut Agent) {
    a.restart(Instant::now(), String::new(), String::new(), false)
        .unwrap();
}

/// The address each host candidate on `ip` is written with.
fn host_addresses(a: &Agent, ip: &str) -> Vec<String> {
    let ip: IpAddr = ip.parse().unwrap();
    a.get_local_candidates()
        .iter()
        .filter(|c| c.candidate_type() == CandidateType::Host && c.addr().ip() == ip)
        .map(|c| c.address().to_owned())
        .collect()
}

fn is_name(address: &str) -> bool {
    address.ends_with(".local") && address.len() == 36 + ".local".len()
}

fn hidden(a: &Agent, ip: &str) -> bool {
    let addresses = host_addresses(a, ip);
    !addresses.is_empty() && addresses.iter().all(|address| is_name(address))
}

fn exposed(a: &Agent, ip: &str) -> bool {
    let addresses = host_addresses(a, ip);
    !addresses.is_empty() && addresses.iter().all(|address| address == ip)
}

/// One gathering: the public and the private host, then the STUN answer for the public one
/// (no NAT: the mapped address is its base).
fn gather_public_and_private(a: &mut Agent) {
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    a.add_local_candidate(host("192.168.1.3", 5001)).unwrap();
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();
}

/// The settings off (the default): everything is hidden as before, across restarts, and the
/// server-reflexive candidate keeps the Section 3.1.2.2 form.
#[test]
fn test_without_the_settings_every_host_address_stays_hidden_across_restarts() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, false, false);
    assert!(!AgentConfig::default().multicast_dns_expose_known_public_addresses);
    assert!(!AgentConfig::default().multicast_dns_expose_temporary_ipv6_addresses);
    a.set_temporary_ipv6_addresses(vec![PUBLIC_V6.parse().unwrap()]);
    for _ in 0..3 {
        gather_public_and_private(&mut a);
        a.add_local_candidate(host(PUBLIC_V6, 5002)).unwrap();
        assert!(hidden(&a, PUBLIC_V4) && hidden(&a, "192.168.1.3") && hidden(&a, PUBLIC_V6));
        restart(&mut a);
    }
    a.close().unwrap();
}

/// Section 3.1.2.2: the mDNS candidate goes first; the server-reflexive candidate equal to
/// its base follows, not redundant, raddr 0.0.0.0 rport 9; the gathering that shows the
/// address public is not changed ("future ICE gathering phases"); from the next restart the
/// host candidate carries the address, and only that one: the private address stays hidden.
#[test]
fn test_an_address_shown_public_is_unwrapped_from_the_next_gathering_only() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    gather_public_and_private(&mut a);
    assert!(
        hidden(&a, PUBLIC_V4),
        "the gathering that shows it keeps the name"
    );
    let reflexive: Vec<String> = a
        .get_local_candidates()
        .iter()
        .filter(|c| c.candidate_type() == CandidateType::ServerReflexive)
        .map(|c| c.marshal())
        .collect();
    assert_eq!(reflexive.len(), 1, "not redundant with the mDNS candidate");
    assert!(
        reflexive[0].contains(&format!("{PUBLIC_V4} 5000 typ srflx raddr 0.0.0.0 rport 9")),
        "{}",
        reflexive[0]
    );
    // A host candidate added later in the same gathering (TCP, another socket) still hides.
    a.add_local_candidate(host(PUBLIC_V4, 5003)).unwrap();
    assert!(hidden(&a, PUBLIC_V4));

    restart(&mut a);
    gather_public_and_private(&mut a);
    assert!(exposed(&a, PUBLIC_V4));
    assert!(hidden(&a, "192.168.1.3"));
    assert!(
        a.get_local_candidates()
            .iter()
            .all(|c| c.candidate_type() != CandidateType::ServerReflexive),
        "the server-reflexive candidate is redundant with the host candidate now"
    );
    a.close().unwrap();
}

/// "a restart re-evaluates": each restart takes only what the gathering just before showed;
/// a gathering that does not show the address public again wraps it from the next restart.
#[test]
fn test_each_restart_takes_only_what_the_gathering_before_showed() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    gather_public_and_private(&mut a);
    restart(&mut a);
    // This gathering's STUN answer is a NAT's now: not public.
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert!(exposed(&a, PUBLIC_V4));
    a.add_local_candidate(srflx("93.184.216.99", 6000, PUBLIC_V4, 5000))
        .unwrap();
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert!(
        hidden(&a, PUBLIC_V4),
        "the cache was dropped at the restart"
    );
    // Shown again: unwrapped again from the next restart.
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert!(exposed(&a, PUBLIC_V4));
    a.close().unwrap();
}

/// Section 3.1.2.2: "if the set of STUN servers changes, any cached information SHOULD be
/// discarded". The same set (in another order, other credentials) keeps it.
#[test]
fn test_a_change_of_the_stun_servers_discards_what_was_shown_public() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    gather_public_and_private(&mut a);
    a.set_ice_servers(vec![Url::parse_url("stun:stun.example.org:3478").unwrap()]);
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert!(exposed(&a, PUBLIC_V4), "the same set keeps it");
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();

    a.set_ice_servers(vec![
        Url::parse_url("stun:stun.example.net:3478").unwrap(),
        Url::parse_url("stun:stun.example.org:3478").unwrap(),
    ]);
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert!(hidden(&a, PUBLIC_V4), "a new set of servers forgets it");
    a.close().unwrap();
}

/// A STUN server cannot make the agent unwrap an address it does not have: the address is
/// recorded only when the server-reflexive candidate's base is the address of one of the
/// agent's own host candidates, and the mapped address is that base (no NAT).
#[test]
fn test_only_an_address_of_the_agents_own_interfaces_is_recorded_public() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    a.add_local_candidate(host("192.168.1.3", 5001)).unwrap();
    // Mapped and base agree, but the agent holds no host candidate on that address.
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();
    // A NAT: the mapped address is not the base.
    a.add_local_candidate(srflx("93.184.216.35", 5000, "192.168.1.3", 5001))
        .unwrap();
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    a.add_local_candidate(host("93.184.216.35", 5004)).unwrap();
    a.add_local_candidate(host("192.168.1.3", 5001)).unwrap();
    assert!(hidden(&a, PUBLIC_V4));
    assert!(hidden(&a, "93.184.216.35"));
    assert!(hidden(&a, "192.168.1.3"));
    a.close().unwrap();
}

/// The hard check: a private, loopback, link-local, unique-local, CGNAT or otherwise
/// non-global address is never unwrapped, even when the server-reflexive candidate equals it
/// and when the application marks it temporary.
#[test]
fn test_a_non_global_address_is_never_unwrapped() {
    let not_global = [
        "10.0.0.5",
        "172.16.4.4",
        "192.168.1.3",
        "100.64.0.5",
        "127.0.0.1",
        "169.254.10.10",
        "192.0.2.7",
        "fd00::5",
        "fe80::5",
        "::1",
        "2001:db8::5",
        "64:ff9b::5db8:d822",
        "::ffff:93.184.216.34",
    ];
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, true);
    a.set_temporary_ipv6_addresses(
        not_global
            .iter()
            .filter_map(|ip| ip.parse::<Ipv6Addr>().ok())
            .collect(),
    );
    for round in 0..2 {
        for (i, ip) in not_global.iter().enumerate() {
            let port = 5000 + i as u16;
            a.add_local_candidate(host(ip, port)).unwrap();
            a.add_local_candidate(srflx(ip, port, ip, port)).unwrap();
        }
        for ip in not_global {
            assert!(hidden(&a, ip), "{ip} unwrapped in round {round}");
        }
        restart(&mut a);
    }
    a.close().unwrap();
}

/// Section 3.1.2.3: only an address the application marked temporary is unwrapped, and only
/// with the setting; an unmarked address (the stable one) stays hidden.
#[test]
fn test_only_a_marked_temporary_ipv6_address_is_unwrapped() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, false, true);
    a.set_temporary_ipv6_addresses(vec![PUBLIC_V6.parse().unwrap()]);
    a.add_local_candidate(host(PUBLIC_V6, 5000)).unwrap();
    a.add_local_candidate(host(STABLE_V6, 5001)).unwrap();
    a.add_local_candidate(host(PUBLIC_V4, 5002)).unwrap();
    a.add_local_candidate(host("192.168.1.3", 5003)).unwrap();
    assert!(exposed(&a, PUBLIC_V6));
    assert!(hidden(&a, STABLE_V6));
    assert!(hidden(&a, PUBLIC_V4));
    assert!(hidden(&a, "192.168.1.3"));
    assert!(
        a.get_local_candidates()[0]
            .marshal()
            .contains(&format!("{PUBLIC_V6} 5000 typ host"))
    );

    // Unmarked again: candidates added afterwards hide it.
    a.set_temporary_ipv6_addresses(vec![]);
    restart(&mut a);
    a.add_local_candidate(host(PUBLIC_V6, 5000)).unwrap();
    assert!(hidden(&a, PUBLIC_V6));
    a.close().unwrap();
}

/// Both settings narrow what `QueryAndGather` hides; in the other modes nothing is hidden and
/// they change nothing.
#[test]
fn test_the_settings_change_nothing_outside_query_and_gather() {
    for mode in [MulticastDnsMode::QueryOnly, MulticastDnsMode::Disabled] {
        let mut lines = vec![];
        for on in [false, true] {
            let mut a = agent(mode, on, on);
            a.set_temporary_ipv6_addresses(vec![PUBLIC_V6.parse().unwrap()]);
            gather_public_and_private(&mut a);
            a.add_local_candidate(host(PUBLIC_V6, 5002)).unwrap();
            restart(&mut a);
            gather_public_and_private(&mut a);
            a.add_local_candidate(host(PUBLIC_V6, 5002)).unwrap();
            assert!(exposed(&a, PUBLIC_V4) && exposed(&a, "192.168.1.3"));
            assert!(a.mdns_known_public.is_empty(), "{mode:?}: nothing recorded");
            lines.push(
                a.get_local_candidates()
                    .iter()
                    .map(|c| (c.candidate_type(), c.address().to_owned(), c.port()))
                    .collect::<Vec<_>>(),
            );
            a.close().unwrap();
        }
        assert_eq!(lines[0], lines[1], "{mode:?}");
    }
}

/// A restart taken back (the local offer was rolled back) takes back what its gathering
/// learned and its generation: the session that showed the address keeps hiding it.
#[test]
fn test_a_reverted_restart_does_not_unwrap_in_the_gathering_that_showed_the_address() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    a.apply_restart_revertible(Instant::now(), false).unwrap();
    assert!(a.revert_restart(Instant::now()));
    a.add_local_candidate(host(PUBLIC_V4, 5005)).unwrap();
    assert!(hidden(&a, PUBLIC_V4));
    a.close().unwrap();
}

/// A restart that keeps the local candidates hands them to the new generation, a new
/// gathering phase: the kept host candidate takes the new generation's form (its address
/// once shown public; its name again once no longer), the server-reflexive candidate it
/// makes redundant goes, and adding it again does not duplicate it.
#[test]
fn test_a_host_candidate_kept_across_a_restart_takes_the_new_generations_form() {
    let mut a = agent(MulticastDnsMode::QueryAndGather, true, false);
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    a.add_local_candidate(host("192.168.1.3", 5001)).unwrap();
    a.add_local_candidate(srflx(PUBLIC_V4, 5000, PUBLIC_V4, 5000))
        .unwrap();
    let name = host_addresses(&a, PUBLIC_V4)[0].clone();
    a.restart(Instant::now(), String::new(), String::new(), true)
        .unwrap();
    assert!(exposed(&a, PUBLIC_V4));
    assert!(hidden(&a, "192.168.1.3"));
    assert!(
        a.get_local_candidates()
            .iter()
            .all(|c| c.candidate_type() != CandidateType::ServerReflexive),
        "redundant with the host candidate now"
    );
    a.add_local_candidate(host(PUBLIC_V4, 5000)).unwrap();
    assert_eq!(host_addresses(&a, PUBLIC_V4).len(), 1);

    // This generation does not show it public again: the next restart wraps it again, under
    // the name it had.
    a.restart(Instant::now(), String::new(), String::new(), true)
        .unwrap();
    assert_eq!(host_addresses(&a, PUBLIC_V4), vec![name]);
    a.close().unwrap();
}
