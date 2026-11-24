use super::is_global_unicast;
use std::net::IpAddr;

/// The hard check behind both exposure settings: only globally reachable unicast addresses
/// pass; private, loopback, link-local, unique-local, CGNAT, documentation, multicast,
/// IPv4-mapped and NAT64 addresses never do.
#[test]
fn test_only_global_unicast_addresses_may_be_exposed() {
    let global = [
        "93.184.216.34",
        "1.1.1.1",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "2a00:1450:4001:80b::1",
        "2600::1",
        "2001:4860:4860::8888",
    ];
    let not_global = [
        "0.0.0.0",
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.251",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:93.184.216.34",
        "64:ff9b::5db8:d822",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:1ff::1",
        "2001:db8::1",
        "2002:5db8:d822::1",
        "3fff::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "fec0::1",
        "ff02::fb",
    ];
    for ip in global {
        assert!(is_global_unicast(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    for ip in not_global {
        assert!(!is_global_unicast(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
}
