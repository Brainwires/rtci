/// Platform-specific interface enumeration (FFI into the OS).
pub mod ffi;
pub use ffi::ifaces;
/// The local IPv6 addresses the operating system flags as RFC 4941 temporary (privacy)
/// addresses, for an ICE agent that may leave them unwrapped by mDNS
/// (draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.3).
///
/// Where it comes from: Linux and Android, `/proc/net/if_inet6` (`IFA_F_TEMPORARY`; shown on a
/// hosted Linux runner with a kernel-made temporary address); macOS and iOS, the
/// `SIOCGIFAFLAG_IN6` ioctl (`IN6_IFF_TEMPORARY`, from XNU's `netinet6/in6_var.h`; the request
/// is shown to be taken, a temporary address was not observed on a runner). Windows:
/// `ErrorKind::Unsupported`, no address is ever marked (no flag shown to tell a temporary
/// address from the stable one, see the Windows implementation). Other systems:
/// `ErrorKind::Unsupported`.
///
/// # Errors
///
/// The flags could not be read (the platform has no way, or the call failed).
pub use ffi::temporary_ipv6_addresses;

/// The addresses of `/proc/net/if_inet6` (one line per address: the address in 32 hex
/// digits, the interface index, the prefix length, the scope, the flags, the interface name;
/// all hex) whose flags carry `IFA_F_TEMPORARY` (0x01).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn parse_proc_if_inet6(text: &str) -> Vec<::std::net::Ipv6Addr> {
    const IFA_F_TEMPORARY: u32 = 0x01;
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (address, flags) = (fields.first()?, fields.get(4)?);
            if address.len() != 32 {
                return None;
            }
            let address = u128::from_str_radix(address, 16).ok()?;
            let flags = u32::from_str_radix(flags, 16).ok()?;
            (flags & IFA_F_TEMPORARY != 0).then(|| ::std::net::Ipv6Addr::from(address))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_if_inet6_lines_flagged_temporary_are_the_temporary_addresses() {
        // Lines as a Linux host with a stable (mngtmpaddr, 0x100) and a temporary (0x01)
        // address on eth0 writes them; the second temporary one is deprecated too (0x21).
        let text = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000021122fffe334455 02 40 20 80     eth0
2a0012340000000102112233aabbccdd 02 40 00 100     eth0
2a001234000000014d2f1a2b3c4d5e6f 02 40 00 01     eth0
2a001234000000019a8b7c6d5e4f3a2b 02 40 00 21     eth0
";
        assert_eq!(
            parse_proc_if_inet6(text),
            vec![
                "2a00:1234:0:1:4d2f:1a2b:3c4d:5e6f"
                    .parse::<::std::net::Ipv6Addr>()
                    .unwrap(),
                "2a00:1234:0:1:9a8b:7c6d:5e4f:3a2b".parse().unwrap(),
            ]
        );
    }

    /// Windows marks nothing: no flag there has been shown to tell a temporary address from
    /// the stable one, and a wrong guess would publish the stable address.
    #[test]
    fn windows_marks_no_address_temporary() {
        let result = temporary_ipv6_addresses();
        if cfg!(windows) {
            assert!(
                matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::Unsupported),
                "{result:?}"
            );
        }
    }

    #[test]
    fn the_temporary_addresses_the_system_reports_are_among_its_interface_addresses() {
        let temporary = match temporary_ipv6_addresses() {
            Ok(temporary) => temporary,
            // Not read on this system: nothing is marked.
            // (On macOS this is where a wrong `SIOCGIFAFLAG_IN6` request would show: the
            // kernel refuses it for the host's loopback `::1` at least.)
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                if cfg!(any(target_os = "linux", target_os = "macos")) {
                    panic!("the flags are read on this system: {e}");
                }
                return;
            }
            Err(e) => panic!("temporary_ipv6_addresses failed: {e}"),
        };
        let all: Vec<::std::net::IpAddr> = ifaces()
            .unwrap()
            .into_iter()
            .filter_map(|i| i.addr.map(|a| a.ip()))
            .collect();
        for address in &temporary {
            assert!(
                all.contains(&::std::net::IpAddr::V6(*address)),
                "{address} is not an interface address"
            );
            assert!(!address.is_loopback() && !address.is_unicast_link_local());
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// The next hop configured for an interface address.
#[non_exhaustive]
pub enum NextHop {
    /// The broadcast address of the attached network.
    Broadcast(::std::net::SocketAddr),
    /// The destination address, for point-to-point links.
    Destination(::std::net::SocketAddr),
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// The address family or link type an [`Interface`] entry describes.
#[non_exhaustive]
pub enum Kind {
    /// A raw packet-level (link layer) address.
    Packet,
    /// A link-layer address, such as a MAC address.
    Link,
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// An address family this crate does not recognise, carrying the raw OS value.
    Unknow(i32),
}

#[derive(Debug, Clone)]
/// One address on one local network interface.
///
/// ICE gathering walks these to produce host candidates.
pub struct Interface {
    /// The OS name of the interface, such as `en0` or `eth0`.
    pub name: String,
    /// Which address family or link type this entry describes.
    pub kind: Kind,
    /// The address itself, if the OS reported one.
    pub addr: Option<::std::net::SocketAddr>,
    /// The netmask for [`Self::addr`], if the OS reported one.
    pub mask: Option<::std::net::SocketAddr>,
    /// The broadcast or point-to-point destination address, if any.
    pub hop: Option<NextHop>,
}
