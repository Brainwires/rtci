use crate::ifaces::{Interface, Kind, NextHop};

use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
use std::io::Error;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

fn ss_to_netsa(ss: &SockaddrStorage) -> Option<SocketAddr> {
    match ss.family() {
        Some(AddressFamily::Inet) => ss
            .as_sockaddr_in()
            .map(|sin| SocketAddr::V4(SocketAddrV4::new(sin.ip(), sin.port()))),
        Some(AddressFamily::Inet6) => ss.as_sockaddr_in6().map(|sin6| {
            SocketAddr::V6(SocketAddrV6::new(
                sin6.ip(),
                sin6.port(),
                sin6.flowinfo(),
                sin6.scope_id(),
            ))
        }),
        _ => None,
    }
}

/// Query the local system for all interface addresses.
pub fn ifaces() -> Result<Vec<Interface>, Error> {
    let mut ret = Vec::new();
    for ifa in nix::ifaddrs::getifaddrs()? {
        if let Some(kind) = ifa
            .address
            .as_ref()
            .and_then(SockaddrStorage::family)
            .and_then(|af| match af {
                AddressFamily::Inet => Some(Kind::Ipv4),
                AddressFamily::Inet6 => Some(Kind::Ipv6),
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "illumos",
                    target_os = "fuchsia",
                    target_os = "solaris"
                ))]
                AddressFamily::Packet => Some(Kind::Packet),
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "illumos",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                AddressFamily::Link => Some(Kind::Link),
                _ => None,
            })
        {
            let name = ifa.interface_name;
            let dst = ifa.destination.as_ref().and_then(ss_to_netsa);
            let broadcast = ifa.broadcast.as_ref().and_then(ss_to_netsa);
            let hop = dst
                .map(NextHop::Destination)
                .or(broadcast.map(NextHop::Broadcast));
            let addr = ifa.address.as_ref().and_then(ss_to_netsa);
            let mask = ifa.netmask.as_ref().and_then(ss_to_netsa);

            ret.push(Interface {
                name,
                kind,
                addr,
                mask,
                hop,
            });
        }
    }

    Ok(ret)
}

/// The local IPv6 addresses the operating system flags as RFC 4941 temporary addresses.
///
/// Linux and Android: `/proc/net/if_inet6`, whose fifth column is the address's flags
/// (`IFA_F_TEMPORARY`, 0x01, in `linux/if_addr.h`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn temporary_ipv6_addresses() -> Result<Vec<std::net::Ipv6Addr>, Error> {
    let text = std::fs::read_to_string("/proc/net/if_inet6")?;
    Ok(crate::ifaces::parse_proc_if_inet6(&text))
}

/// The local IPv6 addresses the operating system flags as RFC 4941 temporary addresses.
///
/// macOS and iOS: the `SIOCGIFAFLAG_IN6` ioctl on each IPv6 address `getifaddrs` lists, as
/// `ifconfig` asks for an address's flags. XNU `bsd/netinet6/in6_var.h`:
/// `#define IN6_IFF_TEMPORARY       0x0080  /* temporary (anonymous) address. */` and
/// `#define SIOCGIFAFLAG_IN6        _IOWR('i', 73, struct in6_ifreq)`. A hosted macOS runner
/// showed the kernel takes the request (for `::1`); a temporary address was not observed
/// there (it has none). An address the kernel no longer has is skipped; any other refusal
/// is an error, so that a request the kernel does not take cannot pass for "no temporary
/// address".
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn temporary_ipv6_addresses() -> Result<Vec<std::net::Ipv6Addr>, Error> {
    // XNU bsd/netinet6/in6_var.h: "#define IN6_IFF_TEMPORARY 0x0080 /* temporary (anonymous)
    // address. */"
    const IN6_IFF_TEMPORARY: libc::c_int = 0x0080;
    let mut out = Vec::new();
    for (address, flags) in ipv6_address_flags()? {
        match flags {
            Ok(flags) if flags & IN6_IFF_TEMPORARY != 0 => out.push(address),
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Each IPv6 address `getifaddrs` lists, with its `in6_ifaddr` flags (`SIOCGIFAFLAG_IN6`) or
/// the error the kernel answered.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(clippy::type_complexity)]
pub(crate) fn ipv6_address_flags()
-> Result<Vec<(std::net::Ipv6Addr, Result<libc::c_int, Error>)>, Error> {
    // `_IOWR('i', 73, struct in6_ifreq)`, the structure being 288 bytes (the name, then a
    // union whose largest member is `struct icmp6_ifstat`).
    const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xc120_6949;

    #[repr(C)]
    union In6IfreqData {
        addr: libc::sockaddr_in6,
        flags6: libc::c_int,
        _size: [u64; 34],
    }
    #[repr(C)]
    struct In6Ifreq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: In6IfreqData,
    }
    const _: () = assert!(std::mem::size_of::<In6Ifreq>() == 288);

    struct Socket(libc::c_int);
    impl Drop for Socket {
        fn drop(&mut self) {
            // SAFETY: the descriptor is ours and closed once.
            unsafe { libc::close(self.0) };
        }
    }

    // SAFETY: a plain socket(2) call; the descriptor is closed by `Socket`.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    let socket = Socket(fd);
    let mut out = Vec::new();
    for ifa in nix::ifaddrs::getifaddrs()? {
        let Some(sin6) = ifa.address.as_ref().and_then(|a| a.as_sockaddr_in6()) else {
            continue;
        };
        let name = ifa.interface_name.as_bytes();
        if name.len() >= libc::IFNAMSIZ {
            continue;
        }
        // SAFETY: an all-zero `In6Ifreq` is valid (integers and arrays only).
        let mut request: In6Ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.name.iter_mut().zip(name) {
            *dst = *src as libc::c_char;
        }
        // The address as the kernel listed it (a link-local one keeps its embedded scope),
        // as `ifconfig` passes it.
        // SAFETY: `as_ptr` points to the `sockaddr_in6` the storage holds.
        request.data.addr = unsafe { *(sin6.as_ptr() as *const libc::sockaddr_in6) };
        // SAFETY: the request is the 288-byte `struct in6_ifreq` the ioctl number encodes.
        let rc = unsafe { libc::ioctl(socket.0, SIOCGIFAFLAG_IN6, &mut request) };
        let flags = if rc < 0 {
            Err(Error::last_os_error())
        } else {
            // SAFETY: the kernel wrote `ifru_flags6`.
            Ok(unsafe { request.data.flags6 })
        };
        out.push((sin6.ip(), flags));
    }
    Ok(out)
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    /// The kernel takes the request: it answers with the flags of the loopback address,
    /// which every host has and which is never temporary.
    #[test]
    fn the_kernel_answers_the_address_flags_request_for_the_loopback_address() {
        let flags = super::ipv6_address_flags().unwrap();
        let loopback = flags
            .iter()
            .find(|(address, _)| address.is_loopback())
            .expect("::1 on lo0");
        match &loopback.1 {
            Ok(flags) => assert_eq!(flags & 0x0080, 0, "::1 is not temporary"),
            Err(e) => panic!("SIOCGIFAFLAG_IN6 refused for ::1: {e}"),
        }
    }
}

/// The local IPv6 addresses the operating system flags as RFC 4941 temporary addresses.
///
/// Other Unix systems: not read; always `ErrorKind::Unsupported` (no address is marked, so
/// every one stays hidden).
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub fn temporary_ipv6_addresses() -> Result<Vec<std::net::Ipv6Addr>, Error> {
    Err(Error::new(
        std::io::ErrorKind::Unsupported,
        "temporary address flags are not read on this system",
    ))
}
