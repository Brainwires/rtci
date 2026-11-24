#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use self::windows::{ifaces, temporary_ipv6_addresses};

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use self::unix::{ifaces, temporary_ipv6_addresses};

/// Enumerates local network interfaces.
///
/// This is the fallback for platforms that are neither Windows nor Unix: it always returns
/// [`ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported). ICE gathering treats that as
/// "no host candidates from interface enumeration" and falls back to the addresses the caller
/// supplied explicitly.
///
/// # Errors
///
/// Always fails on such platforms.
#[cfg(not(any(target_family = "windows", target_family = "unix")))]
pub fn ifaces() -> Result<Vec<super::Interface>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ifaces is not supported on this platform",
    ))
}

/// The local IPv6 addresses the operating system flags as RFC 4941 temporary addresses: not
/// read on this platform, always [`ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported).
///
/// # Errors
///
/// Always fails on such platforms.
#[cfg(not(any(target_family = "windows", target_family = "unix")))]
pub fn temporary_ipv6_addresses() -> Result<Vec<std::net::Ipv6Addr>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "temporary_ipv6_addresses is not supported on this platform",
    ))
}
