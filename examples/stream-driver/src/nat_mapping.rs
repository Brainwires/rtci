//! NAT-assisted candidates (RFC 6544 section 5.3, RFC 8445 section 5.1.1.2): an opt-in client of
//! the Port Control Protocol (PCP, RFC 6887) with a fallback to NAT-PMP (RFC 6886), asking the
//! gateway for a port mapping. Nothing here runs unless the application calls it, and it
//! adds no dependency: one UDP socket of the driver's [`Runtime`].
//!
//! The engine needs nothing new: the mapped address is a candidate the application adds
//! itself, a server-reflexive one whose related address is the base (RFC 6544 section 5.3
//! calls it NAT-assisted; [`candidate_line`] writes it with the type preference 105 RFC 6544
//! section 4.2 recommends). Finding the gateway is the application's: this module does not
//! read routing tables (that would need a platform dependency); the default gateway's address
//! is passed in.
//!
//! [`map_port`] sends a PCP MAP request (RFC 6887 section 11) to `gateway:5351`, retransmitted
//! as section 8.1.1 says (3 s first, doubling, here up to [`MappingConfig::attempts`] times);
//! a gateway that answers with UNSUPP_VERSION, or with a NAT-PMP response, is asked again with
//! NAT-PMP (RFC 6886 section 3.3, retransmitted from 250 ms doubling, at most nine times,
//! section 3.1). Mappings expire: renew them with [`map_port`] again before half their
//! lifetime has passed, and delete one with a lifetime of 0.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::runtime::{AsyncUdpSocket, Runtime};

/// The port PCP and NAT-PMP servers listen on (RFC 6887 section 19.1, RFC 6886 section 3).
pub const SERVER_PORT: u16 = 5351;

/// The transport a mapping is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDP (IANA protocol 17; NAT-PMP opcode 1).
    Udp,
    /// TCP (IANA protocol 6; NAT-PMP opcode 2).
    Tcp,
}

impl Protocol {
    fn iana(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
        }
    }

    fn nat_pmp_opcode(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Tcp => 2,
        }
    }
}

/// Which protocol answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtocol {
    /// PCP (RFC 6887).
    Pcp,
    /// NAT-PMP (RFC 6886).
    NatPmp,
}

/// A mapping the gateway granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The external address and port: the NAT-assisted candidate's address.
    pub external: SocketAddr,
    /// The internal port it maps to.
    pub internal_port: u16,
    /// How long it lasts.
    pub lifetime: Duration,
    /// Which protocol granted it.
    pub protocol: MappingProtocol,
}

/// How [`map_port`] asks.
#[derive(Debug, Clone)]
pub struct MappingConfig {
    /// The lifetime asked for (RFC 6886 section 3.3 recommends 7200 s; 0 deletes).
    pub lifetime: Duration,
    /// The external port suggested (0: none).
    pub suggested_port: u16,
    /// Requests sent per protocol before giving up.
    pub attempts: u32,
    /// The first PCP retransmission interval (RFC 6887 section 8.1.1: 3 s).
    pub pcp_initial: Duration,
    /// The first NAT-PMP retransmission interval (RFC 6886 section 3.1: 250 ms).
    pub nat_pmp_initial: Duration,
    /// Skip PCP and ask with NAT-PMP only.
    pub nat_pmp_only: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(7200),
            suggested_port: 0,
            attempts: 4,
            pcp_initial: Duration::from_secs(3),
            nat_pmp_initial: Duration::from_millis(250),
            nat_pmp_only: false,
        }
    }
}

/// PCP result code UNSUPP_VERSION (RFC 6887 section 7.4); NAT-PMP's is 1 too.
const UNSUPP_VERSION: u8 = 1;

fn mapped_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn unmapped(ip: Ipv6Addr) -> IpAddr {
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

/// A PCP MAP request (RFC 6887 sections 7.1 and 11.1): 24-byte header, 36-byte MAP opcode.
pub fn pcp_map_request(
    client: IpAddr,
    nonce: [u8; 12],
    protocol: Protocol,
    internal_port: u16,
    config: &MappingConfig,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(60);
    m.push(2); // version
    m.push(1); // R = 0, opcode MAP
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&(config.lifetime.as_secs().min(u64::from(u32::MAX)) as u32).to_be_bytes());
    m.extend_from_slice(&mapped_v6(client).octets());
    m.extend_from_slice(&nonce);
    m.push(protocol.iana());
    m.extend_from_slice(&[0, 0, 0]);
    m.extend_from_slice(&internal_port.to_be_bytes());
    m.extend_from_slice(&config.suggested_port.to_be_bytes());
    // Suggested external address: none (the IPv4-mapped all-zeros address for IPv4).
    let none = if client.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()
    } else {
        Ipv6Addr::UNSPECIFIED
    };
    m.extend_from_slice(&none.octets());
    m
}

/// What a PCP response says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcpAnswer {
    /// SUCCESS with the mapping.
    Mapped(Mapping),
    /// Another result code.
    Refused(u8),
}

/// Parses a PCP MAP response to the request with `nonce` (RFC 6887 sections 7.2 and 11.1).
/// `None` for anything else (not PCP, not a MAP response, another nonce).
pub fn parse_pcp_map_response(
    data: &[u8],
    nonce: [u8; 12],
    protocol: Protocol,
) -> Option<PcpAnswer> {
    if data.len() < 60 || data[0] != 2 || data[1] != 0x81 {
        // A version-1-or-2 error answer to an unknown version is shorter; see `answers_nat_pmp`.
        if data.len() >= 4 && data[0] == 2 && data[1] & 0x80 != 0 && data[3] == UNSUPP_VERSION {
            return Some(PcpAnswer::Refused(UNSUPP_VERSION));
        }
        return None;
    }
    let result = data[3];
    if result != 0 {
        return Some(PcpAnswer::Refused(result));
    }
    if data[24..36] != nonce || data[36] != protocol.iana() {
        return None;
    }
    let lifetime = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let internal_port = u16::from_be_bytes([data[40], data[41]]);
    let external_port = u16::from_be_bytes([data[42], data[43]]);
    let ip: [u8; 16] = data[44..60].try_into().ok()?;
    Some(PcpAnswer::Mapped(Mapping {
        external: SocketAddr::new(unmapped(Ipv6Addr::from(ip)), external_port),
        internal_port,
        lifetime: Duration::from_secs(u64::from(lifetime)),
        protocol: MappingProtocol::Pcp,
    }))
}

/// A NAT-PMP external address request (RFC 6886 section 3.2).
pub fn nat_pmp_address_request() -> [u8; 2] {
    [0, 0]
}

/// A NAT-PMP mapping request (RFC 6886 section 3.3).
pub fn nat_pmp_map_request(
    protocol: Protocol,
    internal_port: u16,
    config: &MappingConfig,
) -> [u8; 12] {
    let mut m = [0u8; 12];
    m[1] = protocol.nat_pmp_opcode();
    m[4..6].copy_from_slice(&internal_port.to_be_bytes());
    m[6..8].copy_from_slice(&config.suggested_port.to_be_bytes());
    m[8..12].copy_from_slice(
        &(config.lifetime.as_secs().min(u64::from(u32::MAX)) as u32).to_be_bytes(),
    );
    m
}

/// A NAT-PMP answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPmpAnswer {
    /// The external IPv4 address (opcode 128).
    Address(Ipv4Addr),
    /// A mapping (opcode 129 or 130): internal port, external port, lifetime.
    Mapped(u16, u16, Duration),
    /// A result code other than success.
    Refused(u16),
}

/// Parses a NAT-PMP response to `opcode` (RFC 6886 sections 3.2, 3.3, 3.5).
pub fn parse_nat_pmp_response(data: &[u8], opcode: u8) -> Option<NatPmpAnswer> {
    if data.len() < 8 || data[0] != 0 || data[1] != 128 + opcode {
        return None;
    }
    let result = u16::from_be_bytes([data[2], data[3]]);
    if result != 0 {
        return Some(NatPmpAnswer::Refused(result));
    }
    match opcode {
        0 if data.len() >= 12 => Some(NatPmpAnswer::Address(Ipv4Addr::new(
            data[8], data[9], data[10], data[11],
        ))),
        1 | 2 if data.len() >= 16 => Some(NatPmpAnswer::Mapped(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            Duration::from_secs(u64::from(u32::from_be_bytes(data[12..16].try_into().ok()?))),
        )),
        _ => None,
    }
}

/// Whether `data` is a NAT-PMP response (version 0, a response opcode): a gateway that speaks
/// NAT-PMP only answering a PCP request (RFC 6887 section 9).
fn answers_nat_pmp(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0 && data[1] & 0x80 != 0
}

/// Sends `request` to `to`, retransmitted from `initial` doubling, `attempts` times, and
/// returns the first answer `accept` takes.
async fn exchange<T>(
    runtime: &dyn Runtime,
    socket: &dyn AsyncUdpSocket,
    to: SocketAddr,
    request: &[u8],
    initial: Duration,
    attempts: u32,
    mut accept: impl FnMut(&[u8]) -> Option<T>,
) -> io::Result<Option<T>> {
    let mut wait = initial;
    let mut buf = [0u8; 1100];
    for _ in 0..attempts {
        socket.send_to(request, to).await?;
        let deadline = runtime.now() + wait;
        loop {
            match crate::runtime::timeout_at(runtime, deadline, socket.recv_from(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => break,
                Ok(Err(e)) => return Err(e),
                // RFC 6887 section 8.3 / RFC 6886 section 3.1: only answers from the server.
                Ok(Ok((n, from))) if from == to => {
                    if let Some(t) = accept(&buf[..n]) {
                        return Ok(Some(t));
                    }
                }
                Ok(Ok(_)) => {}
            }
        }
        wait *= 2;
    }
    Ok(None)
}

/// Asks the gateway at `gateway` for a mapping of `internal_port` on `local_ip` (the
/// interface the gateway is reached from): PCP first, NAT-PMP when the gateway does not speak
/// PCP. `Ok(None)` when no gateway answered; an error when it refused.
pub async fn map_port(
    runtime: &dyn Runtime,
    gateway: IpAddr,
    local_ip: IpAddr,
    protocol: Protocol,
    internal_port: u16,
    config: &MappingConfig,
) -> io::Result<Option<Mapping>> {
    let socket = runtime.bind_udp(SocketAddr::new(local_ip, 0))?;
    let server = SocketAddr::new(gateway, SERVER_PORT);
    map_port_at(
        runtime,
        socket.as_ref(),
        server,
        local_ip,
        protocol,
        internal_port,
        config,
    )
    .await
}

/// [`map_port`] from `socket` to the server at `server`.
async fn map_port_at(
    runtime: &dyn Runtime,
    socket: &dyn AsyncUdpSocket,
    server: SocketAddr,
    local_ip: IpAddr,
    protocol: Protocol,
    internal_port: u16,
    config: &MappingConfig,
) -> io::Result<Option<Mapping>> {
    let gateway = server.ip();
    if !config.nat_pmp_only {
        let nonce: [u8; 12] = rand_nonce();
        let request = pcp_map_request(local_ip, nonce, protocol, internal_port, config);
        let mut nat_pmp = false;
        let answer = exchange(
            runtime,
            socket,
            server,
            &request,
            config.pcp_initial,
            config.attempts,
            |data| {
                if answers_nat_pmp(data) {
                    nat_pmp = true;
                    return Some(None);
                }
                parse_pcp_map_response(data, nonce, protocol).map(Some)
            },
        )
        .await?;
        match answer.flatten() {
            Some(PcpAnswer::Mapped(mapping)) => return Ok(Some(mapping)),
            Some(PcpAnswer::Refused(UNSUPP_VERSION)) => {}
            Some(PcpAnswer::Refused(code)) => {
                return Err(io::Error::other(format!("PCP MAP refused: result {code}")));
            }
            None if nat_pmp => {}
            None => return Ok(None),
        }
    }
    // NAT-PMP is IPv4 only (RFC 6886 section 1).
    if !gateway.is_ipv4() {
        return Ok(None);
    }
    let attempts = config.attempts.min(9);
    let address = exchange(
        runtime,
        socket,
        server,
        &nat_pmp_address_request(),
        config.nat_pmp_initial,
        attempts,
        |data| parse_nat_pmp_response(data, 0),
    )
    .await?;
    let external_ip = match address {
        Some(NatPmpAnswer::Address(ip)) => ip,
        Some(NatPmpAnswer::Refused(code)) => {
            return Err(io::Error::other(format!("NAT-PMP refused: result {code}")));
        }
        _ => return Ok(None),
    };
    let opcode = protocol.nat_pmp_opcode();
    let mapped = exchange(
        runtime,
        socket,
        server,
        &nat_pmp_map_request(protocol, internal_port, config),
        config.nat_pmp_initial,
        attempts,
        |data| parse_nat_pmp_response(data, opcode),
    )
    .await?;
    match mapped {
        Some(NatPmpAnswer::Mapped(internal, external, lifetime)) => Ok(Some(Mapping {
            external: SocketAddr::new(IpAddr::V4(external_ip), external),
            internal_port: internal,
            lifetime,
            protocol: MappingProtocol::NatPmp,
        })),
        Some(NatPmpAnswer::Refused(code)) => Err(io::Error::other(format!(
            "NAT-PMP mapping refused: result {code}"
        ))),
        _ => Ok(None),
    }
}

/// A nonce for a PCP MAP request (RFC 6887 section 11.1: random, kept for renewals). From the
/// standard library's hasher seed: no random-number dependency.
fn rand_nonce() -> [u8; 12] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; 12];
    for chunk in out.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or_default(),
        );
        let v = h.finish().to_be_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    out
}

/// The NAT-assisted candidate of `mapping` for the local `base` (RFC 6544 sections 4.2 and
/// 5.3): a server-reflexive candidate with the type preference 105, for the application to add
/// with `add_local_candidate`. Over TCP `tcp_type` names its direction (RFC 6544 section 4.2:
/// for NAT-assisted candidates simultaneous-open 6, active 4, passive 2; an active one is
/// signalled on port 9).
pub fn candidate_line(
    mapping: &Mapping,
    base: SocketAddr,
    tcp_type: Option<&str>,
    foundation: u32,
) -> String {
    let (transport, direction) = match tcp_type {
        None => ("udp", None),
        Some(t) => (
            "tcp",
            Some(match t {
                "so" => 6u32,
                "active" => 4,
                _ => 2,
            }),
        ),
    };
    let local_preference = match direction {
        Some(d) => (d << 13) + 8191,
        None => 65535,
    };
    let priority = (105u32 << 24) + (local_preference << 8) + 255;
    let port = if tcp_type == Some("active") {
        9
    } else {
        mapping.external.port()
    };
    let mut line = format!(
        "candidate:{foundation} 1 {transport} {priority} {} {port} typ srflx raddr {} rport {}",
        mapping.external.ip(),
        base.ip(),
        base.port()
    );
    if let Some(t) = tcp_type {
        line.push_str(&format!(" tcptype {t}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    /// A PCP MAP response (RFC 6887 sections 7.2, 11.1) to `request`.
    fn pcp_response(request: &[u8], result: u8, external: SocketAddr, lifetime: u32) -> Vec<u8> {
        let mut r = vec![2, 0x81, 0, result];
        r.extend_from_slice(&lifetime.to_be_bytes());
        r.extend_from_slice(&7u32.to_be_bytes()); // epoch
        r.extend_from_slice(&[0; 12]);
        r.extend_from_slice(&request[24..42]); // nonce, protocol, reserved, internal port
        r.extend_from_slice(&external.port().to_be_bytes());
        r.extend_from_slice(&mapped_v6(external.ip()).octets());
        r
    }

    /// RFC 6887 sections 7.1 and 11.1: the MAP request is 60 bytes, version 2, opcode 1, the
    /// lifetime, the client's address IPv4-mapped, the nonce, the protocol and ports, and the
    /// all-zeros IPv4-mapped suggested address.
    #[test]
    fn a_pcp_map_request_has_the_rfc_6887_layout() {
        let config = MappingConfig {
            lifetime: Duration::from_secs(7200),
            suggested_port: 40000,
            ..Default::default()
        };
        let m = pcp_map_request(
            "192.168.1.20".parse().unwrap(),
            NONCE,
            Protocol::Tcp,
            7000,
            &config,
        );
        assert_eq!(m.len(), 60);
        assert_eq!(&m[0..4], &[2, 1, 0, 0]);
        assert_eq!(&m[4..8], &7200u32.to_be_bytes());
        assert_eq!(
            &m[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 20]
        );
        assert_eq!(&m[24..36], &NONCE);
        assert_eq!(m[36], 6, "TCP");
        assert_eq!(&m[40..42], &7000u16.to_be_bytes());
        assert_eq!(&m[42..44], &40000u16.to_be_bytes());
        assert_eq!(
            &m[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]
        );
    }

    /// RFC 6887 section 11.1: a response is taken only for the request's nonce; its assigned
    /// address and port are the mapping's.
    #[test]
    fn a_pcp_response_is_taken_for_its_nonce_only() {
        let request = pcp_map_request(
            "192.168.1.20".parse().unwrap(),
            NONCE,
            Protocol::Udp,
            4000,
            &MappingConfig::default(),
        );
        let external: SocketAddr = "203.0.113.4:41000".parse().unwrap();
        let response = pcp_response(&request, 0, external, 3600);
        assert_eq!(
            parse_pcp_map_response(&response, NONCE, Protocol::Udp),
            Some(PcpAnswer::Mapped(Mapping {
                external,
                internal_port: 4000,
                lifetime: Duration::from_secs(3600),
                protocol: MappingProtocol::Pcp,
            }))
        );
        assert_eq!(
            parse_pcp_map_response(&response, [0; 12], Protocol::Udp),
            None
        );
        let refused = pcp_response(&request, 8, external, 0);
        assert_eq!(
            parse_pcp_map_response(&refused, NONCE, Protocol::Udp),
            Some(PcpAnswer::Refused(8))
        );
    }

    /// RFC 6886 sections 3.2 and 3.3: the request layouts and their responses.
    #[test]
    fn nat_pmp_requests_and_responses_have_the_rfc_6886_layout() {
        assert_eq!(nat_pmp_address_request(), [0, 0]);
        let config = MappingConfig {
            lifetime: Duration::from_secs(7200),
            suggested_port: 0,
            ..Default::default()
        };
        assert_eq!(
            nat_pmp_map_request(Protocol::Udp, 4000, &config),
            [0, 1, 0, 0, 0x0f, 0xa0, 0, 0, 0, 0, 0x1c, 0x20]
        );
        let address = [0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 4];
        assert_eq!(
            parse_nat_pmp_response(&address, 0),
            Some(NatPmpAnswer::Address("203.0.113.4".parse().unwrap()))
        );
        let mapped = [
            0, 130, 0, 0, 0, 0, 0, 9, 0x1b, 0x58, 0xa0, 0x28, 0, 0, 0x0e, 0x10,
        ];
        assert_eq!(
            parse_nat_pmp_response(&mapped, 2),
            Some(NatPmpAnswer::Mapped(7000, 41000, Duration::from_secs(3600)))
        );
        assert_eq!(parse_nat_pmp_response(&mapped, 1), None, "another opcode's");
        let refused = [0, 129, 0, 2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_nat_pmp_response(&refused, 1),
            Some(NatPmpAnswer::Refused(2))
        );
    }

    /// RFC 6544 sections 4.2 and 5.3: the NAT-assisted candidate is server-reflexive with the
    /// type preference 105, related to the base; an active one is on port 9.
    #[test]
    fn a_nat_assisted_candidate_has_type_preference_105() {
        let mapping = Mapping {
            external: "203.0.113.4:41000".parse().unwrap(),
            internal_port: 7000,
            lifetime: Duration::from_secs(3600),
            protocol: MappingProtocol::Pcp,
        };
        let base: SocketAddr = "192.168.1.20:7000".parse().unwrap();
        let line = candidate_line(&mapping, base, Some("passive"), 3);
        let priority: u32 = line.split(' ').nth(3).unwrap().parse().unwrap();
        assert_eq!(priority >> 24, 105);
        assert_eq!((priority >> 8) & 0xffff, (2 << 13) + 8191);
        assert!(
            line.ends_with(
                "203.0.113.4 41000 typ srflx raddr 192.168.1.20 rport 7000 tcptype passive"
            ),
            "{line}"
        );
        let active = candidate_line(&mapping, base, Some("active"), 3);
        assert!(active.contains("203.0.113.4 9 typ srflx"), "{active}");
        let udp = candidate_line(&mapping, base, None, 4);
        assert!(udp.contains(" udp "), "{udp}");
    }

    /// RFC 6887 section 9 and RFC 6886: a gateway that answers a PCP request with a NAT-PMP
    /// response (it speaks NAT-PMP only) is asked with NAT-PMP: the external address, then the
    /// mapping. A gateway on loopback, scripted.
    #[cfg(feature = "runtime-tokio")]
    #[tokio::test]
    async fn a_nat_pmp_gateway_is_asked_again_with_nat_pmp() -> io::Result<()> {
        let gateway = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let at = gateway.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 100];
            let mut seen = vec![];
            for _ in 0..3 {
                let (n, from) = gateway.recv_from(&mut buf).await.unwrap();
                seen.push(buf[..n].to_vec());
                let reply: Vec<u8> = match (buf[0], buf[1]) {
                    // PCP: NAT-PMP's "unsupported version" answer (RFC 6886 section 3.5).
                    (2, _) => vec![0, 128 + 1, 0, 1, 0, 0, 0, 0],
                    (0, 0) => vec![0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 4],
                    _ => vec![
                        0, 129, 0, 0, 0, 0, 0, 1, 0x0f, 0xa0, 0xa0, 0x28, 0, 0, 0x0e, 0x10,
                    ],
                };
                gateway.send_to(&reply, from).await.unwrap();
            }
            seen
        });
        // The test's gateway listens on an ephemeral port: ask through `exchange` the way
        // `map_port` does, against it.
        let runtime = crate::runtime::TokioRuntime::new();
        let socket = runtime.bind_udp("127.0.0.1:0".parse().unwrap())?;
        let config = MappingConfig {
            pcp_initial: Duration::from_millis(50),
            nat_pmp_initial: Duration::from_millis(50),
            ..Default::default()
        };
        let mapping = map_port_at(
            &runtime,
            socket.as_ref(),
            at,
            "127.0.0.1".parse().unwrap(),
            Protocol::Udp,
            4000,
            &config,
        )
        .await?;
        let seen = task.await.unwrap();
        assert_eq!(seen[0][0], 2, "PCP first");
        assert_eq!(seen[1], vec![0, 0], "then the NAT-PMP external address");
        assert_eq!(seen[2][1], 1, "then the NAT-PMP UDP mapping");
        assert_eq!(
            mapping,
            Some(Mapping {
                external: "203.0.113.4:41000".parse().unwrap(),
                internal_port: 4000,
                lifetime: Duration::from_secs(3600),
                protocol: MappingProtocol::NatPmp,
            })
        );
        Ok(())
    }

    /// RFC 6887 section 8.1.1: an unanswered request is sent again; a PCP gateway's answer to
    /// the retransmission is taken.
    #[cfg(feature = "runtime-tokio")]
    #[tokio::test]
    async fn an_unanswered_pcp_request_is_retransmitted() -> io::Result<()> {
        let gateway = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let at = gateway.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 100];
            let (_, _) = gateway.recv_from(&mut buf).await.unwrap(); // dropped
            let (n, from) = gateway.recv_from(&mut buf).await.unwrap();
            let external: SocketAddr = "203.0.113.4:41000".parse().unwrap();
            gateway
                .send_to(&pcp_response(&buf[..n], 0, external, 600), from)
                .await
                .unwrap();
        });
        let runtime = crate::runtime::TokioRuntime::new();
        let socket = runtime.bind_udp("127.0.0.1:0".parse().unwrap())?;
        let config = MappingConfig {
            pcp_initial: Duration::from_millis(50),
            ..Default::default()
        };
        let mapping = map_port_at(
            &runtime,
            socket.as_ref(),
            at,
            "127.0.0.1".parse().unwrap(),
            Protocol::Tcp,
            7000,
            &config,
        )
        .await?;
        task.await.unwrap();
        assert_eq!(
            mapping.map(|m| (m.external.port(), m.protocol)),
            Some((41000, MappingProtocol::Pcp))
        );
        Ok(())
    }
}
