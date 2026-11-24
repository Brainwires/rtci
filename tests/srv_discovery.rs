//! Finding STUN and TURN servers whose URI gives no port (RFC 5928 section 3, RFC 3958
//! S-NAPTR, RFC 2782 SRV, RFC 8489 section 8, RFC 7064 / RFC 7065): the engine asks its driver
//! for NAPTR and SRV records (`StreamCommand::ResolveRecords`), then for the addresses of each
//! target in turn; with a port in the URI it asks only for the addresses. The driver here is
//! the test.

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngine;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::stream::{DnsRecord, RECORDS_TIMEOUT, RecordKind, StreamCommand, StreamEvent};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Driver {
    pc: RTCPeerConnection,
    now: Instant,
    commands: Vec<StreamCommand>,
    sent_to: Vec<SocketAddr>,
}

impl Driver {
    fn new(url: &str) -> Result<Self> {
        Self::with_settings(url, SettingEngine::default())
    }

    fn with_settings(url: &str, settings: SettingEngine) -> Result<Self> {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![url.to_owned()],
                        username: "user".to_owned(),
                        credential: "pass".to_owned(),
                    }])
                    .build(),
            )
            .with_setting_engine(settings)
            .build(now)?;
        pc.create_data_channel("dns", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer)?;
        let mut d = Self {
            pc,
            now,
            commands: vec![],
            sent_to: vec![],
        };
        d.pump();
        Ok(d)
    }

    fn add_host(&mut self) -> Result<()> {
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host".to_owned(),
            ..Default::default()
        })?;
        self.pump();
        Ok(())
    }

    fn pump(&mut self) {
        while let Some(c) = self.pc.poll_stream_command() {
            self.commands.push(c);
        }
        while let Some(w) = self.pc.poll_write() {
            self.sent_to.push(w.transport.peer_addr);
        }
    }

    fn event(&mut self, e: StreamEvent) -> Result<()> {
        self.pc.handle_stream_event(self.now, e)?;
        self.pump();
        Ok(())
    }

    fn advance(&mut self, by: Duration) {
        let until = self.now + by;
        loop {
            self.pump();
            match self.pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now);
                    self.pc.handle_timeout(self.now).unwrap();
                }
                _ => break,
            }
        }
        self.now = until;
        self.pc.handle_timeout(self.now).unwrap();
        self.pump();
    }

    /// The last records query for `name`.
    fn records_query(&self, name: &str, kind: RecordKind) -> Option<u64> {
        self.commands.iter().rev().find_map(|c| match c {
            StreamCommand::ResolveRecords {
                query,
                name: n,
                kind: k,
            } if n == name && *k == kind => Some(*query),
            _ => None,
        })
    }

    fn address_query(&self, host: &str, port: u16) -> Option<u64> {
        self.commands.iter().rev().find_map(|c| match c {
            StreamCommand::Resolve {
                query,
                host: h,
                port: p,
            } if h == host && *p == port => Some(*query),
            _ => None,
        })
    }

    fn connects_to(&self, remote: SocketAddr) -> bool {
        self.commands
            .iter()
            .any(|c| matches!(c, StreamCommand::Connect { remote: r, .. } if *r == remote))
    }
}

fn naptr(flags: &str, services: &str, replacement: &str) -> DnsRecord {
    DnsRecord::Naptr {
        order: 10,
        preference: 10,
        flags: flags.to_owned(),
        services: services.to_owned(),
        regexp: String::new(),
        replacement: replacement.to_owned(),
    }
}

fn srv(priority: u16, port: u16, target: &str) -> DnsRecord {
    DnsRecord::Srv {
        priority,
        weight: 0,
        port,
        target: target.to_owned(),
    }
}

/// RFC 5928 section 3 (rows 3-5, 7.1-3 of RFC 8656): a `turn:` URI over TCP without a port is
/// found by S-NAPTR (`RELAY:turn.tcp`), then the SRV name the record gives, then the SRV
/// target's addresses with the SRV port; the engine connects there.
#[test]
fn a_turn_server_without_a_port_is_found_by_naptr_then_srv() -> Result<()> {
    let mut d = Driver::new("turn:example.net?transport=tcp")?;
    let q = d
        .records_query("example.net", RecordKind::Naptr)
        .expect("S-NAPTR first");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![
            naptr("S", "RELAY:turn.udp", "_turn._udp.example.net."),
            naptr("S", "RELAY:turn.tcp", "_turn._tcp.example.net."),
        ],
    })?;
    let q = d
        .records_query("_turn._tcp.example.net", RecordKind::Srv)
        .expect("the SRV name of the turn.tcp record");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![srv(10, 3479, "relay.example.net.")],
    })?;
    let q = d
        .address_query("relay.example.net", 3479)
        .expect("the target's addresses, with the SRV port");
    d.event(StreamEvent::Resolved {
        query: q,
        addresses: vec![a("192.0.2.30:3479")],
    })?;
    assert!(d.connects_to(a("192.0.2.30:3479")));
    Ok(())
}

/// RFC 5928 section 3 (row 3-4): with a port in the URI only the host's addresses are looked
/// up; no NAPTR or SRV query.
#[test]
fn a_turn_server_with_a_port_is_resolved_directly() -> Result<()> {
    let d = Driver::new("turn:turn.example.net:3478?transport=tcp")?;
    assert!(d.address_query("turn.example.net", 3478).is_some());
    assert!(
        !d.commands
            .iter()
            .any(|c| matches!(c, StreamCommand::ResolveRecords { .. })),
        "{:?}",
        d.commands
    );
    Ok(())
}

/// A driver that never answers a records query: after `RECORDS_TIMEOUT` it counts as empty,
/// so the engine goes on to SRV and then to the host with the scheme's default port.
#[test]
fn unanswered_record_queries_fall_back_to_the_hosts_addresses() -> Result<()> {
    let mut d = Driver::new("turn:example.net?transport=tcp")?;
    assert!(d.records_query("example.net", RecordKind::Naptr).is_some());
    d.advance(RECORDS_TIMEOUT);
    assert!(
        d.records_query("_turn._tcp.example.net", RecordKind::Srv)
            .is_some()
    );
    assert!(d.address_query("example.net", 3478).is_none());
    d.advance(RECORDS_TIMEOUT);
    assert!(
        d.address_query("example.net", 3478).is_some(),
        "{:?}",
        d.commands
    );
    Ok(())
}

/// RFC 8489 section 8 / RFC 7064: a `stun:` URI without a port is found by SRV
/// (`_stun._udp`); the targets are tried in priority order, the next when the first has no
/// address, and the Binding request goes to the target's address and SRV port.
#[test]
fn a_stun_server_without_a_port_is_found_by_srv_target_by_target() -> Result<()> {
    let mut d = Driver::new("stun:example.org")?;
    d.add_host()?;
    let q = d
        .records_query("_stun._udp.example.org", RecordKind::Srv)
        .expect("SRV for STUN over UDP");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![
            srv(20, 3480, "second.example.org"),
            srv(10, 3479, "first.example.org"),
        ],
    })?;
    let q = d
        .address_query("first.example.org", 3479)
        .expect("the lower priority first");
    d.event(StreamEvent::Resolved {
        query: q,
        addresses: vec![],
    })?;
    let q = d
        .address_query("second.example.org", 3480)
        .expect("then the next target");
    d.event(StreamEvent::Resolved {
        query: q,
        addresses: vec![a("192.0.2.40:3480")],
    })?;
    assert!(d.sent_to.contains(&a("192.0.2.40:3480")), "{:?}", d.sent_to);
    Ok(())
}

/// RFC 5928 section 3 (row 3-6): a `turns:` server found through SRV is checked against the
/// URI's host, not the SRV target: the TLS ClientHello names `example.net` (SNI, the name the
/// certificate is verified against), never `tls.example.net`.
#[test]
fn a_turns_server_found_by_srv_is_checked_against_the_uris_host() -> Result<()> {
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::peer_connection::turn_tls::TurnTlsConfig;
    let settings = SettingEngineBuilder::new()
        .with_turn_tls(TurnTlsConfig {
            roots: Some(std::sync::Arc::new(rustls::RootCertStore::empty())),
            ..Default::default()
        })
        .build();
    let mut d = Driver::with_settings("turns:example.net?transport=tcp", settings)?;
    let q = d.records_query("example.net", RecordKind::Naptr).unwrap();
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![],
    })?;
    let q = d
        .records_query("_turns._tcp.example.net", RecordKind::Srv)
        .expect("SRV for TURN over TLS");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![srv(0, 443, "tls.example.net")],
    })?;
    let q = d.address_query("tls.example.net", 443).unwrap();
    let server = a("192.0.2.50:443");
    d.event(StreamEvent::Resolved {
        query: q,
        addresses: vec![server],
    })?;
    let id = d
        .commands
        .iter()
        .find_map(|c| match c {
            StreamCommand::Connect { id, remote, .. } if *remote == server => Some(*id),
            _ => None,
        })
        .expect("a connection to the target");
    d.event(StreamEvent::Connected {
        id,
        local: a("10.0.0.1:50000"),
    })?;
    let hello: Vec<u8> = std::iter::from_fn(|| d.pc.poll_stream_transmit())
        .filter(|t| t.id == id)
        .flat_map(|t| t.data)
        .collect();
    let has = |name: &[u8]| hello.windows(name.len()).any(|w| w == name);
    assert!(has(b"example.net"), "the URI's host in the ClientHello");
    assert!(!has(b"tls.example.net"), "not the SRV target");
    Ok(())
}

/// RFC 7350 section 4.2 with RFC 5928 section 3: a `turns:...?transport=udp` URI without a
/// port is found by S-NAPTR (the `turn.dtls` protocol tag) and SRV (`_turns._udp`); the DTLS
/// ClientHello goes from the host candidate to the target's address and SRV port.
#[test]
fn a_turns_dtls_server_without_a_port_is_found_by_naptr_turn_dtls_then_srv_turns_udp() -> Result<()>
{
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::peer_connection::turn_tls::TurnTlsConfig;
    let provider = rtci::crypto::default_provider()?;
    let cert = rtci::dtls::crypto::Certificate::generate_self_signed(
        vec!["example.net".to_owned()],
        provider.crypto(),
    )?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.certificate[0].clone())?;
    let mut d = Driver::with_settings(
        "turns:example.net?transport=udp",
        SettingEngineBuilder::new()
            .with_turn_tls(TurnTlsConfig {
                roots: Some(std::sync::Arc::new(roots)),
                ..Default::default()
            })
            .build(),
    )?;
    d.add_host()?;
    let q = d
        .records_query("example.net", RecordKind::Naptr)
        .expect("S-NAPTR first");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![
            naptr("S", "RELAY:turn.tls", "_turns._tcp.example.net."),
            naptr("S", "RELAY:turn.dtls", "_turns._udp.example.net."),
        ],
    })?;
    let q = d
        .records_query("_turns._udp.example.net", RecordKind::Srv)
        .expect("the SRV name of the turn.dtls record");
    d.event(StreamEvent::ResolvedRecords {
        query: q,
        records: vec![srv(10, 5350, "relay.example.net.")],
    })?;
    let q = d
        .address_query("relay.example.net", 5350)
        .expect("the target's addresses, with the SRV port");
    d.event(StreamEvent::Resolved {
        query: q,
        addresses: vec![a("192.0.2.31:5350")],
    })?;
    assert!(
        d.sent_to.contains(&a("192.0.2.31:5350")),
        "the ClientHello: {:?}",
        d.sent_to
    );
    Ok(())
}
