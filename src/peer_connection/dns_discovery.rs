//! Finding a STUN or TURN server whose URI gives no port: S-NAPTR (RFC 3958) for TURN (RFC
//! 5928 section 3, application service `RELAY`), then SRV (RFC 2782; `_turn._udp`,
//! `_turn._tcp`, `_turns._tcp`; for STUN `_stun._udp`, `_stun._tcp`, `_stuns._tcp`, RFC 8489
//! section 8), then the addresses of each target in turn. With no NAPTR and no SRV record the
//! URI's host and the scheme's default port are used. The driver looks the records up
//! ([`StreamCommand::ResolveRecords`](shared::stream::StreamCommand::ResolveRecords)); this is
//! the sans-I/O state of one lookup.

use rand::RngExt;
use shared::stream::{DnsRecord, RECORDS_TIMEOUT, RecordKind};
use std::collections::VecDeque;
use std::time::Instant;

/// How many non-terminal NAPTR records are followed at most (RFC 3958 section 2.2.4 leaves
/// the bound to the client).
const MAX_NAPTR_HOPS: usize = 5;

/// What to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    /// Look up these records.
    Records { name: String, kind: RecordKind },
    /// Resolve this name's addresses, with this port.
    Address { host: String, port: u16 },
    /// Every target has been tried.
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Naptr,
    Srv,
    Targets,
}

/// One server's discovery.
#[derive(Debug, Clone)]
pub(crate) struct Discovery {
    host: String,
    default_port: u16,
    /// The S-NAPTR application protocol tag (`turn.tcp`, `turn.tls`, ...); none for STUN.
    naptr_tag: Option<&'static str>,
    /// The SRV name of the URI's host (`_turns._tcp.example.org`).
    srv_name: String,
    step: Step,
    hops: usize,
    targets: VecDeque<(String, u16)>,
    /// The records query outstanding, and when it counts as unanswered.
    pub(crate) query: Option<u64>,
    deadline: Option<Instant>,
}

impl Discovery {
    /// A discovery for `host`: `srv_service` is `_turns._tcp` and the like.
    pub(crate) fn new(
        host: &str,
        default_port: u16,
        naptr_tag: Option<&'static str>,
        srv_service: &str,
    ) -> Self {
        Self {
            host: host.to_owned(),
            default_port,
            naptr_tag,
            srv_name: format!("{srv_service}.{}", host.trim_end_matches('.')),
            step: if naptr_tag.is_some() {
                Step::Naptr
            } else {
                Step::Srv
            },
            hops: 0,
            targets: VecDeque::new(),
            query: None,
            deadline: None,
        }
    }

    /// The first lookup.
    pub(crate) fn start(&self) -> Next {
        match self.step {
            Step::Naptr => Next::Records {
                name: self.host.clone(),
                kind: RecordKind::Naptr,
            },
            _ => Next::Records {
                name: self.srv_name.clone(),
                kind: RecordKind::Srv,
            },
        }
    }

    /// A records query went out as `query` at `now`.
    pub(crate) fn asked(&mut self, query: u64, now: Instant) {
        self.query = Some(query);
        self.deadline = Some(now + RECORDS_TIMEOUT);
    }

    /// When an unanswered records query counts as empty.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.query.and(self.deadline)
    }

    /// Whether the outstanding query has gone unanswered too long.
    pub(crate) fn timed_out(&self, now: Instant) -> bool {
        self.poll_timeout().is_some_and(|d| now >= d)
    }

    /// The answer to the outstanding records query.
    pub(crate) fn on_records(&mut self, records: &[DnsRecord]) -> Next {
        self.query = None;
        self.deadline = None;
        match self.step {
            Step::Naptr => self.on_naptr(records),
            Step::Srv => {
                self.targets = order_srv(records, |total| rand::rng().random_range(0..=total));
                self.step = Step::Targets;
                if self.targets.is_empty() {
                    // RFC 5928 section 3 / RFC 2782: no SRV record, the host itself.
                    self.targets
                        .push_back((self.host.clone(), self.default_port));
                }
                self.next_target()
            }
            Step::Targets => self.next_target(),
        }
    }

    fn on_naptr(&mut self, records: &[DnsRecord]) -> Next {
        let tag = self.naptr_tag.unwrap_or_default();
        let mut matching: Vec<(u16, u16, String, String)> = records
            .iter()
            .filter_map(|r| match r {
                DnsRecord::Naptr {
                    order,
                    preference,
                    flags,
                    services,
                    replacement,
                    ..
                } => {
                    let mut parts = services.split(':');
                    let service = parts.next()?;
                    let wanted = service.eq_ignore_ascii_case("RELAY")
                        && parts.any(|p| p.eq_ignore_ascii_case(tag));
                    wanted.then(|| (*order, *preference, flags.clone(), replacement.clone()))
                }
                _ => None,
            })
            .collect();
        // RFC 3403 section 4.1: by order, then preference.
        matching.sort_by_key(|(order, preference, _, _)| (*order, *preference));
        if let Some((_, _, flags, replacement)) = matching.into_iter().next() {
            let name = replacement.trim_end_matches('.').to_owned();
            if flags.eq_ignore_ascii_case("S") {
                self.step = Step::Srv;
                return Next::Records {
                    name,
                    kind: RecordKind::Srv,
                };
            }
            if flags.eq_ignore_ascii_case("A") {
                self.step = Step::Targets;
                self.targets = VecDeque::from([(name, self.default_port)]);
                return self.next_target();
            }
            if flags.is_empty() && self.hops < MAX_NAPTR_HOPS {
                // A non-terminal record: the next NAPTR set (RFC 3958 section 2.2.4).
                self.hops += 1;
                return Next::Records {
                    name,
                    kind: RecordKind::Naptr,
                };
            }
        }
        // No usable NAPTR record: SRV of the host (RFC 5928 section 3).
        self.step = Step::Srv;
        Next::Records {
            name: self.srv_name.clone(),
            kind: RecordKind::Srv,
        }
    }

    /// The next target to resolve, once the previous one's addresses all failed (RFC 5928
    /// section 3: the next in the list).
    pub(crate) fn next_target(&mut self) -> Next {
        match self.targets.pop_front() {
            Some((host, port)) => Next::Address { host, port },
            None => Next::Exhausted,
        }
    }
}

/// RFC 2782's order of SRV targets: by priority, and within one priority by weighted random
/// selection (`pick(total)` draws from `0..=total`). A lone "." target means the service is not
/// offered: no target.
pub(crate) fn order_srv(
    records: &[DnsRecord],
    mut pick: impl FnMut(u32) -> u32,
) -> VecDeque<(String, u16)> {
    let mut srv: Vec<(u16, u16, u16, String)> = records
        .iter()
        .filter_map(|r| match r {
            DnsRecord::Srv {
                priority,
                weight,
                port,
                target,
            } => Some((
                *priority,
                *weight,
                *port,
                target.trim_end_matches('.').to_owned(),
            )),
            _ => None,
        })
        .collect();
    if srv.len() == 1 && srv[0].3.is_empty() {
        return VecDeque::new();
    }
    srv.retain(|r| !r.3.is_empty());
    srv.sort_by_key(|r| r.0);
    let mut out = VecDeque::new();
    while let Some(priority) = srv.first().map(|r| r.0) {
        let mut group: Vec<(u16, u16, u16, String)> = vec![];
        while srv.first().is_some_and(|r| r.0 == priority) {
            group.push(srv.remove(0));
        }
        // Weight-zero records first, as RFC 2782 says to arrange them.
        group.sort_by_key(|r| r.1 != 0);
        while !group.is_empty() {
            let total: u32 = group.iter().map(|r| u32::from(r.1)).sum();
            let n = pick(total);
            let mut running = 0u32;
            let index = group
                .iter()
                .position(|r| {
                    running += u32::from(r.1);
                    running >= n
                })
                .unwrap_or(0);
            let chosen = group.remove(index);
            out.push_back((chosen.3, chosen.2));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> DnsRecord {
        DnsRecord::Srv {
            priority,
            weight,
            port,
            target: target.to_owned(),
        }
    }

    fn naptr(
        order: u16,
        preference: u16,
        flags: &str,
        services: &str,
        replacement: &str,
    ) -> DnsRecord {
        DnsRecord::Naptr {
            order,
            preference,
            flags: flags.to_owned(),
            services: services.to_owned(),
            regexp: String::new(),
            replacement: replacement.to_owned(),
        }
    }

    /// RFC 2782: lower priority first; within a priority a weighted random draw, the running
    /// sum of weights deciding (here the draw is fixed); a lone "." target is no service.
    #[test]
    fn srv_targets_go_by_priority_then_by_weighted_draw() {
        let records = [
            srv(20, 0, 3478, "c.example.org."),
            srv(10, 60, 3478, "a.example.org."),
            srv(10, 40, 3479, "b.example.org."),
        ];
        // Draw 70 of 100: past a's 60, so b first; then a alone.
        let mut draws = vec![70, 0, 0].into_iter();
        let order = order_srv(&records, |_| draws.next().unwrap());
        assert_eq!(
            Vec::from(order),
            vec![
                ("b.example.org".to_owned(), 3479),
                ("a.example.org".to_owned(), 3478),
                ("c.example.org".to_owned(), 3478),
            ]
        );
        assert!(order_srv(&[srv(0, 0, 0, ".")], |_| 0).is_empty());
    }

    /// RFC 5928 section 3 with RFC 3958: the NAPTR record whose service is `RELAY` with the
    /// transport's protocol tag (among several in one service field) is followed, by order and
    /// preference; `S` leads to SRV, then to the targets' addresses.
    #[test]
    fn turn_discovery_follows_naptr_then_srv_then_targets() {
        let mut d = Discovery::new("example.net", 5349, Some("turn.tls"), "_turns._tcp");
        assert_eq!(
            d.start(),
            Next::Records {
                name: "example.net".to_owned(),
                kind: RecordKind::Naptr
            }
        );
        let next = d.on_records(&[
            naptr(100, 10, "S", "RELAY:turn.udp", "_turn._udp.example.net."),
            naptr(
                300,
                10,
                "S",
                "RELAY:turn.tcp:turn.tls",
                "_turns._tcp.example.net.",
            ),
            naptr(200, 10, "S", "RELAY:turn.dtls", "_turns._udp.example.net."),
        ]);
        assert_eq!(
            next,
            Next::Records {
                name: "_turns._tcp.example.net".to_owned(),
                kind: RecordKind::Srv
            }
        );
        let next = d.on_records(&[srv(0, 0, 443, "tls.example.net.")]);
        assert_eq!(
            next,
            Next::Address {
                host: "tls.example.net".to_owned(),
                port: 443
            }
        );
        assert_eq!(d.next_target(), Next::Exhausted);
    }

    /// Without a NAPTR record for the transport, SRV of the host; without SRV records, the host
    /// with the default port. An `A` NAPTR record names the host to resolve at once.
    #[test]
    fn without_records_the_host_and_its_default_port_are_used() {
        let mut d = Discovery::new("turn.example.org", 3478, Some("turn.tcp"), "_turn._tcp");
        assert_eq!(
            d.on_records(&[naptr(10, 10, "S", "RELAY:turn.udp", "_turn._udp.x.")]),
            Next::Records {
                name: "_turn._tcp.turn.example.org".to_owned(),
                kind: RecordKind::Srv
            }
        );
        assert_eq!(
            d.on_records(&[]),
            Next::Address {
                host: "turn.example.org".to_owned(),
                port: 3478
            }
        );

        let mut d = Discovery::new("example.net", 5349, Some("turn.tls"), "_turns._tcp");
        assert_eq!(
            d.on_records(&[naptr(10, 10, "A", "RELAY:turn.tls", "a.example.net.")]),
            Next::Address {
                host: "a.example.net".to_owned(),
                port: 5349
            }
        );

        // STUN: SRV only (RFC 8489 section 8).
        let d = Discovery::new("stun.example.org", 3478, None, "_stun._udp");
        assert_eq!(
            d.start(),
            Next::Records {
                name: "_stun._udp.stun.example.org".to_owned(),
                kind: RecordKind::Srv
            }
        );
    }

    /// A non-terminal NAPTR record (empty flags) leads to the next NAPTR set, at most a few
    /// times; an unanswered query times out after `RECORDS_TIMEOUT`.
    #[test]
    fn a_non_terminal_naptr_is_followed_and_an_unanswered_query_times_out() {
        let mut d = Discovery::new("example.net", 3478, Some("turn.tcp"), "_turn._tcp");
        assert_eq!(
            d.on_records(&[naptr(
                200,
                10,
                "",
                "RELAY:turn.tcp:turn.tls",
                "stream.example.net."
            )]),
            Next::Records {
                name: "stream.example.net".to_owned(),
                kind: RecordKind::Naptr
            }
        );
        let now = Instant::now();
        d.asked(9, now);
        assert!(!d.timed_out(now + RECORDS_TIMEOUT / 2));
        assert!(d.timed_out(now + RECORDS_TIMEOUT));
    }
}
