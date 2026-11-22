//! The responder half of [`Mdns`]: the unique address records it owns, from probing to goodbye
//! (RFC 6762 sections 6 to 10).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::wire::{
    self, CLASS_ANY, CLASS_IN, CLASS_TOP_BIT, FLAGS_QUERY, FLAGS_RESPONSE, InRecord, Inbound,
    MAX_INBOUND_MESSAGE, MAX_OUTBOUND_MESSAGE, OutQuestion, OutRecord, TYPE_ANY,
};
use super::{MAX_LOCAL_NAMES, MDNS_DEST_ADDR, MDNS_PORT, Mdns, MdnsEvent, When};
use crate::config::{MdnsProbePolicy, RESPONSE_TTL};

/// Probes sent for a name, 250 ms apart; 250 ms after the last, the name is ours
/// (RFC 6762 section 8.1).
const PROBE_COUNT: u8 = 3;
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// The second announcement follows the first by one second; later ones double the gap
/// (RFC 6762 section 8.3).
const ANNOUNCE_GAP: Duration = Duration::from_secs(1);

/// A record is not multicast again within one second (RFC 6762 section 6).
const RECORD_GAP: Duration = Duration::from_secs(1);

/// ... except to answer a probe, where 250 ms is enough (RFC 6762 section 6).
const DEFENCE_GAP: Duration = Duration::from_millis(250);

/// A quarter of the record TTL: a question that asks for a unicast response gets one only when
/// the record was multicast this recently (RFC 6762 section 5.4).
const QUARTER_TTL: Duration = Duration::from_secs(RESPONSE_TTL as u64 / 4);

/// The TTL of the records in a reply to a legacy querier (RFC 6762 section 6.7: no more than
/// ten seconds).
const LEGACY_TTL: u32 = 10;

/// The loser of a simultaneous-probe tiebreak waits a second, then probes again
/// (RFC 6762 section 8.2).
const TIEBREAK_WAIT: Duration = Duration::from_secs(1);

/// Fifteen conflicts within ten seconds: each further probe attempt waits five seconds
/// (RFC 6762 section 8.1).
pub(super) const CONFLICT_LIMIT: usize = 15;
const CONFLICT_WINDOW: Duration = Duration::from_secs(10);
const CONFLICT_BACKOFF: Duration = Duration::from_secs(5);

/// The announcements a live record still owes.
#[derive(Debug)]
pub(super) struct Announce {
    left: u8,
    next: When,
    /// The wait after the next announcement.
    gap: Duration,
}

#[derive(Debug)]
pub(super) enum Phase {
    /// Not ours yet: `sent` probes are out, and `next` is the next probe or, after the third,
    /// the end of probing. The name is not answered.
    Probing { sent: u8, next: When },
    /// Ours: answered, and announced while `announce` lasts.
    Live { announce: Option<Announce> },
}

/// A multicast of a record that a query asked for.
#[derive(Debug)]
pub(super) struct Planned {
    due: Instant,
    /// Answers a probe: the shorter gap applies, and no delay.
    defensive: bool,
    /// The one asker whose truncated query this waits on; its later packets may list the
    /// record as known and call the answer off (RFC 6762 section 7.2). `None` once anyone
    /// else wants it.
    tc_from: Option<IpAddr>,
}

/// A unique address record this connection owns, with its NSEC companion: the record that
/// says the name has no record of any other type (RFC 6762 section 6.1).
#[derive(Debug)]
pub(super) struct LocalRecord {
    /// The name as registered, with its trailing dot.
    pub(super) name: String,
    /// The name in ASCII lower case.
    pub(super) key: String,
    pub(super) ip: IpAddr,
    /// Registered with `add_local_name` (counts against `MAX_LOCAL_NAMES`), not configured.
    pub(super) registered: bool,
    pub(super) phase: Phase,
    /// Whether the record ever went to the link: only then is there something to withdraw.
    published: bool,
    last_multicast: Option<Instant>,
    /// When the NSEC record was last multicast.
    last_negative: Option<Instant>,
    answer: Option<Planned>,
    /// A multicast of the NSEC record alone, for a question about a type the name lacks.
    negative: Option<Planned>,
}

/// A record that was removed and is still to be withdrawn from the neighbours' caches.
#[derive(Debug)]
pub(super) struct Goodbye {
    name: String,
    pub(super) key: String,
    pub(super) ip: IpAddr,
    pub(super) due: When,
    /// The record's own gap: not before a second after it was last multicast.
    not_before: Option<Instant>,
}

/// Where a record's messages leave from: its own address when that is IPv4, so that the
/// application can send them on that address's interface (RFC 6762 section 14). Everything
/// goes to the IPv4 group, so an IPv6 record leaves from the unspecified IPv4 address.
fn from_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

/// `items` (indexes) grouped by `key`, in first-seen order. Records are aggregated into one
/// message only when they leave from the same address (RFC 6762 sections 6.4, 14).
fn grouped(items: &[usize], key: impl Fn(usize) -> IpAddr) -> Vec<(IpAddr, Vec<usize>)> {
    let mut groups: Vec<(IpAddr, Vec<usize>)> = Vec::new();
    for &item in items {
        let from = key(item);
        match groups.iter_mut().find(|(ip, _)| *ip == from) {
            Some((_, group)) => group.push(item),
            None => groups.push((from, vec![item])),
        }
    }
    groups
}

/// `<uuid>.local.`: a UUID in its textual form as the only label before `local`.
fn is_uuid_local(key: &str) -> bool {
    let Some(label) = key.strip_suffix(".local.") else {
        return false;
    };
    label.len() == 36
        && label.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn merge(slot: &mut Option<Planned>, new: Planned) {
    match slot {
        None => *slot = Some(new),
        Some(old) => {
            if old.tc_from.is_some() && old.tc_from == new.tc_from {
                // The same asker, truncated again: wait from its latest packet.
                old.due = new.due;
            } else {
                old.due = old.due.min(new.due);
                old.tc_from = None;
            }
            old.defensive |= new.defensive;
        }
    }
}

impl LocalRecord {
    fn typ(&self) -> u16 {
        wire::addr_type(self.ip)
    }

    pub(super) fn is_live(&self) -> bool {
        matches!(self.phase, Phase::Live { .. })
    }

    fn is_probing(&self) -> bool {
        matches!(self.phase, Phase::Probing { sent, .. } if sent > 0)
    }

    fn rdata(&self) -> Vec<u8> {
        match self.ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        }
    }

    fn out(&self, nsec: bool, flush: bool, ttl: u32) -> OutRecord<'_> {
        OutRecord {
            name: &self.name,
            ip: self.ip,
            nsec,
            flush,
            ttl,
        }
    }

    /// Whether the NSEC record may be multicast at `now`.
    fn nsec_due(&self, now: Instant) -> bool {
        self.last_negative.is_none_or(|t| t + RECORD_GAP <= now)
    }

    /// Whether a query's Known-Answer section lists this record with at least half its TTL
    /// (RFC 6762 section 7.1).
    fn is_known_to(&self, inbound: &Inbound) -> bool {
        inbound.answers.iter().any(|known| {
            known.key == self.key
                && known.class == CLASS_IN
                && known.addr() == Some(self.ip)
                && known.ttl >= RESPONSE_TTL / 2
        })
    }

    pub(super) fn deadlines(&self, consider: &mut impl FnMut(When)) {
        match &self.phase {
            Phase::Probing { next, .. } => consider(*next),
            Phase::Live { announce } => {
                if let Some(announce) = announce {
                    consider(announce.next);
                }
            }
        }
        for planned in [&self.answer, &self.negative].into_iter().flatten() {
            consider(When::At(planned.due));
        }
    }

    /// Books a multicast of the record at `now`: the address record with, when `with_nsec`,
    /// its NSEC record beside it, or (`negative_only`) the NSEC record alone.
    fn multicast_sent(&mut self, now: Instant, negative_only: bool, with_nsec: bool) {
        self.published = true;
        if negative_only {
            self.last_negative = Some(now);
            self.negative = None;
            return;
        }
        if with_nsec && self.nsec_due(now) {
            self.last_negative = Some(now);
            self.negative = None;
        }
        self.last_multicast = Some(now);
        self.answer = None;
        if let Phase::Live { announce } = &mut self.phase {
            let finished = match announce {
                Some(a) if a.next.due(now) => {
                    a.left = a.left.saturating_sub(1);
                    a.next = When::At(now + a.gap);
                    a.gap *= 2;
                    a.left == 0
                }
                _ => false,
            };
            if finished {
                *announce = None;
            }
        }
    }
}

impl Mdns {
    /// A record for `name`, in the phase a new name starts in. `None` when `name` cannot be
    /// written as a DNS name.
    pub(super) fn new_record(
        &self,
        name: String,
        key: String,
        ip: IpAddr,
        registered: bool,
    ) -> Option<LocalRecord> {
        let probe = OutQuestion {
            name: &name,
            typ: TYPE_ANY,
            class: CLASS_IN,
        };
        wire::pack(0, FLAGS_QUERY, &[probe], &[], &[], &[])?;
        let phase = if self.probes(&key) {
            Phase::Probing {
                sent: 0,
                next: When::Asap,
            }
        } else {
            self.live_phase(When::Asap)
        };
        Some(LocalRecord {
            name,
            key,
            ip,
            registered,
            phase,
            published: false,
            last_multicast: None,
            last_negative: None,
            answer: None,
            negative: None,
        })
    }

    /// The phase of a record that has just become ours: live, with its announcements owed
    /// (RFC 6762 section 8.3).
    fn live_phase(&self, first: When) -> Phase {
        Phase::Live {
            announce: Some(Announce {
                left: self.config.announce_count,
                next: first,
                gap: ANNOUNCE_GAP,
            }),
        }
    }

    /// Puts every record back to where a new name starts: probing, or its announcements.
    pub(super) fn restart_records(&mut self) {
        for index in 0..self.records.len() {
            let probes = matches!(self.records[index].phase, Phase::Probing { .. })
                || self.probes(&self.records[index].key);
            self.records[index].phase = if probes {
                Phase::Probing {
                    sent: 0,
                    next: When::Asap,
                }
            } else {
                self.live_phase(When::Asap)
            };
        }
    }

    /// RFC 6762 section 8.1: a name that cannot already be in use skips probing, which is
    /// what draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 asks for its random names.
    fn probes(&self, key: &str) -> bool {
        match self.config.probe_policy {
            MdnsProbePolicy::Always => true,
            MdnsProbePolicy::Never => false,
            MdnsProbePolicy::Auto => !is_uuid_local(key),
        }
    }

    /// Queues the goodbye of a removed record, when the record ever went to the link.
    pub(super) fn withdraw(&mut self, record: LocalRecord) {
        if !record.published {
            return;
        }
        if self.goodbyes.len() >= MAX_LOCAL_NAMES {
            self.goodbyes.remove(0);
        }
        self.goodbyes.push(Goodbye {
            due: When::Asap,
            not_before: record.last_multicast.map(|t| t + RECORD_GAP),
            name: record.name,
            key: record.key,
            ip: record.ip,
        });
    }

    fn note_conflict_time(&mut self, now: Instant) {
        self.conflicts.push_back(now);
        while self.conflicts.len() > CONFLICT_LIMIT {
            self.conflicts.pop_front();
        }
    }

    /// When probing may start, asked at `now`: after a random 0 to 250 ms, and after five
    /// more seconds while conflicts come in at fifteen per ten seconds (RFC 6762 section 8.1).
    fn probe_start(&mut self, now: Instant) -> Instant {
        let flooded = self.conflicts.len() >= CONFLICT_LIMIT
            && self
                .conflicts
                .front()
                .is_some_and(|&first| now.saturating_duration_since(first) <= CONFLICT_WINDOW);
        let backoff = if flooded {
            CONFLICT_BACKOFF
        } else {
            Duration::ZERO
        };
        now + backoff + self.jitter.millis(0, 250)
    }

    /// Gives a time to what was registered or removed since the caller last gave one.
    pub(super) fn start_records(&mut self, now: Instant) {
        for index in 0..self.records.len() {
            match &mut self.records[index].phase {
                Phase::Probing {
                    next: When::Asap, ..
                } => {
                    let at = self.probe_start(now);
                    self.records[index].phase = Phase::Probing {
                        sent: 0,
                        next: When::At(at),
                    };
                }
                Phase::Live {
                    announce: Some(announce),
                } if announce.next == When::Asap => announce.next = When::At(now),
                _ => {}
            }
        }
        for goodbye in &mut self.goodbyes {
            if goodbye.due == When::Asap {
                goodbye.due = When::At(goodbye.not_before.map_or(now, |t| t.max(now)));
            }
        }
    }

    /// A query: answers what it asks about our names (RFC 6762 section 6), and takes note of
    /// what it says to the resolver (a duplicate of a question of ours, section 7.3) and to
    /// the names being probed for (a simultaneous probe, section 8.2).
    pub(super) fn process_query(
        &mut self,
        inbound: &Inbound,
        src: SocketAddr,
        unicast_arrival: bool,
        now: Instant,
    ) {
        // RFC 6762 section 6.7: a query from another port is from a legacy resolver.
        let legacy = src.port() != MDNS_PORT;
        let on_link = self.is_on_link(src.ip());
        let truncated = inbound.header.truncated;

        if !legacy {
            // RFC 6762 section 7.2: a truncated query is followed by more Known-Answer
            // packets from the same host. An answer that waits on that host is called off
            // when a later packet lists it, and waits again when the packet is truncated too.
            let again = truncated.then(|| now + self.jitter.millis(400, 500));
            for record in &mut self.records {
                let known = record.is_known_to(inbound);
                if let Some(planned) = &mut record.answer
                    && planned.tc_from == Some(src.ip())
                {
                    if known {
                        record.answer = None;
                    } else if let Some(due) = again {
                        planned.due = due;
                    }
                }
                if let Some(planned) = &mut record.negative
                    && planned.tc_from == Some(src.ip())
                    && let Some(due) = again
                {
                    planned.due = due;
                }
            }
            // What a query tells the names being probed for and the pending queries is taken
            // only from the link (RFC 6762 section 11), like the answers of a response.
            if on_link {
                self.break_probe_ties(inbound, now);
                if !unicast_arrival {
                    self.note_duplicate_questions(inbound, src, now);
                }
            }
        }

        // RFC 6762 section 5.5: a query that came by unicast from off the link is ignored. A
        // legacy reply is unicast too, so it goes only to an on-link asker.
        if (unicast_arrival || legacy) && !on_link {
            return;
        }

        // What to answer: (record, NSEC only, by unicast).
        let mut wanted: Vec<(usize, bool, bool)> = Vec::new();
        let mut all_ours = !inbound.questions.is_empty();
        for question in &inbound.questions {
            // RFC 6762 section 6: name, class (or ANY) and type (or ANY) decide.
            let index = (question.class == CLASS_IN || question.class == CLASS_ANY)
                .then(|| {
                    self.records
                        .iter()
                        .position(|r| r.is_live() && r.key == question.key)
                })
                .flatten();
            let Some(index) = index else {
                all_ours = false;
                continue;
            };
            let record = &self.records[index];
            // The name is ours alone, so a question for a type it lacks gets the NSEC record
            // (RFC 6762 section 6.1).
            let negative = question.typ != TYPE_ANY && question.typ != record.typ();
            // RFC 6762 section 7.1: no answer the asker already has.
            if !negative && !legacy && record.is_known_to(inbound) {
                continue;
            }
            match wanted
                .iter_mut()
                .find(|(i, n, _)| *i == index && *n == negative)
            {
                Some((_, _, unicast)) => *unicast |= question.unicast,
                None => wanted.push((index, negative, question.unicast)),
            }
        }
        if wanted.is_empty() {
            return;
        }
        if legacy {
            self.reply_to_legacy(inbound, src, &wanted, now);
            return;
        }

        // RFC 6762 sections 6, 6.3, 7.2: 400 to 500 ms when more Known-Answer packets follow;
        // no delay when every question is about a name of ours, since then no other responder
        // answers this message; 20 to 120 ms otherwise.
        let delay = if truncated {
            Some(self.jitter.millis(400, 500))
        } else if all_ours {
            None
        } else {
            Some(self.jitter.millis(20, 120))
        };
        let unicast_replies = self.config.unicast_replies;
        let mut by_unicast: Vec<(usize, bool)> = Vec::new();
        for &(index, negative, unicast) in &wanted {
            let record = &mut self.records[index];
            // A probe carries the record its sender proposes in the Authority section
            // (RFC 6762 section 8.2). Defending the name is not delayed (section 8.1).
            let defensive = inbound.authorities.iter().any(|a| a.key == record.key);
            let delay = if defensive { None } else { delay };
            let last = if negative {
                record.last_negative
            } else {
                record.last_multicast
            };
            let recent = last.is_some_and(|t| now.saturating_duration_since(t) < QUARTER_TTL);
            // RFC 6762 sections 5.4, 5.5, 11: by unicast when asked, when the neighbours had
            // the record by multicast within a quarter of its TTL (always, to a probe), and
            // when the asker is on the link, where a unicast reply will be believed.
            if (unicast || unicast_arrival)
                && unicast_replies
                && on_link
                && delay.is_none()
                && (defensive || recent)
            {
                by_unicast.push((index, negative));
                continue;
            }
            let planned = Planned {
                due: now + delay.unwrap_or_default(),
                defensive,
                tc_from: (truncated && !defensive).then_some(src.ip()),
            };
            merge(
                if negative {
                    &mut record.negative
                } else {
                    &mut record.answer
                },
                planned,
            );
        }

        if by_unicast.is_empty() {
            return;
        }
        let positive = |index: usize| by_unicast.contains(&(index, false));
        let answers: Vec<OutRecord<'_>> = by_unicast
            .iter()
            .filter(|&&(index, negative)| !negative || !positive(index))
            .map(|&(index, negative)| self.records[index].out(negative, true, RESPONSE_TTL))
            .collect();
        // RFC 6762 section 6.2: with an address record, the NSEC record for the other family.
        let additionals: Vec<OutRecord<'_>> = by_unicast
            .iter()
            .filter(|&&(_, negative)| !negative)
            .map(|&(index, _)| self.records[index].out(true, true, RESPONSE_TTL))
            .collect();
        let bytes = wire::pack(0, FLAGS_RESPONSE, &[], &answers, &[], &additionals)
            .filter(|bytes| bytes.len() <= MAX_OUTBOUND_MESSAGE)
            .or_else(|| wire::pack(0, FLAGS_RESPONSE, &[], &answers, &[], &[]));
        let from = from_ip(self.records[by_unicast[0].0].ip);
        if let Some(bytes) = bytes
            && self.emit(now, from, src, &bytes)
        {
            for (index, _) in by_unicast {
                self.records[index].published = true;
            }
        }
    }

    /// RFC 6762 section 6.7: the reply to a legacy resolver is a conventional DNS response,
    /// sent straight back: the query's ID and questions repeated, no cache-flush bit, TTLs of
    /// at most ten seconds. A question for a type our name lacks gets an empty answer.
    fn reply_to_legacy(
        &mut self,
        inbound: &Inbound,
        src: SocketAddr,
        wanted: &[(usize, bool, bool)],
        now: Instant,
    ) {
        let questions: Vec<OutQuestion<'_>> = inbound
            .questions
            .iter()
            .map(|q| OutQuestion {
                name: &q.name,
                typ: q.typ,
                class: q.class | if q.unicast { CLASS_TOP_BIT } else { 0 },
            })
            .collect();
        let answers: Vec<OutRecord<'_>> = wanted
            .iter()
            .filter(|&&(_, negative, _)| !negative)
            .map(|&(index, _, _)| self.records[index].out(false, false, LEGACY_TTL))
            .collect();
        // No message is over 9000 bytes (RFC 6762 section 17); a query whose echo would be
        // gets no reply.
        let bytes = wire::pack(
            inbound.header.id,
            FLAGS_RESPONSE,
            &questions,
            &answers,
            &[],
            &[],
        )
        .filter(|bytes| bytes.len() <= MAX_INBOUND_MESSAGE);
        let from = from_ip(self.records[wanted[0].0].ip);
        if let Some(bytes) = bytes
            && self.emit(now, from, src, &bytes)
        {
            for &(index, negative, _) in wanted {
                self.records[index].published |= !negative;
            }
        }
    }

    /// RFC 6762 section 8.2: another host probes for a name we are probing for. Its proposed
    /// records are in the Authority section; the lexicographically later data wins, and the
    /// loser waits a second before probing again. Equal data is no conflict (and is what our
    /// own probe looks like when the link hands it back).
    fn break_probe_ties(&mut self, inbound: &Inbound, now: Instant) {
        if inbound.authorities.is_empty() {
            return;
        }
        for record in &mut self.records {
            if !record.is_probing() {
                continue;
            }
            let mut theirs: Vec<(u16, u16, Vec<u8>)> = inbound
                .authorities
                .iter()
                .filter(|a| a.key == record.key)
                .map(|a| (a.class, a.typ, a.rdata()))
                .collect();
            theirs.sort();
            theirs.dedup();
            let Some(first) = theirs.first() else {
                continue;
            };
            // Class, then type, then the raw data, bytes compared as unsigned. Ours is one
            // record: a longer list that starts with it has records left over, and wins.
            let ours = (CLASS_IN, record.typ(), record.rdata());
            let lost = match ours.cmp(first) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Equal => theirs.len() > 1,
                std::cmp::Ordering::Greater => false,
            };
            if lost {
                log::debug!(
                    "mDNS lost a simultaneous probe for {}: probing again in a second",
                    record.name
                );
                record.phase = Phase::Probing {
                    sent: 0,
                    next: When::At(now + TIEBREAK_WAIT),
                };
            }
        }
    }

    /// A record of a response from the link, held against our names (RFC 6762 sections 6.6,
    /// 8.1, 9).
    pub(super) fn note_conflict(&mut self, theirs: &InRecord, now: Instant) {
        let Some(index) = self.records.iter().position(|r| r.key == theirs.key) else {
            return;
        };
        let record = &mut self.records[index];
        let same_type = theirs.typ == record.typ();
        let identical = same_type && theirs.addr() == Some(record.ip);
        match record.phase {
            // What arrives before the first probe is out says nothing (RFC 6762 section 8.1).
            Phase::Probing { sent: 0, .. } => {}
            Phase::Probing { .. } => {
                // Probing asks for type ANY, so any record under the name, of any type, means
                // the name is taken; the same data is the same host, or a cooperating one.
                if identical {
                    return;
                }
                let lost = self.records.remove(index);
                log::warn!(
                    "mDNS gives up the name {}: another host answers for it",
                    lost.name
                );
                self.note_conflict_time(now);
                // No goodbye: the name is the other host's now, and its announcements, which
                // carry the cache-flush bit, replace what the neighbours had from us.
                let name = lost.name.strip_suffix('.').unwrap_or(&lost.name).to_owned();
                self.event_outs
                    .push_back(MdnsEvent::LocalNameConflict(name));
            }
            Phase::Live { .. } => {
                if !same_type {
                    return;
                }
                if identical {
                    // RFC 6762 section 6.6: a cooperating responder gave our record with less
                    // than half its TTL (a goodbye, at the extreme). Ours goes out again so
                    // that the neighbours keep it.
                    if theirs.ttl < RESPONSE_TTL / 2 {
                        merge(
                            &mut record.answer,
                            Planned {
                                due: now,
                                defensive: false,
                                tc_from: None,
                            },
                        );
                    }
                    return;
                }
                // RFC 6762 section 9: other data under our name, type and class is a conflict,
                // and the record goes back to probing at once.
                log::warn!(
                    "mDNS probes again for {}: another host gave it a different address",
                    record.name
                );
                record.answer = None;
                record.negative = None;
                self.note_conflict_time(now);
                let at = self.probe_start(now);
                self.records[index].phase = Phase::Probing {
                    sent: 0,
                    next: When::At(at),
                };
            }
        }
    }

    /// Sends the probes that are due: one question of type ANY per name, asking for a unicast
    /// response, with the proposed record in the Authority section (RFC 6762 sections 8.1,
    /// 8.2). A name whose third probe is 250 ms old without a defender becomes live.
    pub(super) fn flush_probes(&mut self, now: Instant) -> bool {
        let mut due = Vec::new();
        for index in 0..self.records.len() {
            if let Phase::Probing { sent, next } = self.records[index].phase
                && next.due(now)
            {
                if sent >= PROBE_COUNT {
                    self.records[index].phase = self.live_phase(When::At(now));
                } else {
                    due.push(index);
                }
            }
        }
        for (from, group) in grouped(&due, |i| from_ip(self.records[i].ip)) {
            let mut packets = Vec::new();
            {
                let records = &self.records;
                wire::split(
                    &group,
                    &|items, _| {
                        let questions: Vec<OutQuestion<'_>> = items
                            .iter()
                            .map(|&i| OutQuestion {
                                name: &records[i].name,
                                typ: TYPE_ANY,
                                class: CLASS_IN | CLASS_TOP_BIT,
                            })
                            .collect();
                        let proposed: Vec<OutRecord<'_>> = items
                            .iter()
                            .map(|&i| records[i].out(false, false, RESPONSE_TTL))
                            .collect();
                        wire::pack(0, FLAGS_QUERY, &questions, &[], &proposed, &[])
                    },
                    &mut packets,
                );
            }
            for packet in packets {
                if let Some(bytes) = &packet.bytes
                    && !self.emit(now, from, MDNS_DEST_ADDR, bytes)
                {
                    return false;
                }
                for index in packet.items {
                    if let Phase::Probing { sent, next } = &mut self.records[index].phase {
                        *sent += 1;
                        *next = When::At(now + PROBE_INTERVAL);
                    }
                }
            }
        }
        true
    }

    /// Multicasts the records that are due, as announcements or as answers: the address
    /// record with the cache-flush bit and TTL 120, its NSEC record in the Additional section
    /// (RFC 6762 sections 6.1, 6.2, 8.3, 10, 10.2), or the NSEC record alone where only a
    /// type the name lacks was asked for. A record inside its gap (one second; 250 ms to
    /// answer a probe; section 6) waits until the gap is over.
    pub(super) fn flush_records(&mut self, now: Instant) -> bool {
        let mut due = Vec::new();
        let mut negative_only = vec![false; self.records.len()];
        for (index, record) in self.records.iter_mut().enumerate() {
            let Phase::Live { announce } = &mut record.phase else {
                record.answer = None;
                record.negative = None;
                continue;
            };
            let mut positive = false;
            if let Some(announce) = announce
                && announce.next.due(now)
            {
                match record.last_multicast {
                    Some(t) if t + RECORD_GAP > now => announce.next = When::At(t + RECORD_GAP),
                    _ => positive = true,
                }
            }
            if let Some(planned) = &mut record.answer
                && planned.due <= now
            {
                let gap = if planned.defensive {
                    DEFENCE_GAP
                } else {
                    RECORD_GAP
                };
                match record.last_multicast {
                    Some(t) if t + gap > now => planned.due = t + gap,
                    _ => positive = true,
                }
            }
            if positive {
                due.push(index);
                continue;
            }
            if let Some(planned) = &mut record.negative
                && planned.due <= now
            {
                let gap = if planned.defensive {
                    DEFENCE_GAP
                } else {
                    RECORD_GAP
                };
                match record.last_negative {
                    Some(t) if t + gap > now => planned.due = t + gap,
                    _ => {
                        negative_only[index] = true;
                        due.push(index);
                    }
                }
            }
        }

        for (from, group) in grouped(&due, |i| from_ip(self.records[i].ip)) {
            let mut packets = Vec::new();
            {
                let records = &self.records;
                let negative_only = &negative_only;
                wire::split(
                    &group,
                    &|items, full| {
                        let answers: Vec<OutRecord<'_>> = items
                            .iter()
                            .map(|&i| records[i].out(negative_only[i], true, RESPONSE_TTL))
                            .collect();
                        let additionals: Vec<OutRecord<'_>> = items
                            .iter()
                            .filter(|&&i| full && !negative_only[i] && records[i].nsec_due(now))
                            .map(|&i| records[i].out(true, true, RESPONSE_TTL))
                            .collect();
                        wire::pack(0, FLAGS_RESPONSE, &[], &answers, &[], &additionals)
                    },
                    &mut packets,
                );
            }
            for packet in packets {
                if let Some(bytes) = &packet.bytes
                    && !self.emit(now, from, MDNS_DEST_ADDR, bytes)
                {
                    return false;
                }
                for index in packet.items {
                    self.records[index].multicast_sent(now, negative_only[index], !packet.trimmed);
                }
            }
        }
        true
    }

    /// Sends the goodbyes that are due: the removed record with TTL 0 (RFC 6762 section 10.1).
    pub(super) fn flush_goodbyes(&mut self, now: Instant) -> bool {
        let due: Vec<usize> = (0..self.goodbyes.len())
            .filter(|&i| self.goodbyes[i].due.due(now))
            .collect();
        let mut sent = vec![false; self.goodbyes.len()];
        let mut budget_left = true;
        'groups: for (from, group) in grouped(&due, |i| from_ip(self.goodbyes[i].ip)) {
            let mut packets = Vec::new();
            {
                let goodbyes = &self.goodbyes;
                wire::split(
                    &group,
                    &|items, _| {
                        let answers: Vec<OutRecord<'_>> =
                            items.iter().map(|&i| goodbyes[i].out()).collect();
                        wire::pack(0, FLAGS_RESPONSE, &[], &answers, &[], &[])
                    },
                    &mut packets,
                );
            }
            for packet in packets {
                if let Some(bytes) = &packet.bytes
                    && !self.emit(now, from, MDNS_DEST_ADDR, bytes)
                {
                    budget_left = false;
                    break 'groups;
                }
                for index in packet.items {
                    sent[index] = true;
                }
            }
        }
        let mut sent = sent.into_iter();
        self.goodbyes.retain(|_| !sent.next().unwrap_or(false));
        budget_left
    }

    /// On close: the goodbyes of every name that went to the link, and those still owed for
    /// names removed earlier. They do not draw on the message budget: nothing can be sent
    /// later, and a name has at most one.
    pub(super) fn queue_closing_goodbyes(&mut self) {
        let now = self.last_now;
        let mut leaving: Vec<Goodbye> = std::mem::take(&mut self.goodbyes);
        for record in std::mem::take(&mut self.records) {
            if record.is_live() && record.published {
                leaving.push(Goodbye {
                    due: When::At(now),
                    not_before: None,
                    name: record.name,
                    key: record.key,
                    ip: record.ip,
                });
            }
        }
        let all: Vec<usize> = (0..leaving.len()).collect();
        for (from, group) in grouped(&all, |i| from_ip(leaving[i].ip)) {
            let mut packets = Vec::new();
            wire::split(
                &group,
                &|items, _| {
                    let answers: Vec<OutRecord<'_>> =
                        items.iter().map(|&i| leaving[i].out()).collect();
                    wire::pack(0, FLAGS_RESPONSE, &[], &answers, &[], &[])
                },
                &mut packets,
            );
            for packet in packets {
                if let Some(bytes) = &packet.bytes {
                    self.push_packet(now, from, MDNS_DEST_ADDR, bytes);
                }
            }
        }
    }

    /// Whether a response that arrived by unicast may speak about `key`: we are probing for
    /// it, and probes ask for unicast responses (RFC 6762 sections 6, 8.1).
    pub(super) fn probes_for(&self, key: &str) -> bool {
        self.records.iter().any(|r| r.key == key && r.is_probing())
    }
}

impl Goodbye {
    fn out(&self) -> OutRecord<'_> {
        OutRecord {
            name: &self.name,
            ip: self.ip,
            nsec: false,
            flush: true,
            ttl: 0,
        }
    }
}
