//! The resolver half of [`Mdns`]: query series and the address cache (RFC 6762 sections 5, 7.3,
//! 10, 11).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::wire::{
    self, CLASS_ANY, CLASS_IN, CLASS_TOP_BIT, FLAGS_QUERY, InData, Inbound, OutQuestion, TYPE_A,
    TYPE_AAAA, TYPE_ANY,
};
use super::{
    CACHE_TTL_CAP, MAX_CACHED_ADDRESSES, MAX_QUERY_INTERVAL, MDNS_DEST_ADDR, Mdns, MdnsEvent,
    QueryId, When, normalize,
};

/// A unicast response is taken only for a question that asked for one this recently
/// (RFC 6762 section 6).
const UNICAST_WINDOW: Duration = Duration::from_secs(2);

/// A question seen this soon after ours went out is taken to be ours, handed back by the link
/// (multicast loops back to its sender), not another host's.
const OWN_ECHO: Duration = Duration::from_millis(200);

/// A record that says goodbye, or one a cache-flush record replaces, leaves the cache a
/// second later (RFC 6762 sections 10.1, 10.2).
const FLUSH_DELAY: Duration = Duration::from_secs(1);

/// A pending query: one name, asked for as A and AAAA.
#[derive(Debug)]
pub(super) struct Query {
    pub(super) id: QueryId,
    /// The name with its trailing dot, as asked.
    name: String,
    /// The name in ASCII lower case.
    key: String,
    /// When the series began; `None` until a scheduled query is given the time.
    pub(super) started: Option<Instant>,
    /// The next packet of the series.
    pub(super) next: When,
    /// The wait after the next packet; doubles each time.
    interval: Duration,
    /// Packets sent, or taken as sent.
    sent: u32,
    last_sent: Option<Instant>,
    /// When the series last asked for a unicast response.
    unicast_asked: Option<Instant>,
    /// Another host's question for the A (AAAA) record was seen since our last packet.
    seen_a: bool,
    seen_aaaa: bool,
}

impl Query {
    /// Books a packet of the series as sent at `now`, by us or (a duplicate question,
    /// RFC 6762 section 7.3) by another host.
    fn packet_sent(&mut self, now: Instant, unicast: bool) {
        self.sent += 1;
        self.last_sent = Some(now);
        if unicast {
            self.unicast_asked = Some(now);
        }
        // RFC 6762 section 5.2: the interval at least doubles, up to an hour.
        self.next = When::At(now + self.interval);
        self.interval = (self.interval * 2).min(MAX_QUERY_INTERVAL);
        self.seen_a = false;
        self.seen_aaaa = false;
    }
}

/// An address learned from a response.
#[derive(Debug)]
pub(super) struct Cached {
    pub(super) key: String,
    pub(super) addr: IpAddr,
    pub(super) received: Instant,
    pub(super) expires: Instant,
    /// Other hosts' queries this address would answer, unanswered (RFC 6762 section 10.5).
    pub(super) unanswered: Option<super::reconfirm::Unanswered>,
}

impl Mdns {
    pub(super) fn new_query(
        &mut self,
        name: &str,
        next: When,
        started: Option<Instant>,
    ) -> QueryId {
        let (name, key) = normalize(name);
        let id = self.next_query_id;
        self.next_query_id += 1;
        if !self.closed {
            self.queries.push(Query {
                id,
                name,
                key,
                started,
                next,
                interval: self.query_interval,
                sent: 0,
                last_sent: None,
                unicast_asked: None,
                seen_a: false,
                seen_aaaa: false,
            });
        }
        id
    }

    /// The addresses the cache holds for `key` at `now`.
    fn cached(&self, key: &str, now: Instant) -> Vec<IpAddr> {
        self.cache
            .iter()
            .filter(|cached| cached.key == key && cached.expires > now)
            .map(|cached| cached.addr)
            .collect()
    }

    /// How a query ends when `addrs` are what its name resolves to: with the address, or,
    /// when there are several and only one is allowed, without one
    /// (draft-ietf-mmusic-mdns-ice-candidates section 3.2.2). `None` for no address.
    fn outcome(&self, id: QueryId, addrs: &[IpAddr]) -> Option<MdnsEvent> {
        match addrs {
            [] => None,
            [addr] => Some(MdnsEvent::QueryAnswered(id, *addr)),
            [first, ..] if self.config.multiple_addresses => {
                Some(MdnsEvent::QueryAnswered(id, *first))
            }
            _ => {
                // The draft's SHOULD (ignore the candidate), not a fault: debug, like the
                // other ends of a query without an address.
                log::debug!("mDNS query {id} ends: its name has more than one address");
                Some(MdnsEvent::QueryTimeout(id))
            }
        }
    }

    /// Ends the queries that have sent nothing yet and whose name is in the cache.
    pub(super) fn answer_from_cache(&mut self, now: Instant) {
        let mut index = 0;
        while index < self.queries.len() {
            let query = &self.queries[index];
            let event = (query.sent == 0 && query.started.is_some())
                .then(|| self.outcome(query.id, &self.cached(&query.key, now)))
                .flatten();
            match event {
                Some(event) => {
                    self.event_outs.push_back(event);
                    self.queries.remove(index);
                }
                None => index += 1,
            }
        }
    }

    /// Starts the scheduled queries: answered from the cache, or first sent after a random
    /// 20 to 120 ms (RFC 6762 section 5.2).
    pub(super) fn start_queries(&mut self, now: Instant) {
        let delay = self.config.first_query_delay;
        for index in 0..self.queries.len() {
            if self.queries[index].next == When::Asap {
                let wait = if delay {
                    self.jitter.millis(20, 120)
                } else {
                    Duration::ZERO
                };
                let query = &mut self.queries[index];
                query.started = Some(now);
                query.next = When::At(now + wait);
            }
        }
        self.answer_from_cache(now);
    }

    /// Ends the queries whose timeout has passed.
    pub(super) fn expire_queries(&mut self, now: Instant) {
        let Some(timeout) = self.query_timeout else {
            return;
        };
        let events = &mut self.event_outs;
        self.queries.retain(|query| {
            let expired = query
                .started
                .is_some_and(|started| now.saturating_duration_since(started) >= timeout);
            if expired {
                log::debug!("mDNS query {} timed out after {timeout:?}", query.id);
                events.push_back(MdnsEvent::QueryTimeout(query.id));
            }
            !expired
        });
    }

    /// Sends the query packets that are due. The first packet of a series goes alone, and
    /// asks for a unicast response when the configuration says so; retries never do
    /// (RFC 6762 section 5.4) and share a message (section 5.3).
    pub(super) fn flush_queries(&mut self, now: Instant) -> bool {
        // Both families: a `.local` name carries no hint of which it resolves to, and a host
        // publishes its IPv6 addresses under names of their own.
        fn questions<'a>(name: &'a str, class: u16) -> [OutQuestion<'a>; 2] {
            [TYPE_A, TYPE_AAAA].map(|typ| OutQuestion { name, typ, class })
        }
        let from = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let unicast = self.config.unicast_response;
        let first_class = CLASS_IN | if unicast { CLASS_TOP_BIT } else { 0 };

        for index in 0..self.queries.len() {
            let query = &self.queries[index];
            if query.sent != 0 || !query.next.due(now) {
                continue;
            }
            let bytes = wire::pack(
                0,
                FLAGS_QUERY,
                &questions(&query.name, first_class),
                &[],
                &[],
                &[],
            );
            match bytes {
                Some(bytes) => {
                    if !self.emit(now, from, MDNS_DEST_ADDR, &bytes) {
                        return false;
                    }
                }
                None => log::warn!("mDNS cannot ask for {}: not a DNS name", query.name),
            }
            self.queries[index].packet_sent(now, unicast);
        }

        let retries: Vec<usize> = (0..self.queries.len())
            .filter(|&i| self.queries[i].sent != 0 && self.queries[i].next.due(now))
            .collect();
        let mut packets = Vec::new();
        {
            let queries = &self.queries;
            wire::split(
                &retries,
                &|items, _| {
                    let all: Vec<OutQuestion<'_>> = items
                        .iter()
                        .flat_map(|&i| questions(&queries[i].name, CLASS_IN))
                        .collect();
                    wire::pack(0, FLAGS_QUERY, &all, &[], &[], &[])
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
                self.queries[index].packet_sent(now, false);
            }
        }
        true
    }

    /// RFC 6762 section 7.3: another host multicast a question we are about to send (again),
    /// with no known answers that would keep the answer from us. Ours counts as sent.
    pub(super) fn note_duplicate_questions(
        &mut self,
        inbound: &Inbound,
        src: SocketAddr,
        now: Instant,
    ) {
        if self.queries.is_empty() || self.is_own_address(src.ip()) {
            return;
        }
        for question in &inbound.questions {
            // A question that asks for a unicast response ("QU") brings its answer to the
            // asker alone.
            if question.unicast || !(question.class == CLASS_IN || question.class == CLASS_ANY) {
                continue;
            }
            let (a, aaaa) = match question.typ {
                TYPE_A => (true, false),
                TYPE_AAAA => (false, true),
                TYPE_ANY => (true, true),
                _ => continue,
            };
            if inbound
                .answers
                .iter()
                .any(|known| known.key == question.key)
            {
                continue;
            }
            for query in &mut self.queries {
                if query.key != question.key
                    || query.started.is_none()
                    || query
                        .last_sent
                        .is_some_and(|t| now.saturating_duration_since(t) < OWN_ECHO)
                {
                    continue;
                }
                query.seen_a |= a;
                query.seen_aaaa |= aaaa;
                if query.seen_a && query.seen_aaaa {
                    query.packet_sent(now, false);
                }
            }
        }
    }

    /// Whether a response that arrived by unicast may speak about `key`: a question of ours
    /// for it asked for a unicast response within the last two seconds, or we are probing for
    /// it. Every other unicast response is ignored (RFC 6762 section 6).
    fn expects_unicast(&self, key: &str, now: Instant) -> bool {
        self.queries.iter().any(|query| {
            query.key == key
                && query
                    .unicast_asked
                    .is_some_and(|t| now.saturating_duration_since(t) <= UNICAST_WINDOW)
        }) || self.probes_for(key)
    }

    /// Takes an address into the cache for its TTL (RFC 6762 sections 5.2, 10).
    fn cache_address(&mut self, key: &str, addr: IpAddr, ttl: u32, flush: bool, now: Instant) {
        let soon = now + FLUSH_DELAY;
        if ttl == 0 {
            // RFC 6762 section 10.1: a goodbye is not acted on at once, but a second later.
            for cached in &mut self.cache {
                if cached.key == key && cached.addr == addr {
                    cached.expires = cached.expires.min(soon);
                }
            }
            return;
        }
        if flush {
            // RFC 6762 section 10.2: the cache-flush bit says this is the whole truth for the
            // name and type; what was heard more than a second ago goes in a second.
            for cached in &mut self.cache {
                if cached.key == key
                    && cached.addr != addr
                    && cached.addr.is_ipv4() == addr.is_ipv4()
                    && now.saturating_duration_since(cached.received) > FLUSH_DELAY
                {
                    cached.expires = cached.expires.min(soon);
                }
            }
        }
        let expires = now + Duration::from_secs(u64::from(ttl.min(CACHE_TTL_CAP)));
        if let Some(cached) = self
            .cache
            .iter_mut()
            .find(|cached| cached.key == key && cached.addr == addr)
        {
            cached.received = now;
            cached.expires = expires;
            cached.unanswered = None;
            return;
        }
        if self.cache.len() >= MAX_CACHED_ADDRESSES {
            self.cache.retain(|cached| cached.expires > now);
        }
        if self.cache.len() >= MAX_CACHED_ADDRESSES {
            // Full of live entries: the one nearest its expiry gives way, unless the newcomer
            // would go first.
            let Some((index, soonest)) = self
                .cache
                .iter()
                .enumerate()
                .map(|(i, cached)| (i, cached.expires))
                .min_by_key(|&(_, expires)| expires)
            else {
                return;
            };
            if soonest >= expires {
                return;
            }
            self.cache.swap_remove(index);
        }
        self.cache.push(Cached {
            key: key.to_owned(),
            addr,
            received: now,
            expires,
            unanswered: None,
        });
    }

    /// A response: its records are held against our names (conflicts), cached, and matched
    /// with the pending queries. Whatever is in its Question section is ignored (RFC 6762
    /// section 6), as is its ID (section 18.1).
    pub(super) fn process_response(
        &mut self,
        inbound: &Inbound,
        src: SocketAddr,
        unicast_arrival: bool,
        multicast_arrival: bool,
        now: Instant,
    ) {
        // RFC 6762 section 11: only what originates on the link counts; a response the driver
        // says arrived at the multicast address did, whatever its source.
        let on_link = multicast_arrival || self.is_on_link(src.ip());
        // Addresses this response gives, by name; and the names it says have no address.
        let mut resolved: Vec<(&str, IpAddr)> = Vec::new();
        let mut without_address: Vec<&str> = Vec::new();

        let sections = [
            (&inbound.answers, true),
            (&inbound.authorities, false),
            (&inbound.additionals, true),
        ];
        for (records, resolves) in sections {
            for record in records {
                if record.class != CLASS_IN
                    || (unicast_arrival && !self.expects_unicast(&record.key, now))
                {
                    continue;
                }
                // RFC 6762 section 9: a conflicting record in any section counts.
                if on_link {
                    self.note_conflict(record, now);
                }
                if !resolves {
                    continue;
                }
                match record.data {
                    InData::Addr(addr) => {
                        if !self.trusts(addr, src.ip(), multicast_arrival) {
                            log::warn!(
                                "mDNS ignores an answer for {} with address {} from {}: an answer is taken only from an on-link sender, and an A record only from the address it names",
                                record.key,
                                addr,
                                src.ip()
                            );
                            continue;
                        }
                        self.cache_address(&record.key, addr, record.ttl, record.flush, now);
                        // RFC 6762 section 10.1: a TTL of zero is a goodbye; it resolves
                        // nothing.
                        if record.ttl > 0 && !resolved.contains(&(record.key.as_str(), addr)) {
                            resolved.push((&record.key, addr));
                        }
                    }
                    // RFC 6762 section 6.1: the name's owner says which types exist under it.
                    InData::Nsec(_)
                        if on_link
                            && record.ttl > 0
                            && record.nsec_has(TYPE_A) == Some(false)
                            && record.nsec_has(TYPE_AAAA) == Some(false) =>
                    {
                        without_address.push(&record.key);
                    }
                    _ => {}
                }
            }
        }

        let mut index = 0;
        while index < self.queries.len() {
            let query = &self.queries[index];
            let addrs: Vec<IpAddr> = resolved
                .iter()
                .filter(|(key, _)| *key == query.key)
                .map(|&(_, addr)| addr)
                .collect();
            let event = self.outcome(query.id, &addrs).or_else(|| {
                without_address.contains(&query.key.as_str()).then(|| {
                    log::debug!("mDNS query {} ends: its name has no address", query.id);
                    MdnsEvent::QueryTimeout(query.id)
                })
            });
            match event {
                Some(event) => {
                    self.event_outs.push_back(event);
                    self.queries.remove(index);
                }
                None => index += 1,
            }
        }
    }
}
