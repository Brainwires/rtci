//! Records found stale before their TTL ends (RFC 6762 sections 10.4 and 10.5): reconfirmation
//! on a client's hint, and passive observation of other hosts' unanswered queries.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::wire::{
    self, CLASS_ANY, CLASS_IN, FLAGS_QUERY, Inbound, OutQuestion, TYPE_A, TYPE_AAAA, TYPE_ANY,
};
use super::{MDNS_DEST_ADDR, Mdns, When, normalize};

/// How long a record in dispute has to be answered (RFC 6762 sections 10.4, 10.5: "within
/// ten seconds").
pub(super) const STALE_WINDOW: Duration = Duration::from_secs(10);

/// The wait between the queries of a reconfirmation.
const RECONFIRM_INTERVAL: Duration = Duration::from_secs(1);

/// Queries a reconfirmation sends ("two or more").
const RECONFIRM_QUERIES: u32 = 2;

/// A cached name a client said is stale, being asked for again.
#[derive(Debug)]
pub(super) struct Reconfirm {
    name: String,
    key: String,
    /// When the hint came: a cached address not heard of since is flushed at
    /// `since + STALE_WINDOW`.
    since: Instant,
    sent: u32,
    next: Instant,
}

/// Passive observation of failures for one cached address: other hosts' queries it would
/// answer, seen since `first`, with no response bringing it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Unanswered {
    pub(super) first: Instant,
    pub(super) queries: u32,
}

impl Mdns {
    /// RFC 6762 section 10.4: a client found the cached address of `name` to be wrong (its
    /// host did not answer at it, say). The cache "MUST issue two or more queries for the
    /// resource record in dispute. If no response is received within ten seconds, then, even
    /// though its TTL may indicate that it is not yet due to expire, that record SHOULD be
    /// promptly flushed from the cache." Two queries go out, a second apart (from the next
    /// [`handle_timeout`](sansio::Protocol::handle_timeout), or at once when it is due); an
    /// address of the name no response brought in the ten seconds is flushed.
    ///
    /// Returns `false`, and does nothing, when the cache holds no address for `name` or a
    /// reconfirmation of it is already running.
    pub fn reconfirm(&mut self, now: Instant, name: &str) -> bool {
        let (name, key) = normalize(name);
        if self.closed
            || !self.cache.iter().any(|c| c.key == key && c.expires > now)
            || self.reconfirms.iter().any(|r| r.key == key)
        {
            return false;
        }
        self.reconfirms.push(Reconfirm {
            name,
            key,
            since: now,
            sent: 0,
            next: now,
        });
        self.last_now = now;
        self.flush(now);
        self.update_next_timeout();
        true
    }

    /// Whether a reconfirmation of `name` is running.
    pub fn is_reconfirming(&self, name: &str) -> bool {
        let (_, key) = normalize(name);
        self.reconfirms.iter().any(|r| r.key == key)
    }

    /// Sends the reconfirmation queries that are due (QM, A and AAAA). `false` when the rate
    /// limit stopped them.
    pub(super) fn flush_reconfirms(&mut self, now: Instant) -> bool {
        let from = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        for index in 0..self.reconfirms.len() {
            let r = &self.reconfirms[index];
            if r.sent >= RECONFIRM_QUERIES || r.next > now {
                continue;
            }
            let questions = [TYPE_A, TYPE_AAAA].map(|typ| OutQuestion {
                name: &r.name,
                typ,
                class: CLASS_IN,
            });
            if let Some(bytes) = wire::pack(0, FLAGS_QUERY, &questions, &[], &[], &[])
                && !self.emit(now, from, MDNS_DEST_ADDR, &bytes)
            {
                return false;
            }
            let r = &mut self.reconfirms[index];
            r.sent += 1;
            r.next = now + RECONFIRM_INTERVAL;
        }
        true
    }

    /// RFC 6762 section 10.5: another host multicast a question that a cached address answers,
    /// without that address among its known answers. Counted per address; a response that
    /// brings the address again (`cache_address`) clears the count.
    pub(super) fn observe_unanswered_questions(
        &mut self,
        inbound: &Inbound,
        src: SocketAddr,
        now: Instant,
    ) {
        if self.cache.is_empty() || self.is_own_address(src.ip()) {
            return;
        }
        for question in &inbound.questions {
            if !(question.class == CLASS_IN || question.class == CLASS_ANY) {
                continue;
            }
            let (a, aaaa) = match question.typ {
                TYPE_A => (true, false),
                TYPE_AAAA => (false, true),
                TYPE_ANY => (true, true),
                _ => continue,
            };
            for cached in &mut self.cache {
                if cached.key != question.key
                    || cached.expires <= now
                    || !(if cached.addr.is_ipv4() { a } else { aaaa })
                    || inbound.answers.iter().any(|known| {
                        known.key == question.key && known.data == wire::InData::Addr(cached.addr)
                    })
                {
                    continue;
                }
                match &mut cached.unanswered {
                    Some(seen) => seen.queries += 1,
                    None => {
                        cached.unanswered = Some(Unanswered {
                            first: now,
                            queries: 1,
                        })
                    }
                }
            }
        }
    }

    /// Flushes what sections 10.4 and 10.5 found stale and ends the reconfirmations whose
    /// window has passed.
    pub(super) fn expire_stale(&mut self, now: Instant) {
        let mut ended = Vec::new();
        self.reconfirms.retain(|r| {
            let over = now >= r.since + STALE_WINDOW;
            if over {
                ended.push((r.key.clone(), r.since));
            }
            !over
        });
        self.cache.retain(|cached| {
            let disputed = ended
                .iter()
                .any(|(key, since)| *key == cached.key && cached.received <= *since);
            if disputed {
                log::debug!(
                    "mDNS flushes {} -> {}: not reconfirmed within ten seconds",
                    cached.key,
                    cached.addr
                );
            }
            // Section 10.5: "After seeing two or more of these queries, and seeing no
            // multicast response containing the expected answer within ten seconds".
            let unanswered = cached
                .unanswered
                .is_some_and(|seen| seen.queries >= 2 && now >= seen.first + STALE_WINDOW);
            if unanswered {
                log::debug!(
                    "mDNS flushes {} -> {}: other hosts' queries for it went unanswered",
                    cached.key,
                    cached.addr
                );
            }
            !(disputed || unanswered)
        });
        // One query seen in the window is no indication: the count starts over.
        for cached in &mut self.cache {
            if cached
                .unanswered
                .is_some_and(|seen| seen.queries < 2 && now >= seen.first + STALE_WINDOW)
            {
                cached.unanswered = None;
            }
        }
    }

    /// The instants sections 10.4 and 10.5 need `handle_timeout` at.
    pub(super) fn stale_deadlines(&self, consider: &mut impl FnMut(When)) {
        for r in &self.reconfirms {
            if r.sent < RECONFIRM_QUERIES {
                consider(When::At(r.next));
            }
            consider(When::At(r.since + STALE_WINDOW));
        }
        for cached in &self.cache {
            if let Some(seen) = cached.unanswered {
                consider(When::At(seen.first + STALE_WINDOW));
            }
        }
    }
}
