//! Happy Eyeballs (RFC 8305) for a sans-I/O engine: the order in which a server's addresses
//! are tried and when the next attempt starts. The driver resolves names
//! ([`StreamCommand::Resolve`](super::StreamCommand::Resolve)), answering both families at
//! once ([`StreamEvent::Resolved`](super::StreamEvent::Resolved)) or each as it arrives
//! ([`StreamEvent::ResolvedFamily`](super::StreamEvent::ResolvedFamily)); the engine sorts and
//! staggers the attempts with [`HappyEyeballs`] and keeps the first that succeeds. With answers
//! per family the race starts on the first one (RFC 8305 section 3): at once on IPv6, after the
//! Resolution Delay on IPv4 while IPv6 is outstanding, and a late answer joins the addresses
//! not yet tried.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// RFC 8305 section 8: the recommended Connection Attempt Delay.
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// RFC 8305 section 5: an attempt never starts within 10 ms of the previous one.
pub const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(10);
/// RFC 8305 section 5: the upper bound of the delay ("Maximum Connection Attempt Delay").
pub const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);
/// RFC 8305 section 8: the recommended Resolution Delay, how long an IPv4 answer waits for the
/// IPv6 one before the race starts on it.
pub const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// RFC 8305 section 4: addresses interleaved by family, the preferred family first ("First
/// Address Family Count" of one), each family keeping its own order. IPv6 is preferred, as
/// the RFC's default; duplicates are dropped.
pub fn sort_addresses(addresses: &[SocketAddr], prefer_ipv6: bool) -> Vec<SocketAddr> {
    let mut first: VecDeque<SocketAddr> = VecDeque::new();
    let mut second: VecDeque<SocketAddr> = VecDeque::new();
    for a in addresses {
        if first.contains(a) || second.contains(a) {
            continue;
        }
        if a.is_ipv6() == prefer_ipv6 {
            first.push_back(*a);
        } else {
            second.push_back(*a);
        }
    }
    let mut out = Vec::with_capacity(first.len() + second.len());
    loop {
        match (first.pop_front(), second.pop_front()) {
            (None, None) => break,
            (a, b) => {
                out.extend(a);
                out.extend(b);
            }
        }
    }
    out
}

/// One Happy Eyeballs race over sorted addresses: [`next_attempt`](Self::next_attempt) says
/// which address to try when, a failure moves to the next at once, the first success ends it
/// (the attempts still running are to be cancelled, the rest ignored).
#[derive(Debug, Clone)]
pub struct HappyEyeballs {
    remaining: VecDeque<SocketAddr>,
    delay: Duration,
    last_start: Option<Instant>,
    running: usize,
    done: bool,
    /// Families still to answer (IPv6, IPv4); none for a race made from a complete list.
    awaiting: (bool, bool),
    /// Every address ever given, so a late answer adds only new ones.
    known: Vec<SocketAddr>,
    /// The race does not start before this (the Resolution Delay of an IPv4 answer).
    hold_until: Option<Instant>,
    /// Whether the last address tried was IPv6.
    last_ipv6: Option<bool>,
}

impl HappyEyeballs {
    /// A race over `addresses` (already sorted, [`sort_addresses`]) with the Connection
    /// Attempt Delay `delay`, held between 10 ms and 2 s (RFC 8305 section 5).
    pub fn new(addresses: Vec<SocketAddr>, delay: Duration) -> Self {
        Self {
            known: addresses.clone(),
            remaining: addresses.into(),
            delay: delay.clamp(MIN_CONNECTION_ATTEMPT_DELAY, MAX_CONNECTION_ATTEMPT_DELAY),
            last_start: None,
            running: 0,
            done: false,
            awaiting: (false, false),
            hold_until: None,
            last_ipv6: None,
        }
    }

    /// A race whose addresses arrive per family ([`Self::answer`]): it is not lost while a
    /// family is outstanding.
    pub fn awaiting_answers(delay: Duration) -> Self {
        Self {
            awaiting: (true, true),
            ..Self::new(vec![], delay)
        }
    }

    /// The answer of one family at `now` (RFC 8305 section 3): the race starts on the first
    /// answer, at once for IPv6 and after [`RESOLUTION_DELAY`] for IPv4 while IPv6 is still
    /// outstanding; an answer that comes once the race has started is sorted into the
    /// addresses not yet tried, the families still alternating (`prefer_ipv6`: the family
    /// that goes first before any attempt).
    pub fn answer(
        &mut self,
        now: Instant,
        ipv6: bool,
        addresses: &[SocketAddr],
        prefer_ipv6: bool,
    ) {
        if ipv6 {
            self.awaiting.0 = false;
            // The IPv6 answer ends any wait for it.
            self.hold_until = None;
        } else {
            self.awaiting.1 = false;
            if self.awaiting.0 && self.last_start.is_none() && self.hold_until.is_none() {
                self.hold_until = Some(now + RESOLUTION_DELAY);
            }
        }
        if self.done {
            return;
        }
        let fresh: Vec<SocketAddr> = addresses
            .iter()
            .filter(|a| !self.known.contains(a))
            .copied()
            .collect();
        self.known.extend(&fresh);
        let mut pending: Vec<SocketAddr> = self.remaining.drain(..).collect();
        pending.extend(fresh);
        let first = self.last_ipv6.map_or(prefer_ipv6, |last| !last);
        self.remaining = sort_addresses(&pending, first).into();
    }

    /// Whether a family has yet to answer.
    pub fn awaiting(&self) -> bool {
        self.awaiting.0 || self.awaiting.1
    }

    /// The address to try now, if one is due: the first at once; the next when the delay since
    /// the previous start has passed, or when nothing is running (the previous failed), but
    /// never within 10 ms of the previous start.
    pub fn next_attempt(&mut self, now: Instant) -> Option<SocketAddr> {
        if self.done || self.hold_until.is_some_and(|until| now < until) {
            return None;
        }
        let due = match self.last_start {
            None => true,
            Some(last) => {
                let since = now.saturating_duration_since(last);
                since >= self.delay || (self.running == 0 && since >= MIN_CONNECTION_ATTEMPT_DELAY)
            }
        };
        if !due {
            return None;
        }
        let address = self.remaining.pop_front()?;
        self.last_ipv6 = Some(address.is_ipv6());
        self.last_start = Some(now);
        self.running += 1;
        Some(address)
    }

    /// When [`next_attempt`](Self::next_attempt) will next have something, once an attempt
    /// has started (before that, at once).
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.done || self.remaining.is_empty() {
            return None;
        }
        if let Some(until) = self.hold_until
            && self.last_start.is_none()
        {
            return Some(until);
        }
        Some(match self.last_start {
            // Nothing started: the first attempt is due at once, on the next call.
            None => return None,
            Some(last) if self.running == 0 => last + MIN_CONNECTION_ATTEMPT_DELAY,
            Some(last) => last + self.delay,
        })
    }

    /// An attempt failed.
    pub fn failed(&mut self) {
        self.running = self.running.saturating_sub(1);
    }

    /// An attempt connected: the race is over.
    pub fn succeeded(&mut self) {
        self.done = true;
        self.remaining.clear();
    }

    /// Every address was tried and nothing is running or left: the race is lost.
    pub fn exhausted(&self) -> bool {
        !self.done && self.running == 0 && self.remaining.is_empty() && !self.awaiting()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn families_interleave_preferred_first_each_in_its_order() {
        let list = [
            a("192.0.2.1:3478"),
            a("192.0.2.2:3478"),
            a("192.0.2.3:3478"),
            a("[2001:db8::1]:3478"),
            a("[2001:db8::2]:3478"),
            a("192.0.2.1:3478"),
        ];
        assert_eq!(
            sort_addresses(&list, true),
            vec![
                a("[2001:db8::1]:3478"),
                a("192.0.2.1:3478"),
                a("[2001:db8::2]:3478"),
                a("192.0.2.2:3478"),
                a("192.0.2.3:3478"),
            ]
        );
        assert_eq!(sort_addresses(&list, false)[0], a("192.0.2.1:3478"));
        assert_eq!(sort_addresses(&[], true), vec![]);
    }

    #[test]
    fn attempts_are_staggered_by_the_delay_and_a_failure_moves_on_at_once() {
        let t0 = Instant::now();
        let mut race = HappyEyeballs::new(
            vec![a("[2001:db8::1]:1"), a("192.0.2.1:1"), a("192.0.2.2:1")],
            CONNECTION_ATTEMPT_DELAY,
        );
        assert_eq!(race.next_attempt(t0), Some(a("[2001:db8::1]:1")));
        assert_eq!(race.next_attempt(t0 + Duration::from_millis(100)), None);
        assert_eq!(race.poll_timeout(), Some(t0 + CONNECTION_ATTEMPT_DELAY));
        assert_eq!(
            race.next_attempt(t0 + CONNECTION_ATTEMPT_DELAY),
            Some(a("192.0.2.1:1"))
        );
        // Both fail: the next starts at once, though not within 10 ms of the last start.
        race.failed();
        race.failed();
        let t1 = t0 + CONNECTION_ATTEMPT_DELAY;
        assert_eq!(race.next_attempt(t1 + Duration::from_millis(5)), None);
        assert_eq!(
            race.next_attempt(t1 + Duration::from_millis(10)),
            Some(a("192.0.2.2:1"))
        );
        race.failed();
        assert!(race.exhausted());
    }

    #[test]
    fn the_first_success_ends_the_race() {
        let t0 = Instant::now();
        let mut race = HappyEyeballs::new(
            vec![a("[2001:db8::1]:1"), a("192.0.2.1:1")],
            Duration::from_millis(1),
        );
        assert!(race.next_attempt(t0).is_some());
        race.succeeded();
        assert_eq!(race.next_attempt(t0 + Duration::from_secs(1)), None);
        assert_eq!(race.poll_timeout(), None);
        assert!(!race.exhausted());
    }

    #[test]
    fn an_ipv6_answer_starts_the_race_at_once_and_a_late_ipv4_answer_joins_it() {
        let t0 = Instant::now();
        let mut race = HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY);
        assert_eq!(
            race.next_attempt(t0),
            None,
            "nothing to try before an answer"
        );
        assert!(
            !race.exhausted(),
            "not lost while both families are outstanding"
        );
        race.answer(
            t0,
            true,
            &[a("[2001:db8::1]:3478"), a("[2001:db8::2]:3478")],
            true,
        );
        assert_eq!(
            race.next_attempt(t0),
            Some(a("[2001:db8::1]:3478")),
            "RFC 8305 section 3: no wait for the A answer"
        );
        // The A answer arrives while the race runs: it is interleaved with what is left.
        race.answer(
            t0 + Duration::from_millis(5),
            false,
            &[a("192.0.2.1:3478")],
            true,
        );
        let t1 = t0 + CONNECTION_ATTEMPT_DELAY;
        assert_eq!(race.next_attempt(t1), Some(a("192.0.2.1:3478")));
        let t2 = t1 + CONNECTION_ATTEMPT_DELAY;
        assert_eq!(race.next_attempt(t2), Some(a("[2001:db8::2]:3478")));
    }

    #[test]
    fn an_ipv4_answer_first_waits_the_resolution_delay_for_ipv6() {
        let t0 = Instant::now();
        let mut race = HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY);
        race.answer(t0, false, &[a("192.0.2.1:3478")], true);
        assert_eq!(race.next_attempt(t0), None, "held for the AAAA answer");
        assert_eq!(race.poll_timeout(), Some(t0 + RESOLUTION_DELAY));
        assert_eq!(
            race.next_attempt(t0 + RESOLUTION_DELAY),
            Some(a("192.0.2.1:3478")),
            "the AAAA answer did not come in time: IPv4 goes"
        );

        // An IPv6 answer within the delay goes first.
        let mut race = HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY);
        race.answer(t0, false, &[a("192.0.2.1:3478")], true);
        let t1 = t0 + Duration::from_millis(20);
        race.answer(t1, true, &[a("[2001:db8::1]:3478")], true);
        assert_eq!(race.next_attempt(t1), Some(a("[2001:db8::1]:3478")));
        // Both families answered and every attempt failed: the race is lost.
        race.failed();
        let t2 = t1 + MIN_CONNECTION_ATTEMPT_DELAY;
        assert_eq!(race.next_attempt(t2), Some(a("192.0.2.1:3478")));
        race.failed();
        assert!(race.exhausted());
    }

    #[test]
    fn the_delay_is_held_between_ten_milliseconds_and_two_seconds() {
        let t0 = Instant::now();
        let mut race = HappyEyeballs::new(vec![a("192.0.2.1:1"), a("192.0.2.2:1")], Duration::ZERO);
        race.next_attempt(t0);
        assert_eq!(race.next_attempt(t0 + Duration::from_millis(9)), None);
        assert!(race.next_attempt(t0 + Duration::from_millis(10)).is_some());
        let slow = HappyEyeballs::new(vec![a("192.0.2.1:1")], Duration::from_secs(60));
        assert_eq!(slow.delay, MAX_CONNECTION_ATTEMPT_DELAY);
    }
}
