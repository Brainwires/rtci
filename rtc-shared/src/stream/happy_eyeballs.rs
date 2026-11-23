//! Happy Eyeballs (RFC 8305) for a sans-I/O engine: the order in which a server's addresses
//! are tried and when the next attempt starts. The driver resolves names
//! ([`StreamCommand::Resolve`](super::StreamCommand::Resolve), both families at once); the
//! engine sorts and staggers the connection attempts with [`HappyEyeballs`] and keeps the first
//! that connects.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// RFC 8305 section 8: the recommended Connection Attempt Delay.
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// RFC 8305 section 5: an attempt never starts within 10 ms of the previous one.
pub const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(10);
/// RFC 8305 section 5: the upper bound of the delay ("Maximum Connection Attempt Delay").
pub const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);

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
}

impl HappyEyeballs {
    /// A race over `addresses` (already sorted, [`sort_addresses`]) with the Connection
    /// Attempt Delay `delay`, held between 10 ms and 2 s (RFC 8305 section 5).
    pub fn new(addresses: Vec<SocketAddr>, delay: Duration) -> Self {
        Self {
            remaining: addresses.into(),
            delay: delay.clamp(MIN_CONNECTION_ATTEMPT_DELAY, MAX_CONNECTION_ATTEMPT_DELAY),
            last_start: None,
            running: 0,
            done: false,
        }
    }

    /// The address to try now, if one is due: the first at once; the next when the delay since
    /// the previous start has passed, or when nothing is running (the previous failed), but
    /// never within 10 ms of the previous start.
    pub fn next_attempt(&mut self, now: Instant) -> Option<SocketAddr> {
        if self.done {
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
        !self.done && self.running == 0 && self.remaining.is_empty()
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
