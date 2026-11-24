//! The message budget and the jitter source of an [`Mdns`](super::Mdns).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default burst of [`MdnsRateLimit`]: the messages that may leave back to back.
pub(crate) const DEFAULT_RATE_BURST: u32 = 40;

/// Default sustained rate of [`MdnsRateLimit`], in messages per second.
pub(crate) const DEFAULT_RATE_PER_SECOND: u32 = 10;

#[derive(Debug)]
struct Bucket {
    burst: u32,
    /// The time one message's worth of budget takes to come back.
    interval: Duration,
    tokens: u32,
    /// The instant the budget was last brought up to date.
    refilled_at: Option<Instant>,
}

impl Bucket {
    fn refill(&mut self, now: Instant) {
        let Some(last) = self.refilled_at else {
            self.refilled_at = Some(now);
            return;
        };
        let elapsed = now.saturating_duration_since(last);
        let earned =
            (elapsed.as_nanos() / self.interval.as_nanos().max(1)).min(u128::from(u32::MAX)) as u32;
        if earned == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(earned).min(self.burst);
        self.refilled_at = Some(if self.tokens == self.burst {
            now
        } else {
            last + self.interval * earned
        });
    }
}

/// A limit on the mDNS messages sent, as a token bucket: `burst` messages may leave back to
/// back, after which `per_second` leave each second.
///
/// Every message an [`Mdns`](crate::Mdns) queues (query, probe, announcement, response, goodbye)
/// takes one message of the budget; with none left, the message waits and
/// [`poll_timeout`](sansio::Protocol::poll_timeout) names the instant it can go. This is the
/// message rate limit draft-ietf-mmusic-mdns-ice-candidates section 7.1 requires beside the
/// per-question and per-record rules of RFC 6762: those do not slow a sender that keeps making
/// new names.
///
/// Each `Mdns` has a limit of its own unless one is given with
/// [`MdnsConfig::with_rate_limit`](crate::MdnsConfig::with_rate_limit). A clone shares its
/// budget with the original, so one limit handed to every `Mdns` of a process bounds them
/// together, which is what the draft asks of a browser.
///
/// # Example
///
/// ```rust
/// use rtci_mdns::{MdnsConfig, MdnsRateLimit};
///
/// // At most 20 messages at once, then 5 a second, for both connections together.
/// let limit = MdnsRateLimit::new(20, 5);
/// let first = MdnsConfig::default().with_rate_limit(limit.clone());
/// let second = MdnsConfig::default().with_rate_limit(limit);
/// ```
#[derive(Debug, Clone)]
pub struct MdnsRateLimit {
    bucket: Arc<Mutex<Bucket>>,
}

impl Default for MdnsRateLimit {
    /// 40 messages at once, then 10 a second.
    fn default() -> Self {
        Self::new(DEFAULT_RATE_BURST, DEFAULT_RATE_PER_SECOND)
    }
}

impl MdnsRateLimit {
    /// A limit of `burst` messages at once and `per_second` sustained. Zero is taken as one.
    pub fn new(burst: u32, per_second: u32) -> Self {
        let burst = burst.max(1);
        Self {
            bucket: Arc::new(Mutex::new(Bucket {
                burst,
                interval: Duration::from_secs(1) / per_second.max(1),
                tokens: burst,
                refilled_at: None,
            })),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Bucket) -> T) -> T {
        // The bucket holds plain numbers: a panic elsewhere while it was locked leaves it
        // usable.
        let mut bucket = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut bucket)
    }

    /// Takes one message of the budget at `now`; `false` when none is left. For a driver that
    /// sends mDNS of several sources through one budget (the `Mdns` of a connection takes from
    /// its own limit by itself).
    pub fn take(&self, now: Instant) -> bool {
        self.with(|bucket| {
            bucket.refill(now);
            if bucket.tokens == 0 {
                return false;
            }
            bucket.tokens -= 1;
            true
        })
    }

    /// When the next message may go: `now` when the budget has one.
    pub fn ready_at(&self, now: Instant) -> Instant {
        self.with(|bucket| {
            bucket.refill(now);
            if bucket.tokens > 0 {
                now
            } else {
                bucket.refilled_at.unwrap_or(now) + bucket.interval
            }
        })
    }
}

/// The source of the random delays RFC 6762 asks for (sections 5.2, 6, 6.3, 7.2, 8.1). They
/// desynchronise hosts; nothing secret rests on them, so this is a small generator (SplitMix64)
/// and not the crypto provider.
#[derive(Debug)]
pub(crate) struct Jitter(u64);

impl Jitter {
    /// Seeded with `seed`, or from the process's hash seed when none is given. Under
    /// `cfg(fuzzing)` the default seed is fixed, so a fuzz input replays identically.
    pub(crate) fn new(seed: Option<u64>) -> Self {
        Self(seed.unwrap_or_else(|| {
            if cfg!(fuzzing) {
                0
            } else {
                RandomState::new().build_hasher().finish()
            }
        }))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A delay between `min_ms` and `max_ms` milliseconds, both included.
    pub(crate) fn millis(&mut self, min_ms: u64, max_ms: u64) -> Duration {
        let span = max_ms.saturating_sub(min_ms) + 1;
        Duration::from_millis(min_ms + self.next() % span)
    }
}

#[cfg(test)]
mod rate_test {
    use super::*;

    #[test]
    fn test_rate_limit_spends_its_burst_then_refills_at_its_rate() {
        let t0 = Instant::now();
        let limit = MdnsRateLimit::new(3, 10);
        assert!(limit.take(t0) && limit.take(t0) && limit.take(t0));
        assert!(!limit.take(t0), "the burst is spent");
        assert_eq!(limit.ready_at(t0), t0 + Duration::from_millis(100));
        assert!(!limit.take(t0 + Duration::from_millis(99)));
        assert!(limit.take(t0 + Duration::from_millis(100)));
        assert!(!limit.take(t0 + Duration::from_millis(100)));
        // A long quiet time gives the burst back, and no more than the burst.
        let later = t0 + Duration::from_secs(60);
        assert!(limit.take(later) && limit.take(later) && limit.take(later));
        assert!(!limit.take(later));
    }

    #[test]
    fn test_rate_limit_clones_share_one_budget() {
        let t0 = Instant::now();
        let limit = MdnsRateLimit::new(2, 1);
        let other = limit.clone();
        assert!(limit.take(t0));
        assert!(other.take(t0));
        assert!(!limit.take(t0) && !other.take(t0));
    }

    #[test]
    fn test_jitter_stays_in_its_range_and_follows_its_seed() {
        let mut a = Jitter::new(Some(7));
        let mut b = Jitter::new(Some(7));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let d = a.millis(20, 120);
            assert_eq!(d, b.millis(20, 120), "one seed, one sequence");
            assert!((20..=120).contains(&d.as_millis()));
            seen.insert(d.as_millis());
        }
        assert!(seen.contains(&20) && seen.contains(&120), "both ends occur");
    }
}
