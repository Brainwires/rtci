//! The retransmission timer of RFC 8489 section 6.2, as data and arithmetic without I/O.
//!
//! [`Client`](crate::client::Client) runs on it, and so does every other transaction layer
//! that sends STUN requests to a server (the TURN client), so that there is one schedule:
//!
//! * over UDP a request is sent at 0, RTO, 3 RTO, 7 RTO and so on (the interval doubles), Rc
//!   times in all, and its transaction fails Rm x RTO after the last one (section 6.2.1);
//! * over a reliable transport it is sent once and fails Ti after it started (section 6.2.2);
//! * the RTO starts at a configured value and then follows the server's round-trip times as
//!   RFC 6298 computes it, kept per server and dropped after ten minutes without a
//!   transaction ([`RtoEstimator`](crate::timer::RtoEstimator)).

use std::time::{Duration, Instant};

/// RFC 8489 section 6.2.1: the initial RTO "SHOULD be greater than or equal to 500 ms".
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);
/// RFC 8489 section 6.2.1: Rc, the number of times a request is sent.
pub const DEFAULT_RC: u32 = 7;
/// RFC 8489 section 6.2.1: Rm, the last wait in units of RTO.
pub const DEFAULT_RM: u32 = 16;
/// RFC 8489 section 6.2.2: Ti, how long a request over a reliable transport waits.
pub const DEFAULT_TI: Duration = Duration::from_millis(39_500);
/// RFC 8489 section 6.2: outstanding transactions to one server.
pub const DEFAULT_MAX_OUTSTANDING: usize = 10;
/// RFC 8489 section 6.2.1: a cached RTO is stale after ten minutes without a transaction.
pub const RTO_CACHE_LIFETIME: Duration = Duration::from_secs(600);
/// RFC 6298 section 2: the clock granularity G; RFC 8489 asks for 1 ms accuracy.
const CLOCK_GRANULARITY: Duration = Duration::from_millis(1);
/// RFC 6298 section 2.5: an upper bound on the RTO.
const MAX_RTO: Duration = Duration::from_secs(60);

/// `now + d`, without the panic `Instant` reserves for an overflow.
#[must_use]
pub fn after(now: Instant, d: Duration) -> Instant {
    now.checked_add(d)
        .or_else(|| now.checked_add(Duration::from_secs(86_400)))
        .unwrap_or(now)
}

/// The parameters of the retransmission schedule (RFC 8489 sections 6.2.1 and 6.2.2). The
/// default is the RFC's: Rc 7, Rm 16, Ti 39.5 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Rc: how many times a request is sent over an unreliable transport. At least 1.
    pub rc: u32,
    /// Rm: the transaction fails Rm x RTO after the last request.
    pub rm: u32,
    /// Ti: how long a request waits over a reliable transport, where it is sent once.
    pub ti: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            rc: DEFAULT_RC,
            rm: DEFAULT_RM,
            ti: DEFAULT_TI,
        }
    }
}

impl Schedule {
    /// When a request that was just sent at `now` for the `sent`-th time (1 for the first) is
    /// due again, or, after the last one, when its transaction fails. `start` is when the
    /// transaction started and `rto` the RTO it started with; `reliable` says the transport
    /// retransmits for the client.
    #[must_use]
    pub fn next_deadline(
        &self,
        reliable: bool,
        start: Instant,
        rto: Duration,
        sent: u32,
        now: Instant,
    ) -> Instant {
        if reliable {
            // Sent once; the transaction fails Ti after it started.
            after(start, self.ti)
        } else if sent < self.rc {
            // The interval doubles after each retransmission: RTO, 2 RTO, 4 RTO, ...
            let doublings = 1u32.checked_shl(sent.saturating_sub(1)).unwrap_or(u32::MAX);
            after(now, rto.saturating_mul(doublings))
        } else {
            // The last request waits Rm x RTO.
            after(now, rto.saturating_mul(self.rm))
        }
    }

    /// Whether a request that was sent `sent` times is not sent again: its next deadline ends
    /// the transaction.
    #[must_use]
    pub fn is_last(&self, reliable: bool, sent: u32) -> bool {
        reliable || sent >= self.rc
    }
}

/// The retransmission timeout of RFC 6298, as RFC 8489 section 6.2.1 uses it: kept per
/// server, to 1 ms, never below the configured initial value, and forgotten after ten minutes
/// without a transaction.
#[derive(Debug, Clone, Copy)]
pub struct RtoEstimator {
    initial: Duration,
    enabled: bool,
    /// Smoothed round-trip time and its variation, once a round trip has been measured.
    estimate: Option<(Duration, Duration)>,
    rto: Duration,
    last_transaction: Option<Instant>,
}

impl RtoEstimator {
    /// An estimator that starts at `initial`. With `enabled` false every transaction starts
    /// at `initial` whatever the round-trip times are.
    #[must_use]
    pub fn new(initial: Duration, enabled: bool) -> Self {
        Self {
            initial,
            enabled,
            estimate: None,
            rto: initial,
            last_transaction: None,
        }
    }

    /// The RTO the next transaction starts with.
    #[must_use]
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Whether nothing was sent to or heard from the server for ten minutes at `now`, so that
    /// the estimate is no longer used (and the estimator can be dropped).
    #[must_use]
    pub fn is_stale(&self, now: Instant) -> bool {
        self.last_transaction
            .is_some_and(|last| now.saturating_duration_since(last) > RTO_CACHE_LIFETIME)
    }

    /// The RTO a transaction that starts at `now` uses.
    pub fn start(&mut self, now: Instant) -> Duration {
        if self.is_stale(now) {
            self.estimate = None;
            self.rto = self.initial;
        }
        self.last_transaction = Some(now);
        self.rto
    }

    /// Takes the round-trip time of a request that was answered without being retransmitted
    /// (RFC 6298 sections 2.2, 2.3 and 3; RFC 8489 section 6.2.1 has Karn's rule: no sample
    /// from a request that was sent more than once).
    pub fn sample(&mut self, rtt: Duration, now: Instant) {
        self.last_transaction = Some(now);
        if !self.enabled {
            return;
        }
        let (srtt, rttvar) = match self.estimate {
            None => (rtt, rtt / 2),
            Some((srtt, rttvar)) => {
                let rttvar = (rttvar * 3 + srtt.abs_diff(rtt)) / 4;
                let srtt = (srtt * 7 + rtt) / 8;
                (srtt, rttvar)
            }
        };
        self.estimate = Some((srtt, rttvar));
        self.rto = (srtt + (rttvar * 4).max(CLOCK_GRANULARITY))
            .max(self.initial)
            .min(MAX_RTO.max(self.initial));
    }
}
