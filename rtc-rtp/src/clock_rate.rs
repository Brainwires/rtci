//! Several clock rates in one RTP session ([RFC 7160]).
//!
//! A source that changes payload type may change clock rate with it (PCMU at 8000 Hz to Opus
//! at 48000 Hz, say). RFC 7160 says what then happens to the SSRC, the RTP timestamp and the
//! receiver's jitter estimate. This module holds those rules as plain arithmetic: nothing here
//! reads a clock. Instants are `Duration`s since an epoch the caller chooses.
//!
//! * `ClockRateHistory`: section 4.1, whether a clock rate change needs a new SSRC.
//! * `MultiRateTimestamp`: section 4.2, the timestamp of a sender that keeps one SSRC.
//! * `interarrival_difference` and `JitterEstimator`: section 4.3, the receiver's jitter.
//!
//! [RFC 7160]: https://datatracker.ietf.org/doc/html/rfc7160

use std::time::Duration;

/// `duration * clock_rate`, in timestamp units, rounded to the nearest unit.
fn ticks(duration: Duration, clock_rate: u32) -> u128 {
    (duration.as_nanos() * u128::from(clock_rate) + 500_000_000) / 1_000_000_000
}

/// What a sender that sends RTCP does with its SSRC when the clock rate of its stream changes
/// (RFC 7160 section 4.1).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SsrcForClockRate {
    /// The clock rate is the one in use: keep the SSRC.
    Keep,
    /// A clock rate this stream has not used: a different SSRC is used for it.
    New,
    /// A clock rate the stream used before: an RTCP BYE is sent for the SSRC that used it and a
    /// new SSRC is taken.
    NewAfterBye,
}

/// The clock rates one RTP stream has used, for the SSRC rule of RFC 7160 section 4.1: a
/// different SSRC for each clock rate, and a BYE and a new SSRC when the stream switches back
/// to a rate it already used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockRateHistory {
    current: Option<u32>,
    seen: Vec<u32>,
}

impl ClockRateHistory {
    /// A stream that has sent nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The clock rate in use, once a packet was sent.
    pub fn current(&self) -> Option<u32> {
        self.current
    }

    /// The other clock rates seen, most recent last: the ones whose mapping the next compound
    /// RTCP packet carries in further SR packets after the current rate's (section 4.1).
    pub fn previous(&self) -> impl Iterator<Item = u32> + '_ {
        let current = self.current;
        self.seen
            .iter()
            .copied()
            .filter(move |&rate| Some(rate) != current)
    }

    /// Records that the next packet is sent with `clock_rate` and says what happens to the
    /// SSRC. The first packet of a stream keeps the SSRC it was given.
    pub fn switch_to(&mut self, clock_rate: u32) -> SsrcForClockRate {
        if self.current == Some(clock_rate) {
            return SsrcForClockRate::Keep;
        }
        let first = self.current.is_none();
        let seen_before = self.seen.contains(&clock_rate);
        self.current = Some(clock_rate);
        if seen_before {
            // Move it to the end: the most recent.
            self.seen.retain(|&rate| rate != clock_rate);
        }
        self.seen.push(clock_rate);
        if first {
            SsrcForClockRate::Keep
        } else if seen_before {
            SsrcForClockRate::NewAfterBye
        } else {
            SsrcForClockRate::New
        }
    }
}

/// The RTP timestamp of a sender that keeps one SSRC across clock rate changes, which RFC 7160
/// section 4.2 allows only with RTCP turned off:
///
/// ```text
/// start_offset += (capture_time - capture_start) * previous_clock_rate   (on a change)
/// capture_start = capture_time                                           (on a change)
/// timestamp = (capture_time - capture_start) * clock_rate + start_offset
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiRateTimestamp {
    start_offset: u32,
    capture_start: Duration,
    clock_rate: u32,
}

impl MultiRateTimestamp {
    /// The state for a stream whose first packet is captured at `capture_time` with
    /// `clock_rate`. `initial_offset` is the stream's random initial timestamp (RFC 3550
    /// section 5.1), which the caller draws.
    pub fn new(initial_offset: u32, capture_time: Duration, clock_rate: u32) -> Self {
        MultiRateTimestamp {
            start_offset: initial_offset,
            capture_start: capture_time,
            clock_rate,
        }
    }

    /// The RTP timestamp of a packet captured at `capture_time` and sent with `clock_rate`.
    /// A capture time before the last clock rate change is taken as that change's instant.
    pub fn timestamp(&mut self, capture_time: Duration, clock_rate: u32) -> u32 {
        let since_start = capture_time.saturating_sub(self.capture_start);
        if clock_rate != self.clock_rate {
            // Timestamps wrap: the truncation is the modulo 2^32 arithmetic of RTP.
            self.start_offset = self
                .start_offset
                .wrapping_add(ticks(since_start, self.clock_rate) as u32);
            self.capture_start = capture_time.max(self.capture_start);
            self.clock_rate = clock_rate;
            return self.start_offset;
        }
        self.start_offset
            .wrapping_add(ticks(since_start, clock_rate) as u32)
    }
}

/// One received packet, as the jitter calculation needs it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Arrival {
    /// When the packet arrived.
    pub arrival_time: Duration,
    /// Its RTP timestamp.
    pub timestamp: u32,
    /// The clock rate of its payload type.
    pub clock_rate: u32,
}

/// `D(i,j)` of RFC 7160 section 4.3, in units of packet i's clock:
///
/// ```text
/// D(i,j) = (arrival_time_j * clock_rate_i - timestamp_j)
///          - (arrival_time_i * clock_rate_i - timestamp_i)
/// ```
///
/// The clock rate of packet `i` (the earlier one) is used for both arrival times, which is
/// what keeps the difference zero across a clock rate change on a path without jitter.
pub fn interarrival_difference(i: Arrival, j: Arrival) -> i64 {
    let arrival = if j.arrival_time >= i.arrival_time {
        ticks(j.arrival_time - i.arrival_time, i.clock_rate) as i64
    } else {
        -(ticks(i.arrival_time - j.arrival_time, i.clock_rate) as i64)
    };
    // The timestamp difference is signed and modulo 2^32.
    let sent = i64::from(j.timestamp.wrapping_sub(i.timestamp) as i32);
    arrival - sent
}

/// The interarrival jitter estimator of RFC 3550 section 6.4.1 and Appendix A.8, fed with the
/// difference of RFC 7160 section 4.3 so that a stream may change clock rate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JitterEstimator {
    last: Option<Arrival>,
    /// The estimate, scaled by 16 as in Appendix A.8.
    jitter_q4: u64,
}

impl JitterEstimator {
    /// An estimator that has seen no packet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a packet, in the order of arrival, and returns the jitter estimate after it.
    pub fn update(&mut self, packet: Arrival) -> u32 {
        if let Some(last) = self.last {
            let d = interarrival_difference(last, packet).unsigned_abs();
            // J += (|D| - J) / 16, in the integer form of Appendix A.8.
            self.jitter_q4 = self.jitter_q4 + d - ((self.jitter_q4 + 8) >> 4);
        }
        self.last = Some(packet);
        self.jitter()
    }

    /// The jitter estimate, as an RTCP reception report carries it.
    pub fn jitter(&self) -> u32 {
        u32::try_from(self.jitter_q4 >> 4).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
#[path = "clock_rate_test.rs"]
mod clock_rate_test;
