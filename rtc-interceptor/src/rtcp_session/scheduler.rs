//! RTCP transmission timing: RFC 3550 section 6.3 (and its Appendix A.7), the RTP/AVPF rules
//! of RFC 4585 section 3.5, and their amendments for several local SSRCs in RFC 8108 5.3.
//!
//! Everything here is arithmetic on values handed in: no clock is read and no random number
//! is drawn that the caller did not supply.

use std::time::{Duration, Instant};

/// RFC 3550 6.2: the minimum interval between RTCP packets of the RTP/AVP profile, seconds.
pub(crate) const RTCP_MIN_TIME: f64 = 5.0;
/// RFC 3550 6.2: the fraction of the RTCP bandwidth shared by the senders.
pub(crate) const RTCP_SENDER_BW_FRACTION: f64 = 0.25;
/// RFC 3550 6.3.1: `e - 3/2`, which compensates for timer reconsideration converging to a
/// rate below the intended average.
pub(crate) const COMPENSATION: f64 = std::f64::consts::E - 1.5;
/// RFC 3550 6.2: the recommended share of the session bandwidth given to RTCP.
pub(crate) const RTCP_BW_FRACTION: f64 = 0.05;
/// RFC 3550 6.3.5 (as RFC 8108 7.1.4 settles it): a member is timed out after this many
/// deterministic intervals without a packet.
pub(crate) const TIMEOUT_MULTIPLIER: f64 = 5.0;
/// RFC 3550 6.3.7: with more members than this, a BYE is sent with the back-off algorithm.
pub(crate) const BYE_BACKOFF_MEMBERS: usize = 50;
/// The size added to an RTCP packet for its lower layers when averaging packet sizes (RFC 3550
/// 6.2: "including lower-layer transport and network protocol headers"): UDP over IPv4.
pub(crate) const LOWER_LAYER_OVERHEAD: usize = 28;

/// What the interval computation of RFC 3550 6.3.1 takes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct IntervalInput {
    /// The estimated number of session members, this participant included.
    pub(crate) members: usize,
    /// The estimated number of senders.
    pub(crate) senders: usize,
    /// The total bandwidth for RTCP of all members, in octets per second.
    pub(crate) rtcp_bw: f64,
    /// The share of `rtcp_bw` reserved for senders: 0.25, or `RS / (RS + RR)` when the
    /// session description gives both (RFC 3556).
    pub(crate) sender_fraction: f64,
    /// Whether this participant has sent RTP in the last two intervals.
    pub(crate) we_sent: bool,
    /// The average compound RTCP packet size, in octets.
    pub(crate) avg_rtcp_size: f64,
    /// The minimum interval in seconds, before the halving for an initial packet.
    pub(crate) t_min: f64,
    /// Whether this participant has not yet sent an RTCP packet.
    pub(crate) initial: bool,
}

/// The deterministic calculated interval Td of RFC 3550 6.3.1, in seconds.
///
/// Infinite when the participant's share of the RTCP bandwidth is zero (`b=RR:0` for a
/// receiver, RFC 3556): such a participant sends no regular RTCP.
pub(crate) fn deterministic_interval(input: &IntervalInput) -> f64 {
    let mut t_min = input.t_min;
    if input.initial {
        t_min /= 2.0;
    }

    let mut n = input.members as f64;
    let mut rtcp_bw = input.rtcp_bw;
    // Senders get a dedicated fraction of the RTCP bandwidth while they are no more than
    // that fraction of the membership; otherwise everyone shares all of it alike.
    if (input.senders as f64) <= (input.members as f64) * input.sender_fraction {
        if input.we_sent {
            rtcp_bw *= input.sender_fraction;
            n = input.senders as f64;
        } else {
            rtcp_bw *= 1.0 - input.sender_fraction;
            n -= input.senders as f64;
        }
    }

    if rtcp_bw <= 0.0 {
        return f64::INFINITY;
    }
    // The effective number of sites times the average packet size is the octets sent when
    // each site sends a report; divided by the bandwidth it is the interval that keeps them
    // within it.
    let t = input.avg_rtcp_size * n / rtcp_bw;
    t.max(t_min)
}

/// The calculated interval T: Td varied over [0.5, 1.5] by `random` (uniform in [0, 1)) and
/// divided by [`COMPENSATION`].
pub(crate) fn randomized_interval(td: f64, random: f64) -> f64 {
    td * (random + 0.5) / COMPENSATION
}

/// RFC 3550 6.2: the reduced minimum interval, 360 divided by the session bandwidth in
/// kilobits per second, in seconds. It is below five seconds above 72 kbit/s.
pub(crate) fn reduced_minimum(session_bandwidth_bps: f64) -> f64 {
    if session_bandwidth_bps <= 0.0 {
        return RTCP_MIN_TIME;
    }
    (360.0 / (session_bandwidth_bps / 1000.0)).min(RTCP_MIN_TIME)
}

/// RFC 3550 6.3.3: the running average of the compound RTCP packet size.
pub(crate) fn update_avg_rtcp_size(avg_rtcp_size: f64, packet_size: f64) -> f64 {
    packet_size / 16.0 + avg_rtcp_size * 15.0 / 16.0
}

/// `base + seconds`, saturating far in the future for an infinite or absurd interval.
pub(crate) fn after(base: Instant, seconds: f64) -> Instant {
    /// Ten years: further than any timer needs to reach, and safely inside `Instant`.
    const FAR: f64 = 315_360_000.0;
    let seconds = if seconds.is_finite() {
        seconds.clamp(0.0, FAR)
    } else {
        FAR
    };
    base + Duration::from_secs_f64(seconds)
}

/// The seconds from `from` to `to`, negative when `to` is earlier.
pub(crate) fn seconds_between(from: Instant, to: Instant) -> f64 {
    if to >= from {
        to.duration_since(from).as_secs_f64()
    } else {
        -from.duration_since(to).as_secs_f64()
    }
}

/// The RTCP timer of one local SSRC (RFC 8108 5.3.2: each is scheduled on its own).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Timing {
    /// The last time an RTCP packet was transmitted (or its transmission suppressed).
    pub(crate) tp: Instant,
    /// The next scheduled transmission time.
    pub(crate) tn: Instant,
    /// Whether no RTCP packet has been sent yet.
    pub(crate) initial: bool,
    /// RFC 4585 3.5: whether an Early RTCP packet may be sent before `tn`.
    pub(crate) allow_early: bool,
    /// RFC 4585 3.5: when the last Regular RTCP packet was sent; `None` is the RFC's NaN.
    pub(crate) t_rr_last: Option<Instant>,
    /// The first packet goes at `tn` without timer reconsideration ([`Timing::immediate`]).
    pub(crate) immediate: bool,
}

impl Timing {
    /// RFC 3550 6.3.2 and RFC 4585 3.5.1: the timer of a participant that joins at `tc` and
    /// whose first calculated interval is `t` seconds.
    pub(crate) fn new(tc: Instant, t: f64) -> Self {
        Self {
            tp: tc,
            tn: after(tc, t),
            initial: true,
            allow_early: true,
            t_rr_last: None,
            immediate: false,
        }
    }

    /// The timer of a participant that joins at `tc` and sends its first compound packet
    /// then: RFC 8834 section 4.1 (with RFC 3550 section 6.2 as RFC 8108 updates it), "the
    /// delay before sending the initial compound RTCP packet can be set to zero".
    pub(crate) fn immediate(tc: Instant) -> Self {
        Self {
            immediate: true,
            ..Self::new(tc, 0.0)
        }
    }

    /// RFC 3550 6.3.6, timer reconsideration: with the interval `t` calculated now, whether
    /// the packet is to be transmitted at `tc`. If not, `tn` moves to `tp + t`.
    pub(crate) fn reconsider(&mut self, tc: Instant, t: f64) -> bool {
        let candidate = after(self.tp, t);
        if candidate <= tc {
            true
        } else {
            self.tn = candidate;
            false
        }
    }

    /// RFC 3550 6.3.6: a packet was transmitted (or suppressed, RFC 4585 3.5.3) at `tp`, and
    /// the next interval calculated is `t`.
    pub(crate) fn rescheduled(&mut self, tp: Instant, t: f64) {
        self.immediate = false;
        self.tp = tp;
        self.tn = after(tp, t);
        self.allow_early = true;
    }

    /// RFC 3550 6.3.4, reverse reconsideration: the membership fell from `pmembers` to
    /// `members` at `tc`, so the time to the next packet and since the last shrink with it.
    pub(crate) fn reverse_reconsider(&mut self, tc: Instant, members: usize, pmembers: usize) {
        if pmembers == 0 || members >= pmembers {
            return;
        }
        let ratio = members as f64 / pmembers as f64;
        // tn = tc + (members / pmembers) * (tn - tc)
        let until_next = seconds_between(tc, self.tn);
        self.tn = if until_next >= 0.0 {
            after(tc, ratio * until_next)
        } else {
            self.tn
        };
        // tp = tc - (members / pmembers) * (tc - tp); tp can lie after tc (RFC 8108 5.3.2).
        let since_last = seconds_between(self.tp, tc);
        self.tp = if since_last >= 0.0 {
            tc - Duration::from_secs_f64(ratio * since_last)
        } else {
            after(tc, ratio * -since_last)
        };
    }

    /// RFC 4585 3.5.2 step 6: an Early RTCP packet was sent. The next Regular packet is put
    /// off by one interval (`tn = tp + 2 * T_rr`, `tp` = the previous `tn`), and no further
    /// Early packet is allowed until then.
    pub(crate) fn early_sent(&mut self) {
        let t_rr = seconds_between(self.tp, self.tn).max(0.0);
        let previous_tn = self.tn;
        self.tn = after(self.tp, 2.0 * t_rr);
        self.tp = previous_tn;
        self.allow_early = false;
    }
}

/// RFC 4585 3.5.3 (T_rr_interval != 0): what happens to a Regular RTCP packet whose timer
/// expired and passed reconsideration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegularDecision {
    /// Cases 1 and 2a: a Regular (full compound) packet is sent; `t_rr_last` becomes `tn`.
    Send,
    /// Case 2b: feedback is waiting, so a packet carrying it is sent; `t_rr_last` stays.
    SendFeedbackOnly,
    /// Case 2c: the packet is suppressed.
    Suppress,
}

/// The decision of RFC 4585 3.5.3 for a timer that expired at `tn`.
///
/// `random` is uniform in [0, 1): `T_rr_current_interval` is `T_rr_interval` varied over
/// [0.5, 1.5].
pub(crate) fn regular_decision(
    t_rr_interval: f64,
    t_rr_last: Option<Instant>,
    tn: Instant,
    random: f64,
    feedback_waiting: bool,
) -> RegularDecision {
    if t_rr_interval <= 0.0 {
        return RegularDecision::Send;
    }
    let Some(t_rr_last) = t_rr_last else {
        return RegularDecision::Send;
    };
    let t_rr_current_interval = (random + 0.5) * t_rr_interval;
    if after(t_rr_last, t_rr_current_interval) <= tn {
        RegularDecision::Send
    } else if feedback_waiting {
        RegularDecision::SendFeedbackOnly
    } else {
        RegularDecision::Suppress
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> IntervalInput {
        IntervalInput {
            members: 2,
            senders: 1,
            rtcp_bw: 400.0,
            sender_fraction: RTCP_SENDER_BW_FRACTION,
            we_sent: true,
            avg_rtcp_size: 100.0,
            t_min: RTCP_MIN_TIME,
            initial: false,
        }
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// RFC 3550 6.2: "the recommended value for a fixed minimum interval is 5 seconds".
    #[test]
    fn a_small_session_is_held_to_the_five_second_minimum() {
        // 64 kbit/s session: 5% is 400 octets/s. Two members sharing it with 100-octet
        // packets could report every half second; the minimum holds them to five.
        assert!(close(5.0, deterministic_interval(&input())));
    }

    /// RFC 3550 6.2: the first packet is delayed by "half the minimum interval".
    #[test]
    fn the_initial_interval_halves_the_minimum() {
        let initial = IntervalInput {
            initial: true,
            ..input()
        };
        assert!(close(2.5, deterministic_interval(&initial)));
    }

    /// RFC 3550 6.2: with senders no more than a quarter of the members, a quarter of the
    /// RTCP bandwidth is theirs and the rest the receivers'. A session of 1000 members and 10
    /// senders at 1600 octets/s of RTCP, 200-octet packets.
    #[test]
    fn senders_and_receivers_split_the_bandwidth_one_to_three() {
        let session = IntervalInput {
            members: 1000,
            senders: 10,
            rtcp_bw: 1600.0,
            avg_rtcp_size: 200.0,
            ..input()
        };
        // Senders: 10 share 400 octets/s: 200 * 10 / 400 = 5 s.
        assert!(close(5.0, deterministic_interval(&session)));
        // Receivers: 990 share 1200 octets/s: 200 * 990 / 1200 = 165 s.
        let receiver = IntervalInput {
            we_sent: false,
            ..session
        };
        assert!(close(165.0, deterministic_interval(&receiver)));
    }

    /// RFC 3550 6.3.1: when more than a quarter of the members are senders, senders and
    /// receivers are treated together.
    #[test]
    fn with_many_senders_everyone_shares_the_whole_bandwidth() {
        let session = IntervalInput {
            members: 100,
            senders: 50,
            rtcp_bw: 100.0,
            avg_rtcp_size: 100.0,
            ..input()
        };
        // 100 members share 100 octets/s with 100-octet packets: 100 s, sender or not.
        assert!(close(100.0, deterministic_interval(&session)));
        let receiver = IntervalInput {
            we_sent: false,
            ..session
        };
        assert!(close(100.0, deterministic_interval(&receiver)));
    }

    /// RFC 3550 6.3.1: the interval is "a number uniformly distributed between 0.5 and 1.5
    /// times the calculated interval", divided by e - 3/2 = 1.21828.
    #[test]
    fn the_interval_varies_from_half_to_one_and_a_half_over_the_compensation() {
        assert!((COMPENSATION - 1.21828).abs() < 1e-5);
        assert!(close(
            5.0 * 0.5 / COMPENSATION,
            randomized_interval(5.0, 0.0)
        ));
        assert!(close(5.0 / COMPENSATION, randomized_interval(5.0, 0.5)));
        let top = randomized_interval(5.0, 0.999_999);
        assert!(top < 5.0 * 1.5 / COMPENSATION && top > 6.15);
        // The bounds the RFC's 5 s minimum gives on the wire: 2.05 s to 6.16 s.
        assert!((randomized_interval(5.0, 0.0) - 2.052).abs() < 1e-3);
    }

    /// RFC 3550 6.2: the reduced minimum is "360 divided by the session bandwidth in
    /// kilobits/second", which "becomes less than 5 seconds for bandwidths greater than
    /// 72 kb/s".
    #[test]
    fn the_reduced_minimum_is_360_over_the_bandwidth_in_kilobits() {
        assert!(close(5.0, reduced_minimum(72_000.0)));
        assert!(close(5.0, reduced_minimum(32_000.0)));
        assert!(close(0.5, reduced_minimum(720_000.0)));
        assert!(close(0.18, reduced_minimum(2_000_000.0)));
    }

    /// RFC 3556: `b=RR:0` gives receivers no RTCP bandwidth, so they send no regular RTCP.
    #[test]
    fn a_share_of_zero_gives_an_infinite_interval() {
        let receiver = IntervalInput {
            members: 10,
            senders: 1,
            sender_fraction: 1.0,
            we_sent: false,
            ..input()
        };
        assert!(deterministic_interval(&receiver).is_infinite());
        let base = Instant::now();
        assert!(after(base, f64::INFINITY) > base + Duration::from_secs(86_400 * 365));
    }

    /// RFC 3550 6.3.3: avg_rtcp_size = (1/16) * packet_size + (15/16) * avg_rtcp_size.
    #[test]
    fn the_average_packet_size_moves_a_sixteenth_towards_each_packet() {
        assert!(close(106.25, update_avg_rtcp_size(100.0, 200.0)));
        assert!(close(100.0, update_avg_rtcp_size(100.0, 100.0)));
    }

    /// RFC 3550 6.3.6: "If tp + T is less than or equal to tc, an RTCP packet is
    /// transmitted ... If tp + T is greater than tc, tn is set to tp + T."
    #[test]
    fn reconsideration_sends_or_moves_the_timer_to_tp_plus_t() {
        let base = Instant::now();
        let mut timing = Timing::new(base, 2.0);
        assert_eq!(base + Duration::from_secs(2), timing.tn);

        // The membership grew meanwhile: the interval calculated at expiry is 5 s.
        let tc = timing.tn;
        assert!(!timing.reconsider(tc, 5.0));
        assert_eq!(base + Duration::from_secs(5), timing.tn);

        // At the new expiry the interval is 4 s: tp + 4 <= tc, transmit.
        let tc = timing.tn;
        assert!(timing.reconsider(tc, 4.0));
        timing.rescheduled(tc, 3.0);
        assert_eq!(tc, timing.tp);
        assert_eq!(tc + Duration::from_secs(3), timing.tn);
    }

    /// RFC 3550 6.3.4: tn = tc + (members/pmembers) * (tn - tc) and
    /// tp = tc - (members/pmembers) * (tc - tp).
    #[test]
    fn reverse_reconsideration_scales_both_times_by_the_membership_ratio() {
        let base = Instant::now();
        let mut timing = Timing::new(base, 100.0);
        let tc = base + Duration::from_secs(40);

        // Four members become one.
        timing.reverse_reconsider(tc, 1, 4);
        assert_eq!(tc + Duration::from_secs(15), timing.tn);
        assert_eq!(tc - Duration::from_secs(10), timing.tp);

        // A membership that did not fall changes nothing.
        let before = timing;
        timing.reverse_reconsider(tc, 4, 4);
        assert_eq!(before, timing);
    }

    /// RFC 4585 3.5.2 step 6: "set allow_early = FALSE, recalculate tn = tp + 2*T_rr, and set
    /// tp to the previous tn".
    #[test]
    fn an_early_packet_skips_one_regular_interval() {
        let base = Instant::now();
        let mut timing = Timing::new(base, 4.0);
        timing.early_sent();
        assert!(!timing.allow_early);
        assert_eq!(base + Duration::from_secs(8), timing.tn);
        assert_eq!(base + Duration::from_secs(4), timing.tp);

        // When that tn is reached the packet is sent or suppressed, and early is allowed.
        timing.rescheduled(timing.tn, 4.0);
        assert!(timing.allow_early);
    }

    /// RFC 4585 3.5.3: the four cases for T_rr_interval != 0.
    #[test]
    fn regular_packets_are_suppressed_inside_t_rr_interval() {
        let base = Instant::now();
        let secs = Duration::from_secs_f64;

        // 1. Nothing sent yet (t_rr_last is NaN): send.
        assert_eq!(
            RegularDecision::Send,
            regular_decision(1.0, None, base, 0.5, false)
        );
        // 2a. T_rr_current_interval (1.0 at random 0.5) has passed since t_rr_last: send.
        assert_eq!(
            RegularDecision::Send,
            regular_decision(1.0, Some(base), base + secs(1.0), 0.5, false)
        );
        // 2c. It has not, and nothing waits: suppress.
        assert_eq!(
            RegularDecision::Suppress,
            regular_decision(1.0, Some(base), base + secs(0.9), 0.5, false)
        );
        // 2b. It has not, but feedback waits: send it.
        assert_eq!(
            RegularDecision::SendFeedbackOnly,
            regular_decision(1.0, Some(base), base + secs(0.9), 0.5, true)
        );
        // The interval is dithered over [0.5, 1.5]: at 0.6 s a low draw sends, a high one
        // does not.
        assert_eq!(
            RegularDecision::Send,
            regular_decision(1.0, Some(base), base + secs(0.6), 0.0, false)
        );
        assert_eq!(
            RegularDecision::Suppress,
            regular_decision(1.0, Some(base), base + secs(0.6), 0.99, false)
        );
        // T_rr_interval == 0: every Regular packet is sent.
        assert_eq!(
            RegularDecision::Send,
            regular_decision(0.0, Some(base), base, 0.99, false)
        );
    }
}
