//! The RTP sequence numbers of a stream that never left, for reading a receiver report's loss.
//!
//! The pacer sits application-ward of the congestion controller and the circuit breaker, and with
//! `PacerQueueOverflow::Drop` it discards media the target has no room for. Those packets were
//! already numbered by the application's packetizer, so the remote receiver sees a gap in the
//! sequence numbers and counts them as lost in its reports (RFC 3550 section 6.4.1: the fraction
//! lost and the cumulative number lost are both taken from the sequence numbers expected and the
//! packets received). An interceptor wire-ward of the pacer sees exactly the packets that left:
//! a sequence number it was jumped over is one the sender never sent, and the path cannot have
//! lost it. [`NeverSent`] keeps those numbers for one stream and gives, for each report, how
//! many of the packets the report counts as lost were never sent.

use std::collections::BTreeSet;

/// A jump in the sequence numbers this large or larger is not recorded as numbers never sent:
/// RFC 3550 appendix A.1 has the receiver take such a jump (MAX_DROPOUT, 3000) as the source
/// starting over, not as loss.
const MAX_DROPOUT: u64 = 3000;

/// The most numbers never sent kept for one stream; the oldest go first. Reports normally prune
/// them long before: what a report has covered is not kept.
const MAX_TRACKED: usize = 8192;

/// Where the extended numbering starts: far enough from zero that a number a little behind the
/// first one sent still has a place.
const ORIGIN: u64 = 1 << 32;

/// The interval one receiver report covers, from the previous report's extended highest sequence
/// number (exclusive) to this one's (inclusive), as RFC 3550 appendix A.3 computes the fraction
/// lost over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReportInterval {
    /// The packets the receiver expected in the interval.
    expected: i64,
    /// What the cumulative number lost moved by over the interval.
    lost: i64,
    /// The sequence numbers of the interval that never left this sender.
    never_sent: i64,
}

impl ReportInterval {
    /// The sequence numbers of the interval that never left this sender.
    pub(crate) fn never_sent(&self) -> i64 {
        self.never_sent
    }

    /// The interval's net loss with the numbers never sent taken out. It is negative where the
    /// receiver's cumulative count gave packets back (a duplicate, or a packet reordered across
    /// the previous report), as the reported count's own movement is.
    pub(crate) fn net_lost(&self) -> i64 {
        self.lost - self.never_sent
    }

    /// The packets of the interval that actually left.
    pub(crate) fn sent(&self) -> i64 {
        (self.expected - self.never_sent).max(0)
    }

    /// The fraction lost of the packets that actually left, in RFC 3550 appendix A.3's
    /// resolution (an 8-bit fixed point number): 0 when none left or none was lost.
    pub(crate) fn fraction_lost(&self) -> f64 {
        let (lost, sent) = (self.net_lost(), self.sent());
        if sent <= 0 || lost <= 0 {
            return 0.0;
        }
        (((lost << 8) / sent).min(255)) as f64 / 256.0
    }
}

/// The sequence numbers one local stream (one SSRC, one sequence space) never sent, and the
/// last receiver report on it.
#[derive(Debug, Default)]
pub(crate) struct NeverSent {
    /// The highest sequence number seen leaving, extended.
    highest: Option<u64>,
    /// The first sequence number seen leaving, extended: where the first report's interval
    /// starts.
    first: u64,
    /// The sequence numbers jumped over, extended.
    skipped: BTreeSet<u64>,
    /// The previous report: its extended highest sequence number, in this numbering, and its
    /// cumulative number lost.
    previous: Option<(u64, i64)>,
}

impl NeverSent {
    /// `sequence_number` extended to the cycle that puts it nearest the highest number sent.
    fn extend(&self, sequence_number: u16) -> Option<u64> {
        self.highest.map(|highest| {
            let delta = sequence_number.wrapping_sub(highest as u16) as i16;
            highest.wrapping_add_signed(i64::from(delta))
        })
    }

    /// A packet of the stream left with `sequence_number`.
    ///
    /// The numbers between the highest sent so far and this one are recorded as never sent. A
    /// number recorded so that leaves later (a retransmission on the media SSRC, which reuses the
    /// original number) is sent after all.
    pub(crate) fn on_sent(&mut self, sequence_number: u16) {
        let Some(highest) = self.highest else {
            let first = ORIGIN + u64::from(sequence_number);
            self.highest = Some(first);
            self.first = first;
            return;
        };
        let Some(extended) = self.extend(sequence_number) else {
            return;
        };
        if extended > highest {
            if extended - highest <= MAX_DROPOUT {
                self.skipped.extend(highest + 1..extended);
                while self.skipped.len() > MAX_TRACKED {
                    self.skipped.pop_first();
                }
            }
            self.highest = Some(extended);
        } else if highest - extended >= MAX_DROPOUT {
            // So far behind that the stream started over: so does what is known of it.
            *self = Self::default();
            self.on_sent(sequence_number);
        } else {
            self.skipped.remove(&extended);
        }
    }

    /// A receiver report on the stream: its extended highest sequence number received and its
    /// cumulative number lost (RFC 3550 section 6.4.1). Returns the interval it covers, from the
    /// previous report (or, for the first one, from the first number sent), with how many of its
    /// numbers were never sent; `None` when nothing of the stream has left yet, or when the
    /// report is older than the previous one.
    ///
    /// The numbers the report covers are forgotten: a later report does not cover them again.
    pub(crate) fn on_report(
        &mut self,
        extended_highest: u32,
        cumulative_lost: i32,
    ) -> Option<ReportInterval> {
        // The low 16 bits are the sequence number; the cycle count is the receiver's own and
        // starts wherever its first packet fell, so the number is placed against what was sent.
        let end = self.extend(extended_highest as u16)?;
        let (start, previous_lost) = self.previous.unwrap_or((self.first - 1, 0));
        if end < start {
            return None;
        }
        let never_sent = self.skipped.range(start + 1..=end).count() as i64;
        let cumulative_lost = i64::from(cumulative_lost);
        self.previous = Some((end, cumulative_lost));
        self.skipped = self.skipped.split_off(&(end + 1));
        Some(ReportInterval {
            expected: (end - start) as i64,
            lost: cumulative_lost - previous_lost,
            never_sent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(never_sent: &mut NeverSent, numbers: impl IntoIterator<Item = u16>) {
        for number in numbers {
            never_sent.on_sent(number);
        }
    }

    #[test]
    fn numbers_jumped_over_count_against_the_report_that_covers_them() {
        let mut never_sent = NeverSent::default();
        send(&mut never_sent, (0..100).chain(150..200));
        let interval = never_sent.on_report(199, 50).expect("interval");
        assert_eq!(200, interval.expected);
        assert_eq!(50, interval.never_sent());
        assert_eq!(0, interval.net_lost());
        assert_eq!(150, interval.sent());
        assert_eq!(0.0, interval.fraction_lost());
    }

    #[test]
    fn the_next_report_covers_only_what_came_after_the_previous_one() {
        let mut never_sent = NeverSent::default();
        send(&mut never_sent, 0..100);
        assert_eq!(0, never_sent.on_report(99, 0).expect("first").never_sent());
        // 100 to 109 never sent, and 5 more of the next 90 lost on the path.
        send(&mut never_sent, 110..200);
        let interval = never_sent.on_report(199, 15).expect("second");
        assert_eq!(100, interval.expected);
        assert_eq!(10, interval.never_sent());
        assert_eq!(5, interval.net_lost());
        // RFC 3550 A.3: (5 << 8) / 90.
        assert_eq!(f64::from((5 << 8) / 90) / 256.0, interval.fraction_lost());
    }

    #[test]
    fn a_number_that_leaves_late_was_sent() {
        let mut never_sent = NeverSent::default();
        send(&mut never_sent, (0..10).chain(12..20));
        never_sent.on_sent(10);
        let interval = never_sent.on_report(19, 1).expect("interval");
        assert_eq!(1, interval.never_sent());
        assert_eq!(0, interval.net_lost());
    }

    #[test]
    fn a_gap_across_the_wrap_is_counted() {
        let mut never_sent = NeverSent::default();
        send(&mut never_sent, 65_500..=65_533);
        // 65534, 65535, 0, 1 never sent.
        send(&mut never_sent, 2..40);
        // The receiver's cycle count is one past its first packet's.
        let interval = never_sent.on_report((1 << 16) | 39, 4).expect("interval");
        assert_eq!(76, interval.expected);
        assert_eq!(4, interval.never_sent());
        assert_eq!(0, interval.net_lost());
    }

    #[test]
    fn a_report_before_anything_left_has_no_interval() {
        let mut never_sent = NeverSent::default();
        assert_eq!(None, never_sent.on_report(100, 10));
    }

    #[test]
    fn a_jump_the_receiver_takes_for_a_restart_is_not_recorded() {
        let mut never_sent = NeverSent::default();
        send(&mut never_sent, [0, 1, 5000, 5001]);
        assert!(never_sent.skipped.is_empty());
    }

    #[test]
    fn what_a_report_covered_is_forgotten_and_the_set_is_capped() {
        let mut never_sent = NeverSent::default();
        let mut number = 0u16;
        for _ in 0..10 {
            never_sent.on_sent(number);
            number = number.wrapping_add(2_000);
        }
        assert!(never_sent.skipped.len() <= MAX_TRACKED);
        never_sent.on_report(u32::from(number.wrapping_sub(2_000)), 0);
        assert!(never_sent.skipped.is_empty());
    }
}
