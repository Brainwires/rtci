//! One remote stream's arrival record.

use crate::jitterbuffer::sequence::SequenceExtender;
use rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReportBlock, Ecn,
};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The most packets one report block can describe, from the 16-bit `num_reports` field.
pub(crate) const MAX_REPORTS_PER_BLOCK: usize = 16384;

/// The arrival-time offset meaning "this packet arrived *after* the report timestamp".
const OFFSET_AFTER_REPORT: u16 = 0x1FFF;

/// The arrival-time offset meaning "longer ago than this field can express".
const OFFSET_TOO_OLD: u16 = 0x1FFE;

/// The largest offset that fits before the two reserved values above.
const OFFSET_MAX: u16 = 0x1FFD;

/// How long a packet already reported stays in the log, so a late arrival just before it can be
/// reported in a report that overlaps it.
///
/// RFC 8888 section 3.1 asks for overlapping reports when packets are reordered across a report
/// boundary, and requires a packet once reported as received to be reported as received in every
/// later report that covers it. Both need the arrivals of the overlapped range, for as long as a
/// reordered packet is still worth reporting. Half a second is the reordering window the
/// transport-wide recorder uses as well; a packet later than that has long been declared lost by
/// the sender.
pub(crate) const REORDER_WINDOW: Duration = Duration::from_millis(500);

/// What was observed about one packet.
#[derive(Debug, Clone, Copy)]
struct PacketReport {
    arrival: Instant,
    ecn: Ecn,
}

/// Arrival times for one media stream, kept until they have been reported and the reordering
/// window has passed.
///
/// Sequence numbers are extended before use: the log spans an unbounded run of packets, and a
/// wrap would otherwise put a newer packet behind an older one.
#[derive(Debug)]
pub(crate) struct StreamLog {
    ssrc: u32,
    extender: SequenceExtender,
    /// The next sequence number a report should start from.
    next_to_report: u64,
    /// The highest sequence number seen.
    highest_received: u64,
    /// The lowest sequence number whose fate is still known: everything from here up is either
    /// in `log` or was not received. A report never starts below it.
    floor: u64,
    /// Where each past report ended (exclusive) and when it was built, oldest first: what
    /// moves `floor` once the reordering window has passed.
    reported: VecDeque<(Instant, u64)>,
    initialised: bool,
    log: HashMap<u64, PacketReport>,
}

impl StreamLog {
    pub(crate) fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            extender: SequenceExtender::new(),
            next_to_report: 0,
            highest_received: 0,
            floor: 0,
            reported: VecDeque::new(),
            initialised: false,
            log: HashMap::new(),
        }
    }

    /// Record a packet's arrival.
    ///
    /// A duplicate keeps the arrival time of the first copy, and reports ECN-CE if any copy
    /// carried it (RFC 8888 section 3.1). A packet that arrives after a report already described
    /// its sequence number as not received moves the start of the next report back to it, so the
    /// next report overlaps the previous one; one older than the reordering window is dropped.
    pub(crate) fn add(&mut self, arrival: Instant, sequence_number: u16, ecn: Ecn) {
        let extended = self.extender.extend(sequence_number);

        if !self.initialised {
            self.initialised = true;
            self.next_to_report = extended;
            self.floor = extended;
            self.highest_received = extended;
        }
        if extended < self.floor {
            return;
        }

        match self.log.entry(extended) {
            Entry::Occupied(mut first) => {
                if ecn == Ecn::Ce && first.get().ecn != Ecn::Ce {
                    first.get_mut().ecn = Ecn::Ce;
                    // The mark changed what the sender must be told about this packet.
                    self.next_to_report = self.next_to_report.min(extended);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(PacketReport { arrival, ecn });
                self.next_to_report = self.next_to_report.min(extended);
            }
        }
        self.highest_received = self.highest_received.max(extended);
    }

    /// Forget what the reordering window no longer needs.
    fn prune(&mut self, now: Instant) {
        let mut floor = self.floor;
        while let Some(&(at, end)) = self.reported.front() {
            if now.saturating_duration_since(at) < REORDER_WINDOW {
                break;
            }
            floor = floor.max(end);
            self.reported.pop_front();
        }
        // Never past what has not been reported yet.
        let floor = floor.min(self.next_to_report);
        if floor > self.floor {
            self.floor = floor;
            self.log
                .retain(|&sequence_number, _| sequence_number >= floor);
        }
    }

    /// Build the report block for what has not been reported yet, at most `max_blocks` packets
    /// of it, oldest first. What does not fit stays for the next call, so a window too large for
    /// one feedback packet continues in the next one.
    ///
    /// Offsets are measured back from `reference`, which is the instant the whole report is
    /// stamped with: every stream in a report shares it, so the sender can compare arrival times
    /// across streams.
    ///
    /// Every packet is described once. A packet missing when its range is reported is reported
    /// as not received, and the report moves on: a gap that never fills does not make every later
    /// report repeat everything after it. If the packet does arrive within the reordering
    /// window, [`add`](Self::add) moves the start back and the next report overlaps.
    pub(crate) fn metrics_after(
        &mut self,
        reference: Instant,
        max_blocks: usize,
    ) -> CcFeedbackReportBlock {
        self.prune(reference);

        if self.is_empty() || max_blocks == 0 {
            // Nothing new: the block says so with the highest sequence number received and no
            // metric blocks (RFC 8888 section 3.1).
            return CcFeedbackReportBlock {
                media_ssrc: self.ssrc,
                begin_sequence: self.highest_received as u16,
                metric_blocks: Vec::new(),
            };
        }

        // One block describes at most a quarter of the sequence space. A jump further than that
        // (a stream that restarted its numbering) gives up the oldest end: the format cannot
        // express the range.
        let pending = self.highest_received - self.next_to_report + 1;
        if pending > MAX_REPORTS_PER_BLOCK as u64 {
            let new_next = self.highest_received + 1 - MAX_REPORTS_PER_BLOCK as u64;
            self.next_to_report = new_next;
            self.floor = self.floor.max(new_next);
            self.log
                .retain(|&sequence_number, _| sequence_number >= new_next);
        }

        let begin = self.next_to_report;
        let count = (self.highest_received - begin + 1).min(max_blocks as u64);
        let end = begin + count;

        let metric_blocks = (begin..end)
            .map(|extended| match self.log.get(&extended) {
                Some(report) => CcFeedbackMetricBlock {
                    received: true,
                    ecn: report.ecn,
                    arrival_time_offset: arrival_time_offset(reference, report.arrival),
                },
                None => CcFeedbackMetricBlock::default(),
            })
            .collect();

        self.next_to_report = end;
        self.reported.push_back((reference, end));

        CcFeedbackReportBlock {
            media_ssrc: self.ssrc,
            begin_sequence: begin as u16,
            metric_blocks,
        }
    }

    /// Whether nothing is waiting to be reported.
    pub(crate) fn is_empty(&self) -> bool {
        !self.initialised || self.next_to_report > self.highest_received
    }
}

/// How long before the report timestamp a packet arrived, in units of 1/1024 s.
///
/// Thirteen bits, with two of the values reserved: a packet that arrived *after* the report was
/// stamped reports `0x1FFF`, and one older than the field can express reports `0x1FFE`. Clamping
/// rather than wrapping matters — a wrapped offset would tell the sender a very old packet had
/// just arrived, which is exactly the measurement congestion control must not get wrong.
fn arrival_time_offset(reference: Instant, arrival: Instant) -> u16 {
    if arrival > reference {
        return OFFSET_AFTER_REPORT;
    }
    let offset = reference.duration_since(arrival).as_secs_f64() * 1024.0;
    if offset > f64::from(OFFSET_MAX) {
        return OFFSET_TOO_OLD;
    }
    offset as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn received(block: &CcFeedbackReportBlock) -> Vec<bool> {
        block
            .metric_blocks
            .iter()
            .map(|metric| metric.received)
            .collect()
    }

    #[test]
    fn an_empty_log_reports_nothing() {
        let mut log = StreamLog::new(1);
        let block = log.metrics_after(Instant::now(), MAX_REPORTS_PER_BLOCK);

        assert_eq!(1, block.media_ssrc);
        assert!(block.metric_blocks.is_empty());
    }

    #[test]
    fn a_contiguous_run_is_reported_once_and_then_forgotten() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for offset in 0..3u16 {
            log.add(now, 100 + offset, Ecn::NotEct);
        }

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(100, block.begin_sequence);
        assert_eq!(vec![true, true, true], received(&block));

        assert!(
            log.is_empty(),
            "everything reported was contiguous, so nothing is held"
        );
        let second = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert!(
            second.metric_blocks.is_empty(),
            "and it is not reported a second time"
        );
    }

    /// A gap is reported once, as not received. The next report starts after it: a packet that
    /// never arrives must not make every later report repeat the window (rfc8888.md bug B6).
    #[test]
    fn a_gap_is_reported_once_and_the_next_report_moves_on() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now, 102, Ecn::NotEct);

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(100, block.begin_sequence);
        assert_eq!(vec![true, false, true], received(&block));

        log.add(now, 103, Ecn::NotEct);
        let second = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(103, second.begin_sequence, "101 is not described again");
        assert_eq!(vec![true], received(&second));
    }

    /// RFC 8888 section 3.1: overlapping reports need to be sent when packets are reordered
    /// across a report boundary, and a packet once reported as received is reported as received
    /// in every later report that covers it.
    #[test]
    fn a_late_arrival_is_reported_in_an_overlapping_report() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now, 102, Ecn::NotEct);
        log.metrics_after(now, MAX_REPORTS_PER_BLOCK);

        // 101 arrives late, inside the reordering window.
        let later = now + Duration::from_millis(100);
        log.add(later, 101, Ecn::NotEct);
        let second = log.metrics_after(later, MAX_REPORTS_PER_BLOCK);
        assert_eq!(101, second.begin_sequence, "back to the late packet");
        assert_eq!(
            vec![true, true],
            received(&second),
            "102 was reported received and is reported received again"
        );
    }

    #[test]
    fn an_arrival_older_than_the_reordering_window_is_dropped() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now, 102, Ecn::NotEct);
        log.metrics_after(now, MAX_REPORTS_PER_BLOCK);

        let later = now + REORDER_WINDOW + Duration::from_millis(1);
        log.add(later, 103, Ecn::NotEct);
        log.metrics_after(later, MAX_REPORTS_PER_BLOCK);
        log.add(later, 101, Ecn::NotEct);
        assert!(log.is_empty(), "too late to be worth an overlapping report");
    }

    /// RFC 8888 section 3.1: the arrival time of the first copy is reported.
    #[test]
    fn a_duplicate_keeps_the_first_arrival_time() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now + Duration::from_millis(50), 100, Ecn::NotEct);

        let block = log.metrics_after(now + Duration::from_millis(60), MAX_REPORTS_PER_BLOCK);
        assert_eq!(1, block.metric_blocks.len());
        assert_eq!(
            arrival_time_offset(now + Duration::from_millis(60), now),
            block.metric_blocks[0].arrival_time_offset,
            "60 ms before the report, not 10"
        );
    }

    /// RFC 8888 section 3.1: ECN-CE if any copy carried it, otherwise the first copy's mark.
    #[test]
    fn a_duplicate_reports_ce_if_any_copy_was_marked() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::Ce);
        log.add(now, 100, Ecn::Ect1);
        log.add(now, 101, Ecn::Ect1);
        log.add(now, 101, Ecn::Ce);
        log.add(now, 102, Ecn::Ect0);
        log.add(now, 102, Ecn::Ect1);

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(
            vec![Ecn::Ce, Ecn::Ce, Ecn::Ect0],
            block
                .metric_blocks
                .iter()
                .map(|metric| metric.ecn)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_packet_already_reported_is_not_reported_again() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.metrics_after(now, MAX_REPORTS_PER_BLOCK);

        log.add(now, 100, Ecn::NotEct);
        assert!(
            log.is_empty(),
            "already reported: a second copy changes nothing the sender was told"
        );
    }

    /// RFC 8888 section 3.1: a window too large for one feedback packet is split, not cut.
    #[test]
    fn a_window_larger_than_the_block_continues_in_the_next_one() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for offset in 0..10u16 {
            log.add(now, 100 + offset, Ecn::NotEct);
        }

        let block = log.metrics_after(now, 4);
        assert_eq!(4, block.metric_blocks.len(), "capped at the limit");
        assert_eq!(100, block.begin_sequence, "oldest first");
        assert!(!log.is_empty());

        let next = log.metrics_after(now, 4);
        assert_eq!(104, next.begin_sequence);
        let last = log.metrics_after(now, 4);
        assert_eq!(108, last.begin_sequence);
        assert_eq!(2, last.metric_blocks.len());
        assert!(log.is_empty());
    }

    /// RFC 8888 section 3.1: with nothing received in the interval the block carries the highest
    /// sequence number received and no metric blocks.
    #[test]
    fn an_idle_stream_reports_the_highest_sequence_number_received() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now, 101, Ecn::NotEct);
        log.metrics_after(now, MAX_REPORTS_PER_BLOCK);

        let idle = log.metrics_after(now + Duration::from_millis(100), MAX_REPORTS_PER_BLOCK);
        assert_eq!(101, idle.begin_sequence);
        assert!(idle.metric_blocks.is_empty());
    }

    #[test]
    fn ecn_markings_are_carried_through() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::Ce);
        log.add(now, 101, Ecn::Ect1);

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(Ecn::Ce, block.metric_blocks[0].ecn);
        assert_eq!(Ecn::Ect1, block.metric_blocks[1].ecn);
    }

    #[test]
    fn a_sequence_number_wrap_does_not_reorder_the_window() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for sequence_number in [65534u16, 65535, 0, 1] {
            log.add(now, sequence_number, Ecn::NotEct);
        }

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(65534, block.begin_sequence);
        assert_eq!(
            vec![true, true, true, true],
            received(&block),
            "0 follows 65535 rather than opening a 65534-packet gap"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Arrival-time offsets
    // ---------------------------------------------------------------------------------------

    #[test]
    fn an_offset_is_measured_back_from_the_report_timestamp() {
        let now = Instant::now();
        // 1/1024 s per unit, so half a second is 512.
        assert_eq!(
            512,
            arrival_time_offset(now, now - Duration::from_millis(500))
        );
        assert_eq!(0, arrival_time_offset(now, now));
    }

    /// The two reserved values at the edges. Wrapping instead of clamping would tell the sender a
    /// very old packet had just arrived.
    #[test]
    fn offsets_clamp_at_both_edges() {
        let now = Instant::now();

        assert_eq!(
            OFFSET_AFTER_REPORT,
            arrival_time_offset(now, now + Duration::from_millis(1)),
            "arrived after the report was stamped"
        );

        // 0x1FFD units is a shade under 8 seconds; beyond that the field cannot express it.
        let far_past = now - Duration::from_secs(60);
        assert_eq!(OFFSET_TOO_OLD, arrival_time_offset(now, far_past));

        let at_limit = now - Duration::from_secs_f64(f64::from(OFFSET_MAX) / 1024.0);
        assert!(
            arrival_time_offset(now, at_limit) <= OFFSET_MAX,
            "the largest expressible offset is not mistaken for a reserved value"
        );
    }
}
