//! Turns observed arrivals into an RFC 8888 feedback report.

use super::stream_log::{MAX_REPORTS_PER_BLOCK, StreamLog};
use rtcp::transport_feedbacks::cc_feedback_report::{CcFeedbackReport, Ecn};
use std::collections::HashMap;
use std::time::Instant;

/// Header, sender SSRC and report timestamp — the fixed cost of any report.
const REPORT_OVERHEAD: usize = 12;

/// Media SSRC, base sequence number and count — the fixed cost of each report block.
const BLOCK_OVERHEAD: usize = 8;

/// Bytes per reported packet.
const METRIC_BLOCK_SIZE: usize = 2;

/// The most feedback packets one call builds. Eight packets of 1200 bytes describe about 4700
/// arrivals, far more than one reporting interval holds at any rate this engine carries.
pub const MAX_REPORTS_PER_CALL: usize = 8;

/// Records packet arrivals per stream and builds feedback reports from them.
#[derive(Debug, Default)]
pub struct CcFeedbackRecorder {
    streams: HashMap<u32, StreamLog>,
}

impl CcFeedbackRecorder {
    /// A recorder with nothing observed yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that a packet of `ssrc` arrived at `arrival`.
    pub fn add_packet(&mut self, arrival: Instant, ssrc: u32, sequence_number: u16, ecn: Ecn) {
        self.streams
            .entry(ssrc)
            .or_insert_with(|| StreamLog::new(ssrc))
            .add(arrival, sequence_number, ecn);
    }

    /// Whether anything is waiting to be reported.
    pub fn is_empty(&self) -> bool {
        self.streams.values().all(StreamLog::is_empty)
    }

    /// Build one feedback report for what has not been reported yet, within `max_size` bytes.
    ///
    /// What does not fit stays in the recorder for the next call:
    /// [`build_reports`](Self::build_reports) is the form that sends all of it.
    pub fn build_report(
        &mut self,
        now: Instant,
        sender_ssrc: u32,
        report_timestamp: u32,
        max_size: usize,
    ) -> CcFeedbackReport {
        self.build_one(now, sender_ssrc, report_timestamp, max_size, true)
    }

    /// Build the feedback for everything not reported yet, as one report or, when it does not
    /// fit `max_size` bytes, as several (RFC 8888 section 3.1: a feedback packet too large for
    /// the path MTU is split into multiple feedback packets).
    ///
    /// The first report carries a block for every stream, the ones with nothing new included;
    /// the following ones only the streams that still have something to say. At most
    /// [`MAX_REPORTS_PER_CALL`] reports are built: what is left after that goes out next time.
    pub fn build_reports(
        &mut self,
        now: Instant,
        sender_ssrc: u32,
        report_timestamp: u32,
        max_size: usize,
    ) -> Vec<CcFeedbackReport> {
        let mut reports = vec![self.build_one(now, sender_ssrc, report_timestamp, max_size, true)];
        while reports.len() < MAX_REPORTS_PER_CALL && !self.is_empty() {
            let report = self.build_one(now, sender_ssrc, report_timestamp, max_size, false);
            // A budget too small for a single metric block makes no progress: stop, rather
            // than emit empty reports.
            if report
                .report_blocks
                .iter()
                .all(|block| block.metric_blocks.is_empty())
            {
                break;
            }
            reports.push(report);
        }
        reports
    }

    fn build_one(
        &mut self,
        now: Instant,
        sender_ssrc: u32,
        report_timestamp: u32,
        max_size: usize,
        every_stream: bool,
    ) -> CcFeedbackReport {
        let mut report = CcFeedbackReport {
            sender_ssrc,
            report_blocks: Vec::new(),
            report_timestamp,
        };

        // Ordered so a report is reproducible; a `HashMap` would otherwise vary run to run.
        let mut ssrcs: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, stream)| every_stream || !stream.is_empty())
            .map(|(&ssrc, _)| ssrc)
            .collect();
        ssrcs.sort_unstable();

        let stream_count = ssrcs.len();
        if stream_count == 0 {
            return report;
        }

        // Split the remaining bytes evenly, so one busy stream cannot crowd out the rest.
        let budget = max_size
            .saturating_sub(REPORT_OVERHEAD)
            .saturating_sub(BLOCK_OVERHEAD * stream_count)
            / METRIC_BLOCK_SIZE;
        let per_stream = (budget / stream_count).min(MAX_REPORTS_PER_BLOCK);

        for ssrc in ssrcs {
            let Some(stream) = self.streams.get_mut(&ssrc) else {
                continue;
            };
            report
                .report_blocks
                .push(stream.metrics_after(now, per_stream));
        }

        report
    }

    /// Forget a stream entirely.
    pub fn remove_stream(&mut self, ssrc: u32) {
        self.streams.remove(&ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait ReportSsrcsForTest {
        fn destination_ssrcs_for_test(&self) -> Vec<u32>;
    }

    impl ReportSsrcsForTest for CcFeedbackReport {
        fn destination_ssrcs_for_test(&self) -> Vec<u32> {
            self.report_blocks
                .iter()
                .map(|block| block.media_ssrc)
                .collect()
        }
    }

    const MTU: usize = 1200;

    #[test]
    fn a_recorder_with_nothing_observed_reports_no_blocks() {
        let mut recorder = CcFeedbackRecorder::new();
        let report = recorder.build_report(Instant::now(), 7, 42, MTU);

        assert_eq!(7, report.sender_ssrc);
        assert_eq!(42, report.report_timestamp);
        assert!(report.report_blocks.is_empty());
        assert!(recorder.is_empty());
    }

    #[test]
    fn each_stream_gets_its_own_report_block() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        recorder.add_packet(now, 1, 100, Ecn::NotEct);
        recorder.add_packet(now, 2, 500, Ecn::NotEct);
        recorder.add_packet(now, 1, 101, Ecn::NotEct);

        let report = recorder.build_report(now, 0, 0, MTU);

        assert_eq!(2, report.report_blocks.len());
        assert_eq!(vec![1, 2], report.destination_ssrcs_for_test());
        assert_eq!(
            2,
            report.report_blocks[0].metric_blocks.len(),
            "two on ssrc 1"
        );
        assert_eq!(
            1,
            report.report_blocks[1].metric_blocks.len(),
            "one on ssrc 2"
        );
    }

    /// Report blocks come out in a stable order, so two runs over the same input produce the same
    /// bytes — a `HashMap` iteration order would not.
    #[test]
    fn report_blocks_are_ordered_by_ssrc() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        for ssrc in [900, 100, 500, 300] {
            recorder.add_packet(now, ssrc, 1, Ecn::NotEct);
        }

        let report = recorder.build_report(now, 0, 0, MTU);
        assert_eq!(
            vec![100, 300, 500, 900],
            report.destination_ssrcs_for_test()
        );
    }

    /// RFC 8888 section 3.1: feedback too large for the path MTU is split into several feedback
    /// packets, each within the budget, together describing every arrival once.
    #[test]
    fn feedback_larger_than_the_budget_is_split_into_several_reports() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        for sequence_number in 0..25u16 {
            recorder.add_packet(now, 1, sequence_number, Ecn::NotEct);
        }

        // 12 report overhead + 8 block overhead leaves 20 bytes, i.e. 10 metric blocks.
        let reports = recorder.build_reports(now, 9, 0, 40);
        assert_eq!(
            vec![(0u16, 10usize), (10, 10), (20, 5)],
            reports
                .iter()
                .map(|report| (
                    report.report_blocks[0].begin_sequence,
                    report.report_blocks[0].metric_blocks.len()
                ))
                .collect::<Vec<_>>()
        );
        assert!(reports.iter().all(|report| report.sender_ssrc == 9));
        assert!(recorder.is_empty());
    }

    /// A report has to fit the path: one report never describes more than the budget holds.
    #[test]
    fn the_byte_budget_bounds_what_a_report_describes() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        for sequence_number in 0..100u16 {
            recorder.add_packet(now, 1, sequence_number, Ecn::NotEct);
        }

        // 12 report overhead + 8 block overhead leaves 20 bytes, i.e. 10 metric blocks.
        let report = recorder.build_report(now, 0, 0, 40);
        assert_eq!(10, report.report_blocks[0].metric_blocks.len());
    }

    #[test]
    fn a_budget_too_small_for_any_packet_reports_none() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        recorder.add_packet(now, 1, 1, Ecn::NotEct);

        let report = recorder.build_report(now, 0, 0, 4);
        assert!(report.report_blocks[0].metric_blocks.is_empty());
    }

    #[test]
    fn the_budget_is_shared_between_streams() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        for sequence_number in 0..50u16 {
            recorder.add_packet(now, 1, sequence_number, Ecn::NotEct);
            recorder.add_packet(now, 2, sequence_number, Ecn::NotEct);
        }

        // 12 + 8*2 = 28 overhead; 72 bytes left is 36 metric blocks, 18 per stream.
        let report = recorder.build_report(now, 0, 0, 100);
        assert_eq!(18, report.report_blocks[0].metric_blocks.len());
        assert_eq!(18, report.report_blocks[1].metric_blocks.len());
    }

    #[test]
    fn removing_a_stream_stops_it_being_reported() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        recorder.add_packet(now, 1, 1, Ecn::NotEct);
        recorder.add_packet(now, 2, 1, Ecn::NotEct);

        recorder.remove_stream(1);
        let report = recorder.build_report(now, 0, 0, MTU);

        assert_eq!(vec![2], report.destination_ssrcs_for_test());
    }

    /// A report describing packets already reported would tell the sender they arrived twice.
    #[test]
    fn a_second_report_describes_only_what_arrived_since() {
        let now = Instant::now();
        let mut recorder = CcFeedbackRecorder::new();
        recorder.add_packet(now, 1, 100, Ecn::NotEct);

        let first = recorder.build_report(now, 0, 0, MTU);
        assert_eq!(1, first.report_blocks[0].metric_blocks.len());

        let second = recorder.build_report(now, 0, 0, MTU);
        assert!(second.report_blocks[0].metric_blocks.is_empty());

        recorder.add_packet(now, 1, 101, Ecn::NotEct);
        let third = recorder.build_report(now, 0, 0, MTU);
        assert_eq!(1, third.report_blocks[0].metric_blocks.len());
        assert_eq!(101, third.report_blocks[0].begin_sequence);
    }
}
