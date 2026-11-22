//! What RFC 8888 congestion control feedback says about one RTP stream.
//!
//! A feedback report describes a run of sequence numbers, each received (R = 1, with the ECN
//! marking it arrived with) or not (R = 0). Reports overlap: a receiver keeps describing a packet
//! it has not seen in every report until it arrives or falls out of its window, and the packets
//! after such a gap with it. So each packet is counted once, by sequence number:
//!
//! * received with ECT(1) / with CE (`packetsReceivedWithEct1`, `packetsReceivedWithCe`);
//! * received Not-ECT although it was sent ECT(1) (`packetsWithBleachedEct1Marking`);
//! * reported lost (`packetsReportedAsLost`), and reported received after that
//!   (`packetsReportedAsLostButRecovered`).

use rtcp::transport_feedbacks::cc_feedback_report::{CcFeedbackReportBlock, Ecn};
use std::fmt;

/// How far behind the newest sequence number a report may still describe a packet: half the
/// sequence number space, so "newer" and "older" stay unambiguous across a wrap.
const WINDOW: u16 = 0x8000;

/// One bit per 16-bit sequence number.
const WORDS: usize = 65536 / 64;

/// A bit per sequence number.
#[derive(Clone)]
struct SequenceBits(Box<[u64]>);

impl SequenceBits {
    fn new() -> Self {
        Self(vec![0u64; WORDS].into_boxed_slice())
    }

    fn get(&self, sequence_number: u16) -> bool {
        let i = usize::from(sequence_number);
        self.0[i / 64] & (1 << (i % 64)) != 0
    }

    fn set(&mut self, sequence_number: u16, value: bool) {
        let i = usize::from(sequence_number);
        if value {
            self.0[i / 64] |= 1 << (i % 64);
        } else {
            self.0[i / 64] &= !(1 << (i % 64));
        }
    }
}

/// Per-packet counts from the RFC 8888 reports about one stream.
#[derive(Clone)]
pub(crate) struct CcfbTally {
    /// The newest sequence number a report described.
    newest: Option<u16>,
    /// Packets reported received.
    received: SequenceBits,
    /// Packets reported lost and not (yet) reported received.
    lost: SequenceBits,
    /// Packets reported received with ECT(1).
    pub(crate) received_with_ect1: u64,
    /// Packets reported received with CE.
    pub(crate) received_with_ce: u64,
    /// Packets reported lost at least once.
    pub(crate) reported_as_lost: u64,
    /// Packets reported lost, then reported received.
    pub(crate) reported_as_lost_but_recovered: u64,
    /// Packets sent ECT(1) and reported received Not-ECT.
    pub(crate) bleached_ect1: u64,
}

impl fmt::Debug for CcfbTally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CcfbTally")
            .field("newest", &self.newest)
            .field("received_with_ect1", &self.received_with_ect1)
            .field("received_with_ce", &self.received_with_ce)
            .field("reported_as_lost", &self.reported_as_lost)
            .field(
                "reported_as_lost_but_recovered",
                &self.reported_as_lost_but_recovered,
            )
            .field("bleached_ect1", &self.bleached_ect1)
            .finish()
    }
}

impl CcfbTally {
    pub(crate) fn new() -> Self {
        Self {
            newest: None,
            received: SequenceBits::new(),
            lost: SequenceBits::new(),
            received_with_ect1: 0,
            received_with_ce: 0,
            reported_as_lost: 0,
            reported_as_lost_but_recovered: 0,
            bleached_ect1: 0,
        }
    }

    /// Counts what one report block says. `sent_with_ect1` is whether the stream's packets
    /// were sent ECT(1), which a Not-ECT report then shows was bleached on the path.
    pub(crate) fn on_report_block(&mut self, block: &CcFeedbackReportBlock, sent_with_ect1: bool) {
        self.on_report_block_marked(block, |_| sent_with_ect1);
    }

    /// [`on_report_block`](Self::on_report_block) for a stream that marks some packets ECT(1)
    /// and not others: `sent_with_ect1` says, by sequence number, which were.
    pub(crate) fn on_report_block_marked(
        &mut self,
        block: &CcFeedbackReportBlock,
        sent_with_ect1: impl Fn(u16) -> bool,
    ) {
        for (offset, metric) in block.metric_blocks.iter().enumerate() {
            let sequence_number = block.begin_sequence.wrapping_add(offset as u16);
            if !self.admit(sequence_number) {
                continue;
            }
            if metric.received {
                if self.received.get(sequence_number) {
                    continue;
                }
                self.received.set(sequence_number, true);
                match metric.ecn {
                    Ecn::Ect1 => self.received_with_ect1 += 1,
                    Ecn::Ce => self.received_with_ce += 1,
                    Ecn::NotEct if sent_with_ect1(sequence_number) => self.bleached_ect1 += 1,
                    _ => {}
                }
                if self.lost.get(sequence_number) {
                    self.lost.set(sequence_number, false);
                    self.reported_as_lost_but_recovered += 1;
                }
            } else if !self.received.get(sequence_number) && !self.lost.get(sequence_number) {
                self.lost.set(sequence_number, true);
                self.reported_as_lost += 1;
            }
        }
    }

    /// Moves the window to `sequence_number` if it is newer, forgetting what was recorded for
    /// the sequence numbers that come back into it from the previous cycle. Returns whether
    /// `sequence_number` is inside the window.
    fn admit(&mut self, sequence_number: u16) -> bool {
        let Some(newest) = self.newest else {
            self.newest = Some(sequence_number);
            return true;
        };
        let ahead = sequence_number.wrapping_sub(newest);
        if ahead != 0 && ahead < WINDOW {
            for step in 1..=ahead {
                let reused = newest.wrapping_add(step);
                self.received.set(reused, false);
                self.lost.set(reused, false);
            }
            self.newest = Some(sequence_number);
            return true;
        }
        newest.wrapping_sub(sequence_number) < WINDOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackMetricBlock;

    /// A block from `begin`: `Some(ecn)` received with that marking, `None` lost.
    fn block(begin: u16, metrics: &[Option<Ecn>]) -> CcFeedbackReportBlock {
        CcFeedbackReportBlock {
            media_ssrc: 1,
            begin_sequence: begin,
            metric_blocks: metrics
                .iter()
                .map(|metric| match metric {
                    Some(ecn) => CcFeedbackMetricBlock {
                        received: true,
                        ecn: *ecn,
                        arrival_time_offset: 0,
                    },
                    None => CcFeedbackMetricBlock::default(),
                })
                .collect(),
        }
    }

    #[test]
    fn markings_are_counted_once_per_packet() {
        let mut tally = CcfbTally::new();
        let report = block(10, &[Some(Ecn::Ect1), Some(Ecn::Ce), Some(Ecn::Ect1)]);
        tally.on_report_block(&report, true);
        // A later report that describes the same packets again (after a gap) adds nothing.
        tally.on_report_block(&report, true);
        assert_eq!(tally.received_with_ect1, 2);
        assert_eq!(tally.received_with_ce, 1);
        assert_eq!(tally.bleached_ect1, 0);
    }

    #[test]
    fn a_not_ect_report_of_an_ect1_packet_is_bleaching() {
        let mut tally = CcfbTally::new();
        tally.on_report_block(&block(0, &[Some(Ecn::NotEct), Some(Ecn::Ect0)]), true);
        assert_eq!(tally.bleached_ect1, 1, "ECT(0) is a remark, not bleaching");

        let mut unmarked = CcfbTally::new();
        unmarked.on_report_block(&block(0, &[Some(Ecn::NotEct)]), false);
        assert_eq!(unmarked.bleached_ect1, 0, "sent Not-ECT, nothing to bleach");
    }

    #[test]
    fn a_lost_packet_is_counted_once_and_recovered_once() {
        let mut tally = CcfbTally::new();
        tally.on_report_block(
            &block(100, &[Some(Ecn::NotEct), None, Some(Ecn::NotEct)]),
            false,
        );
        // The receiver keeps reporting the gap until the packet arrives.
        tally.on_report_block(&block(101, &[None, Some(Ecn::NotEct)]), false);
        assert_eq!(tally.reported_as_lost, 1);
        assert_eq!(tally.reported_as_lost_but_recovered, 0);

        tally.on_report_block(&block(101, &[Some(Ecn::NotEct), Some(Ecn::NotEct)]), false);
        assert_eq!(tally.reported_as_lost, 1);
        assert_eq!(tally.reported_as_lost_but_recovered, 1);

        tally.on_report_block(&block(101, &[Some(Ecn::NotEct)]), false);
        assert_eq!(tally.reported_as_lost_but_recovered, 1, "recovered once");
    }

    #[test]
    fn a_sequence_number_from_the_previous_cycle_counts_again() {
        let mut tally = CcfbTally::new();
        tally.on_report_block(&block(0, &[Some(Ecn::Ce)]), false);
        // Walk the whole sequence number space forward, in steps inside the window.
        for begin in [0x4000u16, 0x8000, 0xC000, 0xFFFF] {
            tally.on_report_block(&block(begin, &[Some(Ecn::NotEct)]), false);
        }
        tally.on_report_block(&block(0, &[Some(Ecn::Ce)]), false);
        assert_eq!(
            tally.received_with_ce, 2,
            "a new packet with the same number"
        );
    }

    #[test]
    fn a_report_older_than_the_window_is_ignored() {
        let mut tally = CcfbTally::new();
        tally.on_report_block(&block(0x9000, &[Some(Ecn::NotEct)]), false);
        tally.on_report_block(&block(0x1000, &[None]), false);
        assert_eq!(tally.reported_as_lost, 0);
    }
}
