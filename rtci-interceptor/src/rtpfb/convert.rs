//! Turning the two feedback formats into a common [`Acknowledgement`].
//!
//! TWCC and RFC 8888 answer the same question — which packets arrived, and when — in different
//! shapes. Converting both to one type is what lets congestion control read either without
//! knowing which is negotiated.

use super::acknowledgement::Acknowledgement;
use rtcp::transport_feedbacks::cc_feedback_report::{CcFeedbackReport, Ecn};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, ReferenceTimeUnwrapper, SymbolTypeTcc, TransportLayerCc,
};
use std::collections::HashMap;
use std::time::Duration;

/// TWCC's reference time counts in multiples of 64 ms.
const TWCC_REFERENCE_TICK: Duration = Duration::from_millis(64);

/// TWCC receive deltas are in microseconds.
const TWCC_DELTA_UNIT: Duration = Duration::from_micros(1);

/// RFC 8888 arrival offsets are in units of 1/1024 s.
const CCFB_OFFSET_DENOMINATOR: u32 = 1024;

/// The RFC 8888 offset meaning "arrived after the report timestamp", which carries no usable
/// arrival time.
const CCFB_OFFSET_AFTER_REPORT: u16 = 0x1FFF;

/// The RFC 8888 offset meaning "arrived 8189/1024 s or more before the report timestamp": the
/// packet arrived, but when is not known (RFC 8888 section 3.1).
const CCFB_OFFSET_TOO_OLD: u16 = 0x1FFE;

/// RFC 8888 report timestamps are the middle 32 bits of an NTP timestamp: units of 1/65536 s.
const CCFB_TIMESTAMP_DENOMINATOR: f64 = 65_536.0;

/// A counter of `bits` bits that wraps, followed from one reading to the next.
#[derive(Debug, Clone, Copy)]
struct WrappingCounter {
    bits: u32,
    /// The last raw reading and the extended value it was given.
    last: Option<(u32, u64)>,
}

impl WrappingCounter {
    const fn new(bits: u32) -> Self {
        Self { bits, last: None }
    }

    /// The reading as a count that does not wrap. The first reading is placed one full period
    /// up, so a later reading a little *behind* it (feedback read out of order) does not go
    /// below zero.
    fn extend(&mut self, raw: u32) -> u64 {
        let period = 1u64 << self.bits;
        let raw = u64::from(raw) & (period - 1);
        let extended = match self.last {
            None => period + raw,
            Some((last_raw, last_extended)) => {
                // The shorter way round the circle: forwards if less than half a period ahead,
                // backwards otherwise.
                let ahead = raw.wrapping_sub(u64::from(last_raw)) & (period - 1);
                if ahead < period / 2 {
                    last_extended + ahead
                } else {
                    last_extended.saturating_sub(period - ahead)
                }
            }
        };
        self.last = Some((raw as u32, extended));
        extended
    }
}

/// The receiver's clock as successive feedback reports give it, without the wraps.
///
/// Both feedback formats time arrivals against a short counter: TWCC's reference time is 24 bits
/// of 64 ms (it wraps every 12.4 days, and is a signed value, so a receiver may start it
/// anywhere), RFC 8888's report timestamp is 32 bits of 1/65536 s (it wraps every 18.2 hours).
/// Arrival times are only useful as differences, across reports as much as within one, so the
/// counters have to be followed through their wraps: read raw, the report after a wrap places
/// its arrivals days before the previous report's.
///
/// One per connection, fed every report in the order it is read.
#[derive(Debug, Clone)]
pub struct FeedbackTimeline {
    twcc_reference: ReferenceTimeUnwrapper,
    ccfb_timestamp: WrappingCounter,
}

impl Default for FeedbackTimeline {
    fn default() -> Self {
        Self {
            twcc_reference: ReferenceTimeUnwrapper::new(),
            ccfb_timestamp: WrappingCounter::new(32),
        }
    }
}

impl FeedbackTimeline {
    /// A timeline that has seen no report yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert a TWCC feedback packet, placing its arrivals after those of the reports before
    /// it.
    pub fn convert_twcc(&mut self, feedback: &TransportLayerCc) -> Vec<Acknowledgement> {
        // Signed ticks from the receiver's own origin; one period is added so a reference time
        // that starts negative, or steps back a little, stays a non-negative duration.
        let ticks = self.twcc_reference.unwrap(feedback.reference_time) + (1i64 << 24);
        twcc_acknowledgements(
            feedback,
            Duration::from_millis(ticks.max(0) as u64 * TWCC_REFERENCE_TICK.as_millis() as u64),
        )
    }

    /// Convert an RFC 8888 report, placing its arrivals after those of the reports before it.
    pub fn convert_ccfb(
        &mut self,
        feedback: &CcFeedbackReport,
    ) -> (Duration, HashMap<u32, Vec<Acknowledgement>>) {
        let units = self.ccfb_timestamp.extend(feedback.report_timestamp);
        ccfb_acknowledgements(
            feedback,
            Duration::from_secs_f64(units as f64 / CCFB_TIMESTAMP_DENOMINATOR),
        )
    }
}

/// Convert a TWCC feedback packet into one acknowledgement per reported packet.
///
/// Arrival times are relative to the feedback's own 24-bit reference time, so they are comparable
/// across successive TWCC reports only until that counter wraps: a connection converts through a
/// [`FeedbackTimeline`], which follows it.
pub fn convert_twcc(feedback: &TransportLayerCc) -> Vec<Acknowledgement> {
    twcc_acknowledgements(feedback, TWCC_REFERENCE_TICK * feedback.reference_time)
}

/// The acknowledgements of one TWCC feedback packet whose reference time is `reference` on the
/// receiver's clock.
fn twcc_acknowledgements(feedback: &TransportLayerCc, reference: Duration) -> Vec<Acknowledgement> {
    let mut acknowledgements = Vec::new();

    // The reference time is a count of 64 ms ticks on the receiver's clock; deltas accumulate
    // from there, so each arrival depends on every arrival before it in the same report.
    let mut arrival = reference;
    let mut delta_index = 0usize;
    let mut offset = 0u16;

    let push = |symbol: SymbolTypeTcc,
                offset: &mut u16,
                arrival: &mut Duration,
                delta_index: &mut usize,
                acknowledgements: &mut Vec<Acknowledgement>| {
        let sequence_number = feedback.base_sequence_number.wrapping_add(*offset);
        *offset = offset.wrapping_add(1);

        match symbol {
            SymbolTypeTcc::PacketNotReceived => {
                acknowledgements.push(Acknowledgement::lost(sequence_number));
            }
            SymbolTypeTcc::PacketReceivedSmallDelta | SymbolTypeTcc::PacketReceivedLargeDelta => {
                // A delta may be negative — packets can be reported out of order — so the running
                // arrival is adjusted in whichever direction the report says.
                if let Some(delta) = feedback.recv_deltas.get(*delta_index) {
                    *delta_index += 1;
                    let magnitude = TWCC_DELTA_UNIT * delta.delta.unsigned_abs() as u32;
                    *arrival = if delta.delta < 0 {
                        arrival.saturating_sub(magnitude)
                    } else {
                        *arrival + magnitude
                    };
                    acknowledgements.push(Acknowledgement::received(
                        sequence_number,
                        Some(*arrival),
                        Ecn::NotEct,
                    ));
                } else {
                    // The chunks claim more received packets than there are deltas. Report the
                    // packet as arrived without a time rather than inventing one.
                    acknowledgements.push(Acknowledgement::received(
                        sequence_number,
                        None,
                        Ecn::NotEct,
                    ));
                }
            }
            SymbolTypeTcc::PacketReceivedWithoutDelta => {
                acknowledgements.push(Acknowledgement::received(
                    sequence_number,
                    None,
                    Ecn::NotEct,
                ));
            }
        }
    };

    // The header's packet status count is the number of packets the report describes. A
    // run-length chunk can claim a run of up to 8191 whatever the count says, so the chunks are
    // walked only as far as the count: one small feedback packet must not expand into millions
    // of acknowledgements.
    let symbols = feedback
        .packet_chunks
        .iter()
        .flat_map(|chunk| -> Box<dyn Iterator<Item = SymbolTypeTcc> + '_> {
            match chunk {
                PacketStatusChunk::RunLengthChunk(run) => Box::new(std::iter::repeat_n(
                    run.packet_status_symbol,
                    run.run_length as usize,
                )),
                PacketStatusChunk::StatusVectorChunk(vector) => {
                    Box::new(vector.symbol_list.iter().copied())
                }
            }
        })
        .take(feedback.packet_status_count as usize);

    for symbol in symbols {
        push(
            symbol,
            &mut offset,
            &mut arrival,
            &mut delta_index,
            &mut acknowledgements,
        );
    }

    acknowledgements
}

/// Convert an RFC 8888 report into acknowledgements per media stream, with the delay the receiver
/// added before sending it.
///
/// The returned delay is the gap between the newest arrival the report describes and the instant
/// it was stamped. A round trip measured without subtracting it counts the receiver's own
/// reporting interval as network time.
///
/// Each arrival time is the report timestamp minus the packet's arrival time offset (RFC 8888
/// section 3.1), on the receiver's clock: a later arrival is a larger value, within a report and
/// from one report to the next, until the 32-bit report timestamp wraps. A connection converts
/// through a [`FeedbackTimeline`], which follows the wrap.
pub fn convert_ccfb(feedback: &CcFeedbackReport) -> (Duration, HashMap<u32, Vec<Acknowledgement>>) {
    FeedbackTimeline::new().convert_ccfb(feedback)
}

/// The acknowledgements of one RFC 8888 report stamped at `report_time` on the receiver's clock.
fn ccfb_acknowledgements(
    feedback: &CcFeedbackReport,
    report_time: Duration,
) -> (Duration, HashMap<u32, Vec<Acknowledgement>>) {
    let mut per_stream = HashMap::new();
    // Arrivals are offsets *back* from the report timestamp, so the newest arrival is the
    // smallest offset.
    let mut newest_arrival: Option<Duration> = None;

    for block in &feedback.report_blocks {
        let mut acknowledgements = Vec::with_capacity(block.metric_blocks.len());

        for (index, metric) in block.metric_blocks.iter().enumerate() {
            let sequence_number = block.begin_sequence.wrapping_add(index as u16);

            if !metric.received {
                acknowledgements.push(Acknowledgement::lost(sequence_number));
                continue;
            }

            // The two reserved offsets say the packet arrived after the report was stamped, or
            // longer before it than the field can express. Neither is a measurement: the packet
            // counts as received and contributes no arrival time.
            let arrival = if metric.arrival_time_offset == CCFB_OFFSET_AFTER_REPORT
                || metric.arrival_time_offset == CCFB_OFFSET_TOO_OLD
            {
                None
            } else {
                let offset = Duration::from_secs_f64(
                    f64::from(metric.arrival_time_offset) / f64::from(CCFB_OFFSET_DENOMINATOR),
                );
                newest_arrival = Some(match newest_arrival {
                    Some(newest) => newest.min(offset),
                    None => offset,
                });
                // The offset counts *back* from the report timestamp.
                Some(report_time.saturating_sub(offset))
            };

            acknowledgements.push(Acknowledgement::received(
                sequence_number,
                arrival,
                metric.ecn,
            ));
        }

        per_stream.insert(block.media_ssrc, acknowledgements);
    }

    (newest_arrival.unwrap_or_default(), per_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::{
        CcFeedbackMetricBlock, CcFeedbackReportBlock,
    };
    use rtcp::transport_feedbacks::transport_layer_cc::{
        RecvDelta, RunLengthChunk, StatusVectorChunk,
    };

    fn run_length(symbol: SymbolTypeTcc, run_length: u16) -> PacketStatusChunk {
        PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            packet_status_symbol: symbol,
            run_length,
            ..Default::default()
        })
    }

    fn status_vector(symbols: Vec<SymbolTypeTcc>) -> PacketStatusChunk {
        PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
            symbol_list: symbols,
            ..Default::default()
        })
    }

    fn delta(microseconds: i64) -> RecvDelta {
        RecvDelta {
            delta: microseconds,
            ..Default::default()
        }
    }

    // ---------------------------------------------------------------------------------------
    // TWCC
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_run_of_lost_packets_converts_to_losses() {
        let feedback = TransportLayerCc {
            base_sequence_number: 100,
            reference_time: 0,
            packet_status_count: 3,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketNotReceived, 3)],
            recv_deltas: vec![],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            vec![
                Acknowledgement::lost(100),
                Acknowledgement::lost(101),
                Acknowledgement::lost(102)
            ],
            acknowledgements
        );
    }

    /// Deltas accumulate: each arrival is relative to the one before it, so a report describes a
    /// *sequence* of arrivals rather than independent timestamps.
    #[test]
    fn deltas_accumulate_from_the_reference_time() {
        let feedback = TransportLayerCc {
            base_sequence_number: 10,
            // One tick of 64 ms.
            reference_time: 1,
            packet_status_count: 3,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 3)],
            recv_deltas: vec![delta(1000), delta(2000), delta(500)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        let arrivals: Vec<Duration> = acknowledgements
            .iter()
            .map(|ack| ack.arrival.expect("arrived with a time"))
            .collect();

        assert_eq!(
            vec![
                Duration::from_millis(64) + Duration::from_micros(1000),
                Duration::from_millis(64) + Duration::from_micros(3000),
                Duration::from_millis(64) + Duration::from_micros(3500),
            ],
            arrivals
        );
        assert!(acknowledgements.iter().all(|ack| ack.arrived));
    }

    /// Packets can be reported arriving out of order, which is a negative delta. Treating it as
    /// positive would report the path as *less* delayed than it is.
    #[test]
    fn a_negative_delta_moves_the_arrival_backwards() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            reference_time: 1,
            packet_status_count: 2,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 2)],
            recv_deltas: vec![delta(5000), delta(-2000)],
            ..Default::default()
        };

        let arrivals: Vec<Duration> = convert_twcc(&feedback)
            .iter()
            .map(|ack| ack.arrival.expect("arrived"))
            .collect();

        assert_eq!(
            Duration::from_millis(64) + Duration::from_micros(5000),
            arrivals[0]
        );
        assert_eq!(
            Duration::from_millis(64) + Duration::from_micros(3000),
            arrivals[1],
            "the second packet arrived before the first"
        );
    }

    #[test]
    fn a_status_vector_converts_symbol_by_symbol() {
        let feedback = TransportLayerCc {
            base_sequence_number: 500,
            reference_time: 0,
            packet_status_count: 3,
            packet_chunks: vec![status_vector(vec![
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketReceivedLargeDelta,
            ])],
            recv_deltas: vec![delta(100), delta(200)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            vec![true, false, true],
            acknowledgements
                .iter()
                .map(|ack| ack.arrived)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![500, 501, 502],
            acknowledgements
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }

    /// "Received without delta" means the receiver got it but cannot say when. Reporting an
    /// invented time would feed congestion control a measurement nobody made.
    #[test]
    fn a_packet_received_without_a_delta_has_no_arrival_time() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            reference_time: 0,
            packet_status_count: 1,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedWithoutDelta, 1)],
            recv_deltas: vec![],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert!(acknowledgements[0].arrived);
        assert_eq!(None, acknowledgements[0].arrival);
    }

    /// A report claiming more received packets than it carries deltas for is malformed. The
    /// packets are still reported as arrived, without times, rather than panicking on the index.
    #[test]
    fn more_received_packets_than_deltas_does_not_panic() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            reference_time: 0,
            packet_status_count: 4,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 4)],
            recv_deltas: vec![delta(100)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(4, acknowledgements.len());
        assert!(acknowledgements[0].arrival.is_some(), "the one real delta");
        assert!(
            acknowledgements[1..]
                .iter()
                .all(|ack| ack.arrival.is_none()),
            "and no invented times for the rest"
        );
    }

    #[test]
    fn sequence_numbers_wrap_across_a_report() {
        let feedback = TransportLayerCc {
            base_sequence_number: 65534,
            reference_time: 0,
            packet_status_count: 4,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketNotReceived, 4)],
            recv_deltas: vec![],
            ..Default::default()
        };

        assert_eq!(
            vec![65534, 65535, 0, 1],
            convert_twcc(&feedback)
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_empty_feedback_converts_to_nothing() {
        let feedback = TransportLayerCc::default();
        assert!(convert_twcc(&feedback).is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // RFC 8888
    // ---------------------------------------------------------------------------------------

    fn metric(received: bool, offset: u16, ecn: Ecn) -> CcFeedbackMetricBlock {
        CcFeedbackMetricBlock {
            received,
            ecn,
            arrival_time_offset: offset,
        }
    }

    #[test]
    fn a_ccfb_report_converts_per_stream() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![
                CcFeedbackReportBlock {
                    media_ssrc: 10,
                    begin_sequence: 100,
                    metric_blocks: vec![
                        metric(true, 512, Ecn::NotEct),
                        metric(false, 0, Ecn::NotEct),
                    ],
                },
                CcFeedbackReportBlock {
                    media_ssrc: 20,
                    begin_sequence: 5,
                    metric_blocks: vec![metric(true, 256, Ecn::Ce)],
                },
            ],
            report_timestamp: 0,
        };

        let (_, per_stream) = convert_ccfb(&feedback);

        let first = &per_stream[&10];
        assert_eq!(100, first[0].sequence_number);
        assert!(!first[1].arrived);

        let second = &per_stream[&20];
        assert_eq!(5, second[0].sequence_number);
        assert_eq!(Ecn::Ce, second[0].ecn, "ECN survives conversion");

        // The arrival time is the report timestamp minus the offset: the packet with the
        // smaller offset (256/1024 s) arrived a quarter of a second after the other.
        assert_eq!(
            Duration::from_millis(250),
            second[0].arrival.unwrap() - first[0].arrival.unwrap()
        );
    }

    fn one_packet_report(report_timestamp: u32, offset: u16, sequence: u16) -> CcFeedbackReport {
        CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: sequence,
                metric_blocks: vec![metric(true, offset, Ecn::NotEct)],
            }],
            report_timestamp,
        }
    }

    /// RFC 8888 section 3.1: the arrival time is "an offset before the time represented by the
    /// Report Timestamp". Across two reports the arrival of a later packet is later by the
    /// difference of the timestamps less the difference of the offsets.
    #[test]
    fn ccfb_arrivals_are_measured_back_from_each_reports_timestamp() {
        let mut timeline = FeedbackTimeline::new();
        // 100 ms apart (6554 units of 1/65536 s); offsets of 10/1024 s and 5/1024 s.
        let (_, first) = timeline.convert_ccfb(&one_packet_report(0x0001_0000, 10, 1));
        let (_, second) = timeline.convert_ccfb(&one_packet_report(0x0001_0000 + 6554, 5, 2));

        let gap = second[&10][0].arrival.unwrap() - first[&10][0].arrival.unwrap();
        let expected = Duration::from_secs_f64(6554.0 / 65536.0 + 5.0 / 1024.0);
        assert!(
            gap.abs_diff(expected) < Duration::from_micros(10),
            "expected {expected:?}, got {gap:?}"
        );
    }

    /// The report timestamp wraps every 18.2 hours. The report after the wrap is later, not
    /// 18 hours earlier.
    #[test]
    fn the_ccfb_report_timestamp_is_followed_through_its_wrap() {
        let mut timeline = FeedbackTimeline::new();
        let (_, before) = timeline.convert_ccfb(&one_packet_report(0xFFFF_F000, 0, 1));
        let (_, after) = timeline.convert_ccfb(&one_packet_report(0x0000_0A00, 0, 2));

        let gap = after[&10][0].arrival.unwrap() - before[&10][0].arrival.unwrap();
        let expected = Duration::from_secs_f64(f64::from(0x1000u32 + 0xA00) / 65536.0);
        assert!(
            gap.abs_diff(expected) < Duration::from_micros(10),
            "expected {expected:?}, got {gap:?}"
        );
    }

    fn one_packet_feedback(reference_time: u32, sequence: u16) -> TransportLayerCc {
        TransportLayerCc {
            base_sequence_number: sequence,
            packet_status_count: 1,
            reference_time,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 1)],
            recv_deltas: vec![RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 0,
            }],
            ..Default::default()
        }
    }

    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1: the reference time is a
    /// 24-bit value in multiples of 64 ms. It wraps every 12.4 days, and a receiver may start it
    /// anywhere: the feedback after 0xFFFFFF is 64 ms later, not 12.4 days earlier (audit bug
    /// T5).
    #[test]
    fn the_twcc_reference_time_is_followed_through_its_wrap() {
        let mut timeline = FeedbackTimeline::new();
        let before = timeline.convert_twcc(&one_packet_feedback(0x00FF_FFFF, 1));
        let after = timeline.convert_twcc(&one_packet_feedback(0x0000_0000, 2));
        let later = timeline.convert_twcc(&one_packet_feedback(0x0000_0002, 3));

        assert_eq!(
            Duration::from_millis(64),
            after[0].arrival.unwrap() - before[0].arrival.unwrap()
        );
        assert_eq!(
            Duration::from_millis(128),
            later[0].arrival.unwrap() - after[0].arrival.unwrap()
        );
    }

    /// Feedback read out of order steps the clock back by the difference, not forward by almost
    /// a whole period.
    #[test]
    fn a_reference_time_behind_the_last_one_steps_back() {
        let mut timeline = FeedbackTimeline::new();
        let first = timeline.convert_twcc(&one_packet_feedback(10, 1));
        let earlier = timeline.convert_twcc(&one_packet_feedback(8, 2));

        assert_eq!(
            Duration::from_millis(128),
            first[0].arrival.unwrap() - earlier[0].arrival.unwrap()
        );
    }

    /// RFC 8888 section 3.1: 0x1FFE is an over-range measurement, not an arrival 8 seconds
    /// before the report (rfc8888.md bug B7).
    #[test]
    fn the_over_range_offset_yields_no_arrival_time() {
        let (delay, per_stream) = convert_ccfb(&one_packet_report(0x0010_0000, 0x1FFE, 1));

        assert!(per_stream[&10][0].arrived, "it did arrive");
        assert_eq!(None, per_stream[&10][0].arrival, "when is not known");
        assert_eq!(Duration::ZERO, delay);
    }

    /// The receiver's own reporting delay is not network time. Without subtracting it, a round
    /// trip includes however long the receiver sat on the report before sending it.
    #[test]
    fn the_reporting_delay_is_the_gap_to_the_newest_arrival() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                // 1024 units = 1 s ago, 102 ≈ 100 ms ago. The newest is the smaller offset.
                metric_blocks: vec![
                    metric(true, 1024, Ecn::NotEct),
                    metric(true, 102, Ecn::NotEct),
                ],
            }],
            report_timestamp: 0,
        };

        let (delay, _) = convert_ccfb(&feedback);
        assert!(
            (Duration::from_millis(99)..=Duration::from_millis(101)).contains(&delay),
            "the newest arrival was ~100 ms before the report, got {delay:?}"
        );
    }

    /// The reserved offset means the packet arrived after the report was stamped, so there is no
    /// usable time — and it must not be taken as the newest arrival either.
    #[test]
    fn the_reserved_offset_yields_no_arrival_time() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                metric_blocks: vec![
                    metric(true, CCFB_OFFSET_AFTER_REPORT, Ecn::NotEct),
                    metric(true, 512, Ecn::NotEct),
                ],
            }],
            report_timestamp: 0,
        };

        let (delay, per_stream) = convert_ccfb(&feedback);
        assert!(per_stream[&10][0].arrived);
        assert_eq!(None, per_stream[&10][0].arrival);
        assert_eq!(
            Duration::from_millis(500),
            delay,
            "the reserved value did not become the newest arrival"
        );
    }

    #[test]
    fn a_report_with_no_arrivals_has_no_reporting_delay() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                metric_blocks: vec![metric(false, 0, Ecn::NotEct)],
            }],
            report_timestamp: 0,
        };

        let (delay, per_stream) = convert_ccfb(&feedback);
        assert_eq!(Duration::ZERO, delay);
        assert!(!per_stream[&10][0].arrived);
    }

    #[test]
    fn ccfb_sequence_numbers_wrap_within_a_block() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 65535,
                metric_blocks: vec![metric(false, 0, Ecn::NotEct), metric(false, 0, Ecn::NotEct)],
            }],
            report_timestamp: 0,
        };

        let (_, per_stream) = convert_ccfb(&feedback);
        assert_eq!(
            vec![65535, 0],
            per_stream[&10]
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }
}
