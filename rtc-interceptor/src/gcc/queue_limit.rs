//! Telling loss at a full queue from loss on the way: the queueing delay the reports show.

use crate::rtpfb::acknowledgement::PacketReport;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How far back the lowest one-way delay is looked for: the path's delay with an empty queue.
pub const QUEUE_BASE_WINDOW: Duration = Duration::from_secs(30);

/// How far back the highest queueing delay is looked for: where the queue overflows.
pub const QUEUE_HIGH_WINDOW: Duration = Duration::from_secs(5);

/// A batch whose packets all met at least this share of the recent highest queueing delay
/// arrived out of a queue at its limit.
pub const QUEUE_AT_LIMIT_SHARE: f64 = 0.75;

/// And at least this much queueing delay: below it there is no queue to speak of, and loss is
/// loss on the way (a radio link, a policer), which the loss-based controller is for.
pub const QUEUE_AT_LIMIT_MIN_DELAY: Duration = Duration::from_millis(10);

/// The queueing delay of the packets reported, and whether a loss among them is the queue
/// overflowing.
///
/// The one-way delay of a packet is its arrival on the receiver's clock less its departure on
/// the sender's: the clocks' offset is unknown but constant, so the lowest one-way delay over
/// [`QUEUE_BASE_WINDOW`] stands for the path with an empty queue and anything above it is
/// queueing. A feedback batch with a loss in it, whose arrived packets all waited at least
/// [`QUEUE_AT_LIMIT_SHARE`] of the highest queueing delay of the last [`QUEUE_HIGH_WINDOW`]
/// (and at least [`QUEUE_AT_LIMIT_MIN_DELAY`]), lost its packets out of a queue at its limit:
/// a tail drop.
#[derive(Debug, Clone, Default)]
pub struct QueueLimitDetector {
    /// The departure the one-way delays are measured from.
    reference: Option<Instant>,
    /// The lowest one-way delay, in milliseconds, per second of feedback.
    base: VecDeque<(Instant, f64)>,
    /// The highest queueing delay of each batch, in milliseconds.
    high: VecDeque<(Instant, f64)>,
}

impl QueueLimitDetector {
    /// A detector that has seen nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    fn one_way_ms(&mut self, departure: Instant, arrival: Duration) -> f64 {
        let reference = *self.reference.get_or_insert(departure);
        let sent = match departure.checked_duration_since(reference) {
            Some(after) => after.as_secs_f64(),
            None => -reference.saturating_duration_since(departure).as_secs_f64(),
        };
        (arrival.as_secs_f64() - sent) * 1_000.0
    }

    fn add_base(&mut self, now: Instant, one_way_ms: f64) {
        match self.base.back_mut() {
            Some((start, lowest))
                if now.saturating_duration_since(*start) < Duration::from_secs(1) =>
            {
                *lowest = lowest.min(one_way_ms);
            }
            _ => self.base.push_back((now, one_way_ms)),
        }
        while self
            .base
            .front()
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) > QUEUE_BASE_WINDOW)
        {
            self.base.pop_front();
        }
    }

    /// Reads one feedback batch, read at `now`: whether a packet in it was lost out of a queue
    /// at its limit.
    pub fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) -> bool {
        let one_way: Vec<f64> = reports
            .iter()
            .filter(|report| report.arrived)
            .filter_map(|report| Some(self.one_way_ms(report.departure, report.arrival?)))
            .collect();
        for delay in &one_way {
            self.add_base(now, *delay);
        }
        let Some(base) = self.base.iter().map(|(_, lowest)| *lowest).reduce(f64::min) else {
            return false;
        };
        let (Some(lowest), Some(highest)) = (
            one_way.iter().copied().reduce(f64::min),
            one_way.iter().copied().reduce(f64::max),
        ) else {
            return false;
        };
        self.high.push_back((now, highest - base));
        while self
            .high
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > QUEUE_HIGH_WINDOW)
        {
            self.high.pop_front();
        }
        let recent_high = self.high.iter().map(|(_, high)| *high).fold(0.0, f64::max);
        let waited = lowest - base;
        reports.iter().any(|report| !report.arrived)
            && waited >= QUEUE_AT_LIMIT_MIN_DELAY.as_secs_f64() * 1_000.0
            && waited >= QUEUE_AT_LIMIT_SHARE * recent_high
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;

    /// A batch of `count` packets 10 ms apart from `first`, each waiting `queue_ms` on a 20 ms
    /// path, with the ones in `lost` missing.
    fn batch(
        epoch: Instant,
        first: u64,
        count: u64,
        queue_ms: impl Fn(u64) -> u64,
        lost: &[u64],
    ) -> Vec<PacketReport> {
        (first..first + count)
            .map(|id| {
                let arrived = !lost.contains(&id);
                PacketReport {
                    ssrc: 1,
                    id,
                    rtp_sequence_number: id as u16,
                    is_twcc: true,
                    twcc_sequence_number: id as u16,
                    size: 1200,
                    arrived,
                    departure: epoch + Duration::from_millis(id * 10),
                    arrival: arrived
                        .then(|| Duration::from_millis(1_000 + id * 10 + 20 + queue_ms(id))),
                    ecn: Ecn::default(),
                }
            })
            .collect()
    }

    /// A queue that fills to 200 ms and drops there: the loss is the queue's limit.
    #[test]
    fn a_loss_out_of_a_full_queue_is_at_the_limit() {
        let epoch = Instant::now();
        let mut detector = QueueLimitDetector::new();
        // An empty queue first, then one that grows to 200 ms and stays.
        assert!(!detector.on_reports(epoch, &batch(epoch, 0, 10, |_| 0, &[])));
        for round in 1..10u64 {
            let at = epoch + Duration::from_millis(round * 100);
            let reports = batch(epoch, round * 10, 10, |id| (id * 2).min(200), &[]);
            assert!(!detector.on_reports(at, &reports), "no loss, round {round}");
        }
        let reports = batch(epoch, 100, 10, |_| 200, &[104]);
        assert!(detector.on_reports(epoch + Duration::from_secs(1), &reports));
    }

    /// Loss with the queue empty is loss on the way, not congestion of a queue.
    #[test]
    fn a_loss_with_no_queue_is_not_at_the_limit() {
        let epoch = Instant::now();
        let mut detector = QueueLimitDetector::new();
        for round in 0..10u64 {
            let at = epoch + Duration::from_millis(round * 100);
            let reports = batch(epoch, round * 10, 10, |_| 0, &[round * 10 + 3]);
            assert!(!detector.on_reports(at, &reports), "round {round}");
        }
    }

    /// Jitter: some packets wait long, others not at all, and one is lost. The batch did not
    /// sit at a limit: its quickest packet hardly waited.
    #[test]
    fn a_loss_on_a_jittery_path_is_not_at_the_limit() {
        let epoch = Instant::now();
        let mut detector = QueueLimitDetector::new();
        for round in 0..20u64 {
            let at = epoch + Duration::from_millis(round * 100);
            let reports = batch(
                epoch,
                round * 10,
                10,
                |id| (id * 37) % 60,
                &[round * 10 + 5],
            );
            assert!(!detector.on_reports(at, &reports), "round {round}");
        }
    }
}
