//! What was sent, joined with what the receiver said about it.

use super::acknowledgement::{Acknowledgement, PacketReport};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Records outgoing packets and matches incoming feedback against them.
///
/// The two feedback formats identify a packet differently — TWCC by its own transport-wide
/// sequence number, RFC 8888 by the stream's SSRC and RTP sequence number — so both indexes are
/// kept, pointing at one record.
#[derive(Debug, Default)]
pub struct History {
    /// Monotonic id, so reports come out in send order however sequence numbers wrap.
    next_id: u64,
    packets: HashMap<u64, Sent>,
    twcc_index: HashMap<u16, u64>,
    ssrc_sequence_index: HashMap<(u32, u16), u64>,
    /// Highest id acknowledged so far.
    highest_acknowledged: Option<u64>,
    /// Lowest id not yet reported to the consumer.
    next_to_report: u64,
    /// The `fb_pkt_count` of the last TWCC feedback read.
    last_feedback_count: Option<u8>,
    /// Feedback packets the count shows were sent and never read.
    lost_feedback: u64,
    /// Sent packets no feedback ever described, released without a verdict.
    unreported: u64,
    /// Packets a feedback reported as not received, held back for one more feedback: a
    /// packet only overtaken on the path arrives after the report that named it missing.
    pending_losses: Vec<u64>,
    /// Packets reported as not received and then as received by a later feedback.
    recovered: u64,
}

/// A sent packet and whether any feedback has described it yet.
#[derive(Debug)]
struct Sent {
    report: PacketReport,
    /// A feedback packet named this packet, as received or as not received. A packet no
    /// feedback named has no verdict: the report that would have carried it was lost, or the
    /// receiver does not report on its stream at all.
    covered: bool,
}

impl History {
    /// An empty history.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many packets are being tracked.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether nothing is being tracked.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Record a packet as it leaves.
    ///
    /// `departure` must be the instant the packet was **released** to the network, not the
    /// instant the application handed it over. A pacer can hold a packet for tens of
    /// milliseconds, and counting that as network delay is exactly the error that makes a
    /// bandwidth estimate collapse (chain contract rule 3).
    #[allow(clippy::too_many_arguments)]
    pub fn add_outgoing(
        &mut self,
        ssrc: u32,
        rtp_sequence_number: u16,
        is_twcc: bool,
        twcc_sequence_number: u16,
        size: usize,
        departure: Instant,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        if is_twcc
            && let Some(previous) = self.twcc_index.insert(twcc_sequence_number, id)
            && let Some(earlier) = self.packets.get_mut(&previous)
        {
            // The same transport-wide number again: a retransmission sent as it was (no RTX),
            // which keeps its number. The receiver reports a number once, so its verdict goes
            // to this transmission; the earlier one was asked for again because it did not
            // arrive, and is reported as the loss it was.
            earlier.covered = true;
        }
        self.ssrc_sequence_index
            .insert((ssrc, rtp_sequence_number), id);

        self.packets.insert(
            id,
            Sent {
                report: PacketReport {
                    ssrc,
                    id,
                    rtp_sequence_number,
                    is_twcc,
                    twcc_sequence_number,
                    size,
                    arrived: false,
                    departure,
                    arrival: None,
                    ecn: Ecn::NotEct,
                },
                covered: false,
            },
        );

        id
    }

    /// Apply TWCC feedback, returning the round trip time it implies.
    ///
    /// `None` when the feedback names a packet this endpoint has no record of — which happens
    /// routinely at startup and after the history has been pruned, and is not an error.
    pub fn on_twcc_feedback(
        &mut self,
        received_at: Instant,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let Some(&id) = self.twcc_index.get(&acknowledgement.sequence_number) else {
            if acknowledgement.arrived {
                log::debug!(
                    "rtpfb: transport-wide {} reported received matches no packet held (released, or never sent)",
                    acknowledgement.sequence_number
                );
            }
            return None;
        };
        if acknowledgement.arrived
            && self
                .packets
                .get(&id)
                .is_some_and(|sent| sent.covered && !sent.report.arrived)
        {
            log::debug!(
                "rtpfb: transport-wide {} reported received after a feedback reported it lost",
                acknowledgement.sequence_number
            );
        }
        self.apply(received_at, id, acknowledgement)
    }

    /// Apply RFC 8888 feedback for one stream, returning the round trip time it implies.
    pub fn on_ccfb_feedback(
        &mut self,
        received_at: Instant,
        ssrc: u32,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let Some(&id) = self
            .ssrc_sequence_index
            .get(&(ssrc, acknowledgement.sequence_number))
        else {
            if acknowledgement.arrived {
                log::debug!(
                    "rtpfb: {ssrc:#x} {} reported received matches no packet held (released, or never sent)",
                    acknowledgement.sequence_number
                );
            }
            return None;
        };
        if acknowledgement.arrived
            && self
                .packets
                .get(&id)
                .is_some_and(|sent| sent.covered && !sent.report.arrived)
        {
            log::debug!(
                "rtpfb: {ssrc:#x} {} reported received after a feedback reported it lost",
                acknowledgement.sequence_number
            );
        }
        self.apply(received_at, id, acknowledgement)
    }

    fn apply(
        &mut self,
        received_at: Instant,
        id: u64,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let sent = self.packets.get_mut(&id)?;
        sent.covered = true;
        let packet = &mut sent.report;

        packet.arrived = acknowledgement.arrived;
        packet.arrival = acknowledgement.arrival;
        packet.ecn = acknowledgement.ecn;

        if packet.arrived {
            self.highest_acknowledged = Some(match self.highest_acknowledged {
                Some(highest) => highest.max(id),
                None => id,
            });
        }

        // Round trip: this feedback arrived now, and the packet left then. Both instants are on
        // this endpoint's clock, so unlike the arrival times this is a real duration.
        Some(received_at.saturating_duration_since(packet.departure))
    }

    /// Note the feedback packet count of a TWCC feedback just read, and return how many feedback
    /// packets the receiver sent between the previous one and this one that never arrived.
    ///
    /// The count is the only thing that tells a lost feedback packet from a quiet receiver
    /// (draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1). The packets a lost
    /// feedback would have described get no verdict at all, see
    /// [`take_reports`](Self::take_reports); this is the measure of how often that happened.
    pub fn on_twcc_feedback_count(&mut self, feedback_packet_count: u8) -> u8 {
        let missed = match self.last_feedback_count {
            // A count at or behind the last one is a reordered or repeated feedback: nothing
            // is known to be missing.
            Some(last) => {
                let ahead = feedback_packet_count.wrapping_sub(last);
                if ahead == 0 || ahead > 127 {
                    return 0;
                }
                ahead - 1
            }
            None => 0,
        };
        self.last_feedback_count = Some(feedback_packet_count);
        self.lost_feedback += u64::from(missed);
        missed
    }

    /// How many TWCC feedback packets were sent by the receiver and never read here.
    pub fn lost_feedback(&self) -> u64 {
        self.lost_feedback
    }

    /// How many sent packets were released without any feedback describing them.
    pub fn unreported(&self) -> u64 {
        self.unreported
    }

    /// Take every packet a feedback described, up to the highest *arrived* one, since the last
    /// call, in send order.
    ///
    /// A packet the receiver reported as not received is a loss. A packet below the highest
    /// arrival that **no feedback described** is neither: the feedback that covered it was lost,
    /// or the receiver does not report on its stream (no transport-wide sequence number, an SSRC
    /// outside the RFC 8888 report). The draft is explicit that such packets are ignored, not
    /// counted as lost or received (section 3), so they are released here without a report.
    /// Loss feedback alone does not advance the reporting window; losses are emitted when a later
    /// packet is reported as arrived.
    pub fn take_reports(&mut self) -> Vec<PacketReport> {
        let mut reports = Vec::new();
        // The losses the previous call held back: lost after all, or received meanwhile. A
        // packet received late is reported as received but without its arrival time: it
        // counts for the loss fraction, while the delay model, which reads reports in send
        // order, does not see an old packet among new ones.
        for id in std::mem::take(&mut self.pending_losses) {
            if let Some(sent) = self.release(id) {
                let mut packet = sent.report;
                if packet.arrived {
                    self.recovered += 1;
                    packet.arrival = None;
                }
                reports.push(packet);
            }
        }
        let Some(highest) = self.highest_acknowledged else {
            return reports;
        };
        if self.next_to_report > highest {
            return reports;
        }
        for id in self.next_to_report..=highest {
            // Held only while a later feedback can still name it: a transmission superseded
            // under the same number never will.
            let held = self.packets.get(&id).is_some_and(|sent| {
                let packet = &sent.report;
                let reachable = if packet.is_twcc {
                    self.twcc_index.get(&packet.twcc_sequence_number) == Some(&id)
                } else {
                    self.ssrc_sequence_index
                        .get(&(packet.ssrc, packet.rtp_sequence_number))
                        == Some(&id)
                };
                sent.covered && !packet.arrived && reachable
            });
            if held {
                // A loss is final only when the next feedback has not reported it received
                // either (libwebrtc's TransportFeedbackAdapter keeps a lost packet "because
                // it might be reported as received by a later feedback").
                self.pending_losses.push(id);
                continue;
            }
            if let Some(sent) = self.release(id) {
                if sent.covered {
                    reports.push(sent.report);
                } else {
                    self.unreported += 1;
                }
            }
        }
        self.next_to_report = highest + 1;

        reports
    }

    /// Take a packet out of the history and its indexes.
    fn release(&mut self, id: u64) -> Option<Sent> {
        let sent = self.packets.remove(&id)?;
        let packet = &sent.report;
        if packet.is_twcc && self.twcc_index.get(&packet.twcc_sequence_number) == Some(&id) {
            self.twcc_index.remove(&packet.twcc_sequence_number);
        }
        if self
            .ssrc_sequence_index
            .get(&(packet.ssrc, packet.rtp_sequence_number))
            == Some(&id)
        {
            self.ssrc_sequence_index
                .remove(&(packet.ssrc, packet.rtp_sequence_number));
        }
        Some(sent)
    }

    /// Packets reported as not received that a later feedback reported as received.
    pub fn recovered(&self) -> u64 {
        self.recovered
    }

    /// Drop records of packets sent before `cutoff` that were never acknowledged.
    ///
    /// Without this the history grows without bound on a lossy path: an unacknowledged packet is
    /// never reported and never removed, so nothing else would ever release it.
    pub fn prune_before(&mut self, cutoff: Instant) {
        let stale: Vec<u64> = self
            .packets
            .iter()
            .filter(|(_, sent)| sent.report.departure < cutoff && !sent.report.arrived)
            .map(|(&id, _)| id)
            .collect();

        for id in stale {
            if let Some(sent) = self.packets.remove(&id) {
                let packet = sent.report;
                // Only a TWCC packet has an entry under its transport-wide sequence number. A
                // non-TWCC packet carries whatever the caller passed — typically 0 — and removing
                // that key would evict whichever real TWCC packet holds it.
                if packet.is_twcc {
                    self.twcc_index.remove(&packet.twcc_sequence_number);
                }
                self.ssrc_sequence_index
                    .remove(&(packet.ssrc, packet.rtp_sequence_number));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history_with_three_packets(now: Instant) -> History {
        let mut history = History::new();
        for sequence_number in 0..3u16 {
            history.add_outgoing(1, 100 + sequence_number, true, sequence_number, 1200, now);
        }
        history
    }

    #[test]
    fn feedback_for_an_unknown_packet_is_ignored() {
        let now = Instant::now();
        let mut history = History::new();

        assert_eq!(
            None,
            history.on_twcc_feedback(now, Acknowledgement::received(5, None, Ecn::NotEct)),
            "nothing was sent with that sequence number"
        );
        assert!(history.take_reports().is_empty());
    }

    #[test]
    fn twcc_feedback_matches_by_transport_wide_sequence_number() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        let rtt = history.on_twcc_feedback(
            now + Duration::from_millis(80),
            Acknowledgement::received(1, Some(Duration::from_millis(5)), Ecn::NotEct),
        );
        assert_eq!(Some(Duration::from_millis(80)), rtt);

        let reports = history.take_reports();
        assert_eq!(1, reports.len(), "only what the feedback described");
        assert_eq!(101, reports[0].rtp_sequence_number);
        assert!(reports[0].arrived);
    }

    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3: when a feedback packet is
    /// lost, the packets it would have reported are ignored, "not counted as lost or received".
    #[test]
    fn packets_whose_feedback_was_lost_are_not_reported_as_lost() {
        let now = Instant::now();
        let mut history = History::new();
        for sequence_number in 0..20u16 {
            history.add_outgoing(1, 100 + sequence_number, true, sequence_number, 1200, now);
        }

        // The feedback for 0..=9 never arrives; the one for 10..=19 does.
        for sequence_number in 10..20u16 {
            history.on_twcc_feedback(
                now + Duration::from_millis(50),
                Acknowledgement::received(sequence_number, None, Ecn::NotEct),
            );
        }

        let reports = history.take_reports();
        assert_eq!(10, reports.len(), "the ten packets the feedback described");
        assert!(
            reports.iter().all(|report| report.arrived),
            "no loss was reported by the receiver, so none is reported here"
        );
        assert_eq!(110, reports[0].rtp_sequence_number);
        assert_eq!(
            10,
            history.unreported(),
            "the uncovered ten have no verdict"
        );
        assert!(history.is_empty(), "and are not kept");
    }

    /// A retransmission that keeps its transport-wide number takes the receiver's verdict; the
    /// transmission it replaces is the loss that caused it, and stays one.
    #[test]
    fn a_transmission_superseded_under_the_same_number_is_reported_lost() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 7, 1200, now);
        history.add_outgoing(1, 100, true, 7, 1200, now + Duration::from_millis(40));

        history.on_twcc_feedback(
            now + Duration::from_millis(80),
            Acknowledgement::received(7, None, Ecn::NotEct),
        );

        let reports = history.take_reports();
        assert_eq!(
            vec![false, true],
            reports
                .iter()
                .map(|report| report.arrived)
                .collect::<Vec<_>>()
        );
        assert_eq!(0, history.unreported());
    }

    /// A packet the receiver itself reports as not received is still a loss, once the next
    /// feedback has not reported it received either.
    #[test]
    fn a_packet_reported_not_received_is_a_loss() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::lost(0));
        history.on_twcc_feedback(now, Acknowledgement::received(1, None, Ecn::NotEct));
        history.on_twcc_feedback(now, Acknowledgement::received(2, None, Ecn::NotEct));

        let arrived = |reports: Vec<PacketReport>| -> Vec<bool> {
            reports.iter().map(|report| report.arrived).collect()
        };
        assert_eq!(vec![true, true], arrived(history.take_reports()));
        assert_eq!(
            vec![false],
            arrived(history.take_reports()),
            "the next feedback's turn"
        );
        assert_eq!(0, history.unreported());
        assert_eq!(0, history.recovered());
    }

    /// A packet only overtaken on the path is reported as not received by the feedback that
    /// covered the packets after it, and as received by the next. It is not a loss
    /// (libwebrtc's `TransportFeedbackAdapter` keeps a lost packet "because it might be
    /// reported as received by a later feedback"): the history holds a reported loss for one
    /// more feedback, and reports the packet as received, without an arrival time for the
    /// delay model, which reads reports in send order.
    #[test]
    fn a_packet_reported_lost_and_then_received_is_not_a_loss() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::lost(0));
        history.on_twcc_feedback(now, Acknowledgement::received(1, None, Ecn::NotEct));
        assert_eq!(1, history.take_reports().len(), "1, and 0 held back");
        history.on_twcc_feedback(
            now,
            Acknowledgement::received(0, Some(Duration::from_millis(50)), Ecn::NotEct),
        );
        history.on_twcc_feedback(now, Acknowledgement::received(2, None, Ecn::NotEct));
        let reports = history.take_reports();
        assert_eq!(2, reports.len());
        assert!(reports.iter().all(|report| report.arrived), "{reports:?}");
        assert_eq!(None, reports[0].arrival, "0 is out of send order now");
        assert_eq!(1, history.recovered());
    }

    /// The feedback packet count is how a lost feedback packet is told from a quiet receiver
    /// (section 3.1).
    #[test]
    fn a_gap_in_the_feedback_packet_count_is_a_lost_feedback_packet() {
        let mut history = History::new();

        assert_eq!(0, history.on_twcc_feedback_count(254), "the first one");
        assert_eq!(0, history.on_twcc_feedback_count(255), "consecutive");
        assert_eq!(
            2,
            history.on_twcc_feedback_count(2),
            "0 and 1 are missing, across the wrap"
        );
        assert_eq!(
            0,
            history.on_twcc_feedback_count(1),
            "a late one is not a gap"
        );
        assert_eq!(0, history.on_twcc_feedback_count(3));
        assert_eq!(2, history.lost_feedback());
    }

    /// RFC 8888 names packets by the stream's own sequence number, so two streams can use the
    /// same one and must not be confused.
    #[test]
    fn ccfb_feedback_matches_by_ssrc_and_sequence_number() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 500, false, 0, 1000, now);
        history.add_outgoing(2, 500, false, 0, 1000, now);

        history.on_ccfb_feedback(
            now + Duration::from_millis(50),
            2,
            Acknowledgement::received(500, Some(Duration::from_millis(1)), Ecn::Ce),
        );

        // Stream 1's packet was sent first and no report block described it: it has no verdict,
        // and is not a loss (draft-ietf-rmcat-gcc bug G2).
        let reports = history.take_reports();
        assert_eq!(1, reports.len());
        assert_eq!(2, reports[0].ssrc);
        assert!(reports[0].arrived, "stream 2's was acknowledged");
        assert_eq!(Ecn::Ce, reports[0].ecn);
    }

    /// Feedback naming a stream that never sent that sequence number must not match another
    /// stream that did. RFC 8888 numbers packets per stream, so the same sequence number is in
    /// use on every stream at once — matching on it alone would attribute one stream's arrival to
    /// another and corrupt both their delay estimates.
    ///
    /// Deterministic by construction: only stream 1 ever sent 500, so a lookup that ignores the
    /// SSRC can only match stream 1's packet, and a correct one can only fail.
    #[test]
    fn ccfb_feedback_for_a_sequence_number_another_stream_sent_does_not_match() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 500, false, 0, 1000, now);

        assert_eq!(
            None,
            history.on_ccfb_feedback(
                now + Duration::from_millis(50),
                2,
                Acknowledgement::received(500, Some(Duration::from_millis(1)), Ecn::NotEct),
            ),
            "stream 2 never sent sequence 500"
        );
        assert!(
            history.take_reports().is_empty(),
            "and nothing was acknowledged, so stream 1's packet is still outstanding"
        );
    }

    #[test]
    fn nothing_is_reported_until_something_is_acknowledged() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        assert!(
            history.take_reports().is_empty(),
            "sent but not yet acknowledged"
        );
        assert_eq!(3, history.len(), "and still tracked");
    }

    /// A packet reported once must not be reported again: congestion control would count it
    /// twice, and a loss re-reported later looks like a reordered arrival.
    #[test]
    fn packets_are_reported_once() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::lost(0));
        history.on_twcc_feedback(now, Acknowledgement::received(1, None, Ecn::NotEct));
        history.on_twcc_feedback(now, Acknowledgement::received(2, None, Ecn::NotEct));
        // 1 and 2, then the loss of 0 a feedback later.
        assert_eq!(2, history.take_reports().len());
        assert_eq!(1, history.take_reports().len());
        assert!(history.take_reports().is_empty());
        assert!(history.is_empty(), "and released");
    }

    #[test]
    fn later_feedback_reports_only_what_follows() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);
        history.add_outgoing(1, 101, true, 1, 1200, now);

        history.on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct));
        assert_eq!(1, history.take_reports().len());

        history.on_twcc_feedback(now, Acknowledgement::received(1, None, Ecn::NotEct));
        let reports = history.take_reports();
        assert_eq!(1, reports.len());
        assert_eq!(101, reports[0].rtp_sequence_number);
    }

    /// A packet reported as lost does not advance the reporting window on its own — otherwise a
    /// long run of losses would flush packets that have not been heard about yet.
    #[test]
    fn a_loss_alone_does_not_advance_the_window() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::lost(1));
        assert!(
            history.take_reports().is_empty(),
            "nothing has been acknowledged as arrived"
        );
        assert_eq!(3, history.len());
    }

    /// The round trip is measured between two instants on *this* endpoint's clock, unlike the
    /// arrival times, which are on the receiver's.
    #[test]
    fn the_round_trip_is_measured_locally() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);

        assert_eq!(
            Some(Duration::from_millis(120)),
            history.on_twcc_feedback(
                now + Duration::from_millis(120),
                Acknowledgement::received(0, Some(Duration::from_secs(9999)), Ecn::NotEct),
            ),
            "the receiver's arrival clock does not affect it"
        );
    }

    /// Without pruning, an unacknowledged packet is never reported and never removed, so a lossy
    /// path grows the history without bound.
    /// A non-TWCC packet carries a meaningless `twcc_sequence_number` (whatever the caller
    /// passed, typically 0) and was never entered into the TWCC index. Removing that key when it
    /// is released evicts whichever *real* TWCC packet happens to hold it, and that packet's
    /// feedback can then never match.
    #[test]
    fn releasing_a_non_twcc_packet_does_not_evict_a_twcc_packets_index_entry() {
        let now = Instant::now();
        let mut history = History::new();

        // The non-TWCC packet is sent *first*, so reporting it does not sweep up the TWCC one:
        // the reporting window runs to the highest arrived id, and anything below it is released
        // regardless. Ordering this way isolates the index eviction from that.
        history.add_outgoing(2, 200, false, 0, 1200, now);
        // A real TWCC packet holding transport-wide sequence 0, sent after.
        history.add_outgoing(1, 100, true, 0, 1200, now);

        // Release the non-TWCC packet by reporting it.
        history.on_ccfb_feedback(now, 2, Acknowledgement::received(200, None, Ecn::NotEct));
        history.take_reports();

        assert!(
            history
                .on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct))
                .is_some(),
            "the TWCC packet is still matchable by its transport-wide sequence number"
        );
    }

    /// The same hazard on the pruning path.
    #[test]
    fn pruning_a_non_twcc_packet_does_not_evict_a_twcc_packets_index_entry() {
        let now = Instant::now();
        let mut history = History::new();

        // Old, non-TWCC, carrying the default 0 it never registered.
        history.add_outgoing(2, 200, false, 0, 1200, now);
        // Recent, a real TWCC packet holding transport-wide sequence 0.
        history.add_outgoing(1, 100, true, 0, 1200, now + Duration::from_secs(5));

        history.prune_before(now + Duration::from_secs(1));

        assert!(
            history
                .on_twcc_feedback(
                    now + Duration::from_secs(5),
                    Acknowledgement::received(0, None, Ecn::NotEct)
                )
                .is_some(),
            "pruning the unrelated packet must not take the TWCC index entry with it"
        );
    }

    /// An acknowledged packet that has not been reported yet must survive pruning, or the arrival
    /// is lost and congestion control never hears about it.
    #[test]
    fn an_acknowledged_packet_is_not_pruned_before_it_is_reported() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);

        history.on_twcc_feedback(
            now + Duration::from_millis(50),
            Acknowledgement::received(0, None, Ecn::NotEct),
        );

        // Well past the cutoff, but it has been acknowledged and not yet collected.
        history.prune_before(now + Duration::from_secs(30));

        let reports = history.take_reports();
        assert_eq!(1, reports.len(), "the arrival survived to be reported");
        assert!(reports[0].arrived);
    }

    #[test]
    fn old_unacknowledged_packets_are_pruned() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);
        history.add_outgoing(1, 101, true, 1, 1200, now + Duration::from_secs(5));

        history.prune_before(now + Duration::from_secs(1));

        assert_eq!(1, history.len(), "only the recent one survives");
        assert_eq!(
            None,
            history.on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct)),
            "and the pruned one is no longer matchable"
        );
    }
}
