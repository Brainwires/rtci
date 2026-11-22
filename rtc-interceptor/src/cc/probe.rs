//! Bandwidth probing: short bursts above the target rate, and the capacity their arrival shows.
//!
//! A delay-based controller finds out that a path has room only by using it, and climbs a few
//! percent a second (8% in `Gcc`): from 300 kbit/s to 2.5 Mbit/s takes most of half a minute.
//! A probe asks the question directly. A cluster of packets leaves at a multiple of the target
//! for some milliseconds; if the receiver reports them arriving as closely spaced as they left,
//! the path carries that rate and the estimate moves there at once.
//!
//! No RFC requires it. RFC 8836 section 2 asks that a congestion controller "adapt as quickly
//! as possible to initial network conditions" and "allow for different modes of adaptation",
//! naming "probing during setup" as one (requirement 4, both SHOULD); draft-ietf-rmcat-gcc-02
//! has no probing at all. It is what libwebrtc does, in outline, and so it is an option that is
//! off by default.
//!
//! The parts:
//!
//! - [`ProbeController`] decides when a cluster is sent and at what rate: two at the start
//!   (three and six times the starting rate), a further one at twice the result while results
//!   keep confirming the rate probed, and one every few seconds while the application sends
//!   less than the target allows, when nothing else would show that the path has grown.
//! - [`ProbeRequest`] is what travels through the chain: the congestion controller announces
//!   it on the read leg, the pacer releases the next packets at its rate and marks them
//!   ([`ProbePacket`]), and the NACK responder fills the cluster with retransmissions of recent
//!   packets on the RTX stream when the application's own media is not enough.
//! - [`probe_estimate`] turns the receiver's reports on a cluster into a bit rate.

use crate::rtpfb::acknowledgement::PacketReport;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a cluster lasts at its rate, at least.
pub const PROBE_MIN_DURATION: Duration = Duration::from_millis(15);
/// How many packets a cluster has, at least.
pub const PROBE_MIN_PACKETS: usize = 5;
/// The size a probe packet is taken to have when a cluster is sized.
const PROBE_PACKET_OCTETS: usize = 1200;
/// The most a cluster asks for, whatever its rate.
pub const PROBE_MAX_OCTETS: usize = 64_000;
/// The clusters at the start, as multiples of the starting rate.
const INITIAL_PROBES: [f64; 2] = [3.0, 6.0];
/// The next cluster after a result, as a multiple of it.
const FURTHER_PROBE: f64 = 2.0;
/// A result confirms the rate probed when it reaches this share of it: the path was not the
/// limit, and probing goes on.
const FURTHER_PROBE_THRESHOLD: f64 = 0.7;
/// How often a cluster is sent while the application sends less than the target.
pub const PROBE_APPLICATION_LIMITED_INTERVAL: Duration = Duration::from_secs(5);
/// The share of the target below which the sender counts as application limited.
const APPLICATION_LIMITED_SHARE: f64 = 0.65;
/// How long a cluster's reports are waited for before it is given up.
pub const PROBE_RESULT_TIMEOUT: Duration = Duration::from_secs(1);
/// The least time between two clusters.
const PROBE_SPACING: Duration = Duration::from_millis(100);

/// A probe cluster the congestion controller asks for.
///
/// Carried as an [`Attribute::Custom`] on an empty RTCP packet on the read leg
/// ([`ProbeRequest::into_packet`]), from the congestion controller towards the application:
/// the pacer and the NACK responder read it on its way past.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeRequest {
    /// Which cluster this is; the packets sent for it carry the same number.
    pub cluster: u32,
    /// The rate the cluster leaves at, bits per second.
    pub bits_per_second: f64,
    /// How much the cluster holds, octets on the wire.
    pub octets: usize,
}

impl ProbeRequest {
    /// The packet that carries this application-ward from where it is read at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// The mark of an RTP packet the pacer released as part of a probe cluster, as an
/// [`Attribute::Custom`] on its way to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePacket {
    /// The cluster it belongs to.
    pub cluster: u32,
}

/// How much a cluster at `bits_per_second` holds.
pub(crate) fn cluster_octets(bits_per_second: f64) -> usize {
    let by_duration = (bits_per_second * PROBE_MIN_DURATION.as_secs_f64() / 8.0) as usize;
    by_duration.clamp(PROBE_MIN_PACKETS * PROBE_PACKET_OCTETS, PROBE_MAX_OCTETS)
}

/// The bit rate a path showed it carries, from the reports on the packets of one cluster.
///
/// The cluster left at the send rate and arrived at the receive rate; the path carries the
/// lower of the two. The send rate is taken over all but the last packet and the span from
/// the first departure to the last, the receive rate over all but the first packet and the
/// span of the arrivals, so that each is octets over the time they took. When the packets
/// arrived more than a tenth slower than they left, the bottleneck was reached and held them
/// apart: the estimate is 95% of the receive rate, to stay below it.
///
/// `None` when fewer than four packets of the cluster arrived with a time, or their times do
/// not span anything: too little to measure.
pub fn probe_estimate(reports: &[PacketReport]) -> Option<f64> {
    let arrived: Vec<(Instant, Duration, usize)> = reports
        .iter()
        .filter(|report| report.arrived)
        .filter_map(|report| Some((report.departure, report.arrival?, report.size)))
        .collect();
    if arrived.len() < 4 {
        return None;
    }
    let total: usize = arrived.iter().map(|(_, _, size)| size).sum();

    let (first_sent, last_sent) =
        arrived
            .iter()
            .fold(None, |span: Option<(Instant, Instant)>, (sent, _, _)| {
                Some(span.map_or((*sent, *sent), |(first, last)| {
                    (first.min(*sent), last.max(*sent))
                }))
            })?;
    let last_sent_size = arrived
        .iter()
        .filter(|(sent, _, _)| *sent == last_sent)
        .map(|(_, _, size)| *size)
        .next_back()?;
    let (first_arrival, last_arrival) =
        arrived
            .iter()
            .fold(None, |span: Option<(Duration, Duration)>, (_, at, _)| {
                Some(span.map_or((*at, *at), |(first, last)| (first.min(*at), last.max(*at))))
            })?;
    let first_arrival_size = arrived
        .iter()
        .find(|(_, at, _)| *at == first_arrival)
        .map(|(_, _, size)| *size)?;

    let send_span = last_sent
        .saturating_duration_since(first_sent)
        .as_secs_f64();
    let receive_span = last_arrival.saturating_sub(first_arrival).as_secs_f64();
    if receive_span <= 0.0 {
        return None;
    }
    let receive_rate = (total - first_arrival_size) as f64 * 8.0 / receive_span;
    // Packets that left in the same instant have no send rate to compare with: the arrivals
    // alone say what the path did with them.
    if send_span <= 0.0 {
        return Some(receive_rate * 0.95);
    }
    let send_rate = (total - last_sent_size) as f64 * 8.0 / send_span;
    if receive_rate < 0.9 * send_rate {
        Some(receive_rate * 0.95)
    } else {
        Some(send_rate.min(receive_rate))
    }
}

/// Decides when a probe cluster is sent and at what rate.
#[derive(Debug)]
pub struct ProbeController {
    next_cluster: u32,
    /// Rates still to probe from the start-up sequence.
    initial: Vec<f64>,
    started: bool,
    /// The cluster awaiting its result: its number, its rate and when it was asked for.
    outstanding: Option<(u32, f64, Instant)>,
    last_probe: Option<Instant>,
    /// A further cluster owed after a result that confirmed its rate.
    further: Option<f64>,
    max_bitrate: f64,
}

impl ProbeController {
    /// A controller for an estimator that starts at `initial_bitrate` and never goes above
    /// `max_bitrate`.
    pub fn new(initial_bitrate: f64, max_bitrate: f64) -> Self {
        Self {
            next_cluster: 1,
            initial: INITIAL_PROBES
                .iter()
                .rev()
                .map(|multiple| initial_bitrate * multiple)
                .collect(),
            started: false,
            outstanding: None,
            last_probe: None,
            further: None,
            max_bitrate,
        }
    }

    /// The ceiling of what is probed for: the estimator's own maximum, or a limit from
    /// outside it (REMB, TMMBR, the session bit rate).
    pub fn set_max_bitrate(&mut self, max_bitrate: f64) {
        self.max_bitrate = max_bitrate;
    }

    /// The cluster to send now, if one is due.
    ///
    /// `target` is the current target bit rate and `sending` the rate the application is
    /// sending at; `media_flowing` is whether a packet has left yet (a probe before the
    /// first one would measure nothing the receiver reports).
    pub fn poll(
        &mut self,
        now: Instant,
        target: f64,
        sending: f64,
        media_flowing: bool,
    ) -> Option<ProbeRequest> {
        if !media_flowing {
            return None;
        }
        if let Some((_, _, asked)) = self.outstanding {
            if now.saturating_duration_since(asked) < PROBE_RESULT_TIMEOUT {
                return None;
            }
            // Its reports never came: the cluster is given up, and with it the sequence it
            // was part of.
            self.outstanding = None;
            self.further = None;
        }
        if self
            .last_probe
            .is_some_and(|last| now.saturating_duration_since(last) < PROBE_SPACING)
        {
            return None;
        }

        self.started = true;
        let rate = if let Some(rate) = self.initial.pop() {
            Some(rate)
        } else if let Some(rate) = self.further.take() {
            Some(rate)
        } else if sending < APPLICATION_LIMITED_SHARE * target
            && self.last_probe.is_none_or(|last| {
                now.saturating_duration_since(last) >= PROBE_APPLICATION_LIMITED_INTERVAL
            })
        {
            // Sending less than the target allows, the delay-based controller learns nothing
            // about the room above what is sent.
            Some(target * FURTHER_PROBE)
        } else {
            None
        }?;

        let rate = rate.min(self.max_bitrate);
        if rate <= target {
            // Nothing above the target is allowed, so there is nothing to ask.
            return None;
        }
        let cluster = self.next_cluster;
        self.next_cluster = self.next_cluster.wrapping_add(1).max(1);
        self.outstanding = Some((cluster, rate, now));
        self.last_probe = Some(now);
        Some(ProbeRequest {
            cluster,
            bits_per_second: rate,
            octets: cluster_octets(rate),
        })
    }

    /// The number of the cluster whose result is awaited.
    pub fn outstanding(&self) -> Option<u32> {
        self.outstanding.map(|(cluster, _, _)| cluster)
    }

    /// The result of `cluster`: `estimate` bits per second. Returns the estimate when it is
    /// the outstanding cluster's, for the estimator to take.
    pub fn on_result(&mut self, cluster: u32, estimate: f64) -> Option<f64> {
        let (outstanding, rate, _) = self.outstanding?;
        if outstanding != cluster {
            return None;
        }
        self.outstanding = None;
        // The path carried what was asked of it: it may carry more.
        if estimate >= FURTHER_PROBE_THRESHOLD * rate && self.initial.is_empty() {
            let next = estimate * FURTHER_PROBE;
            if next <= self.max_bitrate * FURTHER_PROBE {
                self.further = Some(next);
            }
        }
        Some(estimate)
    }

    /// When [`poll`](Self::poll) next has something to say without anything else happening.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if !self.started {
            return None;
        }
        if let Some((_, _, asked)) = self.outstanding {
            return Some(asked + PROBE_RESULT_TIMEOUT);
        }
        let last = self.last_probe?;
        if !self.initial.is_empty() || self.further.is_some() {
            Some(last + PROBE_SPACING)
        } else {
            Some(last + PROBE_APPLICATION_LIMITED_INTERVAL)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;

    fn report(id: u64, departure: Instant, arrival_us: u64, size: usize) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id,
            rtp_sequence_number: id as u16,
            is_twcc: true,
            twcc_sequence_number: id as u16,
            size,
            arrived: true,
            departure,
            arrival: Some(Duration::from_micros(arrival_us)),
            ecn: Ecn::NotEct,
        }
    }

    /// Six 1200-octet packets sent 2 ms apart (4.8 Mbit/s) that arrive 2 ms apart: the path
    /// carried the cluster, and the estimate is the rate it was sent at.
    #[test]
    fn a_cluster_that_arrives_as_it_left_shows_its_own_rate() {
        let epoch = Instant::now();
        let reports: Vec<PacketReport> = (0..6u64)
            .map(|i| {
                report(
                    i,
                    epoch + Duration::from_millis(2 * i),
                    50_000 + 2_000 * i,
                    1200,
                )
            })
            .collect();
        let estimate = probe_estimate(&reports).expect("measurable");
        assert!((estimate - 4_800_000.0).abs() < 1_000.0, "{estimate}");
    }

    /// The same cluster through a 2.4 Mbit/s bottleneck arrives 4 ms apart: the estimate is
    /// 95% of the rate it arrived at, not the rate it was sent at.
    #[test]
    fn a_cluster_spread_out_by_the_bottleneck_shows_the_bottleneck() {
        let epoch = Instant::now();
        let reports: Vec<PacketReport> = (0..6u64)
            .map(|i| {
                report(
                    i,
                    epoch + Duration::from_millis(2 * i),
                    50_000 + 4_000 * i,
                    1200,
                )
            })
            .collect();
        let estimate = probe_estimate(&reports).expect("measurable");
        assert!(
            (estimate - 0.95 * 2_400_000.0).abs() < 1_000.0,
            "{estimate}"
        );
    }

    /// Three arrivals are not a measurement, and neither are packets without arrival times.
    #[test]
    fn too_few_arrivals_give_no_estimate() {
        let epoch = Instant::now();
        let mut reports: Vec<PacketReport> = (0..3u64)
            .map(|i| {
                report(
                    i,
                    epoch + Duration::from_millis(2 * i),
                    50_000 + 2_000 * i,
                    1200,
                )
            })
            .collect();
        assert_eq!(None, probe_estimate(&reports));
        let mut lost = report(3, epoch + Duration::from_millis(6), 0, 1200);
        lost.arrived = false;
        lost.arrival = None;
        reports.push(lost);
        assert_eq!(None, probe_estimate(&reports));
    }

    /// At the start: three times the starting rate, then six times, each once its predecessor
    /// has a result, and nothing before media flows.
    #[test]
    fn the_start_probes_at_three_and_six_times_the_starting_rate() {
        let epoch = Instant::now();
        let mut controller = ProbeController::new(300_000.0, 100_000_000.0);
        assert_eq!(None, controller.poll(epoch, 300_000.0, 0.0, false));

        let first = controller
            .poll(epoch, 300_000.0, 300_000.0, true)
            .expect("first cluster");
        assert_eq!(900_000.0, first.bits_per_second);
        assert_eq!(
            PROBE_MIN_PACKETS * PROBE_PACKET_OCTETS,
            first.octets,
            "five packets at least"
        );
        assert_eq!(
            None,
            controller.poll(
                epoch + Duration::from_millis(200),
                300_000.0,
                300_000.0,
                true
            ),
            "one cluster at a time"
        );

        assert_eq!(
            Some(900_000.0),
            controller.on_result(first.cluster, 900_000.0)
        );
        let second = controller
            .poll(
                epoch + Duration::from_millis(200),
                900_000.0,
                300_000.0,
                true,
            )
            .expect("second cluster");
        assert_eq!(1_800_000.0, second.bits_per_second);
    }

    /// A result that confirms the rate probed is followed by a cluster at twice the result; one
    /// that shows the bottleneck is not.
    #[test]
    fn probing_goes_on_while_the_path_carries_what_is_asked() {
        let epoch = Instant::now();
        let mut controller = ProbeController::new(300_000.0, 100_000_000.0);
        let mut now = epoch;
        let mut target = 300_000.0;
        let mut asked = Vec::new();
        // The path carries 2.5 Mbit/s.
        for _ in 0..8 {
            if let Some(request) = controller.poll(now, target, target, true) {
                asked.push(request.bits_per_second);
                let estimate = request.bits_per_second.min(2_500_000.0 * 0.95);
                target = controller
                    .on_result(request.cluster, estimate)
                    .expect("the outstanding cluster");
            }
            now += Duration::from_millis(150);
        }
        assert_eq!(
            vec![900_000.0, 1_800_000.0, 3_600_000.0],
            asked,
            "the third cluster found the bottleneck (2.375 of 3.6 Mbit/s) and ended the sequence"
        );
        assert_eq!(2_375_000.0, target);
    }

    /// While the application sends less than the target allows, a cluster goes out every five
    /// seconds; at the target, none.
    #[test]
    fn an_application_limited_sender_probes_every_few_seconds() {
        let epoch = Instant::now();
        let mut controller = ProbeController::new(300_000.0, 100_000_000.0);
        // The start-up sequence, answered with the bottleneck at once.
        for at in [epoch, epoch + Duration::from_millis(150)] {
            let request = controller
                .poll(at, 300_000.0, 300_000.0, true)
                .expect("start-up cluster");
            controller.on_result(request.cluster, 500_000.0);
        }

        let later = epoch + Duration::from_secs(6);
        assert_eq!(
            None,
            controller.poll(later, 1_000_000.0, 1_000_000.0, true),
            "sending at the target: the delay-based controller is asking already"
        );
        let request = controller
            .poll(later, 1_000_000.0, 200_000.0, true)
            .expect("application limited");
        assert_eq!(2_000_000.0, request.bits_per_second);
        controller.on_result(request.cluster, 1_200_000.0);
        assert_eq!(
            None,
            controller.poll(later + Duration::from_secs(1), 1_000_000.0, 200_000.0, true),
            "not again within five seconds"
        );
    }

    /// Nothing is probed above the ceiling, and a cluster whose reports never come is given up.
    #[test]
    fn the_ceiling_and_the_timeout_end_a_probe() {
        let epoch = Instant::now();
        let mut controller = ProbeController::new(300_000.0, 600_000.0);
        let request = controller
            .poll(epoch, 300_000.0, 300_000.0, true)
            .expect("capped cluster");
        assert_eq!(600_000.0, request.bits_per_second);
        assert_eq!(Some(request.cluster), controller.outstanding());
        assert_eq!(
            Some(epoch + PROBE_RESULT_TIMEOUT),
            controller.poll_timeout()
        );

        let after = epoch + PROBE_RESULT_TIMEOUT;
        // Given up; the next of the start-up sequence is capped at the ceiling too, which the
        // target has reached by then.
        assert_eq!(None, controller.poll(after, 600_000.0, 600_000.0, true));
        assert_eq!(None, controller.outstanding());
    }
}
