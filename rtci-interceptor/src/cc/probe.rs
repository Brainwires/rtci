//! Bandwidth probing: short bursts above the target rate, and the capacity their arrival shows.
//!
//! A delay-based controller finds out that a path has room only by using it, and climbs a few
//! percent a second (8% in `Gcc`): from 300 kbit/s to 2.5 Mbit/s takes most of half a minute.
//! A probe asks the question directly. A cluster of packets leaves at a multiple of the target
//! for some milliseconds; if the receiver reports them arriving as closely spaced as they left,
//! the path carries that rate and the estimate moves there at once.
//!
//! RFC 8836 section 2 asks that a congestion controller "adapt as quickly as possible to
//! initial network conditions" and "allow for different modes of adaptation", naming "probing
//! during setup" as one (requirement 4, both SHOULD); draft-ietf-rmcat-gcc-02 has no probing at
//! all. It is what libwebrtc does, in outline. The peer connection's default interceptor set
//! probes (a SHOULD is met by default); `DefaultInterceptorOptions::bandwidth_probing` turns it
//! off, and a chain built by hand probes only with
//! [`CongestionControlBuilder::with_bandwidth_probing`](crate::CongestionControlBuilder::with_bandwidth_probing).
//!
//! The parts:
//!
//! - [`ProbeController`] decides when a cluster is sent and at what rate: two at the start
//!   (three and six times the starting rate), a further one at twice the result while results
//!   keep confirming the rate probed, and one every few seconds while the application sends
//!   less than the target allows, when nothing else would show that the path has grown; and,
//!   for a few seconds after the target dropped by a third or more, the rate before the drop.
//! - [`ProbeRequest`] is what travels through the chain: the congestion controller announces
//!   it on the read leg, the pacer releases the next packets at its rate and marks them
//!   ([`ProbePacket`]), and the NACK responder fills the cluster with padding-only packets on
//!   the RTX stream when the application's own media is not enough: they carry no media, so a
//!   receiver never has a packet twice.
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
/// The target falling below this share of its recent high is a large drop.
const LARGE_DROP_SHARE: f64 = 0.66;
/// How long the recent high of the target is remembered for drop detection.
const LARGE_DROP_WINDOW: Duration = Duration::from_secs(2);
/// How long after a large drop the old rate is probed for.
pub const PROBE_AFTER_DROP_TIMEOUT: Duration = Duration::from_secs(5);
/// The first probe after a large drop waits this long: the back-off has to take effect.
const PROBE_AFTER_DROP_DELAY: Duration = Duration::from_secs(1);
/// And they are this far apart.
const PROBE_AFTER_DROP_INTERVAL: Duration = Duration::from_secs(1);
/// A probe after a drop asks for this share of the rate before it.
const PROBE_AFTER_DROP_SHARE: f64 = 0.85;
/// How long the target has to stay below [`LARGE_DROP_SHARE`] of its high for recovery
/// probing to remember that high.
const RECOVERY_LASTING: Duration = Duration::from_secs(2);
/// How far back the high recovery probing compares the target with reaches.
const RECOVERY_HIGH_WINDOW: Duration = Duration::from_secs(10);
/// Recovery probes go out once this long has passed since the last probe.
pub const RECOVERY_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// And only when the target has not fallen for this long.
const RECOVERY_QUIET: Duration = Duration::from_secs(1);

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
    /// Whether the rate before a large drop is probed for (see
    /// [`with_probe_after_drop`](Self::with_probe_after_drop)).
    after_drop: bool,
    /// The highest target of the last [`LARGE_DROP_WINDOW`], and when it was.
    peak: Option<(f64, Instant)>,
    /// The last large drop: the target before it, and when it happened.
    drop: Option<(f64, Instant)>,
    /// Whether the outstanding cluster probes for the rate before a drop.
    drop_probe: bool,
    /// When [`poll`](Self::poll) was last called.
    polled_at: Option<Instant>,
    /// Whether the high before a lasting drop is probed for until the target is back (see
    /// [`with_recovery_probing`](Self::with_recovery_probing)).
    recovery_probing: bool,
    /// The target's high of the last [`RECOVERY_HIGH_WINDOW`] and when it was, and since
    /// when the target has been below [`LARGE_DROP_SHARE`] of it.
    recovery_peak: Option<(f64, Instant)>,
    below_since: Option<Instant>,
    /// The high before a drop that lasted, while the target is below it.
    recovery_high: Option<f64>,
    /// When the target last fell.
    fell_at: Option<Instant>,
    /// The target before the last poll, to tell a fall.
    last_target: Option<f64>,
    /// The target when the outstanding cluster, a recovery probe, was asked for.
    recovery_probe: Option<f64>,
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
            after_drop: true,
            peak: None,
            drop: None,
            drop_probe: false,
            polled_at: None,
            recovery_probing: false,
            recovery_peak: None,
            below_since: None,
            recovery_high: None,
            fell_at: None,
            last_target: None,
            recovery_probe: None,
        }
    }

    /// Whether the rate the target had before a drop that lasted is probed for until the
    /// target is back near it. Off by default.
    ///
    /// Once a sender follows its target, no other rule probes: the start-up probes are
    /// over, a further probe follows only a confirming result, the probe after a drop
    /// ([`with_probe_after_drop`](Self::with_probe_after_drop)) lasts five seconds, and the
    /// sender is not application limited. After a capacity drop that lasts longer than that
    /// and then goes, the estimate climbs back at the delay-based controller's rate (8 % a
    /// second in `Gcc`, draft-ietf-rmcat-gcc-02 section 5.5) from wherever the drop left it.
    /// RFC 8836 section 2 asks for a flow that "should also react quickly to regain its
    /// previous share of the bandwidth when the local bottleneck or link is cleared"
    /// (requirement 1f) and, after a pause, to "rapidly regain its previous share"
    /// (requirement 5a); neither it, draft-ietf-rmcat-gcc-02 nor RFC 8888 names probing for
    /// it (RFC 8836 names "probing during setup with dummy data" for start-up only,
    /// requirement 4a). libwebrtc probes a sender at its target only in application-limited
    /// periods (`probe_controller.cc` `TimeForAlrProbe`) or with a network-state estimate.
    ///
    /// With this, a target that has stayed below two thirds of its high of the last ten
    /// seconds for two seconds makes the controller remember that high (a sudden drop and a
    /// back-off in steps alike).
    /// While the target is below 85 % of it and has not fallen for a second, a cluster at
    /// twice the target (at most the high) is asked for once five seconds have passed since
    /// the last probe; a confirming result allows further probes as at the start. The high
    /// is forgotten when the target reaches 85 % of it, or when a recovery probe's result is
    /// below the target it was asked at (the path has not come back).
    pub fn with_recovery_probing(mut self, enabled: bool) -> Self {
        self.recovery_probing = enabled;
        self
    }

    /// Whether the rate the target had before a large drop is probed for, for a few seconds
    /// after it (the default), as libwebrtc's `ProbeController::RequestProbe` does.
    ///
    /// A short burst of competing traffic, or a moment of loss, makes the delay-based
    /// controller back off by a third or more; once it has passed, the climb back is the
    /// controller's additive increase near the old operating point, half a packet per
    /// response time, and takes tens of seconds (23 s after a 2 s burst at half the capacity,
    /// in `rtci-interceptor/tests/rfc8836_multi_flow.rs`), against RFC 8836 section 2
    /// (requirement 1f: the flow "regains its share quickly"). With this, a drop of the
    /// target below two thirds of its high of the last two seconds is followed, from a second
    /// on and once a second for five seconds, by a cluster at 85% of the rate before the drop
    /// while the target is still below that. A result above the target raises it (as every
    /// probe does); one below it changes nothing: the competing traffic is still there.
    pub fn with_probe_after_drop(mut self, enabled: bool) -> Self {
        self.after_drop = enabled;
        self
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
        self.polled_at = Some(now);
        if !media_flowing {
            return None;
        }
        if self.after_drop {
            self.track_drops(now, target);
        }
        if self.recovery_probing {
            self.track_recovery(now, target);
        }
        if let Some((_, _, asked)) = self.outstanding {
            if now.saturating_duration_since(asked) < PROBE_RESULT_TIMEOUT {
                return None;
            }
            // Its reports never came: the cluster is given up, and with it the sequence it
            // was part of.
            self.outstanding = None;
            self.further = None;
            self.drop_probe = false;
            self.recovery_probe = None;
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
        } else if let Some((before, at)) = self.drop
            && now.saturating_duration_since(at) >= PROBE_AFTER_DROP_DELAY
            && target < PROBE_AFTER_DROP_SHARE * before
            && self
                .last_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= PROBE_AFTER_DROP_INTERVAL)
        {
            // The rate before a large drop, while the drop is recent: if what caused it has
            // gone, the path carries it again.
            self.drop_probe = true;
            Some(PROBE_AFTER_DROP_SHARE * before)
        } else if let Some(high) = self.recovery_high
            && self
                .fell_at
                .is_none_or(|fell| now.saturating_duration_since(fell) >= RECOVERY_QUIET)
            && self
                .last_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= RECOVERY_PROBE_INTERVAL)
        {
            // The rate before a drop that lasted, while the target is still well under it:
            // if the drop has gone, the path carries it again.
            self.recovery_probe = Some(target);
            Some((target * FURTHER_PROBE).min(high))
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
            self.drop_probe = false;
            self.recovery_probe = None;
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

    /// Follows the target's recent high, and notes a large drop below it.
    fn track_drops(&mut self, now: Instant, target: f64) {
        match self.peak {
            Some((peak, at))
                if target < peak && now.saturating_duration_since(at) <= LARGE_DROP_WINDOW =>
            {
                if target < LARGE_DROP_SHARE * peak {
                    self.drop = Some((peak, now));
                    self.peak = Some((target, now));
                }
            }
            _ => self.peak = Some((target, now)),
        }
        if self
            .drop
            .is_some_and(|(_, at)| now.saturating_duration_since(at) > PROBE_AFTER_DROP_TIMEOUT)
        {
            self.drop = None;
        }
    }

    /// Follows the target for recovery probing: a target that stays well under its recent
    /// high makes that high the one to come back to.
    fn track_recovery(&mut self, now: Instant, target: f64) {
        if self.last_target.is_some_and(|last| target < last) {
            self.fell_at = Some(now);
        }
        self.last_target = Some(target);
        match self.recovery_peak {
            Some((peak, at))
                if target < peak && now.saturating_duration_since(at) <= RECOVERY_HIGH_WINDOW => {}
            _ => self.recovery_peak = Some((target, now)),
        }
        let (peak, _) = self.recovery_peak.expect("set above");
        if target < LARGE_DROP_SHARE * peak {
            let since = *self.below_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= RECOVERY_LASTING {
                self.recovery_high = Some(self.recovery_high.map_or(peak, |high| high.max(peak)));
            }
        } else {
            self.below_since = None;
        }
        if self
            .recovery_high
            .is_some_and(|high| target >= PROBE_AFTER_DROP_SHARE * high)
        {
            self.recovery_high = None;
        }
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
        // The path carried what was asked of it: it may carry more. Not after a probe for the
        // rate before a drop: that asks only whether the path is back where it was.
        let drop_probe = std::mem::take(&mut self.drop_probe);
        // A recovery probe whose result is below the target it was asked at: the path has
        // not come back, and the high is forgotten.
        if let Some(target) = self.recovery_probe.take()
            && estimate < target
        {
            self.recovery_high = None;
            self.recovery_peak = self.last_target.zip(self.polled_at);
            self.below_since = None;
        }
        if !drop_probe && estimate >= FURTHER_PROBE_THRESHOLD * rate && self.initial.is_empty() {
            let next = estimate * FURTHER_PROBE;
            if next <= self.max_bitrate * FURTHER_PROBE {
                self.further = Some(next);
            }
        }
        Some(estimate)
    }

    /// When [`poll`](Self::poll) next has something to say without anything else happening.
    ///
    /// Never an instant `poll` has already been called at or after: a deadline that passed
    /// with nothing to send (no media flowing, a sender that is no longer application
    /// limited, a target that recovered by itself) waits for the next write instead of
    /// asking to be woken again at once.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadlines()
            .into_iter()
            .flatten()
            .filter(|deadline| self.polled_at.is_none_or(|polled| *deadline > polled))
            .min()
    }

    /// The instants something may be due: a result to give up, the next cluster of a
    /// sequence or of an application-limited sender, the next probe after a drop.
    fn deadlines(&self) -> [Option<Instant>; 2] {
        if !self.started {
            return [None, None];
        }
        if let Some((_, _, asked)) = self.outstanding {
            return [Some(asked + PROBE_RESULT_TIMEOUT), None];
        }
        let Some(last) = self.last_probe else {
            return [None, None];
        };
        let next = if !self.initial.is_empty() || self.further.is_some() {
            last + PROBE_SPACING
        } else {
            last + PROBE_APPLICATION_LIMITED_INTERVAL
        };
        let after_drop = self
            .drop
            .map(|(_, at)| (at + PROBE_AFTER_DROP_DELAY).max(last + PROBE_AFTER_DROP_INTERVAL));
        let recovery = self
            .recovery_high
            .map(|_| last + RECOVERY_PROBE_INTERVAL)
            .or_else(|| self.below_since.map(|since| since + RECOVERY_LASTING));
        let second = match (after_drop, recovery) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        [Some(next), second]
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

    /// Settles a controller after its start-up sequence: two clusters answered at the
    /// bottleneck, so no further cluster is owed.
    fn settled(epoch: Instant) -> ProbeController {
        let mut controller = ProbeController::new(300_000.0, 100_000_000.0);
        for at in [epoch, epoch + Duration::from_millis(150)] {
            let request = controller
                .poll(at, 300_000.0, 300_000.0, true)
                .expect("start-up cluster");
            controller.on_result(request.cluster, 500_000.0);
        }
        controller
    }

    /// A settled controller at 2 Mbit/s whose target drops to 300 kbit/s at 2 s and stays
    /// there (the drop probes find the path still capped: results at the target); polled
    /// every 100 ms up to `until_ms`. Returns the clusters asked for, as (ms, rate).
    fn capped(controller: &mut ProbeController, epoch: Instant, until_ms: u64) -> Vec<(u64, f64)> {
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        let mut asked = vec![];
        for ms in (1_000..=until_ms).step_by(100) {
            let target = if ms < 2_000 { 2_000_000.0 } else { 300_000.0 };
            if let Some(request) = controller.poll(at(ms), target, target, true) {
                asked.push((ms, request.bits_per_second));
                controller.on_result(request.cluster, target);
            }
        }
        asked
    }

    /// Recovery probing (RFC 8836 section 2, requirement 1f, "regain its previous share"):
    /// once a drop has lasted two seconds, the high before it is probed for every five
    /// seconds at twice the target, while the target is well under it; without the option
    /// nothing is probed after the drop probes.
    #[test]
    fn a_drop_that_lasts_is_probed_for_every_five_seconds_with_recovery_probing() {
        let epoch = Instant::now();
        let mut without = settled(epoch);
        let asked = capped(&mut without, epoch, 20_000);
        assert!(
            asked.iter().all(|(ms, _)| *ms <= 7_000),
            "only the drop probes, for five seconds: {asked:?}"
        );

        let mut with = settled(epoch).with_recovery_probing(true);
        let asked = capped(&mut with, epoch, 20_000);
        let recovery: Vec<_> = asked.iter().filter(|(ms, _)| *ms > 7_000).collect();
        assert!(!recovery.is_empty(), "{asked:?}");
        for pair in recovery.windows(2) {
            assert!(pair[1].0 - pair[0].0 >= 5_000, "{asked:?}");
        }
        assert!(
            recovery.iter().all(|(_, rate)| *rate == 600_000.0),
            "{asked:?}"
        );
    }

    /// A recovery probe whose result is below the target it was asked at says the path has
    /// not come back: the high is forgotten and nothing more is asked.
    #[test]
    fn a_recovery_probe_below_the_target_ends_recovery_probing() {
        let epoch = Instant::now();
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        let mut controller = settled(epoch).with_recovery_probing(true);
        capped(&mut controller, epoch, 9_000);
        let request = (9_100..=20_000)
            .step_by(100)
            .find_map(|ms| controller.poll(at(ms), 300_000.0, 300_000.0, true))
            .expect("a recovery probe");
        controller.on_result(request.cluster, 250_000.0);
        assert!((20_100..=40_000).step_by(100).all(|ms| {
            controller
                .poll(at(ms), 300_000.0, 300_000.0, true)
                .is_none()
        }));
    }

    /// The target back at 85 % of the high ends recovery probing; a confirming recovery
    /// result asks for a further cluster, as at the start.
    #[test]
    fn recovery_probing_ends_when_the_target_is_back() {
        let epoch = Instant::now();
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        let mut controller = settled(epoch).with_recovery_probing(true);
        capped(&mut controller, epoch, 9_000);
        let request = (9_100..=20_000)
            .step_by(100)
            .find_map(|ms| controller.poll(at(ms), 300_000.0, 300_000.0, true))
            .expect("a recovery probe");
        // The path carries what was asked: a further cluster at twice the result follows.
        controller.on_result(request.cluster, 600_000.0);
        let further = controller
            .poll(at(20_200), 600_000.0, 600_000.0, true)
            .expect("a further cluster");
        assert_eq!(1_200_000.0, further.bits_per_second);
        controller.on_result(further.cluster, 1_800_000.0);
        // 1.8 of the 2 Mbit/s high: recovered; the further cluster from that result is the
        // last of the sequence (it finds the bottleneck), and nothing is asked after it.
        if let Some(next) = controller.poll(at(20_400), 1_800_000.0, 1_800_000.0, true) {
            controller.on_result(next.cluster, 1_800_000.0);
        }
        assert!((20_600..=40_000).step_by(100).all(|ms| {
            controller
                .poll(at(ms), 1_800_000.0, 1_800_000.0, true)
                .is_none()
        }));
    }

    /// RFC 8836 section 2 (1f): after a large drop of the target (a burst of competing
    /// traffic), the rate before it is probed for, from a second after the drop and once a
    /// second, and a result never asks for a further cluster above it.
    #[test]
    fn a_large_drop_is_followed_by_a_probe_at_the_rate_before_it() {
        let epoch = Instant::now();
        let mut controller = settled(epoch);
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        // At 2 Mbit/s, sending at the target, for a while.
        for ms in (1_000..2_000).step_by(100) {
            assert_eq!(
                None,
                controller.poll(at(ms), 2_000_000.0, 2_000_000.0, true)
            );
        }
        // Down to 900 kbit/s: a drop of more than a third.
        assert_eq!(None, controller.poll(at(2_000), 900_000.0, 900_000.0, true));
        assert_eq!(
            None,
            controller.poll(at(2_500), 900_000.0, 900_000.0, true),
            "the back-off is given a second first"
        );
        assert_eq!(Some(at(3_000)), controller.poll_timeout());
        let request = controller
            .poll(at(3_000), 900_000.0, 900_000.0, true)
            .expect("the rate before the drop");
        assert_eq!(0.85 * 2_000_000.0, request.bits_per_second);
        // The path carries it again: the estimator takes it, and nothing above it is asked.
        assert_eq!(
            Some(1_700_000.0),
            controller.on_result(request.cluster, 1_700_000.0)
        );
        assert_eq!(
            None,
            controller.poll(at(3_200), 1_700_000.0, 1_700_000.0, true)
        );
        assert_eq!(
            None,
            controller.poll(at(4_500), 1_700_000.0, 1_700_000.0, true)
        );
    }

    /// While the competing traffic is still there the probe shows less than the rate before
    /// the drop: it is asked again a second later, and not after the drop is five seconds old.
    #[test]
    fn probes_after_a_drop_stop_after_a_few_seconds() {
        let epoch = Instant::now();
        let mut controller = settled(epoch);
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        assert_eq!(
            None,
            controller.poll(at(1_000), 2_000_000.0, 2_000_000.0, true)
        );
        assert_eq!(None, controller.poll(at(1_100), 900_000.0, 900_000.0, true));
        let mut probes = 0;
        for ms in (1_200..9_000).step_by(100) {
            if let Some(request) = controller.poll(at(ms), 900_000.0, 900_000.0, true) {
                probes += 1;
                assert!(ms <= 1_100 + 5_000, "at {ms} ms");
                controller.on_result(request.cluster, 950_000.0);
            }
        }
        assert!((3..=5).contains(&probes), "{probes} probes");
    }

    /// `with_probe_after_drop(false)`: a drop is left to the delay-based controller's climb.
    #[test]
    fn without_the_option_a_drop_is_not_probed() {
        let epoch = Instant::now();
        let mut controller = settled(epoch).with_probe_after_drop(false);
        let at = |ms: u64| epoch + Duration::from_millis(ms);
        assert_eq!(
            None,
            controller.poll(at(1_000), 2_000_000.0, 2_000_000.0, true)
        );
        for ms in (1_100..8_000).step_by(100) {
            assert_eq!(None, controller.poll(at(ms), 900_000.0, 900_000.0, true));
        }
    }

    /// A deadline that came with nothing to send (here: an application-limited probe falls due
    /// while the sender has caught up with its target) is not asked for again: a driver that
    /// sleeps until `poll_timeout` would otherwise be woken at once, over and over.
    #[test]
    fn a_deadline_that_passed_with_nothing_due_is_not_asked_again() {
        let epoch = Instant::now();
        let mut controller = settled(epoch);
        let due = controller
            .poll_timeout()
            .expect("the next application-limited probe");
        assert_eq!(None, controller.poll(due, 1_000_000.0, 1_000_000.0, true));
        assert!(
            controller.poll_timeout().is_none_or(|next| next > due),
            "{:?}",
            controller.poll_timeout()
        );
        // Not flowing at all: nothing to wake for either.
        let later = due + Duration::from_secs(10);
        assert_eq!(None, controller.poll(later, 1_000_000.0, 0.0, false));
        assert!(controller.poll_timeout().is_none_or(|next| next > later));
    }
}
