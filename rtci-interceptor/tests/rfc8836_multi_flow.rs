//! RFC 8836 section 2, the requirements that need more than one flow: several senders share
//! one bottleneck, on a virtual clock, everything counted.
//!
//! The harness is deliberately small. One FIFO bottleneck with a capacity that may change over
//! time, a queue limit (tail drop) or a simple AQM, and a propagation delay each way. Flows:
//!
//! - **`Gcc`**: sends 1200-octet packets at its target, the receiver reports every packet
//!   every 100 ms (what transport-wide feedback carries), and the report reaches the sender
//!   one propagation delay later. The estimator is the production `Gcc`, driven through the
//!   `BandwidthEstimator` trait as the congestion control interceptor drives it, and probed
//!   by the production `ProbeController` as the default interceptor set does (bandwidth
//!   probing is on there): a cluster is extra packets at its rate, padding the receiver
//!   discards, so they count as sent and not as goodput.
//! - **TCP-like**: a long bulk transfer with a Reno window in packets (slow start, one packet
//!   per round trip after it, halved once per loss episode, losses noticed a round trip
//!   after the drop). Simple on purpose: what matters is that it fills the queue until it
//!   loses, which a delay-based flow does not.
//! - **Cross traffic**: constant-rate packets switched on and off on a schedule (short bursts,
//!   or DASH-like periodic downloads).
//!
//! Shares are goodput: the bits of a flow that arrived, over a window, as a fraction of the
//! capacity. Run with `--nocapture` to read the numbers.

use rtci_interceptor::{
    BandwidthEstimator, Gcc, PacketReport, ProbeController, ThresholdTimeBase, probe_estimate,
};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const PACKET_BYTES: usize = 1200;
const PACKET_BITS: f64 = (PACKET_BYTES * 8) as f64;
const STEP: Duration = Duration::from_millis(1);
const FEEDBACK_INTERVAL: Duration = Duration::from_millis(100);

/// A repeatable random source (for the AQM's drops).
struct Lcg(u64);

impl Lcg {
    fn unit(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[derive(Clone, Copy)]
enum Queue {
    /// Tail drop once this much is queued, in seconds at the current capacity.
    TailDrop(f64),
    /// Random early drop on the queueing delay: none below `min`, rising linearly to
    /// `max_probability` at `max`, and tail drop at `limit` (seconds).
    Red {
        min: f64,
        max: f64,
        max_probability: f64,
        limit: f64,
    },
}

/// One bottleneck link, FIFO, with a propagation delay each way.
struct Bottleneck {
    /// (from, bits per second), in order: the capacity from each instant on.
    capacity: Vec<(Duration, f64)>,
    queue: Queue,
    propagation: Duration,
    /// When the link has sent everything queued so far.
    free_at: Duration,
    random: Lcg,
    /// The queueing delay each packet met, with the instant it was offered.
    delays: Vec<(Duration, Duration)>,
    /// Extra delay after the queue, drawn for each packet up to this (a radio link's
    /// scheduling, say); packets keep their order.
    jitter: Duration,
    /// When the last packet arrived at the far end, for the order.
    last_arrival: Duration,
}

impl Bottleneck {
    fn new(capacity: f64, queue: Queue, propagation: Duration) -> Self {
        Self {
            capacity: vec![(Duration::ZERO, capacity)],
            queue,
            propagation,
            free_at: Duration::ZERO,
            random: Lcg(0x5eed),
            delays: Vec::new(),
            jitter: Duration::ZERO,
            last_arrival: Duration::ZERO,
        }
    }

    fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    fn with_capacity_from(mut self, from: Duration, capacity: f64) -> Self {
        self.capacity.push((from, capacity));
        self
    }

    fn capacity_at(&self, at: Duration) -> f64 {
        self.capacity
            .iter()
            .rev()
            .find(|(from, _)| *from <= at)
            .map_or(self.capacity[0].1, |(_, capacity)| *capacity)
    }

    /// A packet offered at `now`: when it arrives at the far end, or `None` if dropped.
    fn offer(&mut self, now: Duration, bits: f64) -> Option<Duration> {
        let capacity = self.capacity_at(now);
        let waiting = self.free_at.saturating_sub(now).as_secs_f64();
        let drop = match self.queue {
            Queue::TailDrop(limit) => waiting + bits / capacity > limit,
            Queue::Red {
                min,
                max,
                max_probability,
                limit,
            } => {
                waiting + bits / capacity > limit
                    || (waiting > min
                        && self.random.unit()
                            < max_probability * ((waiting - min) / (max - min)).min(1.0))
            }
        };
        if drop {
            return None;
        }
        self.delays
            .push((now, Duration::from_secs_f64(waiting.max(0.0))));
        self.free_at = self.free_at.max(now) + Duration::from_secs_f64(bits / capacity);
        let mut arrival = self.free_at + self.propagation;
        if !self.jitter.is_zero() {
            arrival += self.jitter.mul_f64(self.random.unit());
        }
        // In order: a packet held back by the jitter holds back the ones behind it.
        self.last_arrival = self.last_arrival.max(arrival);
        Some(self.last_arrival)
    }

    /// The mean and the 95th percentile of the queueing delay of packets offered in
    /// `from..until`.
    fn queueing_delay(&self, from: Duration, until: Duration) -> (Duration, Duration) {
        let mut delays: Vec<Duration> = self
            .delays
            .iter()
            .filter(|(at, _)| (from..until).contains(at))
            .map(|(_, delay)| *delay)
            .collect();
        if delays.is_empty() {
            return (Duration::ZERO, Duration::ZERO);
        }
        delays.sort();
        let mean = delays.iter().sum::<Duration>() / delays.len() as u32;
        (mean, delays[delays.len() * 95 / 100])
    }
}

/// Bits that arrived, by flow, in 100 ms bins.
#[derive(Default)]
struct Goodput {
    bins: Vec<f64>,
}

impl Goodput {
    fn add(&mut self, at: Duration, bits: f64) {
        let bin = (at.as_millis() / 100) as usize;
        if self.bins.len() <= bin {
            self.bins.resize(bin + 1, 0.0);
        }
        self.bins[bin] += bits;
    }

    /// Mean bits per second over `from..until`.
    fn rate(&self, from: Duration, until: Duration) -> f64 {
        let (a, b) = (
            (from.as_millis() / 100) as usize,
            (until.as_millis() / 100) as usize,
        );
        let bits: f64 = (a..b).filter_map(|bin| self.bins.get(bin)).sum();
        bits / (until - from).as_secs_f64()
    }
}

/// A packet a `Gcc` flow sent, until its report.
struct InFlight {
    sent: Duration,
    /// When it arrives, or when the receiver would notice it missing.
    due: Duration,
    arrived: bool,
}

struct GccFlow {
    gcc: Gcc,
    start: Duration,
    /// The application stops sending inside these windows (voice activity, mute).
    pauses: Vec<(Duration, Duration)>,
    next_send: Duration,
    sequence: u64,
    in_flight: BTreeMap<u64, InFlight>,
    next_feedback: Duration,
    /// Reports on their way back: (when they reach the sender, the reports).
    returning: Vec<(Duration, Vec<PacketReport>)>,
    goodput: Goodput,
    /// The target every 100 ms, from the start of the run.
    targets: Vec<f64>,
    probing: Option<ProbeController>,
    /// The cluster being sent: its number, its rate, packets still to send, and when the
    /// next one leaves.
    probe_sending: Option<(u32, f64, usize, Duration)>,
    /// Which cluster each probe packet in flight belongs to.
    probe_packets: BTreeMap<u64, u32>,
    /// The reports on each cluster so far, and how many packets it had.
    probe_reports: BTreeMap<u32, (usize, Vec<PacketReport>)>,
    /// Media packets sent in the last second, for the probe controller's sending rate.
    recently_sent: Vec<Duration>,
    /// Probe bits sent.
    probe_bits: f64,
}

impl GccFlow {
    fn new(initial: f64, start: Duration) -> Self {
        Self {
            gcc: Gcc::new(initial, 30_000.0, 20_000_000.0),
            start,
            pauses: Vec::new(),
            next_send: start,
            sequence: 0,
            in_flight: BTreeMap::new(),
            next_feedback: start + FEEDBACK_INTERVAL,
            returning: Vec::new(),
            goodput: Goodput::default(),
            targets: Vec::new(),
            probing: Some(ProbeController::new(initial, 20_000_000.0)),
            probe_sending: None,
            probe_packets: BTreeMap::new(),
            probe_reports: BTreeMap::new(),
            recently_sent: Vec::new(),
            probe_bits: 0.0,
        }
    }

    /// Without bandwidth probing (`DefaultInterceptorOptions::bandwidth_probing` false).
    fn without_probing(mut self) -> Self {
        self.probing = None;
        self
    }

    fn with_threshold_time_base(mut self, time_base: ThresholdTimeBase) -> Self {
        self.gcc = self.gcc.with_threshold_time_base(time_base);
        self
    }

    /// Puts one packet on the path at `at`; returns its sequence number.
    fn offer(&mut self, epoch: Instant, at: Duration, path: &mut Bottleneck) -> u64 {
        let sequence = self.sequence;
        self.sequence += 1;
        self.gcc.on_packet_sent(epoch + at, PACKET_BYTES);
        let (due, arrived) = match path.offer(at, PACKET_BITS) {
            Some(arrival) => (arrival, true),
            // A loss shows as a gap once later packets arrive: about when it would have.
            None => (at + path.propagation, false),
        };
        self.in_flight.insert(
            sequence,
            InFlight {
                sent: at,
                due,
                arrived,
            },
        );
        sequence
    }

    /// The probe controller's turn, as the congestion control interceptor takes it: a cluster
    /// when one is due, sent at its rate.
    fn probe(&mut self, epoch: Instant, now: Duration, path: &mut Bottleneck) {
        self.recently_sent
            .retain(|at| now.saturating_sub(*at) <= Duration::from_secs(1));
        let sending = self.recently_sent.len() as f64 * PACKET_BITS;
        let target = self.gcc.target_bitrate();
        let media_flowing = !self.recently_sent.is_empty();
        if self.probe_sending.is_none()
            && let Some(probing) = self.probing.as_mut()
            && let Some(request) = probing.poll(epoch + now, target, sending, media_flowing)
        {
            let packets = request.octets.div_ceil(PACKET_BYTES).max(5);
            self.probe_reports
                .insert(request.cluster, (packets, Vec::new()));
            self.probe_sending = Some((request.cluster, request.bits_per_second, packets, now));
        }
        while let Some((cluster, rate, left, at)) = self.probe_sending
            && at <= now
        {
            let sequence = self.offer(epoch, at, path);
            self.probe_bits += PACKET_BITS;
            self.probe_packets.insert(sequence, cluster);
            self.probe_sending = (left > 1).then(|| {
                (
                    cluster,
                    rate,
                    left - 1,
                    at + Duration::from_secs_f64(PACKET_BITS / rate),
                )
            });
        }
    }

    /// Gives the estimator the result of every cluster reported in full.
    fn probe_results(&mut self, epoch: Instant, now: Duration) {
        let complete: Vec<u32> = self
            .probe_reports
            .iter()
            .filter(|(_, (packets, reports))| reports.len() >= *packets)
            .map(|(cluster, _)| *cluster)
            .collect();
        for cluster in complete {
            let (_, reports) = self.probe_reports.remove(&cluster).expect("complete");
            if let Some(estimate) = probe_estimate(&reports)
                && let Some(probing) = self.probing.as_mut()
                && let Some(estimate) = probing.on_result(cluster, estimate)
            {
                self.gcc.on_probe_result(epoch + now, estimate);
            }
        }
    }

    fn paused(&self, at: Duration) -> bool {
        self.pauses
            .iter()
            .any(|(from, until)| (*from..*until).contains(&at))
    }

    fn step(&mut self, epoch: Instant, now: Duration, path: &mut Bottleneck) {
        if now.as_millis().is_multiple_of(100) {
            self.targets.push(if now >= self.start {
                self.gcc.target_bitrate()
            } else {
                0.0
            });
        }
        if now < self.start {
            return;
        }

        // The sender follows the target, unless the application has nothing to send.
        while self.next_send <= now {
            if self.paused(self.next_send) {
                self.next_send = now + STEP;
                break;
            }
            let at = self.next_send;
            self.offer(epoch, at, path);
            self.recently_sent.push(at);
            self.next_send += Duration::from_secs_f64(PACKET_BITS / self.gcc.target_bitrate());
        }
        self.probe(epoch, now, path);

        // The receiver reports what it has seen.
        if now >= self.next_feedback {
            self.next_feedback += FEEDBACK_INTERVAL;
            let seen: Vec<u64> = self
                .in_flight
                .iter()
                .filter(|(_, packet)| packet.due <= now)
                .map(|(sequence, _)| *sequence)
                .collect();
            let mut reports = Vec::with_capacity(seen.len());
            for sequence in seen {
                let packet = self.in_flight.remove(&sequence).expect("seen");
                let cluster = self.probe_packets.remove(&sequence);
                if packet.arrived && cluster.is_none() {
                    self.goodput.add(packet.due, PACKET_BITS);
                }
                let report = PacketReport {
                    ssrc: 1,
                    id: sequence,
                    rtp_sequence_number: sequence as u16,
                    is_twcc: true,
                    twcc_sequence_number: sequence as u16,
                    size: PACKET_BYTES,
                    arrived: packet.arrived,
                    departure: epoch + packet.sent,
                    arrival: packet.arrived.then_some(packet.due),
                    ecn: Ecn::default(),
                };
                if let Some(cluster) = cluster
                    && let Some((_, cluster_reports)) = self.probe_reports.get_mut(&cluster)
                {
                    cluster_reports.push(report.clone());
                }
                reports.push(report);
            }
            if !reports.is_empty() {
                self.returning.push((now + path.propagation, reports));
            }
        }

        // Reports that reached the sender.
        let mut index = 0;
        while index < self.returning.len() {
            if self.returning[index].0 <= now {
                let (_, reports) = self.returning.remove(index);
                self.gcc.on_reports(epoch + now, &reports);
                self.probe_results(epoch, now);
            } else {
                index += 1;
            }
        }
        if self
            .gcc
            .poll_timeout()
            .is_some_and(|deadline| deadline <= epoch + now)
        {
            self.gcc.handle_timeout(epoch + now);
        }
    }

    /// The target at `at`.
    fn target_at(&self, at: Duration) -> f64 {
        let index = (at.as_millis() / 100) as usize;
        self.targets.get(index).copied().unwrap_or(0.0)
    }
}

/// A long bulk transfer with a Reno-like window, in packets.
struct TcpFlow {
    start: Duration,
    window: f64,
    slow_start_threshold: f64,
    sequence: u64,
    /// Sent packets: when the sender hears about each (an acknowledgement or a loss),
    /// whether it was delivered, and when it was sent.
    outstanding: BTreeMap<u64, (Duration, bool, Duration)>,
    last_cut: Option<Duration>,
    /// The smoothed round-trip time, queueing included (RFC 6298).
    round_trip: Duration,
    goodput: Goodput,
}

impl TcpFlow {
    fn new(start: Duration, round_trip: Duration) -> Self {
        Self {
            start,
            window: 10.0,
            slow_start_threshold: f64::INFINITY,
            sequence: 0,
            outstanding: BTreeMap::new(),
            last_cut: None,
            round_trip,
            goodput: Goodput::default(),
        }
    }

    fn step(&mut self, now: Duration, path: &mut Bottleneck) {
        if now < self.start {
            return;
        }
        // What the sender hears by now.
        let heard: Vec<u64> = self
            .outstanding
            .iter()
            .filter(|(_, (at, _, _))| *at <= now)
            .map(|(sequence, _)| *sequence)
            .collect();
        for sequence in heard {
            let (heard_at, delivered, sent) = self.outstanding.remove(&sequence).expect("heard");
            if delivered {
                let sample = heard_at.saturating_sub(sent);
                self.round_trip = self.round_trip.mul_f64(0.875) + sample.mul_f64(0.125);
                if self.window < self.slow_start_threshold {
                    self.window += 1.0;
                } else {
                    self.window += 1.0 / self.window;
                }
            } else if self
                .last_cut
                .is_none_or(|cut| now.saturating_sub(cut) >= self.round_trip)
            {
                // One cut per loss episode: a round trip, queueing included.
                self.window = (self.window / 2.0).max(2.0);
                self.slow_start_threshold = self.window;
                self.last_cut = Some(now);
            }
        }
        while (self.outstanding.len() as f64) < self.window.floor() {
            let sequence = self.sequence;
            self.sequence += 1;
            let heard = match path.offer(now, PACKET_BITS) {
                Some(arrival) => {
                    self.goodput.add(arrival, PACKET_BITS);
                    (arrival + path.propagation, true, now)
                }
                // The duplicate acknowledgements of the packets behind it: about a round trip.
                None => (now + self.round_trip, false, now),
            };
            self.outstanding.insert(sequence, heard);
        }
    }
}

/// Constant-rate traffic, on inside the given windows.
struct CrossTraffic {
    rate: f64,
    on: Vec<(Duration, Duration)>,
    next: Duration,
    goodput: Goodput,
}

impl CrossTraffic {
    fn step(&mut self, now: Duration, path: &mut Bottleneck) {
        while self.next <= now {
            let at = self.next;
            self.next += Duration::from_secs_f64(PACKET_BITS / self.rate);
            if self
                .on
                .iter()
                .any(|(from, until)| (*from..*until).contains(&at))
                && let Some(arrival) = path.offer(at, PACKET_BITS)
            {
                self.goodput.add(arrival, PACKET_BITS);
            }
        }
    }
}

struct World {
    epoch: Instant,
    path: Bottleneck,
    gcc: Vec<GccFlow>,
    tcp: Vec<TcpFlow>,
    cross: Vec<CrossTraffic>,
}

impl World {
    fn new(path: Bottleneck) -> Self {
        Self {
            epoch: Instant::now(),
            path,
            gcc: Vec::new(),
            tcp: Vec::new(),
            cross: Vec::new(),
        }
    }

    fn run(&mut self, duration: Duration) {
        let mut now = Duration::ZERO;
        while now < duration {
            // A different order every step would be fairer still; alternating is enough to
            // keep one flow from always being first at the queue.
            let flip = now.as_millis() % 2 == 1;
            let count = self.gcc.len();
            for n in 0..count {
                let index = if flip { count - 1 - n } else { n };
                self.gcc[index].step(self.epoch, now, &mut self.path);
            }
            for tcp in &mut self.tcp {
                tcp.step(now, &mut self.path);
            }
            for cross in &mut self.cross {
                cross.step(now, &mut self.path);
            }
            now += STEP;
        }
    }
}

const PROPAGATION: Duration = Duration::from_millis(25);
const ROUND_TRIP: Duration = Duration::from_millis(50);

fn share(rate: f64, capacity: f64) -> f64 {
    rate / capacity
}

/// RFC 8836 section 2 (2): two flows of this algorithm with the same round trip, started
/// together, end up with similar shares of the bottleneck, and between them use it.
#[test]
fn two_gcc_flows_share_a_bottleneck() {
    const CAPACITY: f64 = 2_000_000.0;
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world
        .gcc
        .push(GccFlow::new(300_000.0, Duration::from_millis(50)));
    world.run(Duration::from_secs(90));

    let (from, until) = (Duration::from_secs(60), Duration::from_secs(90));
    let a = share(world.gcc[0].goodput.rate(from, until), CAPACITY);
    let b = share(world.gcc[1].goodput.rate(from, until), CAPACITY);
    let (mean_delay, p95_delay) = world.path.queueing_delay(from, until);
    println!(
        "two Gcc flows: shares {a:.2} / {b:.2}, together {:.2}; queueing delay mean {mean_delay:?}, p95 {p95_delay:?}",
        a + b
    );
    assert!(
        (0.25..=0.75).contains(&a) && (0.25..=0.75).contains(&b),
        "{a:.2} / {b:.2}"
    );
    assert!(a + b >= 0.6, "the two use the path: {:.2}", a + b);
}

/// The run of `a_flow_that_joins_late_gets_a_useful_share`: when the newcomer first had a fifth
/// of the path over a second (seconds after it joined), and the two shares over the last 20 s.
fn a_late_flow(flow: impl Fn(Duration) -> GccFlow) -> (Option<u64>, f64, f64) {
    const CAPACITY: f64 = 2_000_000.0;
    let join = Duration::from_secs(40);
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    world.gcc.push(flow(Duration::ZERO));
    world.gcc.push(flow(join));
    world.run(Duration::from_secs(100));

    let before = share(
        world.gcc[0]
            .goodput
            .rate(join - Duration::from_secs(10), join),
        CAPACITY,
    );
    // When the newcomer's goodput first reaches a fifth of the path, over one second.
    let reached = (0..60).find(|second| {
        let from = join + Duration::from_secs(*second);
        share(
            world.gcc[1]
                .goodput
                .rate(from, from + Duration::from_secs(1)),
            CAPACITY,
        ) >= 0.2
    });
    let targets: Vec<String> = (0..30)
        .map(|n| {
            let at = join + Duration::from_secs(2 * n);
            format!(
                "{:.0}/{:.0}",
                world.gcc[0].target_at(at) / 1000.0,
                world.gcc[1].target_at(at) / 1000.0
            )
        })
        .collect();
    println!("a late flow: targets in kbit/s every 2 s from the join: {targets:?}");
    let (from, until) = (Duration::from_secs(80), Duration::from_secs(100));
    let old = share(world.gcc[0].goodput.rate(from, until), CAPACITY);
    let new = share(world.gcc[1].goodput.rate(from, until), CAPACITY);
    let (mean_delay, p95_delay) = world.path.queueing_delay(from, until);
    println!(
        "a late flow: the first had {before:.2} alone; the newcomer reached 0.2 after {reached:?} s; later {old:.2} / {new:.2}; queueing delay mean {mean_delay:?}, p95 {p95_delay:?}"
    );
    assert!(
        before >= 0.6,
        "the first flow used the path alone: {before:.2}"
    );
    (reached, old, new)
}

/// RFC 8836 section 2 (2a), MUST: a flow that joins a bottleneck another flow already fills
/// reaches a useful share quickly: the existing flow makes room.
///
/// Measured before the queue-limit signal (`Gcc::with_loss_at_queue_limit_as_overuse`): the
/// newcomer fell to the 30 kbit/s floor while the established flow kept 98% of the path. The
/// draft's adaptive threshold (section 5.4) was not the cause: it is the draft's, bounded to
/// 6..600 ms, and falls back to 6 ms within seconds of a calm path. The tail-drop queue had
/// filled to its limit, where the delay gradient is zero and the loss-based controller holds
/// (2% to 10% loss): the established flow read normal and kept climbing, the newcomer lost
/// packets and could not grow. With the signal, and the newcomer's start-up probes, it has a
/// fair share within a second.
#[test]
fn a_flow_that_joins_late_gets_a_useful_share() {
    let (reached, _, new) = a_late_flow(|start| GccFlow::new(300_000.0, start));
    let reached = reached.expect("the newcomer reaches a fifth of the path");
    assert!(reached <= 5, "{reached} s");
    assert!(new >= 0.2, "{new:.2}");
}

/// The same without bandwidth probing (`DefaultInterceptorOptions::bandwidth_probing` off): the
/// newcomer climbs from its starting rate at the controller's own pace, and the queue-limit
/// signal is what makes the established flow yield.
#[test]
fn a_flow_that_joins_late_gets_a_share_without_probing_too() {
    let (reached, _, new) = a_late_flow(|start| GccFlow::new(300_000.0, start).without_probing());
    let reached = reached.expect("the newcomer reaches a fifth of the path");
    assert!(reached <= 45, "{reached} s");
    assert!(new >= 0.15, "{new:.2}");
}

/// RFC 8836 section 2 (3) is about how a flow meets TCP, so the TCP-like model has to behave
/// like TCP first: alone on the path it fills it, whatever the buffer.
#[test]
fn the_tcp_like_model_fills_a_path_alone() {
    const CAPACITY: f64 = 2_000_000.0;
    for queue in [0.2, 0.05] {
        let mut world = World::new(Bottleneck::new(
            CAPACITY,
            Queue::TailDrop(queue),
            PROPAGATION,
        ));
        world.tcp.push(TcpFlow::new(Duration::ZERO, ROUND_TRIP));
        world.run(Duration::from_secs(60));
        let tcp = share(
            world.tcp[0]
                .goodput
                .rate(Duration::from_secs(20), Duration::from_secs(60)),
            CAPACITY,
        );
        println!("TCP-like alone, queue {queue} s: {tcp:.2}");
        assert!(tcp >= 0.9, "queue {queue} s: {tcp:.2}");
    }
}

/// And beside a constant-rate flow (which does not react to anything) it takes what that flow
/// leaves: a loss-based flow is not starved by an unresponsive one that leaves room.
#[test]
fn the_tcp_like_model_takes_what_a_constant_rate_flow_leaves() {
    const CAPACITY: f64 = 2_000_000.0;
    for (constant, left) in [(0.5, 0.5), (0.75, 0.25)] {
        let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.2), PROPAGATION));
        world.tcp.push(TcpFlow::new(Duration::ZERO, ROUND_TRIP));
        world.cross.push(CrossTraffic {
            rate: constant * CAPACITY,
            on: vec![(Duration::ZERO, Duration::from_secs(60))],
            next: Duration::ZERO,
            goodput: Goodput::default(),
        });
        world.run(Duration::from_secs(60));
        let (from, until) = (Duration::from_secs(20), Duration::from_secs(60));
        let tcp = share(world.tcp[0].goodput.rate(from, until), CAPACITY);
        let cross = share(world.cross[0].goodput.rate(from, until), CAPACITY);
        println!("TCP-like beside {constant} constant: {tcp:.2} / {cross:.2}");
        assert!(tcp >= 0.8 * left, "{tcp:.2} of the {left} left");
        assert!(
            tcp + cross >= 0.9,
            "together they fill it: {:.2}",
            tcp + cross
        );
    }
}

/// `Gcc` from the start, a long TCP-like transfer from 20 s on: the shares of each over the
/// last minute of two, on a 200 ms and a 50 ms tail-drop buffer.
fn gcc_against_a_tcp_like_transfer(gcc: impl Fn() -> GccFlow, queue: f64) -> (f64, f64) {
    const CAPACITY: f64 = 2_000_000.0;
    let mut world = World::new(Bottleneck::new(
        CAPACITY,
        Queue::TailDrop(queue),
        PROPAGATION,
    ));
    world.gcc.push(gcc());
    world
        .tcp
        .push(TcpFlow::new(Duration::from_secs(20), ROUND_TRIP));
    world.run(Duration::from_secs(120));

    let (from, until) = (Duration::from_secs(60), Duration::from_secs(120));
    let gcc = share(world.gcc[0].goodput.rate(from, until), CAPACITY);
    let tcp = share(world.tcp[0].goodput.rate(from, until), CAPACITY);
    let (mean_delay, p95_delay) = world.path.queueing_delay(from, until);
    println!(
        "Gcc against TCP-like, queue {queue} s: shares {gcc:.2} / {tcp:.2}; queueing delay mean {mean_delay:?}, p95 {p95_delay:?}; Gcc target at the end {:.0}",
        world.gcc[0].target_at(until - Duration::from_millis(100))
    );
    (gcc, tcp)
}

/// RFC 8836 section 2 (3), second SHOULD: against a long loss-based (TCP-like) transfer that
/// fills the queue, the flow is not starved.
#[test]
fn gcc_is_not_starved_by_a_tcp_like_transfer() {
    for queue in [0.2, 0.05] {
        let (gcc, _) =
            gcc_against_a_tcp_like_transfer(|| GccFlow::new(300_000.0, Duration::ZERO), queue);
        assert!(
            gcc >= 0.05,
            "queue {queue} s: Gcc keeps a useful share: {gcc:.2}"
        );
    }
}

/// RFC 8836 section 2 (3), SHOULD NOT: the flow does not starve a competing TCP transfer.
///
/// Measured before the queue-limit signal (`Gcc::with_loss_at_queue_limit_as_overuse`): `Gcc`
/// 0.97, the transfer 0.03 (`the_draft_as_written_starves_a_tcp_like_transfer`). Once the queue
/// is full its delay no longer grows, the delay gradient is zero and `Gcc` keeps increasing,
/// while the drops stay under the 10% the loss-based controller of draft-ietf-rmcat-gcc-02
/// section 6 reacts to: the transfer halves on every loss episode and `Gcc` does not. With the
/// signal, a loss out of the full queue is over-use and `Gcc` backs off as the transfer does.
#[test]
fn gcc_does_not_starve_a_tcp_like_transfer() {
    for queue in [0.2, 0.05] {
        let (_, tcp) =
            gcc_against_a_tcp_like_transfer(|| GccFlow::new(300_000.0, Duration::ZERO), queue);
        assert!(
            tcp >= 0.2,
            "queue {queue} s: the transfer is not starved: {tcp:.2}"
        );
    }
}

/// The draft as written (`with_loss_at_queue_limit_as_overuse(false)`), on the 200 ms buffer:
/// `Gcc` holds the queue full and the transfer gets almost nothing.
#[test]
fn the_draft_as_written_starves_a_tcp_like_transfer() {
    let (gcc, tcp) = gcc_against_a_tcp_like_transfer(
        || {
            let mut flow = GccFlow::new(300_000.0, Duration::ZERO);
            flow.gcc = Gcc::new(300_000.0, 30_000.0, 20_000_000.0)
                .with_loss_at_queue_limit_as_overuse(false);
            flow
        },
        0.2,
    );
    assert!(gcc >= 0.8, "{gcc:.2}");
    assert!(tcp < 0.1, "{tcp:.2}");
}

/// RFC 8836 section 2 (1f): a short burst of competing traffic does not make the flow build
/// a queue of its own (none is left five seconds after it), and the flow regains its share
/// after the burst.
#[test]
fn gcc_regains_its_share_after_a_short_burst_of_cross_traffic() {
    const CAPACITY: f64 = 2_000_000.0;
    let burst = (Duration::from_secs(40), Duration::from_secs(42));
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world.cross.push(CrossTraffic {
        rate: 0.5 * CAPACITY,
        on: vec![burst],
        next: Duration::ZERO,
        goodput: Goodput::default(),
    });
    world.run(Duration::from_secs(80));

    let before = share(
        world.gcc[0]
            .goodput
            .rate(burst.0 - Duration::from_secs(10), burst.0),
        CAPACITY,
    );
    let regained = (0..30).find(|second| {
        let from = burst.1 + Duration::from_secs(*second);
        share(
            world.gcc[0]
                .goodput
                .rate(from, from + Duration::from_secs(1)),
            CAPACITY,
        ) >= 0.8 * before
    });
    let (_, p95_during) = world.path.queueing_delay(burst.0, burst.1);
    let (_, p95_after) = world.path.queueing_delay(
        burst.1 + Duration::from_secs(5),
        burst.1 + Duration::from_secs(25),
    );
    println!(
        "short burst: share before {before:.2}, regained 80% of it {regained:?} s after; p95 queueing delay during {p95_during:?}, after {p95_after:?}"
    );
    // Measured: 4 s (2 s before the Kalman filter's noise weight followed the group rate,
    // draft-ietf-rmcat-gcc-02 5.3). Without the probe after a large drop
    // (`ProbeController::with_probe_after_drop`) it was 23 s: the back-off is prompt, and the
    // climb back was the additive increase of draft-ietf-rmcat-gcc-02 section 5.5 near the
    // convergence band, about half a packet per response time, until the received rate left
    // the band.
    let regained = regained.expect("the share comes back");
    assert!(regained <= 5, "{regained} s");
    assert!(p95_after < Duration::from_millis(100), "{p95_after:?}");
}

/// RFC 8836 section 2 (1g): periodic bursts of competing traffic (a DASH-like client fetching
/// a segment every few seconds) do not make the flow add to the delay: between the bursts the
/// queue drains.
#[test]
fn periodic_bursts_of_cross_traffic_leave_no_standing_queue() {
    const CAPACITY: f64 = 2_000_000.0;
    let bursts: Vec<(Duration, Duration)> = (0..10)
        .map(|n| {
            let from = Duration::from_secs(30 + 6 * n);
            (from, from + Duration::from_millis(1500))
        })
        .collect();
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world.cross.push(CrossTraffic {
        rate: 0.8 * CAPACITY,
        on: bursts.clone(),
        next: Duration::ZERO,
        goodput: Goodput::default(),
    });
    world.run(Duration::from_secs(95));

    // The second half of each gap between bursts.
    let mut quiet = Vec::new();
    for window in bursts.windows(2) {
        let gap = window[1].0 - window[0].1;
        let (_, p95) = world
            .path
            .queueing_delay(window[0].1 + gap / 2, window[1].0);
        quiet.push(p95);
    }
    let share_overall = share(
        world.gcc[0]
            .goodput
            .rate(Duration::from_secs(30), Duration::from_secs(90)),
        CAPACITY,
    );
    println!(
        "periodic bursts: p95 queueing delay late in each gap {quiet:?}; Gcc share over the bursts {share_overall:.2}"
    );
    let worst = quiet.iter().max().copied().unwrap_or_default();
    assert!(worst < Duration::from_millis(100), "{worst:?}");
    assert!(share_overall >= 0.2, "{share_overall:.2}");
}

/// RFC 8836 section 2 (1c): the capacity halves and comes back; the estimate follows each
/// way.
#[test]
fn gcc_follows_the_capacity_down_and_up_again() {
    let down = Duration::from_secs(40);
    let up = Duration::from_secs(80);
    let mut world = World::new(
        Bottleneck::new(2_000_000.0, Queue::TailDrop(0.3), PROPAGATION)
            .with_capacity_from(down, 1_000_000.0)
            .with_capacity_from(up, 2_000_000.0),
    );
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world.run(Duration::from_secs(140));

    let flow = &world.gcc[0];
    let settled_down = (0..400).find(|tenth| {
        flow.target_at(down + Duration::from_millis(100 * tenth)) <= 1.1 * 1_000_000.0
    });
    let settled_up = (0..600)
        .find(|tenth| flow.target_at(up + Duration::from_millis(100 * tenth)) >= 0.8 * 2_000_000.0);
    let (_, p95_low) = world
        .path
        .queueing_delay(down + Duration::from_secs(10), up);
    println!(
        "capacity 2 -> 1 -> 2 Mbit/s: down within {:?} s, up within {:?} s; p95 queueing delay at 1 Mbit/s {p95_low:?}",
        settled_down.map(|t| t as f64 / 10.0),
        settled_up.map(|t| t as f64 / 10.0)
    );
    assert!(
        settled_down.expect("the estimate comes down") <= 50,
        "within 5 s"
    );
    assert!(
        settled_up.expect("the estimate climbs back") <= 400,
        "within 40 s"
    );
}

/// RFC 8836 section 2 (5): the stream halts (voice activity detection, a mute) and resumes:
/// the estimate neither collapses nor runs away across the pause.
#[test]
fn a_pause_in_the_media_leaves_the_estimate_stable() {
    const CAPACITY: f64 = 1_500_000.0;
    let pause = (Duration::from_secs(40), Duration::from_secs(48));
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    let mut flow = GccFlow::new(300_000.0, Duration::ZERO);
    flow.pauses.push(pause);
    world.gcc.push(flow);
    world.run(Duration::from_secs(80));

    let flow = &world.gcc[0];
    let before = flow.target_at(pause.0 - Duration::from_millis(100));
    let during: Vec<f64> = (0..80)
        .map(|tenth| flow.target_at(pause.0 + Duration::from_millis(100 * tenth)))
        .collect();
    let after = share(
        flow.goodput.rate(
            pause.1 + Duration::from_secs(5),
            pause.1 + Duration::from_secs(15),
        ),
        CAPACITY,
    );
    let low = during.iter().copied().fold(f64::INFINITY, f64::min);
    let high = during.iter().copied().fold(0.0, f64::max);
    println!(
        "pause: target before {before:.0}, during {low:.0}..{high:.0}, share 5-15 s after {after:.2}"
    );
    assert!(
        low >= 0.5 * before,
        "no collapse during the pause: {low:.0}"
    );
    assert!(
        high <= 1.2 * before,
        "no run-away during the pause: {high:.0}"
    );
    assert!(after >= 0.5, "{after:.2}");
}

/// RFC 8836 section 2 (11): behind an AQM (random early drop on the queueing delay) the flow
/// is stable and the delay stays low.
#[test]
fn gcc_is_stable_behind_an_aqm() {
    const CAPACITY: f64 = 2_000_000.0;
    let mut world = World::new(Bottleneck::new(
        CAPACITY,
        Queue::Red {
            min: 0.005,
            max: 0.05,
            max_probability: 0.1,
            limit: 0.3,
        },
        PROPAGATION,
    ));
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world.run(Duration::from_secs(80));

    let (from, until) = (Duration::from_secs(40), Duration::from_secs(80));
    let flow = &world.gcc[0];
    let shares: Vec<f64> = (40..80)
        .map(|second| {
            let from = Duration::from_secs(second);
            share(
                flow.goodput.rate(from, from + Duration::from_secs(1)),
                CAPACITY,
            )
        })
        .collect();
    let mean = shares.iter().sum::<f64>() / shares.len() as f64;
    let low = shares.iter().copied().fold(f64::INFINITY, f64::min);
    let (mean_delay, p95_delay) = world.path.queueing_delay(from, until);
    println!(
        "behind an AQM: share mean {mean:.2}, lowest second {low:.2}; queueing delay mean {mean_delay:?}, p95 {p95_delay:?}"
    );
    assert!(mean >= 0.5, "{mean:.2}");
    assert!(low >= 0.25, "{low:.2}");
    assert!(p95_delay < Duration::from_millis(100), "{p95_delay:?}");
}

/// draft-ietf-rmcat-gcc-02 section 5.4 adapts the threshold over t(i) - t(i-1), the arrival
/// times of the groups on the receiver's clock (`ThresholdTimeBase::Arrival`, the default);
/// `ThresholdTimeBase::Departure` (the default until 0.1.0, a setting since) over the gap
/// between the readings on the sender's clock, capped at 100 ms. Both forms on the scenarios
/// above hold the same bounds. The shares and delays each run prints are the comparison
/// recorded in the audit (GCC-5.4-4).
#[test]
fn the_draft_threshold_time_base_meets_the_same_bounds() {
    const CAPACITY: f64 = 2_000_000.0;
    for time_base in [ThresholdTimeBase::Departure, ThresholdTimeBase::Arrival] {
        let flow = |start| GccFlow::new(300_000.0, start).with_threshold_time_base(time_base);

        let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
        world.gcc.push(flow(Duration::ZERO));
        world.gcc.push(flow(Duration::from_millis(50)));
        world.run(Duration::from_secs(90));
        let (from, until) = (Duration::from_secs(60), Duration::from_secs(90));
        let a = share(world.gcc[0].goodput.rate(from, until), CAPACITY);
        let b = share(world.gcc[1].goodput.rate(from, until), CAPACITY);
        let (mean, p95) = world.path.queueing_delay(from, until);
        println!("{time_base:?}: two flows {a:.2} / {b:.2}, delay mean {mean:?} p95 {p95:?}");
        assert!((0.25..=0.75).contains(&a) && (0.25..=0.75).contains(&b));
        assert!(a + b >= 0.6);

        let (reached, _, new) = a_late_flow(flow);
        let reached = reached.unwrap_or(u64::MAX);
        println!("{time_base:?}: late flow a fifth after {reached} s, share {new:.2}");
        assert!(reached <= 5 && new >= 0.2);

        for queue in [0.2, 0.05] {
            let (gcc, tcp) = gcc_against_a_tcp_like_transfer(|| flow(Duration::ZERO), queue);
            println!("{time_base:?}: against TCP-like, queue {queue} s: {gcc:.2} / {tcp:.2}");
            assert!(gcc >= 0.05 && tcp >= 0.2);
        }
    }
}

/// RFC 8836 section 2 (1a): the delay the algorithm tracks includes the short-term maxima of
/// the path's jitter, so jitter is not taken for congestion. Behind 2 Mbit/s whose packets meet
/// up to 30 ms of jitter after the queue (the order kept), one flow alone keeps most of the
/// path, and its own queue stays short: the adaptive threshold (draft-ietf-rmcat-gcc-02 5.4)
/// rises to the jitter's spread instead of reading over-use in it.
#[test]
fn jitter_on_the_path_is_not_taken_for_congestion() {
    const CAPACITY: f64 = 2_000_000.0;
    let mut world = World::new(
        Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION)
            .with_jitter(Duration::from_millis(30)),
    );
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world.run(Duration::from_secs(80));

    let (from, until) = (Duration::from_secs(40), Duration::from_secs(80));
    let flow = &world.gcc[0];
    let shares: Vec<f64> = (40..80)
        .map(|second| {
            let from = Duration::from_secs(second);
            share(
                flow.goodput.rate(from, from + Duration::from_secs(1)),
                CAPACITY,
            )
        })
        .collect();
    let mean = shares.iter().sum::<f64>() / shares.len() as f64;
    let low = shares.iter().copied().fold(f64::INFINITY, f64::min);
    let (mean_delay, p95_delay) = world.path.queueing_delay(from, until);
    println!(
        "30 ms of jitter: share mean {mean:.2}, lowest second {low:.2}; queueing delay mean {mean_delay:?}, p95 {p95_delay:?}"
    );
    assert!(mean >= 0.6, "{mean:.2}");
    assert!(low >= 0.3, "{low:.2}");
    assert!(p95_delay < Duration::from_millis(100), "{p95_delay:?}");
}

/// RFC 8836 section 2 (1b): low delay and little self-induced latency with competing flows.
/// Two flows of this algorithm on one bottleneck, and one beside constant cross traffic that
/// takes half the path: the queue they keep stays short against the 300 ms the tail-drop
/// buffer would allow, and the path is used (the figures measured are in the audit row,
/// `docs/conformance/audit/rfc8836.md` RFC8836-2-1b).
#[test]
fn competing_flows_keep_the_queue_short() {
    const CAPACITY: f64 = 2_000_000.0;
    let (from, until) = (Duration::from_secs(60), Duration::from_secs(90));

    let mut two = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    two.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    two.gcc
        .push(GccFlow::new(300_000.0, Duration::from_millis(50)));
    two.run(until);
    let used = share(
        two.gcc[0].goodput.rate(from, until) + two.gcc[1].goodput.rate(from, until),
        CAPACITY,
    );
    let (two_mean, two_p95) = two.path.queueing_delay(from, until);

    let mut beside = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.3), PROPAGATION));
    beside.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    beside.cross.push(CrossTraffic {
        rate: 0.5 * CAPACITY,
        on: vec![(Duration::ZERO, until)],
        next: Duration::ZERO,
        goodput: Goodput::default(),
    });
    beside.run(until);
    let gcc = share(beside.gcc[0].goodput.rate(from, until), CAPACITY);
    let (beside_mean, beside_p95) = beside.path.queueing_delay(from, until);
    println!(
        "two Gcc flows: path used {used:.2}, queueing delay mean {two_mean:?} p95 {two_p95:?}; beside half the path of cross traffic: Gcc {gcc:.2}, queueing delay mean {beside_mean:?} p95 {beside_p95:?}"
    );
    assert!(used >= 0.6, "{used:.2}");
    assert!(two_mean < Duration::from_millis(30), "{two_mean:?}");
    assert!(two_p95 < Duration::from_millis(150), "{two_p95:?}");
    assert!(gcc >= 0.25, "{gcc:.2}");
    assert!(beside_mean < Duration::from_millis(30), "{beside_mean:?}");
    assert!(beside_p95 < Duration::from_millis(60), "{beside_p95:?}");
}

/// RFC 8836 section 2 (3a): where a useful share and the lowest delay conflict, the share
/// comes first. A TCP-like transfer holds the 200 ms tail-drop buffer full, so no flow can
/// have low delay there; this algorithm does not back off to its floor chasing it, and keeps
/// a useful share of the path (a fifth or more) while the queue is long.
#[test]
fn a_useful_share_is_kept_where_low_delay_is_out_of_reach() {
    const CAPACITY: f64 = 2_000_000.0;
    let mut world = World::new(Bottleneck::new(CAPACITY, Queue::TailDrop(0.2), PROPAGATION));
    world.gcc.push(GccFlow::new(300_000.0, Duration::ZERO));
    world
        .tcp
        .push(TcpFlow::new(Duration::from_secs(20), ROUND_TRIP));
    world.run(Duration::from_secs(120));

    let (from, until) = (Duration::from_secs(60), Duration::from_secs(120));
    let gcc = share(world.gcc[0].goodput.rate(from, until), CAPACITY);
    let (mean_delay, _) = world.path.queueing_delay(from, until);
    println!("beside a TCP-like transfer: Gcc {gcc:.2}, queueing delay mean {mean_delay:?}");
    assert!(
        mean_delay >= Duration::from_millis(50),
        "the conflict is there: {mean_delay:?}"
    );
    assert!(gcc >= 0.15, "{gcc:.2}");
}
