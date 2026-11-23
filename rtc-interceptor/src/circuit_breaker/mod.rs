//! The RTP circuit breaker (RFC 8083).
//!
//! A congestion controller keeps a flow at the rate the path carries. A circuit breaker is what
//! stops the flow when that has failed: the receiver has gone, the path delivers nothing, or the
//! flow has been taking ten times what a TCP connection would get for long enough that it is no
//! longer a transient. RFC 8834 section 7.1 requires both.
//!
//! It works from the plain RTCP every RTP endpoint sends: the report blocks of SR and RR packets.
//! Nothing here depends on a congestion-control feedback format being negotiated.
//!
//! | Breaker | Trips when (RFC 8083) |
//! |---|---|
//! | RTCP timeout (4.1) | media is sent and no RTCP reports on it for three reporting intervals |
//! | Media timeout (4.2) | `MEDIA_TIMEOUT` consecutive reports show the extended highest sequence number not moving |
//! | Congestion (4.3) | the sending rate is more than ten times the TCP throughput for the reported loss and round trip time, averaged over `CB_INTERVAL` reports |
//! | Media usability (4.4) | reported loss or delay stayed past the application's bound for the application's period |
//!
//! A tripped flow ceases transmission (4.5): its RTP is dropped here, above the TWCC sender and the
//! send history, so a packet that does not leave is neither numbered nor counted. It is not
//! restarted automatically; the application restarts it through [`CircuitBreakerHandle`], and not
//! before the interval that tripped it has passed again.

use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::twcc::flow_ssrcs;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The fixed minimum RTCP interval the RTCP timeout is computed with (Tmin, RFC 8083
/// section 4.1).
pub const DEFAULT_RTCP_INTERVAL: Duration = Duration::from_secs(5);

/// The non-reporting threshold k: the RECOMMENDED value (RFC 8083 section 4.2).
pub const DEFAULT_NON_REPORTING_THRESHOLD: u32 = 5;

/// How many reporting intervals without RTCP trip the RTCP timeout breaker.
const RTCP_TIMEOUT_INTERVALS: u32 = 3;

/// How far back frame intervals are looked at for Tf ("the largest inter-frame interval used in
/// the last 10 seconds", RFC 8083 section 3).
const FRAME_INTERVAL_WINDOW: Duration = Duration::from_secs(10);

/// How many sender reports are remembered to turn a report block's LSR into a send instant.
const REMEMBERED_SENDER_REPORTS: usize = 16;

/// Which breaker stopped a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CircuitBreakerReason {
    /// No RTCP reported on the media being sent for three reporting intervals (section 4.1).
    RtcpTimeout,
    /// The receiver's reports showed the media not arriving (section 4.2).
    MediaTimeout,
    /// The flow sent more than ten times what TCP would have achieved (section 4.3).
    Congestion,
    /// Loss or delay stayed past the application's usability bound (section 4.4).
    MediaUnusable,
}

/// What the circuit breaker is doing with one flow.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum CircuitBreakerState {
    /// Sending normally.
    Running,
    /// The congestion breaker tripped once and the flow was given the chance to send at a tenth
    /// of its rate (section 4.3). If the breaker trips again after the next `CB_INTERVAL`
    /// reports, the flow ceases.
    Reduced {
        /// The rate the flow has to stay under, in bits per second.
        limit_bits_per_second: f64,
    },
    /// Transmission has ceased (section 4.5): the flow's RTP is dropped.
    Ceased {
        /// The breaker that tripped.
        reason: CircuitBreakerReason,
        /// When it tripped.
        at: Instant,
        /// The earliest instant a restart is accepted.
        restart_after: Instant,
    },
}

/// The application's bound on what is still usable media (section 4.4). The RFC leaves the
/// bound to the application on purpose.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MediaUsability {
    /// Reported loss fraction (0.0 to 1.0) above which the media is unusable.
    pub max_loss: f64,
    /// Round trip time above which the media is unusable.
    pub max_round_trip_time: Duration,
    /// How long it has to stay unusable before transmission ceases.
    pub period: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Config {
    rtcp_interval: Duration,
    t_rr_interval: Option<Duration>,
    non_reporting_threshold: u32,
    frame_group_size: u32,
    full_tcp_equation: bool,
    reduce_before_ceasing: bool,
    group: bool,
    usability: Option<MediaUsability>,
}

/// Builder for [`CircuitBreakerInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{CircuitBreakerBuilder, Registry, Slot};
///
/// let (breaker, handle) = CircuitBreakerBuilder::new().build();
/// let chain = Registry::new().with(Slot::CircuitBreaker, breaker).build();
/// assert!(handle.ceased().is_empty());
/// # let _ = chain;
/// ```
pub struct CircuitBreakerBuilder {
    config: Config,
}

impl Default for CircuitBreakerBuilder {
    fn default() -> Self {
        Self {
            config: Config {
                rtcp_interval: DEFAULT_RTCP_INTERVAL,
                t_rr_interval: None,
                non_reporting_threshold: DEFAULT_NON_REPORTING_THRESHOLD,
                frame_group_size: 1,
                full_tcp_equation: false,
                reduce_before_ceasing: false,
                group: false,
                usability: None,
            },
        }
    }
}

impl CircuitBreakerBuilder {
    /// A builder with the RFC's recommended values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Td, this endpoint's deterministic RTCP reporting interval, computed with Tmin = 5 s
    /// (section 4.1). The RTCP timeout breaker trips after three of them. Values above 5 s are
    /// held to 5 s: the RFC says not to configure a longer one.
    pub fn with_rtcp_interval(mut self, interval: Duration) -> Self {
        self.config.rtcp_interval = interval.min(DEFAULT_RTCP_INTERVAL);
        self
    }

    /// The AVPF `T_rr_interval` in use, which replaces Tdr in `CB_INTERVAL` when it is larger
    /// (section 4.3). Held to 4 s (sections 4.1 and 4.3).
    pub fn with_t_rr_interval(mut self, interval: Duration) -> Self {
        self.config.t_rr_interval = Some(interval.min(Duration::from_secs(4)));
        self
    }

    /// k, the number of reports without progress that gives assurance the forward path failed
    /// (section 4.2). 5 is recommended.
    pub fn with_non_reporting_threshold(mut self, k: u32) -> Self {
        self.config.non_reporting_threshold = k.max(1);
        self
    }

    /// G, the number of frames the codec needs before it can change rate (section 3). 1 for a
    /// codec that can adapt on every frame.
    pub fn with_frame_group_size(mut self, frames: u32) -> Self {
        self.config.frame_group_size = frames.max(1);
        self
    }

    /// Use the full TCP throughput equation instead of the simplified one (section 4.3: MAY; it
    /// is more sensitive to loss and trips earlier).
    pub fn with_full_tcp_equation(mut self, full: bool) -> Self {
        self.config.full_tcp_equation = full;
        self
    }

    /// When the congestion breaker trips, first ask for a tenth of the rate
    /// ([`CircuitBreakerState::Reduced`]) instead of ceasing at once (section 4.3: MAY). If it
    /// trips again after the next `CB_INTERVAL` reports the flow ceases.
    pub fn with_rate_reduction(mut self, reduce: bool) -> Self {
        self.config.reduce_before_ceasing = reduce;
        self
    }

    /// Treat every flow of the connection as one group: a breaker tripping for one flow applies
    /// to all (section 8: MAY). By default each SSRC is judged on its own.
    pub fn with_grouped_flows(mut self, group: bool) -> Self {
        self.config.group = group;
        self
    }

    /// The bound past which the media is unusable (section 4.4). Without one the media
    /// usability breaker does not run: the RFC defines no bound.
    pub fn with_media_usability(mut self, usability: MediaUsability) -> Self {
        self.config.usability = Some(usability);
        self
    }

    /// Build the interceptor and the handle the application watches it through.
    pub fn build(self) -> (CircuitBreakerInterceptor, CircuitBreakerHandle) {
        let handle = CircuitBreakerHandle::new();
        (self.build_with_handle(&handle), handle)
    }

    /// Build the interceptor `handle` watches (made beforehand, for example to give it to the
    /// congestion controller of the same transport). One interceptor per handle.
    pub fn build_with_handle(self, handle: &CircuitBreakerHandle) -> CircuitBreakerInterceptor {
        CircuitBreakerInterceptor {
            config: self.config,
            flows: HashMap::new(),
            awaiting_rtcp_since: None,
            shared: handle.shared.clone(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

#[derive(Default)]
struct Shared {
    states: HashMap<u32, CircuitBreakerState>,
    restarts: Vec<u32>,
    dropped: u64,
    /// A round trip time measured elsewhere in the chain.
    round_trip_time: Option<Duration>,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The application's view of the circuit breaker, and the only way a ceased flow restarts.
#[derive(Clone)]
pub struct CircuitBreakerHandle {
    shared: Arc<Mutex<Shared>>,
}

impl Default for CircuitBreakerHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerHandle {
    /// A handle with no interceptor yet: [`CircuitBreakerBuilder::build_with_handle`] builds
    /// the one it watches.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
        }
    }

    /// What the breaker is doing with the flow sent on `ssrc`, if it is bound.
    pub fn state(&self, ssrc: u32) -> Option<CircuitBreakerState> {
        lock(&self.shared).states.get(&ssrc).copied()
    }

    /// The flows that have ceased transmission, with the breaker that stopped each.
    pub fn ceased(&self) -> Vec<(u32, CircuitBreakerReason)> {
        let mut ceased: Vec<_> = lock(&self.shared)
            .states
            .iter()
            .filter_map(|(ssrc, state)| match state {
                CircuitBreakerState::Ceased { reason, .. } => Some((*ssrc, *reason)),
                _ => None,
            })
            .collect();
        ceased.sort_unstable_by_key(|(ssrc, _)| *ssrc);
        ceased
    }

    /// The lowest rate any flow has been asked to stay under after the congestion breaker
    /// tripped, in bits per second. A congestion controller takes it as an upper bound.
    pub fn rate_limit(&self) -> Option<f64> {
        lock(&self.shared)
            .states
            .values()
            .filter_map(|state| match state {
                CircuitBreakerState::Reduced {
                    limit_bits_per_second,
                } => Some(*limit_bits_per_second),
                _ => None,
            })
            .reduce(f64::min)
    }

    /// A round trip time measured from congestion-control feedback, for the breaker to use
    /// when it cannot measure one itself.
    ///
    /// Tr is the RFC 3550 round trip time: a report block's LSR and DLSR against the instant
    /// the named sender report left. The breaker only knows that instant for sender reports
    /// that pass it on the way out; when the RTCP session sits wire-ward of it (as the standard
    /// set places it) none does, and without Tr the congestion breaker could never compare the
    /// flow with TCP. The congestion controller's feedback gives the same quantity many times
    /// a second.
    pub fn report_round_trip_time(&self, round_trip_time: Duration) {
        lock(&self.shared).round_trip_time = Some(round_trip_time);
    }

    /// How many RTP packets of ceased flows were dropped.
    pub fn dropped(&self) -> u64 {
        lock(&self.shared).dropped
    }

    /// Restart a ceased flow. Returns whether it restarted.
    ///
    /// A flow is not restarted automatically (section 4.5): this is the application saying the
    /// congestion can be expected to have gone. It is refused until the interval that tripped
    /// the breaker has passed again, so the reaction to a tripped breaker lasts at least that
    /// long however often a restart is attempted.
    pub fn restart(&self, ssrc: u32, now: Instant) -> bool {
        let mut shared = lock(&self.shared);
        match shared.states.get(&ssrc) {
            Some(CircuitBreakerState::Ceased { restart_after, .. }) if now >= *restart_after => {
                shared.states.insert(ssrc, CircuitBreakerState::Running);
                shared.restarts.push(ssrc);
                true
            }
            _ => false,
        }
    }
}

/// One reporting interval as the congestion breaker records it.
#[derive(Debug, Clone, Copy)]
struct LossSample {
    fraction_lost: f64,
    duration: Duration,
    bytes_sent: u64,
    /// What the report's cumulative number lost and extended highest sequence number moved
    /// by since the previous report (RFC 3550 6.4.1): the interval's net loss, in which a
    /// packet that was only reordered counts in neither interval.
    net_lost: i64,
    net_expected: i64,
}

/// One frame's worth of packets, for the average packet size.
#[derive(Debug, Clone, Copy, Default)]
struct FrameSize {
    bytes: u64,
    packets: u64,
}

struct Flow {
    state: CircuitBreakerState,
    /// Packets and bytes sent since the last report block for this flow.
    packets_since_report: u64,
    bytes_since_report: u64,
    /// The RTP timestamp of the frame being sent and when its first packet left.
    current_frame: Option<(u32, Instant)>,
    /// Inter-frame intervals of the last ten seconds, with the instant each ended.
    frame_intervals: VecDeque<(Instant, Duration)>,
    /// Sizes of the last `4 * G` frames, newest last.
    frames: VecDeque<FrameSize>,
    /// When the last report block for this flow arrived.
    last_report_at: Option<Instant>,
    /// Smoothed interval between the receiver's reports: the estimate of Tdr.
    receiver_interval: Option<Duration>,
    /// The extended highest sequence number the receiver last reported.
    highest_sequence: Option<u32>,
    /// The previous report's cumulative number lost and extended highest sequence number,
    /// as reported (for the net loss of the next interval).
    previous_report: Option<(i32, u32)>,
    /// Consecutive reports that showed no progress while media was being sent.
    stalled_reports: u32,
    media_timeout: u32,
    losses: VecDeque<LossSample>,
    reports_received: u64,
    /// Report blocks since the rate was reduced.
    reports_since_reduction: u64,
    /// Smoothed round trip time, Tr.
    round_trip_time: Option<Duration>,
    /// Sender reports sent for this flow: the middle 32 bits of the NTP timestamp, and when.
    sender_reports: VecDeque<(u32, Instant)>,
    unusable_since: Option<Instant>,
}

impl Flow {
    fn new() -> Self {
        Self {
            state: CircuitBreakerState::Running,
            packets_since_report: 0,
            bytes_since_report: 0,
            current_frame: None,
            frame_intervals: VecDeque::new(),
            frames: VecDeque::new(),
            last_report_at: None,
            receiver_interval: None,
            highest_sequence: None,
            previous_report: None,
            stalled_reports: 0,
            media_timeout: 0,
            losses: VecDeque::new(),
            reports_received: 0,
            reports_since_reduction: 0,
            round_trip_time: None,
            sender_reports: VecDeque::new(),
            unusable_since: None,
        }
    }

    fn is_ceased(&self) -> bool {
        matches!(self.state, CircuitBreakerState::Ceased { .. })
    }

    /// Tf: the largest inter-frame interval of the last ten seconds.
    fn frame_interval(&self) -> Duration {
        self.frame_intervals
            .iter()
            .map(|(_, interval)| *interval)
            .max()
            .unwrap_or_default()
    }

    /// s: the average size of the packets of the last `4 * G` frames, in bytes.
    fn packet_size(&self) -> Option<f64> {
        let (bytes, packets) = self
            .frames
            .iter()
            .fold((0u64, 0u64), |(bytes, packets), frame| {
                (bytes + frame.bytes, packets + frame.packets)
            });
        (packets > 0).then(|| bytes as f64 / packets as f64)
    }

    fn on_departure(&mut self, now: Instant, timestamp: u32, size: usize, frames_kept: usize) {
        self.packets_since_report += 1;
        self.bytes_since_report += size as u64;

        match self.current_frame {
            Some((current, _)) if current == timestamp => {}
            previous => {
                if let Some((_, started)) = previous {
                    self.frame_intervals
                        .push_back((now, now.saturating_duration_since(started)));
                }
                self.current_frame = Some((timestamp, now));
                self.frames.push_back(FrameSize::default());
                while self.frames.len() > frames_kept {
                    self.frames.pop_front();
                }
            }
        }
        while let Some((at, _)) = self.frame_intervals.front() {
            if now.saturating_duration_since(*at) <= FRAME_INTERVAL_WINDOW {
                break;
            }
            self.frame_intervals.pop_front();
        }
        if let Some(frame) = self.frames.back_mut() {
            frame.bytes += size as u64;
            frame.packets += 1;
        }
    }
}

/// The RTP circuit breaker of RFC 8083: stops a flow whose receiver has gone, whose media is
/// not arriving, or that is persistently taking far more than its share.
///
/// # Where this belongs in the chain
///
/// [`Slot::CircuitBreaker`](crate::Slot::CircuitBreaker): below the pacer, so it sees every RTP
/// packet when it is released, generated ones included; above the TWCC sender and the send
/// history, so a packet it drops is never numbered or recorded as sent.
pub struct CircuitBreakerInterceptor {
    config: Config,
    flows: HashMap<u32, Flow>,
    /// When media was first sent since RTCP last reported on it: what the RTCP timeout runs
    /// from. `None` while nothing sent is waiting to be reported on.
    awaiting_rtcp_since: Option<Instant>,
    shared: Arc<Mutex<Shared>>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

/// MEDIA_TIMEOUT = ceil(k * max(Tf, Tr, Tdr) / Tdr) (RFC 8083 section 4.2).
fn media_timeout(k: u32, tf: Duration, tr: Duration, tdr: Duration) -> u32 {
    let tdr = tdr.as_secs_f64().max(1e-3);
    let longest = tf.as_secs_f64().max(tr.as_secs_f64()).max(tdr);
    // The small allowance keeps a ratio that is a whole number in exact arithmetic from
    // being rounded up by its floating-point error.
    (f64::from(k) * longest / tdr - 1e-9).ceil().max(1.0) as u32
}

/// CB_INTERVAL = ceil(3 * min(max(10*G*Tf, 10*Tr, 3*Tdr), max(15, 3*Td)) / (3*Tdr))
/// (RFC 8083 section 4.3).
fn cb_interval(g: u32, tf: Duration, tr: Duration, tdr: Duration, td: Duration) -> u32 {
    let tdr = tdr.as_secs_f64().max(1e-3);
    let reaction = (10.0 * f64::from(g) * tf.as_secs_f64())
        .max(10.0 * tr.as_secs_f64())
        .max(3.0 * tdr);
    let cap = 15f64.max(3.0 * td.as_secs_f64());
    ((3.0 * reaction.min(cap)) / (3.0 * tdr) - 1e-9)
        .ceil()
        .max(1.0) as u32
}

/// The share of the packets expected over `samples` that the cumulative count says were lost
/// (RFC 3550 6.4.1: expected less received, late packets counted as received), `None` when
/// the window expected none.
///
/// The fraction lost of each report cannot be negative (RFC 3550 A.3), so a packet that is
/// only reordered across a report's boundary counts as lost in the interval that should have
/// had it and is not given back in the next: on a path that reorders, the average of the
/// fractions shows loss that never happened. RFC 8083 section 4.3 approximates the loss event
/// rate by that average, a figure meant to err on the side of more loss; it cannot be more
/// than the share actually lost, so the breaker takes the smaller of the two.
///
/// The newest report's own count is taken only where it gives packets back: a packet missing
/// at that report may still be on its way (overtaken a moment before the report went), and
/// the next report says whether it was lost. A packet really lost counts from then on, one
/// reporting interval later.
fn net_loss(samples: &VecDeque<LossSample>) -> Option<f64> {
    let newest = samples.len().saturating_sub(1);
    let (lost, expected) =
        samples
            .iter()
            .enumerate()
            .fold((0i64, 0i64), |(lost, expected), (index, sample)| {
                let net_lost = if index == newest {
                    sample.net_lost.min(0)
                } else {
                    sample.net_lost
                };
                (lost + net_lost, expected + sample.net_expected)
            });
    (expected > 0).then(|| lost.max(0) as f64 / expected as f64)
}

/// The throughput, in bytes per second, a TCP connection would achieve with packets of `s`
/// bytes, round trip time `tr` and loss event rate `p` (RFC 8083 section 4.3), with b = 1 and
/// t_RTO = 4 * Tr.
fn tcp_throughput(s: f64, tr: Duration, p: f64, full: bool) -> f64 {
    let tr = tr.as_secs_f64().max(1e-6);
    let b = 1.0;
    let simplified = tr * (2.0 * b * p / 3.0).sqrt();
    let denominator = if full {
        let t_rto = 4.0 * tr;
        simplified + t_rto * (3.0 * (3.0 * b * p / 8.0).sqrt() * p * (1.0 + 32.0 * p * p))
    } else {
        simplified
    };
    s / denominator
}

impl CircuitBreakerInterceptor {
    fn publish(&self, ssrc: u32) {
        if let Some(flow) = self.flows.get(&ssrc) {
            lock(&self.shared).states.insert(ssrc, flow.state);
        }
    }

    /// Apply the restarts the application asked for through the handle.
    fn apply_restarts(&mut self) {
        let restarts = std::mem::take(&mut lock(&self.shared).restarts);
        for ssrc in restarts {
            if self.flows.contains_key(&ssrc) {
                // A restarted flow starts from nothing: what was measured before describes
                // the path that tripped the breaker.
                self.flows.insert(ssrc, Flow::new());
            }
        }
    }

    /// Cease transmission of `ssrc`, or of every flow when flows are grouped.
    fn cease(&mut self, ssrc: u32, reason: CircuitBreakerReason, now: Instant, hold: Duration) {
        let ssrcs: Vec<u32> = if self.config.group {
            self.flows.keys().copied().collect()
        } else {
            vec![ssrc]
        };
        for ssrc in ssrcs {
            if let Some(flow) = self.flows.get_mut(&ssrc)
                && !flow.is_ceased()
            {
                flow.state = CircuitBreakerState::Ceased {
                    reason,
                    at: now,
                    restart_after: now + hold,
                };
                // Stopping a stream cancels its media timeout breaker (section 4.2).
                flow.stalled_reports = 0;
                log::warn!("RTP circuit breaker: SSRC {ssrc:#x} ceased transmission ({reason:?})");
                self.publish(ssrc);
            }
        }
    }

    fn rtcp_timeout(&self) -> Duration {
        self.config.rtcp_interval * RTCP_TIMEOUT_INTERVALS
    }

    /// One report block about a flow this endpoint sends.
    fn on_report_block(&mut self, now: Instant, report: &rtcp::reception_report::ReceptionReport) {
        let config = self.config;
        let Some(flow) = self.flows.get_mut(&report.ssrc) else {
            return;
        };
        if flow.is_ceased() {
            return;
        }

        // Tr: RFC 3550 section 6.4.1, smoothed as RFC 8083 section 3 says.
        if report.last_sender_report != 0
            && let Some((_, sent)) = flow
                .sender_reports
                .iter()
                .rev()
                .find(|(lsr, _)| *lsr == report.last_sender_report)
        {
            let delay = Duration::from_secs_f64(f64::from(report.delay) / 65_536.0);
            let sample = now.saturating_duration_since(*sent).saturating_sub(delay);
            flow.round_trip_time = Some(match flow.round_trip_time {
                Some(previous) => previous.mul_f64(0.8) + sample.mul_f64(0.2),
                None => sample,
            });
        }

        // No sender report of this flow was seen leaving (the report generator is wire-ward of
        // here): Tr is the round trip time the congestion controller measured.
        if flow.sender_reports.is_empty()
            && let Some(reported) = lock(&self.shared).round_trip_time
        {
            flow.round_trip_time = Some(match flow.round_trip_time {
                Some(previous) => previous.mul_f64(0.8) + reported.mul_f64(0.2),
                None => reported,
            });
        }

        // Tdr, from how often this receiver actually reports.
        let since_last = flow
            .last_report_at
            .map(|last| now.saturating_duration_since(last));
        if let Some(interval) = since_last {
            flow.receiver_interval = Some(match flow.receiver_interval {
                Some(previous) => previous.mul_f64(0.8) + interval.mul_f64(0.2),
                None => interval,
            });
        }
        flow.last_report_at = Some(now);
        flow.reports_received += 1;

        let tf = flow.frame_interval();
        let tr = flow.round_trip_time.unwrap_or_default();
        let tdr = flow.receiver_interval.unwrap_or(config.rtcp_interval);
        let sent_packets = std::mem::take(&mut flow.packets_since_report);
        let sent_bytes = std::mem::take(&mut flow.bytes_since_report);
        log::debug!(
            "circuit breaker: report on {:#x}: fraction lost {}/256, cumulative lost {}, \
             extended highest {}, jitter {}, LSR {:#x}, DLSR {}; Tr {:?} (shared {:?}), Tdr {:?}, \
             Tf {:?}, sent since last {} packets / {} bytes, report {}",
            report.ssrc,
            report.fraction_lost,
            report.total_lost,
            report.last_sequence_number,
            report.jitter,
            report.last_sender_report,
            report.delay,
            flow.round_trip_time,
            lock(&self.shared).round_trip_time,
            tdr,
            tf,
            sent_packets,
            sent_bytes,
            flow.reports_received,
        );

        // --- Media timeout (section 4.2) ---
        let timeout = media_timeout(config.non_reporting_threshold, tf, tr, tdr);
        let progressed = match flow.highest_sequence {
            Some(previous) => report.last_sequence_number > previous,
            None => true,
        };
        flow.highest_sequence = Some(
            flow.highest_sequence
                .map_or(report.last_sequence_number, |previous| {
                    previous.max(report.last_sequence_number)
                }),
        );
        let mut trip: Option<(CircuitBreakerReason, Duration)> = None;
        if progressed {
            // The media is arriving: the breaker is cancelled and set anew.
            flow.stalled_reports = 0;
            flow.media_timeout = timeout;
        } else if sent_packets > 0 || flow.stalled_reports > 0 {
            // Media was sent and the receiver did not see it. Reconsider: the timeout only
            // ever extends.
            flow.media_timeout = flow.media_timeout.max(timeout);
            flow.stalled_reports += 1;
            log::debug!(
                "circuit breaker: {:#x}: no progress, {} of MEDIA_TIMEOUT {}",
                report.ssrc,
                flow.stalled_reports,
                flow.media_timeout
            );
            if flow.stalled_reports >= flow.media_timeout {
                trip = Some((CircuitBreakerReason::MediaTimeout, tdr * flow.media_timeout));
            }
        }

        // The interval's net loss by the cumulative count (RFC 3550 6.4.1, A.3).
        let cumulative = report.cumulative_lost();
        let (net_lost, net_expected) = match flow
            .previous_report
            .replace((cumulative, report.last_sequence_number))
        {
            Some((previous_lost, previous_highest)) => (
                i64::from(cumulative) - i64::from(previous_lost),
                i64::from(report.last_sequence_number.wrapping_sub(previous_highest) as i32),
            ),
            None => (0, 0),
        };

        // --- Congestion (section 4.3) ---
        let cb_tdr = config.t_rr_interval.map_or(tdr, |t_rr| t_rr.max(tdr));
        let interval = cb_interval(
            config.frame_group_size,
            tf,
            tr,
            cb_tdr,
            config.rtcp_interval,
        );
        if let Some(duration) = since_last {
            // Only while at least one packet is sent every max(Tdr, Tr): with fewer, the
            // fraction lost is a measurement artefact.
            let period = tdr.max(tr).as_secs_f64().max(1e-3);
            let enough = sent_packets as f64 >= (duration.as_secs_f64() / period).floor().max(1.0);
            if enough {
                flow.losses.push_back(LossSample {
                    fraction_lost: f64::from(report.fraction_lost) / 256.0,
                    duration,
                    bytes_sent: sent_bytes,
                    net_lost,
                    net_expected,
                });
            } else {
                flow.losses.clear();
            }
            while flow.losses.len() > interval as usize {
                flow.losses.pop_front();
            }
        }
        if matches!(flow.state, CircuitBreakerState::Reduced { .. }) {
            flow.reports_since_reduction += 1;
        }
        let window: Duration = flow.losses.iter().map(|sample| sample.duration).sum();
        if trip.is_none()
            && flow.reports_received > u64::from(interval)
            && flow.losses.len() >= interval as usize
            && !window.is_zero()
            && let Some(tr) = flow.round_trip_time
            && let Some(packet_size) = flow.packet_size()
        {
            let average = flow
                .losses
                .iter()
                .map(|sample| sample.fraction_lost * sample.duration.as_secs_f64())
                .sum::<f64>()
                / window.as_secs_f64();
            let loss = average.min(net_loss(&flow.losses).unwrap_or(average));
            let bytes: u64 = flow.losses.iter().map(|sample| sample.bytes_sent).sum();
            let sending_rate = bytes as f64 / window.as_secs_f64();
            log::debug!(
                "circuit breaker: {:#x}: CB_INTERVAL {interval}, loss {loss:.4} over {window:?}, \
                 sending {sending_rate:.0} B/s, s {packet_size:.0} B, Tr {tr:?}, TCP {:.0} B/s",
                report.ssrc,
                tcp_throughput(packet_size, tr, loss, config.full_tcp_equation),
            );
            if loss > 0.0
                && sending_rate
                    > 10.0 * tcp_throughput(packet_size, tr, loss, config.full_tcp_equation)
            {
                match flow.state {
                    CircuitBreakerState::Running if config.reduce_before_ceasing => {
                        flow.state = CircuitBreakerState::Reduced {
                            limit_bits_per_second: sending_rate * 8.0 / 10.0,
                        };
                        flow.reports_since_reduction = 0;
                        // The next verdict is on what is sent from here on.
                        flow.losses.clear();
                        flow.reports_received = 0;
                    }
                    _ => trip = Some((CircuitBreakerReason::Congestion, window)),
                }
            } else if matches!(flow.state, CircuitBreakerState::Reduced { .. })
                && flow.reports_since_reduction >= u64::from(interval)
            {
                // The reduction resolved it.
                flow.state = CircuitBreakerState::Running;
            }
        }

        // --- Media usability (section 4.4) ---
        if let Some(usability) = config.usability {
            let unusable = f64::from(report.fraction_lost) / 256.0 > usability.max_loss
                || flow
                    .round_trip_time
                    .is_some_and(|rtt| rtt > usability.max_round_trip_time);
            if unusable {
                let since = *flow.unusable_since.get_or_insert(now);
                if trip.is_none() && now.saturating_duration_since(since) >= usability.period {
                    trip = Some((CircuitBreakerReason::MediaUnusable, usability.period));
                }
            } else {
                flow.unusable_since = None;
            }
        }

        let ssrc = report.ssrc;
        match trip {
            Some((reason, hold)) => self.cease(ssrc, reason, now, hold),
            None => self.publish(ssrc),
        }
    }

    /// Inbound RTCP: the report blocks feed the breakers, and anything at all shows the
    /// receiver and the return path are alive.
    fn on_rtcp(&mut self, now: Instant, packets: &[Box<dyn rtcp::Packet>]) {
        let mut reports = Vec::new();
        let mut has_report_packet = false;
        for packet in packets {
            let any = packet.as_any();
            if let Some(sr) = any.downcast_ref::<rtcp::sender_report::SenderReport>() {
                has_report_packet = true;
                reports.extend(sr.reports.iter().cloned());
            } else if let Some(rr) = any.downcast_ref::<rtcp::receiver_report::ReceiverReport>() {
                has_report_packet = true;
                reports.extend(rr.reports.iter().cloned());
            }
        }

        // RTCP timeout (section 4.1): a report on any SSRC this endpoint sends shows the
        // receiver and the return path work. A reduced-size packet without SR or RR counts as
        // received for this breaker too (section 5), and for this breaker only.
        let reports_on_us = reports
            .iter()
            .any(|report| self.flows.contains_key(&report.ssrc));
        if !packets.is_empty() && (!has_report_packet || reports_on_us) {
            self.awaiting_rtcp_since = None;
        }

        for report in &reports {
            self.on_report_block(now, report);
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for CircuitBreakerInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.apply_restarts();
        if let Packet::Rtcp(packets) = &msg.message.packet {
            let packets: Vec<_> = packets.to_vec();
            self.on_rtcp(msg.now, &packets);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.apply_restarts();
        match &msg.message.packet {
            Packet::Rtp(rtp_packet) => {
                let frames_kept = 4 * self.config.frame_group_size as usize;
                if let Some(flow) = self.flows.get_mut(&rtp_packet.header.ssrc) {
                    if flow.is_ceased() {
                        // Transmission has ceased (section 4.5): the packet does not leave.
                        lock(&self.shared).dropped += 1;
                        return Ok(());
                    }
                    flow.on_departure(
                        msg.now,
                        rtp_packet.header.timestamp,
                        rtp_packet.marshal_size(),
                        frames_kept,
                    );
                    self.awaiting_rtcp_since.get_or_insert(msg.now);
                }
            }
            Packet::Rtcp(packets) => {
                // The sender reports this endpoint sends: a report block's LSR names one.
                for packet in packets {
                    if let Some(sr) = packet
                        .as_any()
                        .downcast_ref::<rtcp::sender_report::SenderReport>()
                        && let Some(flow) = self.flows.get_mut(&sr.ssrc)
                    {
                        flow.sender_reports
                            .push_back(((sr.ntp_time >> 16) as u32, msg.now));
                        while flow.sender_reports.len() > REMEMBERED_SENDER_REPORTS {
                            flow.sender_reports.pop_front();
                        }
                    }
                }
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.apply_restarts();
        if let Some(since) = self.awaiting_rtcp_since
            && now.saturating_duration_since(since) >= self.rtcp_timeout()
        {
            // Media has been sent for three reporting intervals and nothing reported on it:
            // there is no way to know whether it is causing congestion (section 4.1).
            self.awaiting_rtcp_since = None;
            let hold = self.rtcp_timeout();
            let ssrcs: Vec<u32> = self
                .flows
                .iter()
                .filter(|(_, flow)| !flow.is_ceased() && flow.current_frame.is_some())
                .map(|(ssrc, _)| *ssrc)
                .collect();
            for ssrc in ssrcs {
                self.cease(ssrc, CircuitBreakerReason::RtcpTimeout, now, hold);
            }
        }
        Ok(())
    }

    /// The RTCP timeout's deadline while sent media is waiting to be reported on, `None`
    /// otherwise.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.awaiting_rtcp_since
            .map(|since| since + self.rtcp_timeout())
    }
}

impl Interceptor for CircuitBreakerInterceptor {
    /// The media SSRC and its repair flows are each a flow on the transport.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.flows.entry(ssrc).or_insert_with(Flow::new);
            self.publish(ssrc);
        }
    }

    /// Stopping a stream cancels its breakers (section 4.2).
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.flows.remove(&ssrc);
            lock(&self.shared).states.remove(&ssrc);
        }
        if self.flows.values().all(|flow| flow.current_frame.is_none()) {
            self.awaiting_rtcp_since = None;
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(seconds: f64) -> Duration {
        Duration::from_secs_f64(seconds)
    }

    /// RFC 8083 section 4.2: MEDIA_TIMEOUT = ceil(k * max(Tf, Tr, Tdr) / Tdr).
    #[test]
    fn media_timeout_is_k_reports_scaled_by_the_slowest_interval() {
        // Tdr dominates: k reports.
        assert_eq!(5, media_timeout(5, secs(0.033), secs(0.1), secs(1.0)));
        // A frame every 3 s against reports every second: 15 reports.
        assert_eq!(15, media_timeout(5, secs(3.0), secs(0.1), secs(1.0)));
        // A round trip of 1.5 reporting intervals: ceil(7.5).
        assert_eq!(8, media_timeout(5, secs(0.02), secs(1.5), secs(1.0)));
    }

    /// RFC 8083 section 4.3:
    /// CB_INTERVAL = ceil(3 * min(max(10*G*Tf, 10*Tr, 3*Tdr), max(15, 3*Td)) / (3*Tdr)).
    #[test]
    fn cb_interval_gives_the_congestion_controller_time_to_react() {
        // 30 fps, 100 ms round trip, reports every second: max(0.33, 1, 3) = 3 s, 3 reports.
        assert_eq!(
            3,
            cb_interval(1, secs(1.0 / 30.0), secs(0.1), secs(1.0), secs(5.0))
        );
        // A 600 ms round trip: 10 * Tr = 6 s, 6 reports.
        assert_eq!(
            6,
            cb_interval(1, secs(0.033), secs(0.6), secs(1.0), secs(5.0))
        );
        // A long GOP (G = 300 at 30 fps is 100 s) is capped at max(15, 3 * Td) = 15 s.
        assert_eq!(
            15,
            cb_interval(300, secs(1.0 / 30.0), secs(0.1), secs(1.0), secs(5.0))
        );
        // Reports every 5 s: 3 * Tdr = 15 s, 3 reports.
        assert_eq!(
            3,
            cb_interval(1, secs(0.033), secs(0.1), secs(5.0), secs(5.0))
        );
    }

    /// RFC 8083 section 4.3: X = s / (Tr * sqrt(2*b*p/3)), b = 1.
    #[test]
    fn the_simplified_tcp_equation_matches_the_rfc() {
        // s = 1200 bytes, Tr = 100 ms, p = 0.06: sqrt(0.04) = 0.2, so 1200 / 0.02.
        let x = tcp_throughput(1200.0, secs(0.1), 0.06, false);
        assert!((x - 60_000.0).abs() < 1e-6, "{x}");
    }

    /// RFC 8083 section 4.3 with t_RTO = 4 * Tr (section 3): the full equation is the more
    /// sensitive one, so it gives the lower throughput.
    #[test]
    fn the_full_tcp_equation_matches_the_rfc() {
        let p: f64 = 0.06;
        let tr: f64 = 0.1;
        let expected = 1200.0
            / (tr * (2.0 * p / 3.0).sqrt()
                + 4.0 * tr * (3.0 * (3.0 * p / 8.0).sqrt() * p * (1.0 + 32.0 * p * p)));
        let x = tcp_throughput(1200.0, secs(tr), p, true);
        assert!((x - expected).abs() < 1e-6, "{x} against {expected}");
        assert!(x < tcp_throughput(1200.0, secs(tr), p, false));
    }
}
